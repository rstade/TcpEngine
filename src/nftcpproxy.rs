use crate::FnProxySelectServer;
use crate::{FnProxyPayload, ProxyConnection};
use e2d2::allocators::CacheAligned;
use e2d2::interface::*;
use e2d2::operators::{merge_auto, Batch, ReceiveBatch, SchedulingPolicy};
use e2d2::queues::new_mpsc_queue_pair;
use e2d2::scheduler::StandaloneScheduler;
use std::arch::x86_64::_rdtsc;

#[cfg(feature = "profiling")]
use std::sync::atomic::Ordering;

use uuid::Uuid;

use crate::netfcts::recstore::{Extension, Store64};
use crate::netfcts::tcp_common::*;
use crate::netfcts::RunConfiguration;
use crate::netfcts::{make_reply_packet, prepare_checksum_and_ttl, remove_tcp_options, set_header, tasks};
use crate::proxymanager::ConnectionManager;

use crate::netfcts::comm::MessageFrom;
use crate::netfcts::tasks::TaskType;
use crate::profiling::Profiler;
use crate::proxy_helper::{
    client_sent_fin, forward_established_c2s, forward_established_s2c, handle_server_close_and_fin_acks,
    handle_server_rst_and_rst_acks, handle_timer_tick, ingress_classify, make_context, maybe_enable_tx_offload,
    pass_tcp_port_filter, release_if_needed, server_to_client_common, start_kni_forwarder, DelayedMode, IngressDecision, Me,
    PduAllocator, PROXY_PROF_LABELS,
};
use crate::Configuration;

// (removed unused MIN_FRAME_SIZE)

// Timer wheel configuration and overflow guard are centralized in proxy_common

/// This function actually defines the network function graph (NFG) for the application (tcp proxy) for
/// a port (@pci) and its associated kernel network port (@kni) which the current core (@core) serves.
/// The kni port provides protocol stacks of the kernel, e.g. ARP, ICMP, etc.
/// For this purpose Kni has been assigned one or more MAC and IP addresses. Kni is a Virtio port.
pub fn setup_tcp_proxy<F1, F2>(
    mut delayed_mode: Option<DelayedMode>,
    core: i32,
    pci: CacheAligned<PortQueueTxBuffered>,
    kni: CacheAligned<PortQueue>,
    sched: &mut StandaloneScheduler,
    run_configuration: RunConfiguration<Configuration, Store64<Extension>>,
    f_select_server: F1,
    f_process_payload_c_s: F2,
) where
    F1: FnProxySelectServer,
    F2: FnProxyPayload,
{
    // Build shared proxy context
    let ctx = make_context(core, &pci, &kni, sched, &run_configuration);
    let system_data = ctx.system_data.clone();
    let me = ctx.me.clone();
    let servers: Vec<L234Data> = ctx.servers.clone();
    let pipeline_id = ctx.pipeline_id.clone();
    debug!("enter setup_forwarder {}", pipeline_id);
    let tx = run_configuration.remote_sender.clone();
    let mut cm: ConnectionManager = ctx.cm;
    let timeouts = ctx.timeouts;
    let mut wheel = ctx.wheel;

    // reverse channel already set up in context
    let rx = ctx.rx_runtime;

    // forwarding frames coming from KNI to PCI
    start_kni_forwarder(sched, &kni, &pci, "Kni2Pci");

    let thread_id = format!("<c{}, rx{}>: ", core, pci.port_queue.rxq());
    let tcp_min_port = cm.tcp_port_base();
    let me_clone = me.clone();
    let tx_clone = tx.clone();
    let pipeline_ip = cm.ip();
    let pipeline_id_clone = pipeline_id.clone();
    let mut counter_c = TcpCounter::new();
    let mut counter_s = TcpCounter::new();
    #[cfg(feature = "profiling")]
    let mut profiler = { Profiler::new(PROXY_PROF_LABELS, 10_000, 100) };

    // If this mode provides a bypass consumer, install the bypass pipe task now
    // (before moving `mode` into closures below).
    if let Some(consumer) = delayed_mode.as_mut().and_then(|m| m.take_bypass_consumer()) {
        let uuid_consumer = tasks::install_task(sched, "BypassPipe", consumer.send(pci.clone()));
        tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_consumer, TaskType::BypassPipe))
            .unwrap();
    }

    // set up the generator producing timer tick packets with our private EtherType
    let (producer_timerticks, consumer_timerticks) = new_mpsc_queue_pair();
    let tick_generator = tasks::TickGenerator::new(producer_timerticks, &me.l234, system_data.cpu_clock / 100); // 10 ms
    assert!(wheel.resolution() >= tick_generator.tick_length());
    let wheel_tick_reduction_factor = wheel.resolution() / tick_generator.tick_length();
    let mut ticks = 0;
    let uuid_tick_generator = tasks::install_task(sched, "TickGenerator", tick_generator);
    tx.send(MessageFrom::Task(
        pipeline_id.clone(),
        uuid_tick_generator,
        TaskType::TickGenerator,
    ))
    .unwrap();

    let receive_pci = ReceiveBatch::new(pci.clone());
    let l2_input_stream = merge_auto(
        vec![Box::new(consumer_timerticks.set_urgent()), Box::new(receive_pci)],
        SchedulingPolicy::LongestQueue,
    );

    // group 0 -> dump packets
    // group 1 -> send to PCI
    // group 2 -> send to KNI
    let csum_offload = pci.port_queue.port.csum_offload();
    let uuid_l4groupby = Uuid::new_v4();

    #[cfg(feature = "profiling")]
    let tx_stats = pci.tx_stats();
    #[cfg(feature = "profiling")]
    let rx_stats = pci.rx_stats();

    // time_adders replaced by centralized Profiler

    #[inline]
    fn delayed_mode_on_client_syn(p: &mut Pdu, c: &mut ProxyConnection, _me: &Me) {
        // delayed-proxy behavior: capture client MAC and craft immediate SYN-ACK
        c.client_mac = p.headers().mac(0).src;
        remove_tcp_options(p);
        make_reply_packet(p, 1);
        // Generate initial seq number based on TSC
        c.c_seqn = (unsafe { _rdtsc() } << 8) as u32;
        p.headers_mut().tcp_mut(2).set_seq_num(c.c_seqn);
        c.ackn_p2c = p.headers().tcp(2).ack_num();
        prepare_checksum_and_ttl(p);
    }

    let is_delayed = delayed_mode.is_some();

    let proxy_closure =
        // this is the main closure containing the proxy service logic
        Box::new( move |pdu: &mut Pdu| {
            // this is the major closure for TCP processing
            // moved: local helpers replaced by shared trait hooks and common handlers

            // server_synack_received moved into DelayedMode::on_server_synack via trait hook

// *****  the closure starts here with processing

            #[cfg(feature = "profiling")]
            let timestamp_entry = profiler.start();

            let b_private_etype = match ingress_classify(pdu, &me, pipeline_ip) {
                IngressDecision::Drop => return 0,
                IngressDecision::ToKni => return 2,
                IngressDecision::Continue { b_private_etype } => b_private_etype,
            };

            maybe_enable_tx_offload(pdu, csum_offload);
            let mut group_index = 0usize; // the index of the group to be returned, default 0: dump packet


            //check ports
            if !pass_tcp_port_filter(pdu, &me_clone, tcp_min_port, b_private_etype) {
                return 2;
            }


            let ethertype = pdu.headers().mac(0).etype();


            // if set by the following tcp state machine,
            // the port/connection becomes released afterwards
            // this is cumbersome, but we must make the  borrow checker happy
            let mut release_connection = None;
            // check if we got a packet from generator
            match ethertype {
                tasks::PRIVATE_ETYPE_PACKET => {}
                tasks::PRIVATE_ETYPE_TIMER => {
                    #[cfg(feature = "profiling")]
                    let mut profiler_opt = Some(&mut profiler);
                    #[cfg(not(feature = "profiling"))]
                    let mut profiler_opt: Option<&mut Profiler> = None;

                    #[cfg(feature = "profiling")]
                    let rx_now = Some(rx_stats.stats.load(Ordering::Relaxed) as u64);
                    #[cfg(not(feature = "profiling"))]
                    let rx_now: Option<u64> = None;

                    #[cfg(feature = "profiling")]
                    let tx_now = Some(tx_stats.stats.load(Ordering::Relaxed) as u64);
                    #[cfg(not(feature = "profiling"))]
                    let tx_now: Option<u64> = None;

                    handle_timer_tick(
                        &mut ticks,
                        wheel_tick_reduction_factor,
                        &mut cm,
                        &mut wheel,
                        &rx,
                        &tx_clone,
                        &pipeline_id_clone,
                        &counter_c,
                        &counter_s,
                        profiler_opt.as_deref_mut(),
                        rx_now,
                        tx_now,
                    );
                }
                _ => {
                    // We use a clone for reading tcp header to avoid immutable borrow.
                    // But attention, this clone does not update, when we change the original header!
                    let tcp = pdu.headers().tcp(2).clone();
                    let src_sock = (pdu.headers().ip(1).src(), tcp.src_port());

                    if tcp.dst_port() == me.l234.port {
                        //trace!("client to server");
                        let opt_c = if tcp.syn_flag() {
                            let c = cm.get_mut_or_insert(&src_sock);
                            #[cfg(feature = "profiling")]
                            profiler.add_diff(0, timestamp_entry);
                            c
                        } else {
                            let c = cm.get_mut_by_sock(&src_sock);
                            #[cfg(feature = "profiling")]
                            profiler.add_diff(8, timestamp_entry);
                            c
                        };


                        if opt_c.is_none() {
                            warn!("{} unexpected client side packet: no state for socket ({}, {}), tcp= {}, discarding", thread_id, src_sock.0, src_sock.1, tcp);
                        } else {
                            let mut c = opt_c.unwrap();

                            let old_s_state = c.server_state().clone();
                            let old_c_state = c.client_state().clone();

                            //check seqn
                            if old_c_state != TcpState::Closed && tcp.seq_num() < c.ackn_p2c {
                                let diff = tcp.seq_num() as i64 - c.ackn_p2c as i64;
                                //  a re-sent packet ?
                                debug!("{} state= {:?}, diff= {}, tcp= {}", thread_id, old_s_state, diff, tcp);
                            } else if tcp.syn_flag() {
                                if old_c_state == TcpState::Closed {
                                    if (is_delayed) {
                                        delayed_mode_on_client_syn(pdu, &mut c, &me);
                                        trace!("{} (SYN-)ACK to client, L3: { }, L4: { }", thread_id, pdu.headers().ip(1), pdu.headers().tcp(2));
                                        counter_c[TcpStatistics::SentSynAck] += 1;
                                    }
                                    else { // simple mode
                                        // save client MAC for return packets
                                        c.client_mac = pdu.headers().mac(0).src;
                                        // select server
                                        f_select_server(c, &servers);
                                        // and forward SYN
                                        set_header(&servers[c.server_index()], c.port(), pdu, &me.l234.mac, me.ip_s);
                                        prepare_checksum_and_ttl(pdu);
                                        c.s_push_state(TcpState::SynReceived);
                                        counter_s[TcpStatistics::SentSyn] += 1;
                                        trace!("{} forward SYN to server, L3: { }, L4: { }", thread_id, pdu.headers().ip(1), pdu.headers().tcp(2));
                                    }
                                    c.c_push_state(TcpState::SynSent);
                                    counter_c[TcpStatistics::RecvSyn] += 1;
                                    c.wheel_slot_and_index = wheel.schedule(&(timeouts.established.unwrap() * system_data.cpu_clock / 1000), c.port());
                                    group_index = 1;
                                } else {
                                    warn!("received client SYN in state {:?}/{:?}, {:?}/{:?}, {}", old_c_state, old_s_state, c.c_states(), c.s_states(), tcp);
                                }
                                #[cfg(feature = "profiling")]
                                profiler.add_diff(2, timestamp_entry);
                            } else if tcp.ack_flag() && old_c_state == TcpState::SynSent {
                                c.c_push_state(TcpState::Established);
                                counter_c[TcpStatistics::RecvSynAck2] += 1;
                                if(!is_delayed) {
                                    counter_s[TcpStatistics::SentSynAck2] += 1;    // in simple mode pass through to server
                                    set_header(&servers[c.server_index()], c.port(), pdu, &me.l234.mac, me.ip_s);
                                    c.s_push_state(TcpState::Established);
                                    c.c_push_state(TcpState::Established);
                                    prepare_checksum_and_ttl(pdu);
                                    group_index = 1;
                                }
                                #[cfg(feature = "profiling")]
                                profiler.add_diff(4, timestamp_entry);
                            } else if tcp.fin_flag() {
                                client_sent_fin(&tcp, old_s_state, pdu, c, &mut counter_c, &mut counter_s );
                                 group_index = 1;
                            } else if tcp.rst_flag() {
                                trace!("received RST");
                                counter_c[TcpStatistics::RecvRst] += 1;
                                c.c_push_state(TcpState::Closed);
                                c.set_release_cause(ReleaseCause::ActiveRst);
                                release_connection = Some(c.port());
                            } else if tcp.ack_flag() && tcp.ack_num() == unsafe { c.seqn.ack_for_fin_p2c } && old_s_state >= TcpState::FinWait1 {
                                // ACK from client for FIN of Server
                                trace!(
                                    "{}  ACK from client, src_port= {}, old_s_state = {:?}",
                                    thread_id,
                                    tcp.src_port(),
                                    old_s_state,
                                );
                                match old_s_state {
                                    TcpState::FinWait1 => { c.s_push_state(TcpState::FinWait2); }
                                    TcpState::Closing => { c.s_push_state(TcpState::Closed); }
                                    _ => {}
                                }
                                match old_c_state {
                                    TcpState::Established => { c.c_push_state(TcpState::CloseWait) }
                                    TcpState::FinWait1 => { c.c_push_state(TcpState::Closing) }
                                    TcpState::FinWait2 => { c.c_push_state(TcpState::Closed) }
                                    _ => {}
                                }
                                counter_c[TcpStatistics::RecvAck4Fin] += 1;
                                counter_s[TcpStatistics::SentAck4Fin] += 1;
                            } else if old_s_state == TcpState::LastAck && tcp.ack_flag() && tcp.ack_num() == unsafe { c.seqn.ack_for_fin_p2c } {
                                // received final ack from client for client initiated close
                                trace!(
                                    "{} received final ACK for client initiated close on port {}/{}",
                                    thread_id,
                                    tcp.src_port(),
                                    c.port(),
                                );
                                c.s_push_state(TcpState::Closed);
                                c.c_push_state(TcpState::Closed);
                                counter_c[TcpStatistics::RecvAck4Fin] += 1;
                                counter_s[TcpStatistics::SentAck4Fin] += 1;
                            } else if is_delayed && old_c_state == TcpState::Established
                                && old_s_state == TcpState::Listen {
                                // should be the first payload packet from client
                                counter_c[TcpStatistics::RecvPayload] += tcp_payload_size(pdu);
                                // local select_server moved into DelayedMode::select_server via trait hook
                                // selects the server by calling the closure, sends SYN to server
                                delayed_mode.as_mut().unwrap().select_server(pdu, &mut c, &me, &servers, &f_select_server);
                                //trace!("after  select_server: p.refcnt = {}, packet_in.refcnt() = {}", pdu.refcnt(), pdu_in.refcnt());
                                debug!("{} SYN packet to server - L3: {}, L4: {}", thread_id, pdu.headers().ip(1), pdu.headers().tcp(2));
                                c.s_init();
                                c.s_push_state(TcpState::SynReceived);
                                counter_s[TcpStatistics::SentSyn] += 1;
                                group_index = 1;
                                #[cfg(feature = "profiling")]
                                profiler.add_diff(5, timestamp_entry);
                            } else if old_s_state < TcpState::SynReceived || old_c_state < TcpState::Established {
                                warn!(
                                    "{} unexpected client-side TCP packet on port {}/{} in client/server state {:?}/{:?}, sending to KNI i/f",
                                    thread_id,
                                    tcp.src_port(),
                                    c.port(),
                                    c.c_states(),
                                    c.s_states(),
                                );
                                counter_c[TcpStatistics::Unexpected] += 1;
                                group_index = 2;
                            } else {
                                trace! {"c2s: nothing to do?, tcp= {}, tcp_payload_size={}, expected ackn_for_fin ={}", tcp, tcp_payload_size(pdu), unsafe { c.seqn.ack_for_fin_p2c }}
                            }

                            if c.client_state() == TcpState::Closed && c.server_state() == TcpState::Closed {
                                release_connection = Some(c.port());
                            }

                            // once we established a two-way e2e-connection, we always forward the packets
                            if old_s_state >= TcpState::Established && old_s_state < TcpState::Closed
                                && old_c_state >= TcpState::Established {
                                // concise single call: prepare optional profiling args
                                #[cfg(feature = "profiling")]
                                let (mut prof_opt_c2s, label_c2s, ts_c2s) = (Some(&mut profiler), Some(6usize), Some(timestamp_entry));
                                #[cfg(not(feature = "profiling"))]
                                let (mut prof_opt_c2s, label_c2s, ts_c2s): (Option<&mut Profiler>, Option<usize>, Option<u64>) = (None, None, None);

                                forward_established_c2s(
                                    pdu,
                                    &mut c,
                                    &me,
                                    &servers,
                                    &f_process_payload_c_s,
                                    &f_select_server,
                                    &mut counter_c,
                                    &mut counter_s,
                                    prof_opt_c2s.as_deref_mut(),
                                    label_c2s,
                                    ts_c2s,
                                );
                                group_index = 1;
                            }
                        }
                    } else {
                        // server to client
                        {
                            debug!("looking up state for server side port { }", tcp.dst_port());
                            let mut c = cm.get_mut_by_port(tcp.dst_port());
                            #[cfg(feature = "profiling")]
                            profiler.add_diff(1, timestamp_entry);

                            if c.is_some() {
                                let mut c = c.as_mut().unwrap();
                                let mut b_unexpected = false;
                                let old_s_state = c.server_state();
                                let old_c_state = c.client_state();
                                // **** received SYN+ACK from server
                                if tcp.ack_flag() && tcp.syn_flag() {
                                    counter_s[TcpStatistics::RecvSynAck] += 1;
                                    if old_s_state == TcpState::SynReceived {
                                        if(is_delayed) {
                                            c.s_push_state(TcpState::Established);
                                            debug!("{} established two-way client server connection, SYN-ACK received: L3: {}, L4: {}", thread_id, pdu.headers().ip(1), tcp);
                                            let payload_size = delayed_mode.as_mut().unwrap().on_server_synack(pdu, &mut c);
                                            counter_s[TcpStatistics::SentPayload] += payload_size;
                                            counter_s[TcpStatistics::SentSynAck2] += 1;
                                            group_index = 0; // delayed payload packets are sent via extra queue
                                        }
                                        else {
                                            // ****  valid SYN+ACK received from server
                                            debug!("{}  SYN-ACK received from server : L3: {}, L4: {}", thread_id, pdu.headers().ip(1), tcp);
                                            // translate packet and forward to client
                                            server_to_client_common(pdu, &mut c, &me);
                                            counter_c[TcpStatistics::SentSynAck] += 1;
                                            group_index = 1;
                                        }
                                    } else {
                                        warn!("{} received SYN-ACK in wrong state: {:?}", thread_id, old_s_state);
                                        group_index = 0;
                                    }
                                    #[cfg(feature = "profiling")]
                                    profiler.add_diff(3, timestamp_entry);
                                } else if handle_server_close_and_fin_acks(&tcp, &mut c, old_c_state, old_s_state, &mut counter_c, &mut counter_s, &thread_id) {
                                    // handled by common helper
                                } else if handle_server_rst_and_rst_acks(&tcp, &mut c, old_c_state, old_s_state, &mut counter_c, &mut counter_s, &thread_id) {
                                    server_to_client_common(pdu, &mut c, &ctx.me);
                                    // handled by common helper
                                }
                                else {
                                    debug!("received from server { } in c/s state {:?}/{:?} ", tcp, c.c_states(), c.s_states());
                                    b_unexpected = true; //  may still be revised, see below
                                }

                                if c.client_state() == TcpState::Closed && c.server_state() == TcpState::Closed {
                                    release_connection = Some(c.port());
                                }

                                // once we established a two-way e-2-e connection, we always forward server side packets
                                if old_s_state >= TcpState::Established
                                    && old_c_state >= TcpState::Established
                                    && old_c_state < TcpState::Closed {
                                    // concise single call: prepare optional profiling args
                                    #[cfg(feature = "profiling")]
                                    let (mut prof_opt_s2c, label_s2c, ts_s2c) = (Some(&mut profiler), Some(7usize), Some(timestamp_entry));
                                    #[cfg(not(feature = "profiling"))]
                                    let (mut prof_opt_s2c, label_s2c, ts_s2c): (Option<&mut Profiler>, Option<usize>, Option<u64>) = (None, None, None);

                                    forward_established_s2c(
                                        pdu,
                                        &mut c,
                                        &me,
                                        &mut counter_c,
                                        &mut counter_s,
                                        prof_opt_s2c.as_deref_mut(),
                                        label_s2c,
                                        ts_s2c,
                                    );
                                    group_index = 1;
                                    b_unexpected = false;
                                }

                                if b_unexpected {
                                    warn!(
                                        "{} unexpected server side TCP packet on port {}/{} in client/server state {:?}/{:?}, sending to KNI i/f",
                                        thread_id,
                                        tcp.dst_port(),
                                        c.sock().unwrap().1,
                                        c.c_states(),
                                        c.s_states(),
                                    );
                                    group_index = 2;
                                }
                            } else {
                                warn!("{} unexpected server side packet: no state on port {}, sending to KNI i/f", thread_id, tcp.dst_port());
                                // we send this to KNI which handles out-of-order TCP, e.g. by sending RST
                                group_index = 2;
                            }
                        }
                    }
                }
            }
            // here we check if we shall release the connection state,
            // required because of borrow checker for the state manager sm
            release_if_needed(&mut cm, &mut wheel, &mut release_connection);
            group_index
        });

    let mut l4groups = l2_input_stream.group_by(3, proxy_closure, sched, "L4-Groups".to_string(), uuid_l4groupby);

    let pipe2kni = l4groups.get_group(2).unwrap().send(kni.clone());
    let l4pciflow = l4groups.get_group(1).unwrap();
    let l4dumpflow = l4groups.get_group(0).unwrap().drop();
    let pipe2pci = merge_auto(
        vec![Box::new(l4pciflow), Box::new(l4dumpflow)],
        SchedulingPolicy::LongestQueue,
    )
    .send(pci.clone());

    let uuid_pipe2kni = tasks::install_task(sched, "Pipe2Kni", pipe2kni);
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_pipe2kni, TaskType::Pipe2Kni))
        .unwrap();

    let uuid_pipe2pic = tasks::install_task(sched, "Pipe2Pci", pipe2pci);
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_pipe2pic, TaskType::Pipe2Pci))
        .unwrap();
}
