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
    client_sent_fin, forward_established_c2s, forward_established_s2c, handle_timer_tick, ingress_classify,
    make_context, maybe_enable_tx_offload, pass_tcp_port_filter, release_if_needed, server_to_client_common,
    start_kni_forwarder, DelayedMode, IngressDecision, Me, PROXY_PROF_LABELS,
};
use crate::Configuration;

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
                    let tcp_flags = TcpFlags::from_tcp_header(&tcp);

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
                            } else {
                                match (old_c_state, old_s_state, tcp_flags, is_delayed) {

                                    // SYN in CLOSED state - connection initiation, delayed mode
                                    (TcpState::Closed, _, TcpFlags::Syn, true) => {
                                        delayed_mode_on_client_syn(pdu, &mut c, &me);
                                        trace!("{} (SYN-)ACK to client, L3: { }, L4: { }", thread_id, pdu.headers().ip(1), pdu.headers().tcp(2));
                                        counter_c[TcpStatistics::SentSynAck] += 1;
                                        c.c_push_state(TcpState::SynSent);
                                        counter_c[TcpStatistics::RecvSyn] += 1;
                                        c.wheel_slot_and_index = wheel.schedule(&(timeouts.established.unwrap() * system_data.cpu_clock / 1000), c.port());
                                        group_index = 1;
                                        #[cfg(feature = "profiling")]
                                        profiler.add_diff(2, timestamp_entry);
                                    }

                                    // SYN in CLOSED state - connection initiation, simple mode
                                    (TcpState::Closed, _, TcpFlags::Syn, false) => {
                                        c.client_mac = pdu.headers().mac(0).src;
                                        f_select_server(c, &servers);
                                        set_header(&servers[c.server_index()], c.port(), pdu, &me.l234.mac, me.ip_s);
                                        prepare_checksum_and_ttl(pdu);
                                        c.s_push_state(TcpState::SynReceived);
                                        counter_s[TcpStatistics::SentSyn] += 1;
                                        trace!("{} forward SYN to server, L3: { }, L4: { }", thread_id, pdu.headers().ip(1), pdu.headers().tcp(2));
                                        c.c_push_state(TcpState::SynSent);
                                        counter_c[TcpStatistics::RecvSyn] += 1;
                                        c.wheel_slot_and_index = wheel.schedule(&(timeouts.established.unwrap() * system_data.cpu_clock / 1000), c.port());
                                        group_index = 1;
                                        #[cfg(feature = "profiling")]
                                        profiler.add_diff(2, timestamp_entry);
                                    }

                                    // SYN not in CLOSED state
                                    (_, _, TcpFlags::Syn, _) => {
                                        warn!("received client SYN in state {:?}/{:?}, {:?}/{:?}, {}", old_c_state, old_s_state, c.c_states(), c.s_states(), tcp);
                                    }

                                    // ACK after SYN-SYN/ACK handshake
                                    (TcpState::SynSent, _, TcpFlags::Ack, _) => {
                                        c.c_push_state(TcpState::Established);
                                        counter_c[TcpStatistics::RecvSynAck2] += 1;
                                        if !is_delayed {
                                            counter_s[TcpStatistics::SentSynAck2] += 1;
                                            set_header(&servers[c.server_index()], c.port(), pdu, &me.l234.mac, me.ip_s);
                                            c.s_push_state(TcpState::Established);
                                            prepare_checksum_and_ttl(pdu);
                                            group_index = 1;
                                        }
                                        #[cfg(feature = "profiling")]
                                        profiler.add_diff(4, timestamp_entry);
                                    }

                                    // FIN received - connection teardown
                                    (_, old_s, TcpFlags::Fin | TcpFlags::FinAck, _) => {
                                        client_sent_fin(&tcp, old_s, pdu, c, &mut counter_c, &mut counter_s);
                                        group_index = 1;
                                    }

                                    // RST received - abrupt connection close
                                    (_, _, TcpFlags::Rst, _) => {
                                        trace!("received RST");
                                        counter_c[TcpStatistics::RecvRst] += 1;
                                        c.c_push_state(TcpState::Closed);
                                        c.set_release_cause(ReleaseCause::ActiveRst);
                                        release_connection = Some(c.port());
                                    }

                                    // ACK from client for server's FIN
                                    (_, TcpState::FinWait1 | TcpState::Closing | TcpState::FinWait2 | TcpState::Closed, TcpFlags::Ack, _)
                                    if tcp.ack_num() == unsafe { c.seqn.ack_for_fin_p2c } => {
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
                                    }

                                    // Final ACK in LastAck state
                                    (_, TcpState::LastAck, TcpFlags::Ack, _)
                                    if tcp.ack_num() == unsafe { c.seqn.ack_for_fin_p2c } => {
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
                                    }

                                    // First payload in delayed mode
                                    (TcpState::Established, TcpState::Listen, _, true) => {
                                        counter_c[TcpStatistics::RecvPayload] += tcp_payload_size(pdu);
                                        delayed_mode.as_mut().unwrap().select_server(pdu, &mut c, &me, &servers, &f_select_server);
                                        c.s_init();
                                        c.s_push_state(TcpState::SynReceived);
                                        counter_s[TcpStatistics::SentSyn] += 1;
                                        group_index = 1;
                                        #[cfg(feature = "profiling")]
                                        profiler.add_diff(5, timestamp_entry);
                                    }

                                    // Unexpected packet in non-established states
                                    (c_state, s_state, _, _) if s_state < TcpState::SynReceived || c_state < TcpState::Established => {
                                        warn!(
                                            "{} unexpected client-side TCP packet on port {}/{} in client/server state {:?}/{:?}",
                                            thread_id, tcp.src_port(), c.port(), c.c_states(), c.s_states()
                                        );
                                        counter_c[TcpStatistics::Unexpected] += 1;
                                        group_index = 2;
                                    }

                                    // Default case
                                    _ => {
                                        trace!("c2s: nothing to do?, tcp= {}, tcp_payload_size={}", tcp, tcp_payload_size(pdu));
                                    }
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
                        }
                    } else {
                        // server to client

                        debug!("looking up state for server side port { }", tcp.dst_port());
                        let mut c = cm.get_mut_by_port(tcp.dst_port());
                        #[cfg(feature = "profiling")]
                        profiler.add_diff(1, timestamp_entry);

                        if c.is_some() {
                            let mut c = c.as_mut().unwrap();
                            let mut b_unexpected = false;
                            let old_s_state = c.server_state();
                            let old_c_state = c.client_state();

                            if tcp.ack_flag() && tcp.syn_flag() {
                                counter_s[TcpStatistics::RecvSynAck] += 1;
                            }

                            match (old_c_state, old_s_state, tcp_flags, is_delayed) {
                                // SYN-ACK from server - delayed mode
                                (_, TcpState::SynReceived, TcpFlags::SynAck, true) => {
                                    c.s_push_state(TcpState::Established);
                                    debug!("{} established two-way client server connection, SYN-ACK received: L3: {}, L4: {}", thread_id, pdu.headers().ip(1), tcp);
                                    let payload_size = delayed_mode.as_mut().unwrap().on_server_synack(pdu, &mut c);
                                    counter_s[TcpStatistics::SentPayload] += payload_size;
                                    counter_s[TcpStatistics::SentSynAck2] += 1;
                                    group_index = 0;
                                    #[cfg(feature = "profiling")]
                                    profiler.add_diff(3, timestamp_entry);
                                }

                                // SYN-ACK from server - simple mode
                                (_, TcpState::SynReceived, TcpFlags::SynAck, false) => {
                                    debug!("{}  SYN-ACK received from server : L3: {}, L4: {}", thread_id, pdu.headers().ip(1), tcp);
                                    server_to_client_common(pdu, &mut c, &me);  // translate packet and forward to client
                                    counter_c[TcpStatistics::SentSynAck] += 1;
                                    group_index = 1;
                                    #[cfg(feature = "profiling")]
                                    profiler.add_diff(3, timestamp_entry);
                                }

                                // SYN-ACK in wrong state
                                (_, _, TcpFlags::SynAck, _) => {
                                    warn!("{} received SYN-ACK in wrong state: {:?}", thread_id, old_s_state);
                                    #[cfg(feature = "profiling")]
                                    profiler.add_diff(3, timestamp_entry);
                                    group_index = 0;
                                }

                                // Server FIN-ACK reply after client initiated close (client in FinWait1+)
                                (c_state, _, TcpFlags::FinAck, _)
                                    if c_state >= TcpState::FinWait1
                                    && tcp.ack_num() == c.seqn_fin_p2s.wrapping_add(1) => {
                                    counter_s[TcpStatistics::RecvFinPssv] += 1;
                                    counter_c[TcpStatistics::SentFinPssv] += 1;
                                    counter_s[TcpStatistics::RecvAck4Fin] += 1;
                                    counter_c[TcpStatistics::SentAck4Fin] += 1;
                                    trace!("{} received FIN-reply from server on proxy port {}", thread_id, tcp.dst_port());
                                    c.s_set_release_cause(ReleaseCause::PassiveClose);
                                    c.s_push_state(TcpState::LastAck);
                                }

                                // Server FIN (simultaneous close) while client closing (client in FinWait1+)
                                (TcpState::FinWait1, _, TcpFlags::Fin, _) => {
                                    trace!("simultaneous active close from server on port {}", tcp.dst_port());
                                    counter_s[TcpStatistics::RecvFin] += 1;
                                    counter_c[TcpStatistics::SentFin] += 1;
                                    c.s_set_release_cause(ReleaseCause::ActiveClose);
                                    c.s_push_state(TcpState::Closing);
                                    c.c_push_state(TcpState::Closing);
                                }

                                // Server FIN (simultaneous close) while client in FinWait2
                                (TcpState::FinWait2, _, TcpFlags::Fin, _) => {
                                    trace!("simultaneous active close from server on port {}", tcp.dst_port());
                                    counter_s[TcpStatistics::RecvFin] += 1;
                                    counter_c[TcpStatistics::SentFin] += 1;
                                    c.s_set_release_cause(ReleaseCause::ActiveClose);
                                    c.s_push_state(TcpState::Closing);
                                    c.c_push_state(TcpState::Closed);
                                }

                                // Server FIN (simultaneous close) - other client tcp states
                                (c_state, _, TcpFlags::Fin, _) if c_state >= TcpState::FinWait1 => {
                                    trace!("simultaneous active close from server on port {}", tcp.dst_port());
                                    counter_s[TcpStatistics::RecvFin] += 1;
                                    counter_c[TcpStatistics::SentFin] += 1;
                                    c.s_set_release_cause(ReleaseCause::ActiveClose);
                                    c.s_push_state(TcpState::Closing);
                                }

                                // Server initiated close (FIN) - client not closing yet
                                (_, _, TcpFlags::Fin | TcpFlags::FinAck, _) => {
                                    trace!(
                                        "{} server closes connection on port {}/{} in state {:?}",
                                        thread_id,
                                        tcp.dst_port(),
                                        c.sock().unwrap().1,
                                        c.s_states(),
                                    );
                                    c.s_push_state(TcpState::FinWait1);
                                    c.s_set_release_cause(ReleaseCause::ActiveClose);
                                    counter_s[TcpStatistics::RecvFin] += 1;
                                    counter_c[TcpStatistics::SentFin] += 1;
                                }

                                // ACK from server for client's FIN - LastAck state
                                (TcpState::LastAck, _, TcpFlags::Ack, _)
                                    if tcp.ack_num() == c.seqn_fin_p2s.wrapping_add(1) => {
                                    c.c_push_state(TcpState::Closed);
                                    c.s_push_state(TcpState::Closed);
                                    counter_s[TcpStatistics::RecvAck4Fin] += 1;
                                    counter_c[TcpStatistics::SentAck4Fin] += 1;
                                    trace!("{} on proxy port {} transition to client/server state {:?}/{:?}",
                                        thread_id, c.port(), c.c_states(), c.s_states());
                                }

                                // ACK from server for client's FIN - FinWait1 state
                                (TcpState::FinWait1, _, TcpFlags::Ack, _)
                                    if tcp.ack_num() == c.seqn_fin_p2s.wrapping_add(1) => {
                                    c.c_push_state(TcpState::FinWait2);
                                    counter_s[TcpStatistics::RecvAck4Fin] += 1;
                                    counter_c[TcpStatistics::SentAck4Fin] += 1;
                                    trace!("{} on proxy port {} transition to client/server state {:?}/{:?}",
                                        thread_id, c.port(), c.c_states(), c.s_states());
                                }

                                // ACK from server for client's FIN - Closing state
                                (TcpState::Closing, _, TcpFlags::Ack, _)
                                    if tcp.ack_num() == c.seqn_fin_p2s.wrapping_add(1) => {
                                    c.c_push_state(TcpState::Closed);
                                    counter_s[TcpStatistics::RecvAck4Fin] += 1;
                                    counter_c[TcpStatistics::SentAck4Fin] += 1;
                                    trace!("{} on proxy port {} transition to client/server state {:?}/{:?}",
                                        thread_id, c.port(), c.c_states(), c.s_states());
                                }

                                // Server RST
                                (_, _, TcpFlags::Rst, _) => {
                                    counter_s[TcpStatistics::RecvRst] += 1;
                                    server_to_client_common(pdu, &mut c, &me);
                                    group_index = 1;
                                }

                                // All other cases
                                _ => {
                                    debug!("received from server { } in c/s state {:?}/{:?} ", tcp, c.c_states(), c.s_states());
                                    b_unexpected = true; //  may still be revised, see below
                                }
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
                        }
                        else {
                            warn!("{} unexpected server side packet: no state on port {}, sending to KNI i/f", thread_id, tcp.dst_port());
                            // we send this to KNI which handles out-of-order TCP, e.g. by sending RST
                            group_index = 2;
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
