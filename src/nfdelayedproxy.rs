use crate::FnProxyPayload;
use crate::FnProxySelectServer;
use e2d2::operators::{ReceiveBatch, Batch, merge_auto, SchedulingPolicy};
use e2d2::scheduler::StandaloneScheduler;
use e2d2::allocators::CacheAligned;
use e2d2::interface::*;
use e2d2::queues::new_mpsc_queue_pair;

#[cfg(feature = "profiling")]
use std::sync::atomic::Ordering;
use std::arch::x86_64::_rdtsc;

use uuid::Uuid;

use crate::proxymanager::ConnectionManager;
use crate::netfcts::tcp_common::*;
use crate::netfcts::tasks;
use crate::netfcts::tasks::private_etype;
use crate::netfcts::{prepare_checksum_and_ttl, RunConfiguration, make_reply_packet};
use crate::netfcts::recstore::{Extension, Store64};

#[cfg(feature = "profiling")]
use netfcts::utils::TimeAdder;

use crate::Configuration;
use crate::netfcts::comm::{ MessageFrom, MessageTo };
use crate::netfcts::tasks::TaskType;

use crate::proxy_common::{start_kni_forwarder, PduAllocator, make_context, DelayedMode, client_to_server_common, server_to_client_common, ProxyMode};

// (removed unused MIN_FRAME_SIZE)

// Timer wheel configuration and overflow guard are centralized in proxy_common

/// This function actually defines the network function graph (NFG) for the application (tcp proxy) for
/// a port (@pci) and its associated kernel network port (@kni) which the current core (@core) serves.
/// The kni port is used to utilize protocol stacks of the kernel, e.g. ARP, ICMP, etc.
/// For this purpose Kni has been assigned one or more MAC and IP addresses. Kni may be either a native Kni or a Virtio port.
pub fn setup_delayed_proxy<F1, F2>(
    core: i32,
    pci: CacheAligned<PortQueueTxBuffered>,
    kni: CacheAligned<PortQueue>,
    sched: &mut StandaloneScheduler,
    run_configuration: RunConfiguration<Configuration,Store64<Extension>>,
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

    // we need this queue pair for the delayed bindrequest
    let (producer, consumer) = new_mpsc_queue_pair();

    // reverse channel already set up in context
    let rx = ctx.rx_runtime;

    // forwarding frames coming from KNI to PCI
    start_kni_forwarder(sched, &kni, &pci, "Kni2Pci");

    // Initialize delayed mode with its own PDU allocator (used for crafting packets as needed)
    let mut mode = DelayedMode { pdu_allocator: PduAllocator::new(), producer: producer.clone() };
    let thread_id = format!("<c{}, rx{}>: ", core, pci.port_queue.rxq());
    let tcp_min_port = cm.tcp_port_base();
    let me_clone = me.clone();
    let tx_clone = tx.clone();
    let pipeline_ip = cm.ip();
    let pipeline_id_clone = pipeline_id.clone();
    let mut counter_c = TcpCounter::new();
    let mut counter_s = TcpCounter::new();
    #[cfg(feature = "profiling")]
        let mut rx_tx_stats = Vec::with_capacity(10000);

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

    #[cfg(feature = "profiling")]
        let mut time_adders;
    #[cfg(feature = "profiling")]
    {
        let sample_size = 100000 as u64;
        let warm_up = 100 as u64;
        time_adders = [
            TimeAdder::new_with_warm_up("c_cmanager_syn", sample_size, warm_up),
            TimeAdder::new_with_warm_up("s_cmanager", sample_size * 2, warm_up),
            TimeAdder::new_with_warm_up("c_recv_syn", sample_size, warm_up),
            TimeAdder::new_with_warm_up("s_recv_syn_ack", sample_size, warm_up),
            TimeAdder::new_with_warm_up("c_recv_syn_ack2", sample_size, warm_up),
            TimeAdder::new_with_warm_up("c_recv_1_payload", sample_size, warm_up),
            TimeAdder::new_with_warm_up("c2s_stable", sample_size, warm_up),
            TimeAdder::new_with_warm_up("s2c_stable", sample_size, warm_up),
            TimeAdder::new_with_warm_up("c_cmanager_not_syn", sample_size * 2, warm_up),
            TimeAdder::new_with_warm_up("", sample_size, warm_up),
            TimeAdder::new_with_warm_up("", sample_size, warm_up),
            TimeAdder::new_with_warm_up("", sample_size, warm_up),
        ];
    }

    let delayed_binding_closure =
        // this is the main closure containing the proxy service logic
        Box::new( move |pdu: &mut Pdu| {
            // this is the major closure for TCP processing

            // moved: local helpers replaced by shared trait hooks and common handlers

            /// attention: after calling select_server, p points to a different mbuf and has different headers
            /// selects the server by calling the closure, sends SYN to server
            // local select_server moved into DelayedMode::select_server via trait hook

            // server_synack_received moved into DelayedMode::on_server_synack via trait hook

// *****  the closure starts here with processing

            #[cfg(feature = "profiling")]
                let timestamp_entry = unsafe { _rdtsc() };

            let b_private_etype;
            {
                let mac_header = pdu.headers().mac(0);
                b_private_etype = private_etype(&mac_header.etype());
                if !b_private_etype {
                    if mac_header.dst != me.l234.mac && !mac_header.dst.is_multicast() && !mac_header.dst.is_broadcast() {
                        debug!("{} from pci: discarding because mac unknown: {} ", thread_id, mac_header);
                        return 0;
                    }
                    if mac_header.etype() != 0x0800 && !b_private_etype {
                        // everything other than Ipv4 or our own packets we send to KNI, i.e. group 2
                        return 2;
                    }
                }
            }

            {
                let ip_header = pdu.headers().ip(1);
                if !b_private_etype {
                    // everything other than TCP, and everything not addressed to us we send to KNI, i.e. group 2
                    if ip_header.protocol() != 6 || ip_header.dst() != pipeline_ip && ip_header.dst() != me.l234.ip {
                        return 2;
                    }
                }
            }

            if csum_offload {
                pdu.set_tcp_ipv4_checksum_tx_offload();
            }
            let mut group_index = 0usize; // the index of the group to be returned, default 0: dump packet


            //check ports
            if !b_private_etype && pdu.headers().tcp(2).dst_port() != me_clone.l234.port && pdu.headers().tcp(2).dst_port() < tcp_min_port {
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
                    ticks += 1;
                    match rx.try_recv() {
                        Ok(MessageTo::FetchCounter) => {
                            debug!("{}: received FetchCounter", pipeline_id_clone);
                            #[cfg(feature = "profiling")]
                            tx_clone
                                .send(MessageFrom::Counter(
                                    pipeline_id_clone.clone(),
                                    counter_c.clone(),
                                    counter_s.clone(),
                                    Some(rx_tx_stats.clone()),
                                )).unwrap();
                            #[cfg(not(feature = "profiling"))]
                            tx_clone
                                .send(MessageFrom::Counter(
                                    pipeline_id_clone.clone(),
                                    counter_c.clone(),
                                    counter_s.clone(),
                                    None,
                                )).unwrap();
                        }
                        Ok(MessageTo::FetchCRecords) => {
                            let c_recs = cm.fetch_c_records();
                            debug!("{}: received FetchCRecords, returning {} records", pipeline_id_clone, if c_recs.is_some() { c_recs.as_ref().unwrap().len() } else { 0 });
                            tx_clone
                                .send(MessageFrom::CRecords(pipeline_id_clone.clone(), c_recs, None))
                                .unwrap();
                        }
                        _ => {}
                    }
                    // check for timeouts
                    // debug!("ticks = {}", ticks);
                    if ticks % wheel_tick_reduction_factor == 0 {
                        let current_tsc = unsafe { _rdtsc() };
                        cm.release_timeouts(&current_tsc, &mut wheel);
                    }
                    #[cfg(feature = "profiling")]
                    {   //save stats
                        let tx_stats_now = tx_stats.stats.load(Ordering::Relaxed);
                        let rx_stats_now = rx_stats.stats.load(Ordering::Relaxed);
                        // only save changes
                        if rx_tx_stats.last().is_none() || tx_stats_now != rx_tx_stats.last().unwrap().2 || rx_stats_now != rx_tx_stats.last().unwrap().1 {
                            rx_tx_stats.push(( unsafe { _rdtsc() }, rx_stats_now, tx_stats_now));
                        }
                    }
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
                            time_adders[0].add_diff(unsafe { _rdtsc() } - timestamp_entry);
                            c
                        } else {
                            let c = cm.get_mut_by_sock(&src_sock);
                            #[cfg(feature = "profiling")]
                            time_adders[8].add_diff(unsafe { _rdtsc() } - timestamp_entry);
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
                                    // Handle client SYN via delayed-mode hook (craft SYN-ACK)
                                    mode.on_client_syn(pdu, &mut c, &me);
                                    c.c_push_state(TcpState::SynSent);
                                    trace!("{} (SYN-)ACK to client, L3: { }, L4: { }", thread_id, pdu.headers().ip(1), pdu.headers().tcp(2));
                                    counter_c[TcpStatistics::RecvSyn] += 1;
                                    counter_c[TcpStatistics::SentSynAck] += 1;

                                    c.wheel_slot_and_index = wheel.schedule(&(timeouts.established.unwrap() * system_data.cpu_clock / 1000), c.port());
                                    group_index = 1;
                                } else {
                                    warn!("received client SYN in state {:?}/{:?}, {:?}/{:?}, {}", old_c_state, old_s_state, c.c_states(), c.s_states(), tcp);
                                }
                                #[cfg(feature = "profiling")]
                                time_adders[2].add_diff(unsafe { _rdtsc() } - timestamp_entry);
                            } else if tcp.ack_flag() && old_c_state == TcpState::SynSent {
                                c.c_push_state(TcpState::Established);
                                counter_c[TcpStatistics::RecvSynAck2] += 1;
                                #[cfg(feature = "profiling")]
                                time_adders[4].add_diff(unsafe { _rdtsc() } - timestamp_entry);
                            } else if tcp.fin_flag() {
                                if old_s_state >= TcpState::FinWait1 { // server in active close, client in passive or also active close
                                    if tcp.ack_flag() && tcp.ack_num() == unsafe { c.seqn.ack_for_fin_p2c } {
                                        counter_c[TcpStatistics::RecvFinPssv] += 1;
                                        counter_s[TcpStatistics::SentFinPssv] += 1;
                                        counter_c[TcpStatistics::RecvAck4Fin] += 1;
                                        counter_s[TcpStatistics::SentAck4Fin] += 1;
                                        c.set_release_cause(ReleaseCause::PassiveClose);
                                        c.c_push_state(TcpState::LastAck);
                                    } else { // no ACK
                                        counter_c[TcpStatistics::RecvFin] += 1;
                                        counter_s[TcpStatistics::SentFin] += 1;
                                        c.set_release_cause(ReleaseCause::ActiveClose);
                                        c.c_push_state(TcpState::Closing); //will still receive FIN of server
                                        if old_s_state == TcpState::FinWait1 {
                                            c.s_push_state(TcpState::Closing);
                                        } else if old_s_state == TcpState::FinWait2 {
                                            c.s_push_state(TcpState::Closed)
                                        }
                                    }
                                    group_index = 1;
                                } else { // client in active close
                                    c.set_release_cause(ReleaseCause::ActiveClose);
                                    counter_c[TcpStatistics::RecvFin] += 1;
                                    c.c_push_state(TcpState::FinWait1);
                                    if old_s_state < TcpState::Established {
                                        // in case the server connection is still not established
                                        // proxy must close connection and sends Fin-Ack to client
                                        make_reply_packet(pdu, 1);
                                        pdu.headers_mut().tcp_mut(2).set_ack_flag();
                                        c.c_seqn = c.c_seqn.wrapping_add(1);
                                        pdu.headers_mut().tcp_mut(2).set_seq_num(c.c_seqn);
                                        //debug!("data_len= { }, p= { }",p.data_len(), p);
                                        prepare_checksum_and_ttl(pdu);
                                        c.s_push_state(TcpState::LastAck); // pretend that server received the FIN
                                        c.s_set_release_cause(ReleaseCause::PassiveClose);
                                        counter_c[TcpStatistics::SentFinPssv] += 1;
                                        counter_c[TcpStatistics::SentAck4Fin] += 1;
                                        // do not use the clone "tcp" here:
                                        c.seqn.ack_for_fin_p2c = c.c_seqn.wrapping_add(1);
                                        //TODO send restart to server?
                                        trace!("FIN-ACK to client, L3: { }, L4: { }", pdu.headers().ip(1), tcp);
                                    } else {
                                        counter_s[TcpStatistics::SentFin] += 1;
                                    }
                                    group_index = 1;
                                }
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
                            } else if old_c_state == TcpState::Established
                                && old_s_state == TcpState::Listen {
                                // should be the first payload packet from client
                                counter_c[TcpStatistics::RecvPayload] += tcp_payload_size(pdu);
                                mode.select_server(pdu, &mut c, &me, &servers, &f_select_server);
                                //trace!("after  select_server: p.refcnt = {}, packet_in.refcnt() = {}", pdu.refcnt(), pdu_in.refcnt());
                                debug!("{} SYN packet to server - L3: {}, L4: {}", thread_id, pdu.headers().ip(1), pdu.headers().tcp(2));
                                c.s_init();
                                c.s_push_state(TcpState::SynReceived);
                                counter_s[TcpStatistics::SentSyn] += 1;
                                group_index = 1;
                                #[cfg(feature = "profiling")]
                                time_adders[5].add_diff(unsafe { _rdtsc() } - timestamp_entry);
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
                                counter_c[TcpStatistics::RecvPayload] += tcp_payload_size(pdu);
                                counter_s[TcpStatistics::SentPayload] += tcp_payload_size(pdu);
                                client_to_server_common(&mut mode, pdu, &mut c, &me, &servers, &f_process_payload_c_s, &f_select_server);
                                group_index = 1;
                                #[cfg(feature = "profiling")]
                                time_adders[6].add_diff(unsafe { _rdtsc() } - timestamp_entry);
                            }
                        }
                    } else {
                        // server to client
                        {
                            debug!("looking up state for server side port { }", tcp.dst_port());
                            let mut c = cm.get_mut_by_port(tcp.dst_port());
                            #[cfg(feature = "profiling")]
                            time_adders[1].add_diff(unsafe { _rdtsc() } - timestamp_entry);

                            if c.is_some() {
                                let mut c = c.as_mut().unwrap();
                                let mut b_unexpected = false;
                                let old_s_state = c.server_state();
                                let old_c_state = c.client_state();
                                // **** received SYN+ACK from server
                                if tcp.ack_flag() && tcp.syn_flag() {
                                    counter_s[TcpStatistics::RecvSynAck] += 1;
                                    if old_s_state == TcpState::SynReceived {
                                        c.s_push_state(TcpState::Established);
                                        debug!("{} established two-way client server connection, SYN-ACK received: L3: {}, L4: {}", thread_id, pdu.headers().ip(1), tcp);
                                        let payload_size = mode.on_server_synack(pdu, &mut c);
                                        counter_s[TcpStatistics::SentPayload] += payload_size;
                                        counter_s[TcpStatistics::SentSynAck2] += 1;
                                        group_index = 0; // delayed payload packets are sent via extra queue
                                    } else {
                                        warn!("{} received SYN-ACK in wrong state: {:?}", thread_id, old_s_state);
                                        group_index = 0;
                                    }
                                    #[cfg(feature = "profiling")]
                                    time_adders[3].add_diff(unsafe { _rdtsc() } - timestamp_entry);
                                } else if tcp.fin_flag() {
                                    if old_c_state >= TcpState::FinWait1 {
                                        if tcp.ack_flag() && tcp.ack_num() == c.seqn_fin_p2s.wrapping_add(1) {
                                            counter_s[TcpStatistics::RecvFinPssv] += 1;
                                            counter_c[TcpStatistics::SentFinPssv] += 1;
                                            counter_s[TcpStatistics::RecvAck4Fin] += 1;
                                            counter_c[TcpStatistics::SentAck4Fin] += 1;
                                            trace!("{} received FIN-reply from server on proxy port {}", thread_id, tcp.dst_port());
                                            c.s_set_release_cause(ReleaseCause::PassiveClose);
                                            c.s_push_state(TcpState::LastAck);
                                        } else {
                                            trace!("simultaneous active close from server on port {}", tcp.dst_port());
                                            counter_s[TcpStatistics::RecvFin] += 1;
                                            counter_c[TcpStatistics::SentFin] += 1;
                                            c.s_set_release_cause(ReleaseCause::ActiveClose);
                                            c.s_push_state(TcpState::Closing);
                                            if old_c_state == TcpState::FinWait1 {
                                                c.c_push_state(TcpState::Closing);
                                            } else if old_c_state == TcpState::FinWait2 {
                                                c.c_push_state(TcpState::Closed)
                                            }
                                        }
                                    } else {
                                        // server initiated TCP close
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
                                } else if old_c_state >= TcpState::LastAck && tcp.ack_flag() {
                                    if tcp.ack_num() == c.seqn_fin_p2s.wrapping_add(1) {
                                        // received  Ack from server for a FIN
                                        match old_c_state {
                                            TcpState::LastAck => {
                                                c.c_push_state(TcpState::Closed);
                                                c.s_push_state(TcpState::Closed);
                                            }
                                            TcpState::FinWait1 => { c.c_push_state(TcpState::FinWait2) }
                                            TcpState::Closing => {
                                                c.c_push_state(TcpState::Closed);
                                            }
                                            _ => {}
                                        }
                                        match old_s_state {
                                            TcpState::FinWait1 => {}
                                            _ => {}
                                        }
                                        counter_s[TcpStatistics::RecvAck4Fin] += 1;
                                        counter_c[TcpStatistics::SentAck4Fin] += 1;
                                        trace!("{} on proxy port {} transition to client/server state {:?}/{:?}", thread_id, c.port(), c.c_states(), c.s_states());
                                    }
                                } else {
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
                                    counter_s[TcpStatistics::RecvPayload] += tcp_payload_size(pdu);
                                    // translate packets and forward to client
                                    server_to_client_common(&mut mode, pdu, &mut c, &me);
                                    counter_c[TcpStatistics::SentPayload] += tcp_payload_size(pdu);
                                    group_index = 1;
                                    b_unexpected = false;
                                    #[cfg(feature = "profiling")]
                                    time_adders[7].add_diff(unsafe { _rdtsc() } - timestamp_entry);
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
            if let Some(sport) = release_connection {
                trace!("releasing connection on port {}", sport);
                cm.release_port(sport, &mut wheel);
            }
            group_index
        });

    let mut l4groups = l2_input_stream.group_by(
        3,
        delayed_binding_closure,
        sched,
        "L4-Groups".to_string(),
        uuid_l4groupby,
    );

    let pipe2kni = l4groups.get_group(2).unwrap().send(kni.clone());
    let l4pciflow = l4groups.get_group(1).unwrap();
    let l4dumpflow = l4groups.get_group(0).unwrap().drop();
    let pipe2pci = merge_auto(vec![Box::new(l4pciflow), Box::new(l4dumpflow)], SchedulingPolicy::LongestQueue).send(pci.clone());

    let uuid_pipe2kni = tasks::install_task(sched, "Pipe2Kni", pipe2kni);
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_pipe2kni, TaskType::Pipe2Kni))
        .unwrap();

    let uuid_pipe2pic = tasks::install_task(sched, "Pipe2Pci", pipe2pci);
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_pipe2pic, TaskType::Pipe2Pci))
        .unwrap();

    let uuid_consumer = tasks::install_task(sched, "BypassPipe", consumer.send(pci.clone()));
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_consumer, TaskType::BypassPipe))
        .unwrap();
}
