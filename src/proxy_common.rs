use crate::Timeouts;
use crate::netfcts::timer_wheel::TimerWheel;
use crate::netfcts::tcp_common::L234Data;
use crate::netfcts::tcp_common::{TcpState, TcpStatistics, ReleaseCause, TcpCounter};
use crate::netfcts::recstore::{Extension, ProxyRecStore, Store64};
use crate::netfcts::comm::{MessageFrom, MessageTo, PipelineId};
use crate::netfcts::RunConfiguration;
use crate::Configuration;
use crate::proxymanager::ConnectionManager;
use crate::{FnProxyPayload, FnProxySelectServer, ProxyConnection};
use crate::get_server_addresses;
use crate::netfcts::system::SystemData;
use e2d2::allocators::CacheAligned;
use e2d2::interface::{PortQueue, PortQueueTxBuffered};
use e2d2::operators::{ReceiveBatch, Batch};
use e2d2::scheduler::{Runnable, StandaloneScheduler, Scheduler};
use uuid::Uuid;
use std::sync::mpsc::{channel, Receiver, Sender};
use e2d2::interface::Pdu;
use e2d2::headers::TcpHeader;
use crate::netfcts::{prepare_checksum_and_ttl, set_header};
use crate::netfcts::tcp_common::tcp_payload_size;
use crate::netfcts::{remove_tcp_options, make_reply_packet};
use std::arch::x86_64::_rdtsc;
use e2d2::queues::MpscProducer;
use e2d2::headers::Header;
use crate::profiling::Profiler; // only for label shape; no runtime dependency
use crate::netfcts::tasks::private_etype;

// Shared timer wheel configuration for proxy pipelines
pub const TIMER_WHEEL_RESOLUTION_MS: u64 = 10;
pub const TIMER_WHEEL_SLOTS: usize = 1002;
pub const TIMER_WHEEL_SLOT_CAPACITY: usize = 2500;

// Centralized profiler labels used by both proxy variants
pub const PROXY_PROF_LABELS: &[&str] = &[
    "c_cmanager_syn",   // 0
    "s_cmanager",       // 1
    "c_recv_syn",       // 2
    "s_recv_syn_ack",   // 3
    "c_recv_syn_ack2",  // 4
    "c_recv_1_payload", // 5
    "c2s_stable",       // 6
    "s2c_stable",       // 7
    "c_cmanager_not_syn", // 8
    "",                 // 9 (reserved)
    "",                 // 10 (reserved)
    "",                 // 11 (reserved)
];

// ========================= Ingress helpers (shared) =========================

pub enum IngressDecision {
    Drop,                      // discard (group 0)
    ToKni,                     // send to KNI (group 2)
    Continue { b_private_etype: bool },
}

/// Classify ingress frame based on L2/L3 rules common to both proxies.
/// Mirrors the existing logic in both engines.
pub fn ingress_classify(pdu: &Pdu, me: &Me, pipeline_ip: u32) -> IngressDecision {
    // L2
    let mac = pdu.headers().mac(0);
    let b_private = private_etype(&mac.etype());
    if !b_private {
        if mac.dst != me.l234.mac && !mac.dst.is_multicast() && !mac.dst.is_broadcast() {
            return IngressDecision::Drop;
        }
        if mac.etype() != 0x0800 {
            return IngressDecision::ToKni;
        }
    }
    // L3
    let ip = pdu.headers().ip(1);
    if !b_private {
        if ip.protocol() != 6 || (ip.dst() != pipeline_ip && ip.dst() != me.l234.ip) {
            return IngressDecision::ToKni;
        }
    }
    IngressDecision::Continue { b_private_etype: b_private }
}

#[inline]
pub fn maybe_enable_tx_offload(pdu: &mut Pdu, csum_offload: bool) {
    if csum_offload {
        pdu.set_tcp_ipv4_checksum_tx_offload();
    }
}

/// Unified TCP port filter used by both proxies. Returns true if packet passes.
#[inline]
pub fn pass_tcp_port_filter(pdu: &Pdu, me: &Me, tcp_min_port: u16, b_private_etype: bool) -> bool {
    if b_private_etype { return true; }
    let dst = pdu.headers().tcp(2).dst_port();
    if dst != me.l234.port && dst < tcp_min_port { return false; }
    true
}

/// Handle PRIVATE_ETYPE_TIMER frames: runtime requests, timeouts, and optional profiling RX/TX sampling.
/// This consolidates identical logic across both proxy variants.
pub fn handle_timer_tick(
    ticks: &mut u64,
    wheel_tick_reduction_factor: u64,
    cm: &mut ConnectionManager,
    wheel: &mut TimerWheel<u16>,
    rx_runtime: &Receiver<MessageTo<ProxyRecStore>>,
    tx_runtime: &Sender<MessageFrom<Store64<Extension>>>,
    pipeline_id: &PipelineId,
    counter_c: &TcpCounter,
    counter_s: &TcpCounter,
    mut profiler: Option<&mut Profiler>,
    rx_stats_now: Option<u64>,
    tx_stats_now: Option<u64>,
) {
    *ticks += 1;
    match rx_runtime.try_recv() {
        Ok(MessageTo::FetchCounter) => {
            debug!("{}: received FetchCounter", pipeline_id);
            let stats_opt: Option<Vec<(u64, usize, usize)>> = profiler
                .as_ref()
                .and_then(|p| p.snapshot_rx_tx())
                .map(|v| v.iter().map(|(t, rx, tx)| (*t, *rx as usize, *tx as usize)).collect());
            tx_runtime
                .send(MessageFrom::Counter(
                    pipeline_id.clone(),
                    counter_c.clone(),
                    counter_s.clone(),
                    stats_opt,
                ))
                .unwrap();
        }
        Ok(MessageTo::FetchCRecords) => {
            let c_recs = cm.fetch_c_records();
            debug!(
                "{}: received FetchCRecords, returning {} records",
                pipeline_id,
                if c_recs.is_some() { c_recs.as_ref().unwrap().len() } else { 0 }
            );
            tx_runtime
                .send(MessageFrom::CRecords(pipeline_id.clone(), c_recs, None))
                .unwrap();
        }
        _ => {}
    }

    // check for timeouts
    if *ticks % wheel_tick_reduction_factor == 0 {
        let current_tsc = unsafe { _rdtsc() };
        cm.release_timeouts(&current_tsc, wheel);
    }

    // Optional RX/TX profiling sample
    if let (Some(p), Some(rx), Some(tx)) = (profiler.as_deref_mut(), rx_stats_now, tx_stats_now) {
        p.record_rx_tx_if_changed(unsafe { _rdtsc() }, rx, tx);
    }
}

/// Common epilogue: release connection state if a port was marked for release.
/// Resets the `release_port` option after releasing to avoid double-free on re-entry.
#[inline]
pub fn release_if_needed(
    cm: &mut ConnectionManager,
    wheel: &mut TimerWheel<u16>,
    release_port: &mut Option<u16>,
) {
    if let Some(sport) = *release_port {
        trace!("releasing connection on port {}", sport);
        cm.release_port(sport, wheel);
        *release_port = None;
    }
}

/// Wrapper for established client->server forwarding: updates counters, calls shared handler, and profiles.
pub fn forward_established_c2s<M, FP, FSel>(
    mode: &mut M,
    p: &mut Pdu,
    c: &mut ProxyConnection,
    me: &Me,
    servers: &Vec<L234Data>,
    f_process_payload_c_s: &FP,
    f_select_server: &FSel,
    counter_c: &mut TcpCounter,
    counter_s: &mut TcpCounter,
    profiler: Option<&mut Profiler>,
    profile_label_idx: Option<usize>,
    timestamp_entry: Option<u64>,
) where
    M: ProxyMode,
    FP: FnProxyPayload,
    FSel: FnProxySelectServer,
{
    let sz = tcp_payload_size(p);
    counter_c[TcpStatistics::RecvPayload] += sz;
    counter_s[TcpStatistics::SentPayload] += sz;
    client_to_server_common(mode, p, c, me, servers, f_process_payload_c_s, f_select_server);
    #[cfg(feature = "profiling")]
    if let (Some(prof), Some(idx), Some(ts)) = (profiler, profile_label_idx, timestamp_entry) {
        prof.add_diff(idx, ts);
    }
}

/// Wrapper for established server->client forwarding: updates counters, calls shared handler, and profiles.
pub fn forward_established_s2c<M>(
    mode: &mut M,
    p: &mut Pdu,
    c: &mut ProxyConnection,
    me: &Me,
    counter_c: &mut TcpCounter,
    counter_s: &mut TcpCounter,
    profiler: Option<&mut Profiler>,
    profile_label_idx: Option<usize>,
    timestamp_entry: Option<u64>,
) where
    M: ProxyMode,
{
    let sz = tcp_payload_size(p);
    counter_s[TcpStatistics::RecvPayload] += sz;
    server_to_client_common(mode, p, c, me);
    counter_c[TcpStatistics::SentPayload] += tcp_payload_size(p);
    #[cfg(feature = "profiling")]
    if let (Some(prof), Some(idx), Some(ts)) = (profiler, profile_label_idx, timestamp_entry) {
        prof.add_diff(idx, ts);
    }
}

/// Builds a `TimerWheel` using the shared configuration and clamps `timeouts.established`
/// to the maximum supported duration of the wheel (in cycles) if necessary.
///
/// This mirrors the identical logic previously present in both proxy variants.
pub fn make_timer_wheel_and_fix_timeouts(timeouts: &mut Timeouts, cpu_clock: u64) -> TimerWheel<u16> {
    let wheel = TimerWheel::new(
        TIMER_WHEEL_SLOTS,
        cpu_clock * TIMER_WHEEL_RESOLUTION_MS / 1000,
        TIMER_WHEEL_SLOT_CAPACITY,
    );

    if let Some(timeout) = timeouts.established {
        if timeout > wheel.get_max_timeout_cycles() {
            warn!(
                "timeout defined in configuration file overflows timer wheel: reset to {} millis",
                wheel.get_max_timeout_cycles() * 1000 / cpu_clock
            );
            timeouts.established = Some(wheel.get_max_timeout_cycles());
        }
    }

    wheel
}

#[derive(Clone)]
pub struct Me {
    pub l234: L234Data, // client-side IP/MAC/port of the proxy
    pub ip_s: u32,      // server-side IP used in this pipeline
}

/// Sets up the reverse channel between this pipeline and the runtime thread and returns
/// the receiver for messages directed to the pipeline.
pub fn setup_reverse_channel(
    pipeline_id: &PipelineId,
    run_configuration: &RunConfiguration<Configuration, Store64<Extension>>,
) -> Receiver<MessageTo<ProxyRecStore>> {
    let tx = run_configuration.remote_sender.clone();
    debug!("{} setting up reverse channel", pipeline_id);
    let (remote_tx, rx) = channel::<MessageTo<ProxyRecStore>>();
    tx.send(MessageFrom::Channel(pipeline_id.clone(), remote_tx)).unwrap();
    rx
}

/// Installs a simple KNI->PCI forwarder task into the scheduler.
pub fn start_kni_forwarder(
    sched: &mut StandaloneScheduler,
    kni: &CacheAligned<PortQueue>,
    pci: &CacheAligned<PortQueueTxBuffered>,
    name: &str,
) {
    let forward2pci = ReceiveBatch::new(kni.clone()).send(pci.clone());
    let uuid = Uuid::new_v4();
    let task_name = String::from(name);
    sched.add_runnable(Runnable::from_task(uuid, task_name, forward2pci).move_ready());
}

/// Batch-based PDU allocator used by delayed proxy for crafting server-side SYN etc.
pub struct PduAllocator {
    pdu_batch: Option<Vec<Pdu>>, // pool of reusable PDUs
}

impl PduAllocator {
    pub fn new() -> PduAllocator {
        PduAllocator {
            pdu_batch: Pdu::new_pdu_array(),
        }
    }

    pub fn get_pdu(&mut self) -> Option<Pdu> {
        if let Some(ref mut batch) = self.pdu_batch {
            if batch.is_empty() {
                self.pdu_batch = Pdu::new_pdu_array();
                if let Some(ref mut b2) = self.pdu_batch {
                    b2.pop()
                } else {
                    None
                }
            } else {
                batch.pop()
            }
        } else {
            None
        }
    }
}

pub struct ProxyContext {
    pub me: Me,
    pub servers: Vec<L234Data>,
    pub pipeline_id: PipelineId,
    pub system_data: SystemData,
    pub cm: ConnectionManager,
    pub timeouts: Timeouts,
    pub wheel: TimerWheel<u16>,
    pub rx_runtime: Receiver<MessageTo<ProxyRecStore>>,
}

/// Build a fully initialized `ProxyContext` with common setup shared by both proxies.
pub fn make_context(
    core: i32,
    pci: &CacheAligned<PortQueueTxBuffered>,
    kni: &CacheAligned<PortQueue>,
    _sched: &mut StandaloneScheduler,
    run_configuration: &RunConfiguration<Configuration, Store64<Extension>>,
) -> ProxyContext {
    let l4flow_for_this_core = run_configuration
        .flowdirector_map
        .get(&pci.port_queue.port_id())
        .unwrap()
        .get_flow(pci.port_queue.rxq());

    let mut me = Me {
        l234: kni.port.net_spec().as_ref().unwrap().clone().try_into().unwrap(),
        ip_s: l4flow_for_this_core.ip,
    };
    me.l234.port = run_configuration.engine_configuration.engine.port;

    let engine_config = &run_configuration.engine_configuration.engine;
    let system_data = run_configuration.system_data.clone();
    let servers: Vec<L234Data> = get_server_addresses(&run_configuration.engine_configuration);
    let pipeline_id = PipelineId {
        core: core as u16,
        port_id: pci.port_queue.port_id(),
        rxq: pci.port_queue.rxq(),
    };

    let detailed_records = engine_config.detailed_records.unwrap_or(false);
    let cm: ConnectionManager = ConnectionManager::new(pci.port_queue.clone(), *l4flow_for_this_core, detailed_records);

    let mut timeouts = Timeouts::default_or_some(&engine_config.timeouts);
    let wheel = make_timer_wheel_and_fix_timeouts(&mut timeouts, system_data.cpu_clock);

    // Reverse channel
    let rx_runtime = setup_reverse_channel(&pipeline_id, run_configuration);

    ProxyContext {
        me,
        servers,
        pipeline_id,
        system_data,
        cm,
        timeouts,
        wheel,
        rx_runtime,
    }
}

// ========================= Shared behavioral abstraction =========================

/// Captures behavioral differences between simple and delayed proxy modes.
/// Default implementations are no-ops for simple mode-like behavior.
pub trait ProxyMode {
    /// Called when the first client SYN arrives; can be a no-op for simple mode.
    fn on_client_syn(&mut self, _p: &mut Pdu, _c: &mut ProxyConnection, _me: &Me) {}

    /// Select a server address for this connection; simple mode selects immediately using provided function.
    fn select_server<FSel: FnProxySelectServer>(
        &mut self,
        _p: &mut Pdu,
        c: &mut ProxyConnection,
        _me: &Me,
        servers: &Vec<L234Data>,
        f_select_server: &FSel,
    ) {
        // Default: call provided selector which updates connection in-place.
        f_select_server(c, servers);
    }

    /// Optional per-packet payload processing on client->server path.
    fn process_payload_c_s<FP: FnProxyPayload>(
        &mut self,
        _p: &mut Pdu,
        _c: &mut ProxyConnection,
        _me: &Me,
        _f_process_payload: &FP,
    ) {
    }

    /// Optional periodic tick; default is no-op.
    fn tick(&mut self) {}

    /// Optional PDU allocation facility (used by delayed mode). Default: none.
    fn alloc_pdu(&mut self) -> Option<Pdu> { None }

    /// Called when SYN+ACK is received from server. Should craft and enqueue final ACK to server
    /// and optionally the saved payload packet. Returns payload size enqueued (if any).
    fn on_server_synack(&mut self, _p: &mut Pdu, _c: &mut ProxyConnection) -> usize { 0 }
}

/// Trivial mode with immediate decisions (used by the simple proxy)
pub struct SimpleMode;

impl ProxyMode for SimpleMode {}

/// Delayed mode with facilities for crafting packets (e.g., server-side SYN).
pub struct DelayedMode {
    pub pdu_allocator: PduAllocator,
    pub producer: MpscProducer,
}

impl ProxyMode for DelayedMode {
    fn alloc_pdu(&mut self) -> Option<Pdu> { self.pdu_allocator.get_pdu() }

    fn on_client_syn(&mut self, p: &mut Pdu, c: &mut ProxyConnection, _me: &Me) {
        // Mirror existing delayed-proxy behavior: capture client MAC and craft immediate SYN-ACK
        c.client_mac = p.headers().mac(0).src;
        remove_tcp_options(p);
        make_reply_packet(p, 1);
        // Generate initial seq number based on TSC
        c.c_seqn = (unsafe { _rdtsc() } << 8) as u32;
        p.headers_mut().tcp_mut(2).set_seq_num(c.c_seqn);
        c.ackn_p2c = p.headers().tcp(2).ack_num();
        prepare_checksum_and_ttl(p);
    }

    fn select_server<FSel: FnProxySelectServer>(
        &mut self,
        p: &mut Pdu,
        c: &mut ProxyConnection,
        me: &Me,
        servers: &Vec<L234Data>,
        f_select_server: &FSel,
    ) {
        // Allocate a fresh PDU for crafting the SYN towards the server
        let mut syn = self
            .alloc_pdu()
            .expect("DelayedMode: failed to allocate PDU for server SYN");

        let ip;
        let tcp;
        let payload_sz;
        unsafe {
            // Save clone of the payload packet to connection state (referencing same mbuf)
            let p_clone = Box::new(p.clone_from_same_mbuf());
            payload_sz = tcp_payload_size(&p_clone);
            c.payload_packet = Some(p_clone);

            // Select server via provided closure and compute c2s_inserted_bytes delta
            f_select_server(c, servers);
            c.c2s_inserted_bytes = tcp_payload_size(c.payload_packet.as_ref().unwrap()) as i32 - payload_sz as i32;

            // Set the header for the selected server in the payload packet p
            let server = &servers[c.server_index() ];
            set_header(server, c.port(), p, &me.l234.mac, me.ip_s);

            // Prepare SYN packet by pushing MAC header of p into syn, then swap p to point to syn
            let ok = syn.push_header(p.headers().mac(0));
            assert!(ok);
            // Replace borrowed packet (p) with SYN packet; old p becomes owned as old_p
            let old_p = p.replace(syn);
            // Capture IP/TCP headers from old_p
            ip = old_p.headers().ip(1).clone();
            tcp = old_p.headers().tcp(2).clone();
            // Drop of old_p will deref original mbuf automatically
        }

        // Reconstruct headers on p (the SYN packet)
        let ok = p.push_header(&ip); assert!(ok);
        let ok = p.push_header(&tcp); assert!(ok);
        {
            let hs = p.headers_mut();
            hs.ip_mut(1).trim_length_by(payload_sz as u16);
            let tcp = hs.tcp_mut(2);
            // Initialize server-side seq number one less than chosen, set SYN, clear ACK/PSH
            c.seqn.f_seqn = tcp.seq_num().wrapping_sub(1);
            unsafe { tcp.set_seq_num(c.seqn.f_seqn); }
            tcp.set_syn_flag();
            tcp.set_ack_num(0u32);
            tcp.unset_ack_flag();
            tcp.unset_psh_flag();
        }

        prepare_checksum_and_ttl(p);
    }

    fn on_server_synack(&mut self, p: &mut Pdu, c: &mut ProxyConnection) -> usize {
        // correction for server side seq numbers
        let delta = c.c_seqn.wrapping_sub(p.headers().tcp(2).seq_num());
        c.c_seqn = delta;
        remove_tcp_options(p);
        make_reply_packet(p, 1);
        {
            let tcp = p.headers_mut().tcp_mut(2);
            tcp.unset_syn_flag();
            unsafe {
                c.seqn.f_seqn = c.seqn.f_seqn.wrapping_add(1);
                tcp.set_seq_num(c.seqn.f_seqn);
            }
        }
        prepare_checksum_and_ttl(p);

        // Clone ACK and send via producer; original will be handled by pipeline for client forwarding
        let p_clone = unsafe { p.clone_from_same_mbuf() };
        self.producer.enqueue_one(p_clone);

        let mut result = 0usize;
        if c.payload_packet.is_some() {
            let mut payload_packet = c.payload_packet.take().unwrap();
            // use the same TCP header as in ACK packet
            payload_packet.replace_header(2, &Header::Tcp(p.headers_mut().tcp_mut(2)));
            {
                let h_tcp = payload_packet.headers_mut().tcp_mut(2);
                h_tcp.set_psh_flag();
            }

            // enforce minimal frame size
            const MIN_FRAME_SIZE_LOCAL: usize = 60; // without FCS
            if payload_packet.data_len() < MIN_FRAME_SIZE_LOCAL {
                let n_padding_bytes = MIN_FRAME_SIZE_LOCAL - payload_packet.data_len();
                debug!("padding with {} 0x0 bytes", n_padding_bytes);
                payload_packet.add_padding(n_padding_bytes);
            }

            prepare_checksum_and_ttl(&mut payload_packet);
            c.ackn_p2s = p.headers().tcp(2).ack_num();
            result = tcp_payload_size(payload_packet.as_ref());
            self.producer.enqueue_one_boxed(payload_packet);
        }
        result
    }
}

/// Common handler for client->server path shared by both proxy modes.
pub fn client_to_server_common<M, FP, FSel>(
    mode: &mut M,
    p: &mut Pdu,
    c: &mut ProxyConnection,
    me: &Me,
    servers: &Vec<L234Data>,
    f_process_payload: &FP,
    f_select_server: &FSel,
) where
    M: ProxyMode,
    FP: FnProxyPayload,
    FSel: FnProxySelectServer,
{
    // Optional payload processing
    if tcp_payload_size(p) > 0 {
        let tailroom = p.get_tailroom();
        f_process_payload(c, p.get_payload_mut(2), tailroom);
        mode.process_payload_c_s(p, c, me, f_process_payload);
    }

    // Ensure server selected (simple mode selects immediately, others may defer)
    if c.server_index() >= servers.len() {
        mode.select_server(p, c, me, servers, f_select_server);
    }

    // Rewriting headers client->server
    let server = &servers[c.server_index()];
    set_header(server, c.port(), p, &me.l234.mac, me.ip_s);

    {
        let tcp = p.headers_mut().tcp_mut(2);
        // adapt ackn of client packet
        let oldackn = tcp.ack_num();
        let newackn = oldackn.wrapping_sub(c.c_seqn);
        let oldseqn = tcp.seq_num();
        let newseqn = if c.c2s_inserted_bytes >= 0 {
            oldseqn.wrapping_add(c.c2s_inserted_bytes as u32)
        } else {
            oldseqn.wrapping_sub((-c.c2s_inserted_bytes) as u32)
        };
        if c.c2s_inserted_bytes != 0 {
            tcp.set_seq_num(newseqn);
        }
        tcp.set_ack_num(newackn);
        c.ackn_p2s = newackn;
        if tcp.fin_flag() { c.seqn_fin_p2s = newseqn; }
    }

    prepare_checksum_and_ttl(p);
}

/// Common handler for server->client path shared by both proxy modes.
pub fn server_to_client_common<M>(
    _mode: &mut M,
    p: &mut Pdu,
    c: &mut ProxyConnection,
    me: &Me,
) where
    M: ProxyMode,
{
    let newseqn;
    {
        // translate packets and forward to client
        let sock = c.sock().unwrap();
        let h = p.headers_mut();
        h.mac_mut(0).set_dmac(&c.client_mac);
        h.mac_mut(0).set_smac(&me.l234.mac);
        h.ip_mut(1).set_dst(sock.0);
        h.ip_mut(1).set_src(me.l234.ip);
        let tcp = h.tcp_mut(2);
        tcp.set_src_port(me.l234.port);
        tcp.set_dst_port(sock.1);

        // Mirror simple-proxy semantics
        let oldseqn = tcp.seq_num();
        newseqn = oldseqn.wrapping_add(c.c_seqn);
        let oldackn = tcp.ack_num();
        let newackn = if c.c2s_inserted_bytes >= 0 {
            oldackn.wrapping_sub(c.c2s_inserted_bytes as u32)
        } else {
            oldackn.wrapping_add((-c.c2s_inserted_bytes) as u32)
        };
        if c.c2s_inserted_bytes != 0 { tcp.set_ack_num(newackn); }
        tcp.set_seq_num(newseqn);
        c.ackn_p2c = newackn;
    }

    if p.headers().tcp(2).fin_flag() { c.seqn.ack_for_fin_p2c = newseqn.wrapping_add(tcp_payload_size(p) as u32 + 1); }

    prepare_checksum_and_ttl(p);
}

/// Handle server-side FIN/ACK-for-FIN and related close semantics common to both proxies.
/// Returns true if the packet was handled by this function; false if not (caller may treat as unexpected).
pub fn handle_server_close_and_fin_acks(
    tcp: &TcpHeader,
    c: &mut ProxyConnection,
    old_c_state: TcpState,
    old_s_state: TcpState,
    counter_c: &mut TcpCounter,
    counter_s: &mut TcpCounter,
    thread_id: &str,
) -> bool {
    if tcp.fin_flag() {
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
        return true;
    } else if old_c_state >= TcpState::LastAck && tcp.ack_flag() {
        if tcp.ack_num() == c.seqn_fin_p2s.wrapping_add(1) {
            // received Ack from server for a FIN
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
            return true;
        }
    }
    false
}

// Shared proxy infrastructure for simple and delayed TCP proxies.
//
// This module centralizes:
// - Common runtime/context setup (`make_context`) including timer wheel, reverse channel,
//   server list, connection manager, and per-pipeline identifiers.
// - Reusable helpers (`start_kni_forwarder`, timer wheel builder).
// - A small trait (`ProxyMode`) to capture behavioral differences between proxy variants,
//   with concrete implementations `SimpleMode` and `DelayedMode`.
// - Directional forwarding helpers (`client_to_server_common`, `server_to_client_common`).
//
// Both `nfsimpleproxy` and `nfdelayedproxy` build their graphs using these helpers so that
// maintenance and fixes land once and apply to both modes.