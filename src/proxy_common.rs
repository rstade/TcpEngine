use crate::Timeouts;
use crate::netfcts::timer_wheel::TimerWheel;
use crate::netfcts::tcp_common::L234Data;
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
use std::sync::mpsc::{channel, Receiver};
use e2d2::interface::Pdu;
use crate::netfcts::{prepare_checksum_and_ttl, set_header};
use crate::netfcts::tcp_common::tcp_payload_size;
use crate::netfcts::{remove_tcp_options, make_reply_packet};
use std::arch::x86_64::_rdtsc;
use e2d2::queues::MpscProducer;
use e2d2::headers::Header;

// Shared timer wheel configuration for proxy pipelines
pub const TIMER_WHEEL_RESOLUTION_MS: u64 = 10;
pub const TIMER_WHEEL_SLOTS: usize = 1002;
pub const TIMER_WHEEL_SLOT_CAPACITY: usize = 2500;

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
            let server = &servers[c.server_index() as usize];
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
    if c.server_index() as usize >= servers.len() {
        mode.select_server(p, c, me, servers, f_select_server);
    }

    // Rewriting headers client->server
    let server = &servers[c.server_index() as usize];
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