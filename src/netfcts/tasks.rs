use std::arch::x86_64::_rdtsc;
use e2d2::headers::{IpHeader, MacHeader, TcpHeader};
use e2d2::interface::Pdu;
use e2d2::native::zcsi::{mbuf_alloc_bulk, MBuf};
use e2d2::queues::MpscProducer;
use e2d2::scheduler::{Executable, Runnable, Scheduler, StandaloneScheduler};
use uuid::Uuid;
use crate::netfcts::tcp_common::L234Data;
use log::{warn, error, info};
use std::sync::mpsc::Sender;
use crate::netfcts::comm::MessageFrom;
use crate::netfcts::recstore::{Store64, Extension};

#[derive(Debug)]
pub enum TaskType {
    TcpGenerator = 0,
    Pipe2Kni = 1,
    Pipe2Pci = 2,
    TickGenerator = 3,
    BypassPipe = 4,
    NoTaskTypes = 5, // for iteration over TaskType
}

pub fn install_task<T: Executable + 'static>(sched: &mut StandaloneScheduler, task_name: &str, task: T) -> Uuid {
    let uuid = Uuid::new_v4();
    sched.add_runnable(Runnable::from_task(uuid, task_name.to_string(), task).move_unready());
    uuid
}

pub struct PacketInjector {
    packet_prototype: Pdu,
    producer: MpscProducer,
    no_packets: usize,
    sent_packets: usize,
    // in cycles
    min_inter_batch_gap: u64,
    lastbatch_timestamp: u64,
    start_delay: u64,
    start_time: u64,
    /// Optional notifier to request a graceful shutdown of the runtime on fatal errors
    shutdown_tx: Option<Sender<MessageFrom<Store64<Extension>>>>,
    /// Ensure we only trigger shutdown once
    shutdown_requested: bool,
}

pub const PRIVATE_ETYPE_PACKET: u16 = 0x08FF;
pub const PRIVATE_ETYPE_TIMER: u16 = 0x08FE;
pub const ETYPE_IPV4: u16 = 0x0800;
pub const ETYPE_IPV6: u16 = 0x86dd;
pub const ETYPE_ARP: u16 = 0x0806;
pub const ETYPE_VLAN: u16 = 0x8100;
pub const ETYPE_DOUBLE_VLAN: u16 = 0x9100;

pub const INJECTOR_BATCH_SIZE: usize = 32;

#[inline]
pub fn private_etype(etype: &u16) -> bool {
    return *etype == PRIVATE_ETYPE_PACKET || *etype == PRIVATE_ETYPE_TIMER;
}

impl<'a> PacketInjector {
    // by setting no_packets=0 batch creation is unlimited
    pub fn new(
        producer: MpscProducer,
        hd_src_data: &L234Data,
        no_packets: usize,
        min_inter_batch_gap: u64,
        dst_port: u16,
    ) -> PacketInjector {
        let mut mac = MacHeader::new();
        mac.src = hd_src_data.mac.clone();
        mac.set_etype(PRIVATE_ETYPE_PACKET); // mark this through an unused ethertype as an internal frame, will be re-written later in the pipeline
        let mut ip = IpHeader::new();
        ip.set_src(hd_src_data.ip);
        ip.set_ttl(128);
        ip.set_version(4);
        ip.set_protocol(6); //tcp
        ip.set_ihl(5);
        ip.set_length(40);
        ip.set_flags(0x2); // DF=1, MF=0 flag: don't fragment
        let mut tcp = TcpHeader::new();
        tcp.set_syn_flag();
        tcp.set_src_port(hd_src_data.port);
        tcp.set_dst_port(dst_port);
        tcp.set_data_offset(5);
        let mut packet_prototype = Pdu::new_pdu().unwrap();
        packet_prototype.push_header(&mac);
        packet_prototype.push_header(&ip);
        packet_prototype.push_header(&tcp);

        PacketInjector {
            packet_prototype,
            producer,
            no_packets,
            sent_packets: 0,
            min_inter_batch_gap,
            lastbatch_timestamp: 0,
            start_delay: 0,
            start_time: 0,
            shutdown_tx: None,
            shutdown_requested: false,
        }
    }

    pub fn set_start_delay(mut self, delay: u64) -> PacketInjector {
        self.start_delay = delay;
        self
    }

    /// Provide a shutdown notifier (RunTime message sender) so the injector can
    /// trigger a graceful program exit if a fatal condition occurs.
    pub fn with_shutdown_tx(mut self, tx: Sender<MessageFrom<Store64<Extension>>>) -> PacketInjector {
        self.shutdown_tx = Some(tx);
        self
    }

    #[inline]
    pub fn create_packet_from_mbuf(&mut self, mbuf: *mut MBuf) -> Pdu {
        let p =  self.packet_prototype.copy_use_mbuf(mbuf) ;
        p
    }
}

impl<'a> Executable for PacketInjector {
    fn execute(&mut self) -> (u32, i32) {
        // If a fatal error has already been observed and shutdown was requested,
        // do nothing to avoid spamming logs or allocating again.
        if self.shutdown_requested {
            return (0, self.producer.used_slots() as i32);
        }
        let now = unsafe { _rdtsc() };
        if self.start_time == 0 {
            self.start_time = now;
        }
        let mut inserted = 0;
        // only enqeue new packets if queue has free slots for a full batch (currently we would otherwise create a memory leak)
        if (self.no_packets == 0 || self.sent_packets < self.no_packets)
            && self.producer.free_slots() >= INJECTOR_BATCH_SIZE
            && (now - self.lastbatch_timestamp) >= self.min_inter_batch_gap
            && (now - self.start_time) >= self.start_delay
        {
            let mut mbuf_ptr_array = Vec::<*mut MBuf>::with_capacity(INJECTOR_BATCH_SIZE);
            let ret = unsafe { mbuf_alloc_bulk(mbuf_ptr_array.as_mut_ptr(), INJECTOR_BATCH_SIZE as u32) };
            if ret != 0 {
                // Allocation failed; treat as fatal and request graceful shutdown.
                // Log only once, then suppress further attempts/logs to avoid flooding output.
                if !self.shutdown_requested {
                    error!(
                        "PacketInjector: FATAL: mbuf_alloc_bulk failed (ret={}). Requesting graceful shutdown.",
                        ret
                    );
                    if let Some(tx) = &self.shutdown_tx {
                        // Best-effort: try to request exit; ignore errors if runtime is already down
                        let _ = tx.send(MessageFrom::Exit);
                        info!("PacketInjector: sent Exit to runtime due to fatal allocation failure");
                    } else {
                        error!("PacketInjector: no shutdown_tx available to request graceful exit");
                    }
                    self.shutdown_requested = true;
                }
                // Return without enqueuing anything; the scheduler will soon stop
                return (0, self.producer.used_slots() as i32);
            }
            unsafe { mbuf_ptr_array.set_len(INJECTOR_BATCH_SIZE) };
            for i in 0..INJECTOR_BATCH_SIZE {
                self.create_packet_from_mbuf(mbuf_ptr_array[i]);
            }
            inserted = self.producer.enqueue_mbufs(&mbuf_ptr_array);
            self.sent_packets += inserted;
            if inserted != INJECTOR_BATCH_SIZE {
                warn!(
                    "PacketInjector: enqueued {} of {} packets (queue full?), proceeding",
                    inserted,
                    INJECTOR_BATCH_SIZE
                );
            }
            if inserted > 0 {
                self.lastbatch_timestamp = unsafe { _rdtsc() };
            }
        }
        (inserted as u32, self.producer.used_slots() as i32)
    }
}

pub struct TickGenerator {
    packet_prototype: Pdu,
    producer: MpscProducer,
    last_tick: u64,
    tick_length: u64,
    // in cycles
    tick_count: u64,
}

#[allow(dead_code)]
impl<'a> TickGenerator {
    pub fn new(
        producer: MpscProducer,
        hd_src_data: &L234Data,
        tick_length: u64, // in cycles
    ) -> TickGenerator {
        let mut mac = MacHeader::new();
        mac.src = hd_src_data.mac.clone();
        mac.set_etype(PRIVATE_ETYPE_TIMER); // mark this through an unused ethertype as an internal frame, will be re-written later in the pipeline
        let mut ip = IpHeader::new();
        ip.set_src(hd_src_data.ip);
        ip.set_ttl(128);
        ip.set_version(4);
        ip.set_protocol(6); //tcp
        ip.set_ihl(5);
        ip.set_length(40);
        ip.set_flags(0x2); // DF=1, MF=0 flag: don't fragment
        let mut tcp = TcpHeader::new();
        tcp.set_syn_flag();
        tcp.set_src_port(hd_src_data.port);
        tcp.set_data_offset(5);
        let mut packet_prototype = Pdu::new_pdu().unwrap();
        packet_prototype.push_header(&mac);
        packet_prototype.push_header(&ip);
        packet_prototype.push_header(&tcp);
        packet_prototype.add_to_payload_tail(64).unwrap();
        TickGenerator {
            packet_prototype,
            producer,
            last_tick: 0,
            tick_count: 0,
            tick_length,
        }
    }

    #[inline]
    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    #[inline]
    pub fn tick_length(&self) -> u64 {
        self.tick_length
    }
}

impl<'a> Executable for TickGenerator {
    fn execute(&mut self) -> (u32, i32) {
        let p;
        let now = unsafe { _rdtsc() };
        if now - self.last_tick >= self.tick_length {
            p = self.packet_prototype.copy();
            self.producer.enqueue_one(p.unwrap());
            self.last_tick = now;
            self.tick_count += 1;
            (1, 0)
        } else {
            (0, 0)
        }
    }
}
