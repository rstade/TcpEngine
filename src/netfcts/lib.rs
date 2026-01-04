#[macro_use]
extern crate log;

pub mod comm;
pub mod tasks;
pub mod tcp_common;
pub mod timer_wheel;
pub mod system;
pub mod io;
pub mod utils;
pub mod recstore;
pub mod conrecord;
pub mod cuckoo;

use serde_derive::Deserialize;
use std::collections::{HashMap, HashSet};

use std::net::{Ipv4Addr};
use std::process::Command;
use std::sync::Arc;
use std::env;
use std::fs::File;
use std::io::Read;
use std::sync::mpsc::{channel, Sender, Receiver, RecvTimeoutError};
use std::time::Duration;
use std::thread;
use std::thread::sleep;

use ipnet::Ipv4Net;
use macaddr::MacAddr6 as MacAddress;
use uuid::Uuid;
use separator::Separatable;

use e2d2::allocators::CacheAligned;
use e2d2::interface::{
    FlowDirector, FlowSteeringMode, PmdPort, PortQueue, PciQueueType, KniQueueType, PortType, Pdu, update_tcp_checksum_,
};
use e2d2::common::ErrorKind as E2d2ErrorKind;
use e2d2::common::errors::Result as E2d2Result;
use e2d2::native::zcsi::{ipv4_phdr_chksum, RteLogLevel, RteLogtype};
use e2d2::headers::{EndOffset, IpHeader, MacHeader, TcpHeader};
use e2d2::native::zcsi::fdir_get_infos;
use e2d2::config::{basic_opts, read_matches, NetbricksConfiguration};
use e2d2::scheduler::{NetBricksContext, initialize_system, SchedulerCommand, SchedulerReply, StandaloneScheduler};

use e2d2::native::zcsi::rte_ethdev_api::{
    rte_log_set_global_level, rte_log_set_level, rte_log_get_global_level, rte_log_get_level,
};
use serde::de::DeserializeOwned;
use self::tcp_common::L234Data;
use crate::comm::{MessageFrom, MessageTo, RuntimeMessage};
use crate::comm::PipelineId;
use crate::io::print_hard_statistics;
use crate::recstore::SimpleStore;
use crate::system::SystemData;
use crate::tasks::TaskType;
use crate::tcp_common::tcp_payload_size;


pub struct RunConfiguration<T: Sized + Clone, FM: RuntimeMessage, FW: RuntimeMessage> {
    pub system_data: SystemData,
    pub netbricks_configuration: NetbricksConfiguration,
    pub engine_configuration: T,
    pub flowdirector_map: HashMap<u16, Arc<FlowDirector>>,
    pub main_sender_fm: Sender<FM>,
    pub worker_sender_fw: Sender<FW>,
    /// do we run in interactive mode?
    pub b_interactive: bool,
}

impl<T: Sized + Clone, FM: RuntimeMessage, FW: RuntimeMessage> Clone for RunConfiguration<T, FM, FW> {
    fn clone(&self) -> Self {
        Self {
            system_data: self.system_data.clone(),
            netbricks_configuration: self.netbricks_configuration.clone(),
            engine_configuration: self.engine_configuration.clone(),
            flowdirector_map: self.flowdirector_map.clone(),
            main_sender_fm: self.main_sender_fm.clone(),
            worker_sender_fw: self.worker_sender_fw.clone(),
            b_interactive: self.b_interactive,
        }
    }
}



pub fn setup_kernel_interfaces(context: &NetBricksContext) {
    // set up kni: this requires the executable KniHandleRequest to run (serving rte_kni_handle_request)
    debug!("Number of PMD ports: {}", PmdPort::num_pmd_ports());
    for port in context.ports.values() {
        debug!(
            "port {}:{} -- mac_address= {}",
            port.port_type(),
            port.port_id(),
            port.mac_address()
        );
        if port.is_virtio() {
            let associated_dpdk_port_id = port.associated_dpdk_port_id();
            let associated_port = if associated_dpdk_port_id.is_some() {
                context.id_to_port.get(&associated_dpdk_port_id.unwrap())
            } else {
                None
            };
            let net_spec = port.net_spec().as_ref().unwrap().clone();
            let ip_address_count = if associated_port.is_none() {
                1
            } else {
                if associated_port
                    .unwrap()
                    .flow_steering_mode()
                    .unwrap_or(FlowSteeringMode::Port)
                    == FlowSteeringMode::Ip
                {
                    // in addition to the primary address of the engine, we use for each core an additional IP address
                    associated_port.unwrap().rx_cores.as_ref().unwrap().len() + 1
                } else {
                    1
                }
            };
            // kni interfaces w/o associated port are unusable
            if port.is_virtio() || associated_port.is_some() {
                setup_linux_if(
                    port.linux_if().unwrap(),
                    &net_spec.ip_net.unwrap(),
                    &net_spec.mac.unwrap(),
                    &net_spec.nsname.unwrap(),
                    ip_address_count,
                )
            };
        }
    }
}

#[inline]
pub fn is_kni_core(pci: &CacheAligned<PortQueue>) -> bool {
    pci.rxq() == 0
}

pub fn setup_linux_if(
    kni_name: &str,
    ip_net: &Ipv4Net,
    mac_address: &MacAddress,
    kni_netns: &String,
    ip_address_count: usize,
) {
    let ip_addr_first = ip_net.addr();
    let prefix_len = ip_net.prefix_len();

    debug!("setup_kni");
    //# ip link set dev vEth1 address XX:XX:XX:XX:XX:XX
    let output = Command::new("ip")
        .args(&["link", "set", "dev", kni_name, "address", &mac_address.to_string()])
        .output()
        .expect("failed to assign MAC address to kni i/f");
    let reply = output.stderr;

    debug!(
        "assigning MAC addr {} to {}: {}, {}",
        &mac_address.to_string(),
        kni_name,
        output.status,
        String::from_utf8_lossy(&reply)
    );

    //# ip netns add nskni
    let output = Command::new("ip")
        .args(&["netns", "add", kni_netns])
        .output()
        .expect("failed to create namespace for kni i/f");
    let reply = output.stderr;

    debug!(
        "creating network namespace {}: {}, {}",
        kni_netns,
        output.status,
        String::from_utf8_lossy(&reply)
    );

    // ip link set dev vEth1 netns nskni
    let output = Command::new("ip")
        .args(&["link", "set", "dev", kni_name, "netns", kni_netns])
        .output()
        .expect("failed to move kni i/f to namespace");
    let reply = output.stderr;

    debug!(
        "moving kni i/f {} to namesapce {}: {}, {}",
        kni_name,
        kni_netns,
        output.status,
        String::from_utf8_lossy(&reply)
    );
    for i in 0..ip_address_count {
        // e.g. ip netns exec nskni ip addr add w.x.y.z/24 dev vEth1
        let ip_net = Ipv4Net::new(Ipv4Addr::from(u32::from(ip_addr_first) + i as u32), prefix_len)
            .unwrap()
            .to_string();
        let output = Command::new("ip")
            .args(&["netns", "exec", kni_netns, "ip", "addr", "add", &ip_net, "dev", kni_name])
            .output()
            .expect("failed to assign IP address to kni i/f");
        let reply = output.stderr;
        debug!(
            "assigning IP addr {} to {}: {}, {}",
            ip_net,
            kni_name,
            output.status,
            String::from_utf8_lossy(&reply)
        );
    }
    // e.g. ip netns exec nskni ip link set dev vEth1 up
    let output1 = Command::new("ip")
        .args(&["netns", "exec", kni_netns, "ip", "link", "set", "dev", kni_name, "up"])
        .output()
        .expect("failed to set kni i/f up");
    let reply1 = output1.stderr;
    debug!(
        "ip netns exec {} ip link set dev {} up: {}, {}",
        kni_netns,
        kni_name,
        output1.status,
        String::from_utf8_lossy(&reply1)
    );
    // e.g. ip netns exec nskni ip addr show dev vEth1
    let output2 = Command::new("ip")
        .args(&["netns", "exec", kni_netns, "ip", "addr", "show", "dev", kni_name])
        .output()
        .expect("failed to show IP address of kni i/f");
    let reply2 = output2.stdout;
    info!("show IP addr: {}\n {}", output.status, String::from_utf8_lossy(&reply2));
}

pub fn physical_ports_for_core(core: i32, pmd_ports: &HashMap<String, Arc<PmdPort>>) -> Vec<&Arc<PmdPort>> {
    pmd_ports
        .iter()
        .map(|(_, p)| p)
        .filter(|pmd_port| {
            *pmd_port.port_type() == PortType::Physical
                && pmd_port.rx_cores.as_ref().expect("rx_cores not set").contains(&core)
        })
        .collect()
}

pub fn new_port_queues_for_core(
    core: i32,
    pmd_port: &Arc<PmdPort>,
    associated_kni_port: Option<&Arc<PmdPort>>,
) -> (Option<PciQueueType>, Option<KniQueueType>) {
    let kni: Option<KniQueueType>;
    let pci: Option<PciQueueType>;

    let queue = pmd_port
        .rx_cores
        .as_ref()
        .expect("rx_cores not set")
        .iter()
        .position(|c| *c == core)
        .unwrap();
    // found queue for core
    // currently the pipeline must run the rx and tx queues with the same index
    assert_eq!(pmd_port.tx_cores.as_ref().expect("tx cores not set")[queue], core);

    let port = PmdPort::new_tx_buffered_queue_pair(pmd_port, queue as u16, queue as u16).expect(&format!(
        "Queue {} on port {} could not be initialized",
        queue,
        pmd_port.name()
    ));
    debug!(
        "setup_pipeline on core {} for dpdk port {} --  {} rxq {} txq {}",
        core,
        pmd_port.name(),
        pmd_port.mac_address(),
        port.port_queue.rxq(),
        port.port_queue.txq(),
    );

    if associated_kni_port.is_some() {
        let kni_port = associated_kni_port.unwrap();
        if !kni_port.is_virtio() {
            panic!(
                "associated kernel network interface {} must be of type virtio (type kni no longer supported)",
                kni_port.name()
            );
        }
        let port = PmdPort::new_queue_pair(kni_port, queue as u16, queue as u16).expect(&format!(
            "Queue {} on port {} could not be initialized",
            queue,
            kni_port.name()
        ));
        debug!(
            "setup_pipeline on core {} for kni port {} --  {} rxq {} txq {}",
            core,
            kni_port.name(),
            kni_port.mac_address(),
            port.rxq(),
            port.txq(),
        );
        kni = Some(port);
    } else {
        kni = None;
    }

    pci = Some(port);

    (pci, kni)
}

#[inline]
pub fn get_tcp_port_base(port: &PmdPort, count: u16) -> u16 {
    let port_mask = port.get_tcp_dst_port_mask();
    port_mask - count * (!port_mask + 1)
}

#[inline]
pub fn do_ttl(p: &mut Pdu) {
    let ip = p.headers_mut().ip_mut(1);
    let ttl = ip.ttl();
    if ttl >= 1 {
        ip.set_ttl(ttl - 1);
    }
    ip.update_checksum();
}

#[inline]
pub fn prepare_checksum_and_ttl(p: &mut Pdu) {
    //often the mbuf still contains rx offload flags if we received it from the NIC, this may fail the tx offload logic
    p.clear_rx_offload_flags();

    if p.tcp_checksum_tx_offload() {
        {
            let stack = p.headers_mut();
            let csum;
            {
                let ip = stack.ip_mut(1);
                let ttl = ip.ttl();
                if ttl >= 1 {
                    ip.set_ttl(ttl - 1);
                }
                ip.set_csum(0);
                unsafe {
                    csum = ipv4_phdr_chksum(ip, 0);
                }
            }
            stack.tcp_mut(2).set_checksum(csum);
        }
        p.set_l2_len(size_of::<MacHeader>() as u64);
        p.set_l3_len(size_of::<IpHeader>() as u64);
        p.set_l4_len(size_of::<TcpHeader>() as u64);
        trace!(
            "l234len = {}, {}, {}, ol_flags= 0x{:X}, validate= {}",
            p.l2_len(),
            p.l3_len(),
            p.l4_len(),
            p.ol_flags(),
            p.validate_tx_offload()
        );
    } else {
        let stack = p.headers_mut();
        let psz;
        let src;
        let dst;
        {
            let ip = stack.ip_mut(1);
            let ttl = ip.ttl();
            if ttl >= 1 {
                ip.set_ttl(ttl - 1);
            }
            ip.update_checksum();
            psz = ip.payload_size(0);
            src = ip.src();
            dst = ip.dst();
        }
        update_tcp_checksum_(stack.tcp_mut(2), psz, src, dst);
        trace!("ip-payload_sz= {}, checksum recalc = {:X}", psz, stack.tcp_mut(2).checksum());
    }
}

#[inline]
pub fn set_header(server: &L234Data, port: u16, p: &mut Pdu, me_mac: &MacAddress, me_ip: u32) {
    let stack = p.headers_mut();
    {
        let mac = stack.mac_mut(0);
        mac.set_dmac(&server.mac);
        mac.set_smac(me_mac);
    }
    {
        let ip = stack.ip_mut(1);
        ip.set_dst(server.ip);
        ip.set_src(me_ip);
    }
    {
        let tcp = stack.tcp_mut(2);
        tcp.set_dst_port(server.port);
        tcp.set_src_port(port);
    }
}

// remove tcp options for SYN and SYN-ACK,
// pre-requisite: no payload exists, because any payload is not shifted up
#[inline]
pub fn remove_tcp_options(p: &mut Pdu) {
    let old_offset = p.headers().tcp(2).offset() as u16;
    if old_offset > 20 {
        trace!("trimming tcp-options by { } bytes", old_offset - 20);
        p.headers_mut().tcp_mut(2).set_data_offset(5u8);
        // minimum mbuf data length is 60 bytes
        p.headers_mut().ip_mut(1).trim_length_by(old_offset - 20u16);
        //                        let trim_by = min(p.data_len() - 60usize, (old_offset - 20u16) as usize);
        //                        82599 does padding itself !?
        let trim_by = old_offset - 20;
        let payload_sz = p.payload_size(2); // this may include padding bytes
        let written = p.write_from_tail_down(payload_sz, 0x0u8);
        trace!("erased {} bytes from a payload of {} bytes", written, payload_sz);
        p.trim_payload_size(trim_by as usize);
    }
}

#[inline]
pub fn make_reply_packet(p: &mut Pdu, inc: u32) {
    let payload_sz = tcp_payload_size(p);
    let stack = p.headers_mut();
    {
        let mac = stack.mac_mut(0);
        let smac = mac.src;
        let dmac = mac.dst;
        mac.set_smac(&dmac);
        mac.set_dmac(&smac);
    }
    {
        let ip = stack.ip_mut(1);
        let sip = ip.src();
        let dip = ip.dst();
        ip.set_dst(sip);
        ip.set_src(dip);
    }

    {
        let tcp = stack.tcp_mut(2);
        let sport = tcp.src_port();
        let dport = tcp.dst_port();
        tcp.set_src_port(dport);
        tcp.set_dst_port(sport);
        tcp.set_ack_flag();
        let ack_num = tcp.seq_num().wrapping_add(payload_sz as u32 + inc);
        tcp.set_ack_num(ack_num);
    }
}

#[inline]
pub fn strip_payload(p: &mut Pdu) {
    let payload_len = tcp_payload_size(p);
    if payload_len == 0 {
        return;
    }
    {
        let ip = p.headers_mut().ip_mut(1);
        let ip_sz = ip.length();
        ip.set_length(ip_sz - payload_len as u16);
    }
    p.trim_payload_size(payload_len);
}
