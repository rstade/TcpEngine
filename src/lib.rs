#![feature(box_syntax)]
#![feature(integer_atomics)]
#![feature(trait_alias)]

// Logging
#[macro_use]
extern crate log;
extern crate e2d2;
extern crate env_logger;
extern crate fnv;
extern crate toml;
extern crate separator;
#[macro_use]
extern crate serde_derive;
extern crate eui48;
extern crate uuid;
extern crate serde;
extern crate bincode;
extern crate serde_json;
extern crate ipnet;
extern crate core;
extern crate rand;

pub mod nftraffic;
pub mod nfproxy;
pub mod run_test;
mod tcpmanager;
pub mod proxymanager;
pub mod netfcts;

use std::arch::x86_64::_rdtsc;
use netfcts::tcp_common::{CData, L234Data, ReleaseCause, TcpState, TcpStatistics};
pub use netfcts::conrecord::ConRecord;

pub use tcpmanager::{Connection};
pub use proxymanager::ProxyConnection;

use eui48::MacAddress;
use uuid::Uuid;

use e2d2::scheduler::*;
use e2d2::interface::{PmdPort, Pdu, PciQueueType, KniQueueType};

use netfcts::tasks::*;
use netfcts::{new_port_queues_for_core, physical_ports_for_core, RunConfiguration, RunTime, strip_payload};
use netfcts::utils::Timeouts;

use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bincode::serialize_into;
use netfcts::recstore::{Extension, Store64};
use netfcts::system::{get_mac_from_ifname};
use netfcts::tcp_common::tcp_payload_size;
use nfproxy::setup_delayed_proxy;
use nftraffic::setup_generator;

pub trait FnPayload =
    Fn(&mut Pdu, &mut Connection, Option<CData>, &mut bool, &usize) -> usize + Sized + Send + Sync + Clone + 'static;

pub trait FnNetworkFunctionGraph = Fn(
        i32,
        Option<PciQueueType>,
        Option<KniQueueType>,
        &mut StandaloneScheduler,
        RunConfiguration<Configuration, Store64<Extension>>,
    ) -> ()
    + Sized
    + Send
    + Sync
    + Clone
    + 'static;

pub trait FnProxySelectServer = Fn(&mut ProxyConnection, &Vec<L234Data>) + Sized + Send + Sync + Clone + 'static;
pub trait FnProxyPayload = Fn(&mut ProxyConnection, &mut [u8], usize) + Sized + Send + Sync + Clone + 'static;

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub enum EngineMode {
    SimpleProxy,
    DelayedProxy,
    TrafficGenerator,
}


#[derive(Deserialize, Clone)]
pub struct Configuration {
    pub targets: Vec<TargetConfig>,
    pub engine: EngineConfig,
    pub test_size: Option<usize>,
}


#[derive(Deserialize, Clone)]
pub struct EngineConfig {
    pub timeouts: Option<Timeouts>,
    pub port: u16,
    pub cps_limit: Option<u64>,
    pub max_open: Option<usize>,
    pub detailed_records: Option<bool>,
    pub fin_by_client: Option<usize>,
    pub fin_by_server: Option<usize>,
    pub mode: Option<EngineMode>,
}

impl EngineConfig {
    pub fn cps_limit(&self) -> u64 {
        self.cps_limit.unwrap_or(10000000)
    }
}

#[derive(Deserialize, Clone)]
pub struct TargetConfig {
    pub id: String,
    pub ip: Ipv4Addr,
    pub mac: Option<MacAddress>,
    pub linux_if: Option<String>,
    pub port: u16,
}

/// This function is called once by each scheduler running as an independent thread on each active core when the RunTime installs the pipelines.
/// Currently it iterates through all physical ports which use the respective core and sets up the network function graph (NFG) of the engine for that port and that core.
/// This happens by adding Runnables to the scheduler. Each Runnable runs to completion. E.g. it takes a packet batch from an ingress queue, processes the packets
/// following the NFG and puts the packets of the batch into egress queues. After this it returns to the scheduler.
pub fn setup_pipelines<NFG>(
    core: i32,
    pmd_ports: HashMap<String, Arc<PmdPort>>,
    sched: &mut StandaloneScheduler,
    run_configuration: RunConfiguration<Configuration, Store64<Extension>>,
    nfg: Box<NFG>,
) where
    NFG: FnNetworkFunctionGraph,
{
    for pmd_port in physical_ports_for_core(core, &pmd_ports) {
        debug!("setup_pipelines for {} on core {}:", pmd_port.name(), core);
        let mut kni_port = None;
        if pmd_port.kni_name().is_some() {
            kni_port = pmd_ports.get(pmd_port.kni_name().unwrap());
        }
        let (pci, kni) = new_port_queues_for_core(core, &pmd_port, kni_port);
        if pci.is_some() {
            debug!(
                "pmd_port= {}, rxq= {}",
                pci.as_ref().unwrap().port_queue.port,
                pci.as_ref().unwrap().port_queue.rxq()
            );
        } else {
            debug!("pmd_port= None");
        }

        if kni.is_some() {
            debug!(
                "associated kni= {}, rxq= {}",
                kni.as_ref().unwrap().port,
                kni.as_ref().unwrap().rxq()
            );
        } else {
            debug!("associated kni= None");
        }

        let uuid = Uuid::new_v4();
        let name = String::from("KniHandleRequest");

        // Kni request handler runs on first core of the associated pci port (rxq == 0)
        if pci.is_some()
            && kni.is_some()
            && kni.as_ref().unwrap().port.is_native_kni()
            && pci.as_ref().unwrap().port_queue.rxq() == 0
        {
            sched.add_runnable(
                Runnable::from_task(
                    uuid,
                    name,
                    KniHandleRequest {
                        kni_port: kni.as_ref().unwrap().port.clone(),
                        last_tick: 0,
                    },
                )
                .move_ready(), // this task must be ready from the beginning to enable managing the KNI i/f
            );
        }
        nfg(core, pci, kni, sched, run_configuration.clone());
    }
}

pub fn get_server_addresses(configuration: &Configuration) -> Vec<L234Data> {
    configuration
        .targets
        .iter()
        .enumerate()
        .map(|(i, srv_cfg)| L234Data {
            mac: srv_cfg
                .mac
                .unwrap_or_else(|| get_mac_from_ifname(srv_cfg.linux_if.as_ref().unwrap()).unwrap()),
            ip: u32::from(srv_cfg.ip),
            port: srv_cfg.port,
            server_id: srv_cfg.id.clone(),
            index: i,
        })
        .collect()
}


pub trait NFGfn = Fn(
        i32,
        Option<PciQueueType>,
        Option<KniQueueType>,
        &mut StandaloneScheduler,
        RunConfiguration<Configuration, Store64<Extension>>,
    ) + Clone;

/// return the closure which creates the network function graph for the tcp generator (server and client)
pub fn get_tcp_generator_nfg() -> impl NFGfn {
    // set_payload sets up the tcp payload packet in the tcp client
    fn set_payload(p: &mut Pdu, c: &mut Connection, cdata: Option<CData>, b_fin: &mut bool, fin_by_client: &usize) -> usize {
        let pp = c.sent_payload_pkts();
        if pp < 1 {
            // this is the first payload packet sent by client, headers are already prepared with client and server addresses and ports
            let sz;
            let mut buf = [0u8; 16];
            {
                let ip = p.headers_mut().ip_mut(1);
                serialize_into(&mut buf[..], &cdata.unwrap()).expect("cannot serialize");
                //let buf = serialize(&cdata).unwrap();
                sz = buf.len();
                let ip_sz = ip.length();
                ip.set_length(ip_sz + sz as u16);
            }
            p.add_to_payload_tail(sz).expect("insufficient tail room");
            p.copy_payload_from_u8_slice(&buf, 2); // 2 -> tcp_payload
            return tcp_payload_size(p);
        } else if pp == *fin_by_client && c.state() < TcpState::CloseWait {
            strip_payload(p);
            *b_fin = true;
            return 0;
        } else if pp < *fin_by_client && c.state() < TcpState::CloseWait {
            strip_payload(p);
            let stamp = unsafe { _rdtsc() };
            let buf = stamp.to_be_bytes();
            let ip_sz = p.headers().ip(1).length();
            p.add_to_payload_tail(buf.len()).expect("insufficient tail room for u64");
            p.headers_mut().ip_mut(1).set_length(ip_sz + buf.len() as u16);
            p.copy_payload_from_u8_slice(&buf, 2); // 2 -> tcp_payload
            return tcp_payload_size(p);
        }
        return 0;
    }

    move |core: i32,
          pci: Option<PciQueueType>,
          kni: Option<KniQueueType>,
          s: &mut StandaloneScheduler,
          config: RunConfiguration<Configuration, Store64<Extension>>| {
        if pci.is_some() && kni.is_some() {
            setup_generator(core, pci.unwrap(), kni.unwrap(), s, config, set_payload);
        }
    }
}

pub type FnSelectTarget = fn(&mut ProxyConnection, &Vec<L234Data>) -> ();

/// return the closure which creates the network function graph for the delayed tcp proxy
pub fn get_delayed_tcp_proxy_nfg(select_target: Option<FnSelectTarget>) -> impl NFGfn {
    // this function may modify the payload of client to server packets in a TCP connection
    fn process_payload_c_s(_c: &mut ProxyConnection, _payload: &mut [u8], _tailroom: usize) {
        /*
        if let IResult::Done(_, c_tag) = parse_tag(payload) {
            let userdata: &mut MyData = &mut c.userdata
                .as_mut()
                .unwrap()
                .mut_userdata()
                .downcast_mut()
                .unwrap();
            userdata.c2s_count += payload.len();
            debug!(
                "c->s (tailroom { }, {:?}): {:?}",
                tailroom,
                userdata,
                c_tag,
            );
        }

        unsafe {
            let payload_sz = payload.len(); }
            let p_payload= payload[0] as *mut u8;
            process_payload(p_payload, payload_sz, tailroom);
        } */
    }

    // this function selects the target server to use for a new incoming TCP connection received by the tcp proxy
    fn select_target_by_payload(c: &mut ProxyConnection, servers: &Vec<L234Data>) {
        //let cdata: CData = serde_json::from_slice(&c.payload).expect("cannot deserialize CData");
        //no_calls +=1;
        let cdata: CData = bincode::deserialize::<CData>(c.payload_packet.as_ref().unwrap().get_payload(2))
            .expect("cannot deserialize CData");
        //info!("cdata = {:?}", cdata);
        for (i, l234) in servers.iter().enumerate() {
            if l234.port == cdata.reply_socket.port() && l234.ip == u32::from(*cdata.reply_socket.ip()) {
                c.set_server_index(i as u8);
                break;
            }
        }
    }

    let select_target = select_target.unwrap_or(select_target_by_payload);

    move |core: i32,
          pci: Option<PciQueueType>,
          kni: Option<KniQueueType>,
          s: &mut StandaloneScheduler,
          config: RunConfiguration<Configuration, Store64<Extension>>| {
        if pci.is_some() && kni.is_some() {
            setup_delayed_proxy(
                core,
                pci.unwrap(),
                kni.unwrap(),
                s,
                config,
                select_target.clone(),
                process_payload_c_s.clone(),
            );
        }
    }
}

pub fn initialize_engine(indirectly: bool) -> (RunTime<Configuration, Store64<Extension>>, EngineMode, Arc<AtomicBool>) {
    env_logger::init();
    info!("Reading configuration ..");

    // cannot directly read toml file from command line, as cargo test owns it. Thus we take a detour and read it from a file.
    const INDIRECTION_FILE: &str = "./tests/toml_file.txt";

    let mut runtime: RunTime<Configuration, Store64<Extension>> = if indirectly {
        match RunTime::init_indirectly(INDIRECTION_FILE) {
            Ok(run_time) => run_time,
            Err(err) => panic!("failed to initialize RunTime {}", err),
        }
    } else {
        match RunTime::init() {
            Ok(run_time) => run_time,
            Err(err) => panic!("failed to initialize RunTime {}", err),
        }
    };

    let mode = runtime
        .run_configuration
        .engine_configuration
        .engine
        .mode
        .as_ref()
        .unwrap_or(&EngineMode::TrafficGenerator)
        .clone();

    // setup flowdirector for physical ports:
    runtime.setup_flowdirector().expect("failed to setup flowdirector");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("received SIGINT or SIGTERM");
        r.store(false, Ordering::SeqCst);
    })
    .expect("error setting Ctrl-C handler");
    (runtime, mode, running)
}
