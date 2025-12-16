// Note: avoid nightly-only `trait_alias` feature by using normal traits with blanket impls

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
extern crate uuid;
extern crate serde;

pub mod analysis;
extern crate bincode;
extern crate serde_json;
extern crate ipnet;
extern crate core;
extern crate rand;

pub mod nftraffic;
pub mod nftcpproxy;
pub mod run_test;
mod tcpmanager;
pub mod proxymanager;
pub mod netfcts;
pub mod runtime_install;
pub mod proxy_helper;
pub mod profiling;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

use std::arch::x86_64::_rdtsc;
use netfcts::tcp_common::{CData, L234Data, ReleaseCause, TcpState, TcpStatistics};
pub use netfcts::conrecord::ConRecord;

pub use tcpmanager::{Connection};
pub use proxymanager::ProxyConnection;

use macaddr::MacAddr6;
use serde::Deserialize as SerdeDeserialize;
use std::str::FromStr;

use e2d2::scheduler::*;
use e2d2::interface::{PmdPort, Pdu, PciQueueType, KniQueueType};

use netfcts::{new_port_queues_for_core, physical_ports_for_core, RunConfiguration, RunTime, strip_payload};
use netfcts::utils::Timeouts;

use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bincode::serialize_into;
use e2d2::queues::new_mpsc_queue_pair;
use ipnet::Ipv4Net;
use rand::Rng;
use netfcts::recstore::{Extension, Store64};
use netfcts::system::{get_mac_from_ifname};
use netfcts::tcp_common::tcp_payload_size;
// use nfdelayedproxy::setup_delayed_proxy; // removed: no such function, use setup_tcp_proxy below
use nftraffic::setup_generator;

pub use runtime_install::install_pipelines_for_all_cores;
use crate::nftcpproxy::setup_tcp_proxy;
use crate::proxy_helper::{DelayedMode, PduAllocator};

// Replacement for former `trait alias` of a function-like constraint
pub trait FnPayload:
    Fn(&mut Pdu, &mut Connection, Option<CData>, &mut bool, &usize) -> usize + Send + Sync + Clone + 'static
{
}

impl<T> FnPayload for T where
    T: Fn(&mut Pdu, &mut Connection, Option<CData>, &mut bool, &usize) -> usize + Send + Sync + Clone + 'static
{
}

pub trait FnNetworkFunctionGraph:
    Fn(
        i32,
        Option<PciQueueType>,
        Option<KniQueueType>,
        &mut StandaloneScheduler,
        RunConfiguration<Configuration, Store64<Extension>>,
    ) -> ()
    + Send
    + Sync
    + Clone
    + 'static
{
}

impl<T> FnNetworkFunctionGraph for T where
    T: Fn(
            i32,
            Option<PciQueueType>,
            Option<KniQueueType>,
            &mut StandaloneScheduler,
            RunConfiguration<Configuration, Store64<Extension>>,
        ) -> ()
        + Send
        + Sync
        + Clone
        + 'static
{
}

pub trait FnProxySelectServer: Fn(&mut ProxyConnection, &Vec<L234Data>) + Send + Sync + Clone + 'static {}

impl<T> FnProxySelectServer for T where T: Fn(&mut ProxyConnection, &Vec<L234Data>) + Send + Sync + Clone + 'static {}

pub trait FnProxyPayload: Fn(&mut ProxyConnection, &mut [u8], usize) + Send + Sync + Clone + 'static {}

impl<T> FnProxyPayload for T where T: Fn(&mut ProxyConnection, &mut [u8], usize) + Send + Sync + Clone + 'static {}

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

// Flexible deserializer: accept string form ("aa:bb:cc:dd:ee:ff") or [u8;6] array, or omit entirely
fn deserialize_mac_opt<'de, D>(deserializer: D) -> Result<Option<MacAddr6>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(SerdeDeserialize)]
    #[serde(untagged)]
    enum MacRepr {
        Str(String),
        Bytes([u8; 6]),
    }

    let opt = Option::<MacRepr>::deserialize(deserializer)?;
    let mac = match opt {
        None => None,
        Some(MacRepr::Str(s)) => {
            let parsed = MacAddr6::from_str(&s).map_err(serde::de::Error::custom)?;
            Some(parsed)
        }
        Some(MacRepr::Bytes(b)) => Some(MacAddr6::new(b[0], b[1], b[2], b[3], b[4], b[5])),
    };
    Ok(mac)
}

fn deserialize_ipv4net<'de, D>(deserializer: D) -> Result<Ipv4Net, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ipv4Net::from_str(&s).map_err(serde::de::Error::custom)
}

#[derive(Deserialize, Clone)]
pub struct TargetConfig {
    pub id: String,
    #[serde(deserialize_with = "deserialize_ipv4net")]
    pub ipnet: Ipv4Net,
    #[serde(default, deserialize_with = "deserialize_mac_opt")]
    pub mac: Option<MacAddr6>,
    pub linux_if: Option<String>,
    pub port: u16,
}

#[derive(Debug)]
pub enum InterfaceConfigError {
    CommandFailed(String),
    NoInterface(String),
}

impl std::fmt::Display for InterfaceConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            InterfaceConfigError::CommandFailed(msg) => write!(f, "Command failed: {}", msg),
            InterfaceConfigError::NoInterface(id) => {
                write!(f, "No interface specified for target {}", id)
            }
        }
    }
}

impl std::error::Error for InterfaceConfigError {}

/// Check if an IP address is already assigned to an interface
fn is_ip_assigned(interface: &str, ipnet: Ipv4Net) -> Result<bool, InterfaceConfigError> {
    let output = Command::new("ip")
        .args(&["addr", "show", "dev", interface])
        .output()
        .map_err(|e| InterfaceConfigError::CommandFailed(format!("Failed to execute 'ip addr show': {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(InterfaceConfigError::CommandFailed(format!(
            "ip addr show failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Check if the IP appears in the output (with or without prefix)
    // Format in output is typically "inet 192.168.1.10/24"
    let ip_str = ipnet.to_string();
    Ok(stdout.contains(&format!("inet {}", ip_str)))
}

/// Adds an IP address to a network interface
fn add_ip_address(interface: &str, ipnet: Ipv4Net) -> Result<(), InterfaceConfigError> {
    let ip_with_prefix = format!("{}", ipnet);

    // Check if IP is already assigned
    if is_ip_assigned(interface, ipnet)? {
        println!("  ℹ IP {} already assigned to interface {}", ipnet, interface);
        return Ok(());
    }

    println!("  Adding IP {} to interface {}", ip_with_prefix, interface);

    let output = Command::new("ip")
        .args(&["addr", "add", &ip_with_prefix, "dev", interface])
        .output()
        .map_err(|e| InterfaceConfigError::CommandFailed(format!("Failed to execute 'ip addr add': {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(InterfaceConfigError::CommandFailed(format!("ip addr add failed: {}", stderr)));
    }

    println!("    ✓ IP address added");
    Ok(())
}

/// Brings a network interface up
fn bring_interface_up(interface: &str) -> Result<(), InterfaceConfigError> {
    println!("  Bringing interface {} up", interface);

    let output = Command::new("ip")
        .args(&["link", "set", interface, "up"])
        .output()
        .map_err(|e| InterfaceConfigError::CommandFailed(format!("Failed to execute 'ip link set up': {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(InterfaceConfigError::CommandFailed(format!(
            "ip link set up failed: {}",
            stderr
        )));
    }

    println!("    ✓ Interface is up");
    Ok(())
}

//// Configures network interfaces from a vector of TargetConfig
///
/// # Arguments
/// * `targets` - Vector of TargetConfig entries
/// * `prefix_len` - Network prefix length (e.g., 24 for /24)
///
/// # Returns
/// * `Ok(())` if all interfaces were configured successfully
/// * `Err()` with details about the first failure
pub fn configure_interfaces(targets: &[TargetConfig]) -> Result<(), InterfaceConfigError> {
    use std::collections::HashSet;

    println!("\n🔧 Configuring Local Network Interfaces");
    println!("========================================\n");

    // Track what we've already configured: (interface, ip)
    let mut configured: HashSet<(String, Ipv4Net)> = HashSet::new();
    let mut interfaces_brought_up: HashSet<String> = HashSet::new();

    for target in targets {
        println!("📡 Target: {} ({}:{})", target.id, target.ipnet, target.port);

        if let Some(ref interface) = target.linux_if {
            let config_key = (interface.clone(), target.ipnet);

            // Check if we've already configured this interface-IP pair
            if configured.contains(&config_key) {
                println!(
                    "  ℹ Interface {} with IP {} already configured, skipping\n",
                    interface, target.ipnet
                );
                continue;
            }

            // Add IP address
            add_ip_address(interface, target.ipnet)?;
            configured.insert(config_key);

            // Bring interface up (only once per interface)
            if !interfaces_brought_up.contains(interface) {
                bring_interface_up(interface)?;
                interfaces_brought_up.insert(interface.clone());
            } else {
                println!("  ℹ Interface {} already up\n", interface);
            }

            println!("  ✅ Configuration complete\n");
        } else {
            println!("  ⚠ No interface specified, skipping\n");
        }
    }

    println!("✅ All interfaces configured successfully\n");
    Ok(())
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
    nfg: &NFG,
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
            ip: u32::from(srv_cfg.ipnet.addr()),
            port: srv_cfg.port,
            server_id: srv_cfg.id.clone(),
            index: i,
        })
        .collect()
}

/// return the closure which creates the network function graph for the tcp generator (server and client)
pub fn get_tcp_generator_nfg() -> impl FnNetworkFunctionGraph {
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
        0
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

// this function selects the target server to use for a new incoming TCP connection received by the tcp proxy
fn select_target_by_payload(c: &mut ProxyConnection, servers: &Vec<L234Data>) {
    let cdata: CData =
        bincode::deserialize::<CData>(c.payload_packet.as_ref().unwrap().get_payload(2)).expect("cannot deserialize CData");
    //info!("cdata = {:?}", cdata);
    for (i, l234) in servers.iter().enumerate() {
        if l234.port == cdata.reply_socket.port() && l234.ip == u32::from(*cdata.reply_socket.ip()) {
            c.set_server_index(i as u8);
            break;
        }
    }
}

fn select_target_randomly(c: &mut ProxyConnection, servers: &Vec<L234Data>) {
    let server_count = servers.len();
    let mut rng = rand::thread_rng();
    let random_number = rng.gen_range(0..server_count);
    c.set_server_index(random_number as u8);
}

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
        let payload_sz = payload.len();
        let p_payload= payload[0] as *mut u8;
        process_payload(p_payload, payload_sz, tailroom);
    } */
}

/// return the closure which creates the network function graph for the delayed tcp proxy
pub fn get_delayed_tcp_proxy_nfg(select_target: Option<FnSelectTarget>) -> impl FnNetworkFunctionGraph {
    let select_target = select_target.unwrap_or(select_target_by_payload);
    // Build the mode inside the closure to avoid capturing non-Send/Sync state.
    move |core: i32,
          pci: Option<PciQueueType>,
          kni: Option<KniQueueType>,
          s: &mut StandaloneScheduler,
          config: RunConfiguration<Configuration, Store64<Extension>>| {
        if let (Some(pci), Some(kni)) = (pci, kni) {
            let (producer, consumer) = new_mpsc_queue_pair();
            let mode = DelayedMode {
                pdu_allocator: PduAllocator::new(),
                producer,
                bypass_consumer: Some(consumer),
            };
            setup_tcp_proxy(
                Some(mode),
                core,
                pci,
                kni,
                s,
                config,
                select_target.clone(),
                process_payload_c_s.clone(),
            );
        }
    }
}

/// return the closure which creates the network function graph for the tcp proxy w/o delayed binding
pub fn get_simple_tcp_proxy_nfg(select_target: Option<FnSelectTarget>) -> impl FnNetworkFunctionGraph {
    let select_target = select_target.unwrap_or(select_target_randomly);

    move |core: i32,
          pci: Option<PciQueueType>,
          kni: Option<KniQueueType>,
          s: &mut StandaloneScheduler,
          config: RunConfiguration<Configuration, Store64<Extension>>| {
        if pci.is_some() && kni.is_some() {
            setup_tcp_proxy(
                None,
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
