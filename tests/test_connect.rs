extern crate ctrlc;
extern crate e2d2;
extern crate traffic_lib;
extern crate time;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate ipnet;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::env;
use std::time::Duration;
use std::thread;
use std::net::{TcpListener};
use std::sync::mpsc::channel;
use std::sync::mpsc::RecvTimeoutError;
use std::collections::{HashSet, HashMap};

use e2d2::config::{basic_opts, read_matches};
use e2d2::native::zcsi::*;
use e2d2::interface::{PortQueue, PortType};
use e2d2::scheduler::{initialize_system, NetBricksContext};
use e2d2::scheduler::StandaloneScheduler;
use e2d2::allocators::CacheAligned;

use traffic_lib::read_config;
use traffic_lib::{get_mac_from_ifname, print_hard_statistics};
use traffic_lib::setup_pipelines;
use traffic_lib::L234Data;
use traffic_lib::{MessageFrom, MessageTo};
use traffic_lib::spawn_recv_thread;
use traffic_lib::errors::*;

use traffic_lib::ReleaseCause;
use traffic_lib::{TcpState, TcpControls};
use std::vec::Vec;

#[test]
fn test_connect() {
    env_logger::init();
    info!("Testing trafficengine: setup and release of connections ...");
    let toml_file = "tests/test_gen.toml";

    let log_level_rte = if log_enabled!(log::Level::Debug) {
        RteLogLevel::RteLogDebug
    } else {
        RteLogLevel::RteLogInfo
    };
    unsafe {
        rte_log_set_global_level(log_level_rte);
        rte_log_set_level(RteLogtype::RteLogtypePmd, log_level_rte);
        info!("dpdk log global level: {}", rte_log_get_global_level());
        info!("dpdk log level for PMD: {}", rte_log_get_level(RteLogtype::RteLogtypePmd));
    }

    let configuration = read_config(toml_file).unwrap();

    if configuration.test_size.is_none() {
        error!("missing parameter 'test_size' in configuration file {}", toml_file);
        std::process::exit(1);
    };

    fn am_root() -> bool {
        match env::var("USER") {
            Ok(val) => val == "root",
            Err(_e) => false,
        }
    }

    if !am_root() {
        error!(
            " ... must run as root, e.g.: sudo -E env \"PATH=$PATH\" $executable, see also test.sh\n\
             Do not run 'cargo test' as root."
        );
        std::process::exit(1);
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("received SIGINT or SIGTERM");
        r.store(false, Ordering::SeqCst);
    }).expect("error setting Ctrl-C handler");

    let opts = basic_opts();

    let args: Vec<String> = vec!["proxyengine", "-f", toml_file]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let mut netbricks_configuration = read_matches(&matches, &opts);

    let l234data: Vec<L234Data> = configuration
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
        }).collect();

    fn check_system(context: NetBricksContext) -> Result<NetBricksContext> {
        for port in context.ports.values() {
            if port.port_type() == &PortType::Dpdk {
                debug!("Supported filters on port {}:", port.port_id());
                for i in RteFilterType::RteEthFilterNone as i32 + 1..RteFilterType::RteEthFilterMax as i32 {
                    let result = unsafe { rte_eth_dev_filter_supported(port.port_id() as u16, RteFilterType::from(i)) };
                    debug!("{0: <30}: {1: >5}", RteFilterType::from(i), result);
                }
            }
        }
        Ok(context)
    }

    match initialize_system(&mut netbricks_configuration)
        .map_err(|e| e.into())
        .and_then(|ctxt| check_system(ctxt))
    {
        Ok(mut context) => {
            print_hard_statistics(1u16);
            context.start_schedulers();

            let (mtx, mrx) = channel::<MessageFrom>();
            let (reply_mtx, reply_mrx) = channel::<MessageTo>();

            let configuration_cloned = configuration.clone();
            let mtx_clone = mtx.clone();

            context.add_pipeline_to_run(Box::new(
                move |core: i32, p: HashSet<CacheAligned<PortQueue>>, s: &mut StandaloneScheduler| {
                    setup_pipelines(
                        core,
                        configuration_cloned.test_size.unwrap(),
                        p,
                        s,
                        &configuration_cloned.engine,
                        l234data.clone(),
                        mtx_clone.clone(),
                    );
                },
            ));

            // start the controller
            spawn_recv_thread(mrx, context, configuration.clone());

            // give threads some time to do initialization work
            thread::sleep(Duration::from_millis(1000 as u64));


            // set up servers
            for server in configuration.targets {
                let target_port = server.port; // moved into thread
                let target_ip = server.ip;
                let id = server.id;
                thread::spawn(move || match TcpListener::bind((target_ip, target_port)) {
                    Ok(listener1) => {
                        debug!("bound server {} to {}:{}", id, target_ip, target_port);
                        for stream in listener1.incoming() {
                            let mut _stream = stream.unwrap();
                            // debug!("{} received connection from: {}", id, stream.peer_addr().unwrap());
                        }
                    }
                    _ => {
                        panic!("failed to bind server {} to {}:{}", id, target_ip, target_port);
                    }
                });
            }

            thread::sleep(Duration::from_millis(2000 as u64)); // wait for the servers

            // start generator
            mtx.send(MessageFrom::StartEngine(reply_mtx)).unwrap();

            thread::sleep(Duration::from_millis(5000 as u64));
            mtx.send(MessageFrom::PrintPerformance(vec![1,2])).unwrap();
            thread::sleep(Duration::from_millis(100 as u64));
            //main loop
            /* println!("press ctrl-c to terminate proxy ...");
            while running.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(200 as u64)); // Sleep for a bit
            }
            */
            mtx.send(MessageFrom::FetchCounter).unwrap();
            mtx.send(MessageFrom::FetchCRecords).unwrap();

            let mut tcp_counters = HashMap::new();
            let mut con_records = HashMap::new();

            loop {
                match reply_mrx.recv_timeout(Duration::from_millis(1000)) {
                    Ok(MessageTo::Counter(pipeline_id, tcp_counter)) => {
                        info!("{}: {}", pipeline_id, tcp_counter);
                        tcp_counters.insert(pipeline_id, tcp_counter);
                    }
                    Ok(MessageTo::CRecords(pipeline_id, c_records)) =>
                    {
                        con_records.insert(pipeline_id, c_records);
                    }
                    Ok(_m) => error!("illegal MessageTo received from reply_to_main channel"),
                    Err(RecvTimeoutError::Timeout) =>  { break; }
                    Err(e) => {
                        error!("error receiving from reply_to_main channel (reply_mrx): {}", e);
                        break;
                    }
                }
            }

            for (p,c_records) in con_records {
                let mut completed_count = 0;
                debug!("Pipeline {}:", p);
                c_records.iter().enumerate().for_each( |(i,c)| {
                    debug!("{:6}: {}", i, c);
                    if c.get_release_cause() == ReleaseCause::FinServer
                        && c.c_states().last().unwrap() == &TcpState::Closed
                        {
                            completed_count += 1
                        };
                });
                assert_eq!(completed_count, tcp_counters.get(&p).unwrap()[TcpControls::SentSyn]);
            }

            mtx.send(MessageFrom::Exit).unwrap();
            thread::sleep(Duration::from_millis(2000));

            debug!("terminating TrafficEngine");
            std::process::exit(0);
        }
        Err(ref e) => {
            error!("Error: {}", e);
            if let Some(backtrace) = e.backtrace() {
                debug!("Backtrace: {:?}", backtrace);
            }
            std::process::exit(1);
        }
    }
}