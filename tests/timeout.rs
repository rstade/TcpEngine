extern crate ctrlc;
extern crate e2d2;
extern crate time;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate ipnet;
extern crate netfcts;
extern crate traffic_lib;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::thread;
use std::io::Read;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::collections::{HashMap};
use std::process;

use e2d2::interface::{PmdPort};
use e2d2::scheduler::{StandaloneScheduler};

use netfcts::tcp_common::{ReleaseCause, L234Data};
use netfcts::comm::{MessageFrom, MessageTo};
use netfcts::recstore::{Extension, Store64};
use netfcts::conrecord::HasTcpState;
use netfcts::RunTime;
use traffic_lib::{Configuration, EngineMode, get_delayed_tcp_proxy_nfg, ProxyConnection, setup_pipelines};


#[test]
fn delayed_binding_proxy() {
    env_logger::init();

    // cannot directly read toml file from command line, as cargo test owns it. Thus we take a detour and read it from a file.
    const INDIRECTION_FILE: &str = "./tests/toml_file.txt";

    let mut runtime: RunTime<Configuration, Store64<Extension>> = match RunTime::init_indirectly(INDIRECTION_FILE) {
        Ok(run_time) => run_time,
        Err(err) => panic!("failed to initialize RunTime {}", err),
    };

    let mode = runtime
        .run_configuration
        .engine_configuration
        .engine
        .mode
        .as_ref()
        .unwrap_or(&EngineMode::DelayedProxy)
        .clone();

    // setup flowdirector for physical ports:
    runtime.setup_flowdirector().expect("failed to setup flowdirector");

    let run_configuration = runtime.run_configuration.clone();
    let configuration = &run_configuration.engine_configuration;

    if run_configuration.engine_configuration.test_size.is_none() {
        error!(
            "missing parameter 'test_size' in configuration file {}",
            runtime.toml_filename()
        );
        process::exit(1);
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("received SIGINT or SIGTERM");
        r.store(false, Ordering::SeqCst);
    })
    .expect("error setting Ctrl-C handler");

    info!("Testing timeout ..");

    // this is the closure, which selects the target server to use for a new TCP connection
    fn f_by_payload(c: &mut ProxyConnection, l234data: &Vec<L234Data>) {
        let s = String::from_utf8(c.payload_packet.as_ref().unwrap().get_payload(2).to_vec()).unwrap();
        // read first item in string and convert to usize:
        let stars: usize = s.split(" ").next().unwrap().parse().unwrap();
        let remainder = stars % l234data.len();
        c.set_server_index(remainder as u8);
        debug!("selecting {}", l234data[remainder].server_id);
    }

    let run_configuration_cloned = run_configuration.clone();

    runtime.start_schedulers().expect("cannot start schedulers");

    if mode == EngineMode::DelayedProxy {
        runtime
            .install_pipeline_on_cores(Box::new(
                move |core: i32, pmd_ports: HashMap<String, Arc<PmdPort>>, s: &mut StandaloneScheduler| {
                    setup_pipelines(
                        core,
                        pmd_ports,
                        s,
                        run_configuration_cloned.clone(),
                        Box::new(get_delayed_tcp_proxy_nfg(Some(f_by_payload))).clone(),
                    );
                },
            ))
            .expect("cannot install pipelines for DelayedProxy");
    } else {
        error!("mode must be DelayedProxy for this test");
    }

    let associated_ports: Vec<_> = runtime
        .context()
        .unwrap()
        .ports
        .values()
        .filter(|p| p.is_physical() && p.kni_name().is_some())
        .map(|p| &runtime.context().unwrap().ports[p.kni_name().as_ref().unwrap().clone()])
        .collect();

    let proxy_addr = (
        associated_ports[0]
            .net_spec()
            .as_ref()
            .unwrap()
            .ip_net
            .as_ref()
            .unwrap()
            .addr(),
        configuration.engine.port,
    );

    // start the run_time receive thread
    runtime.start();

    let (mtx, reply_mrx) = runtime.get_main_channel().expect("cannot get main channel");
    mtx.send(MessageFrom::StartEngine).unwrap();
    thread::sleep(Duration::from_millis(2000 as u64));

    // emulate clients
    let queries = configuration.test_size.unwrap();

    let timeout = Duration::from_millis(6000 as u64);

    const CLIENT_THREADS: usize = 10;
    for _i in 0..CLIENT_THREADS {
        debug!("starting thread {} with {} test_size", _i, queries);
        thread::spawn(move || {
            for ntry in 0..queries {
                match TcpStream::connect(&SocketAddr::from(proxy_addr)) {
                    Ok(mut stream) => {
                        debug!("test connection {}: TCP connect to proxy successful", _i);
                        stream.set_write_timeout(Some(timeout)).unwrap();
                        stream.set_read_timeout(Some(timeout)).unwrap();
                        match stream.write(&format!("{} stars", ntry).to_string().into_bytes()) {
                            Ok(_) => {
                                debug!("successfully send {} stars", ntry);
                                let mut buf = [0u8; 256];
                                match stream.read(&mut buf[..]) {
                                    Ok(_) => {
                                        info!("on try {} we received {}", ntry, String::from_utf8(buf.to_vec()).unwrap())
                                    }
                                    _ => {
                                        debug!("timeout on connection {} while waiting for answer", _i);
                                    }
                                };
                            }
                            _ => {
                                panic!("error when writing to test connection {}", _i);
                            }
                        }
                    }
                    _ => {
                        panic!("test connection {}: 3-way handshake with proxy failed", _i);
                    }
                }
            }
        });
        thread::sleep(Duration::from_millis(48)); // roughly one event each third slot
    }
    thread::sleep(Duration::from_millis(3000)); // wait for clients to be started

    mtx.send(MessageFrom::FetchCRecords).unwrap();

    match reply_mrx.recv_timeout(Duration::from_millis(5000)) {
        Ok(MessageTo::CRecords(_pipeline_id, Some(con_records), _)) => {
            assert_eq!(con_records.len(), configuration.test_size.unwrap() * CLIENT_THREADS);
            let mut timeouts = 0;
            for c in con_records.iter_0() {
                debug!("{}", c);
                if c.release_cause() == ReleaseCause::Timeout {
                    timeouts += 1;
                }
            }
            assert_eq!(timeouts, configuration.test_size.unwrap() * CLIENT_THREADS);
        }
        Ok(_m) => error!("illegal MessageTo received from reply_to_main channel"),
        Err(e) => {
            error!("error receiving from reply_to_main channel (reply_mrx): {}", e);
        }
    }

    mtx.send(MessageFrom::Exit).unwrap();
    thread::sleep(Duration::from_millis(2000));

    info!("terminating ProxyEngine ...");
    println!("\nPASSED\n");
    std::process::exit(0);
}
