extern crate ctrlc;
extern crate e2d2;
extern crate time;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate ipnet;
extern crate separator;
extern crate tcp_lib;

use std::sync::Arc;
use std::time::Duration;
use std::thread;
use std::io::Read;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::collections::{HashMap};
use std::sync::mpsc::RecvTimeoutError;
use std::process;

use separator::Separatable;

use e2d2::interface::{PmdPort};
use e2d2::scheduler::StandaloneScheduler;

use tcp_lib::netfcts::tcp_common::{ReleaseCause, L234Data, TcpState};
use tcp_lib::netfcts::io::{print_tcp_counters, print_rx_tx_counters};
use tcp_lib::netfcts::conrecord::{HasTcpState};
use tcp_lib::netfcts::comm::{MessageFrom, MessageTo};

use tcp_lib::{EngineMode, get_delayed_tcp_proxy_nfg, initialize_engine, ProxyConnection, setup_pipelines};


#[test]
fn delayed_binding_proxy() {
    let (mut runtime, mode, _running) = initialize_engine(true);

    let run_configuration = runtime.run_configuration.clone();
    let configuration = &run_configuration.engine_configuration;

    if run_configuration.engine_configuration.test_size.is_none() {
        error!(
            "missing parameter 'test_size' in configuration file {}",
            runtime.toml_filename()
        );
        process::exit(1);
    };

    info!("Testing early Fin of client ..");

    // this is the function, which selects the target server to use for a new TCP connection
    fn f_by_payload(c: &mut ProxyConnection, l234data: &Vec<L234Data>) {
        let s = String::from_utf8(c.payload_packet.as_ref().unwrap().get_payload(2).to_vec()).unwrap();
        // read first item in string and convert to usize:
        let stars: usize = s.split(" ").next().unwrap().parse().unwrap();
        let remainder = stars % l234data.len();
        c.set_server_index(remainder as u8);
        debug!("selecting {}", l234data[remainder].server_id);
    }

    runtime.start_schedulers().expect("cannot start schedulers");

    let run_configuration_cloned = run_configuration.clone();
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

    let cores = runtime.context().unwrap().active_cores.clone();

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
    // for this test tcp client timeout must be shorter than timeouts by timer wheel
    let timeout = Duration::from_millis(50 as u64);

    const CLIENT_THREADS: usize = 10;
    for _i in 0..CLIENT_THREADS {
        thread::spawn(move || {
            for ntry in 0..queries {
                match TcpStream::connect(&SocketAddr::from(proxy_addr)) {
                    Ok(mut stream) => {
                        debug!("test connection {}: TCP connect to proxy successful", ntry);
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
                                        debug!("timeout on connection {} while waiting for answer", ntry);
                                    }
                                };
                            }
                            _ => {
                                panic!("error when writing to test connection {}", ntry);
                            }
                        }
                    }
                    _ => {
                        panic!("test connection {}: 3-way handshake with proxy failed", ntry);
                    }
                }
            }
        });
    }
    thread::sleep(Duration::from_millis(5000)); // Wait for client timeouts

    println!("\nTask Performance Data:\n");
    mtx.send(MessageFrom::PrintPerformance(cores)).unwrap();
    thread::sleep(Duration::from_millis(1000 as u64));

    mtx.send(MessageFrom::FetchCounter).unwrap();
    mtx.send(MessageFrom::FetchCRecords).unwrap();

    let mut tcp_counters_c = HashMap::new();
    let mut tcp_counters_s = HashMap::new();
    let mut con_records = HashMap::new();

    loop {
        match reply_mrx.recv_timeout(Duration::from_millis(1000)) {
            Ok(MessageTo::Counter(pipeline_id, tcp_counter_c, tcp_counter_s, rx_tx_stats)) => {
                print_tcp_counters(&pipeline_id, &tcp_counter_c, &tcp_counter_s);
                if rx_tx_stats.is_some() {
                    print_rx_tx_counters(&pipeline_id, &rx_tx_stats.unwrap());
                }
                tcp_counters_c.insert(pipeline_id.clone(), tcp_counter_c);
                tcp_counters_s.insert(pipeline_id, tcp_counter_s);
            }
            Ok(MessageTo::CRecords(pipeline_id, Some(recv_con_records), _)) => {
                debug!("{}: received {} CRecords", pipeline_id, recv_con_records.len());
                con_records.insert(pipeline_id, recv_con_records);
            }
            Ok(_m) => error!("illegal MessageTo received from reply_to_main channel"),
            Err(RecvTimeoutError::Timeout) => {
                break;
            }
            Err(e) => {
                error!("error receiving from reply_to_main channel (reply_mrx): {}", e);
            }
        }
    }

    for (p, c_records) in &con_records {
        info!("Pipeline {}:", p);
        if c_records.len() > 0 {
            let mut completed_count = 0;
            let mut min = c_records.iter_0().last().unwrap();
            let mut max = min;
            c_records.iter_0().enumerate().for_each(|(i, c)| {
                info!("{:6}: {}", i, c);
                if (c.release_cause() == ReleaseCause::PassiveClose || c.release_cause() == ReleaseCause::ActiveClose)
                    && c.states().last().unwrap() == &TcpState::Closed
                {
                    completed_count += 1
                }
                if c.get_first_stamp().unwrap_or(u64::max_value()) < min.get_first_stamp().unwrap_or(u64::max_value()) {
                    min = c
                }
                if c.get_last_stamp().unwrap_or(0) > max.get_last_stamp().unwrap_or(0) {
                    max = c
                }
                if i == (c_records.len() - 1) && min.get_first_stamp().is_some() && max.get_last_stamp().is_some() {
                    let total = max.get_last_stamp().unwrap() - min.get_first_stamp().unwrap();
                    info!(
                        "total used cycles= {}, per connection = {}",
                        total.separated_string(),
                        (total / (i as u64 + 1)).separated_string()
                    );
                }
            });
        }
    }

    let mut completed_count_c = 0;
    let mut completed_count_s = 0;
    for (_p, con_recs) in &con_records {
        for c in con_recs.iter_0() {
            if c.release_cause() == ReleaseCause::ActiveClose && c.last_state() == TcpState::Closed {
                completed_count_c += 1
            };
            assert_eq!(
                c.states(),
                [
                    TcpState::Closed,
                    TcpState::SynSent,
                    TcpState::Established,
                    TcpState::FinWait1,
                    TcpState::Closed
                ]
            );
        }
        for c in con_recs.iter_1() {
            if c.release_cause() == ReleaseCause::PassiveClose && c.last_state() == TcpState::Closed {
                completed_count_s += 1
            };
            assert_eq!(
                c.states(),
                [TcpState::Listen, TcpState::SynReceived, TcpState::LastAck, TcpState::Closed]
            );
        }
    }

    info!("completed connections c/s: {}/{}", completed_count_c, completed_count_s);
    assert_eq!(completed_count_c, configuration.test_size.unwrap() * CLIENT_THREADS);
    assert_eq!(completed_count_s, configuration.test_size.unwrap() * CLIENT_THREADS);

    mtx.send(MessageFrom::Exit).unwrap();
    thread::sleep(Duration::from_millis(2000));

    info!("terminating ProxyEngine ...");
    println!("\nPASSED\n");
    std::process::exit(0);
}
