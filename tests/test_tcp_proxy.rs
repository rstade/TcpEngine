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
use std::io::{Read, BufWriter, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::RecvTimeoutError;
use std::fs::File;
use std::collections::HashMap;
use std::vec::Vec;
use std::mem;
use std::process;
use separator::Separatable;
use e2d2::native::zcsi::*;
use e2d2::interface::{PmdPort};
use e2d2::scheduler::StandaloneScheduler;

use tcp_lib::netfcts::tcp_common::{ReleaseCause, TcpStatistics, L234Data, TcpState};
use tcp_lib::netfcts::io::{print_tcp_counters, print_rx_tx_counters};
use tcp_lib::netfcts::conrecord::{HasTcpState, ConRecord};
use tcp_lib::netfcts::comm::{MessageFrom, MessageTo};
use tcp_lib::netfcts::recstore::Extension;
use tcp_lib::{EngineMode, get_delayed_tcp_proxy_nfg, get_simple_tcp_proxy_nfg, initialize_engine, ProxyConnection,
          setup_pipelines};


#[test]
fn tcp_proxy() {
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

    info!("Testing client to server connections of ProxyEngine ..");

    // this is the function, which selects the target server to use for a new TCP connection
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

    match mode {
        EngineMode::DelayedProxy => {
            runtime
                .install_pipeline_on_cores(Box::new(
                    move |core: i32, pmd_ports: HashMap<String, Arc<PmdPort>>, s: &mut StandaloneScheduler| {
                        setup_pipelines(
                            core,
                            pmd_ports,
                            s,
                            run_configuration_cloned.clone(),
                            &get_delayed_tcp_proxy_nfg(Some(f_by_payload)).clone(),
                        );
                    },
                ))
                .expect("cannot install pipelines for DelayedProxy");
        }
        EngineMode::SimpleProxy => {
            runtime
                .install_pipeline_on_cores(Box::new(
                    move |core: i32, pmd_ports: HashMap<String, Arc<PmdPort>>, s: &mut StandaloneScheduler| {
                        setup_pipelines(
                            core,
                            pmd_ports,
                            s,
                            run_configuration_cloned.clone(),
                            &get_simple_tcp_proxy_nfg(None).clone(),
                        );
                    },
                ))
                .expect("cannot install pipelines for SimpleProxy");
        }
        _ => {
            error!("mode must be either SimpleProxy or DelayedProxy for this test");
        }
    }

    let cores = runtime.context().unwrap().active_cores.clone();

    let associated_ports: Vec<_> = runtime
        .context()
        .unwrap()
        .ports
        .values()
        .filter(|p| p.is_physical() && p.kni_name().is_some())
        .map(|p| &runtime.context().unwrap().ports[p.kni_name().unwrap()])
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

    debug!(
        "Connection record sizes = {} + {} + {}",
        mem::size_of::<ProxyConnection>(),
        mem::size_of::<ConRecord>(),
        mem::size_of::<Extension>()
    );

    debug!("before run: available mbufs in memory pool= {:6}", unsafe {
        mbuf_avail_count()
    });

    // give threads some time to do initialization work
    thread::sleep(Duration::from_millis(1000 as u64));

    // set up servers
    for server in configuration.targets.clone() {
        let target_port = server.port; // moved into thread
        let target_ip = server.ip;
        let id = server.id;
        thread::spawn(move || match TcpListener::bind((target_ip, target_port)) {
            Ok(listener1) => {
                debug!("bound server {} to {}:{}", id, target_ip, target_port);
                for stream in listener1.incoming() {
                    let mut stream = stream.unwrap();
                    let mut buf = [0u8; 256];
                    stream.read(&mut buf[..]).unwrap();
                    debug!("server {} received: {}", id, String::from_utf8(buf.to_vec()).unwrap());
                    stream
                        .write(&format!("Thank You from {}", id).to_string().into_bytes()) // at least 17 bytes
                        .unwrap();
                }
            }
            _ => {
                panic!("failed to bind server {} to {}:{}", id, target_ip, target_port);
            }
        });
    }

    thread::sleep(Duration::from_millis(500 as u64)); // wait for the servers

    if log_enabled!(log::Level::Debug) {
        unsafe {
            fdir_get_infos(1u16);
        }
    }

    // emulate clients

    let timeout = Duration::from_millis(2000 as u64);

    for ntry in 0..configuration.test_size.unwrap() {
        match TcpStream::connect_timeout(&SocketAddr::from(proxy_addr), timeout) {
            Ok(mut stream) => {
                debug!("test connection {}: TCP connect to proxy successful", ntry);
                stream.set_write_timeout(Some(timeout)).unwrap();
                stream.set_read_timeout(Some(timeout)).unwrap();
                match stream.write(&format!("{} stars", ntry).to_string().into_bytes()) {
                    // at least 7 bytes
                    Ok(_) => {
                        debug!("successfully send {} stars", ntry);
                        let mut buf = [0u8; 256];
                        match stream.read(&mut buf[..]) {
                            Ok(_) => debug!("on try {} we received {}", ntry, String::from_utf8(buf.to_vec()).unwrap()),
                            _ => {
                                panic!("timeout on connection {} while waiting for answer", ntry);
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

    thread::sleep(Duration::from_millis(200)); // Sleep for a bit

    mtx.send(MessageFrom::PrintPerformance(cores)).unwrap();
    thread::sleep(Duration::from_millis(1000 as u64));

    mtx.send(MessageFrom::FetchCounter).unwrap();
    if configuration.engine.detailed_records.unwrap_or(false) {
        mtx.send(MessageFrom::FetchCRecords).unwrap();
    }

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
                debug!("{}: received {} CRecords", pipeline_id, recv_con_records.len(),);
                con_records.insert(pipeline_id, recv_con_records);
            }
            Ok(_m) => error!("illegal MessageTo received from reply_to_main channel"),
            Err(RecvTimeoutError::Timeout) => {
                break;
            }
            Err(e) => {
                error!("error receiving from reply_to_main channel (reply_mrx): {}", e);
                break;
            }
        }
    }

    info!("after run: available mbufs in memory pool= {:6}", unsafe {
        mbuf_avail_count()
    });
    println!("\nTask Performance Data:\n");

    if configuration.engine.detailed_records.unwrap_or(false) {
        let mut completed_count_c = 0;
        let mut completed_count_s = 0;
        for (_p, con_recs) in &con_records {
            for c in con_recs.iter_0() {
                if (c.release_cause() == ReleaseCause::PassiveClose || c.release_cause() == ReleaseCause::ActiveClose)
                    && c.last_state() == TcpState::Closed
                {
                    completed_count_c += 1
                };
            }
            for c in con_recs.iter_1() {
                if (c.release_cause() == ReleaseCause::PassiveClose || c.release_cause() == ReleaseCause::ActiveClose)
                    && c.last_state() == TcpState::Closed
                {
                    completed_count_s += 1
                };
            }
        }

        println!("\ncompleted connections c/s: {}/{}\n", completed_count_c, completed_count_s);

        // write connection records into file
        let file = match File::create("c_records.txt") {
            Err(why) => panic!("couldn't create c_records.txt: {}", why),
            Ok(file) => file,
        };
        let mut f = BufWriter::new(file);

        for (p, c_records) in con_records {
            f.write_all(format!("Pipeline {}:\n", p).as_bytes())
                .expect("cannot write c_records");

            if c_records.len() > 0 {
                let mut completed_count = 0;
                let mut min = c_records.iter_0().last().unwrap().clone();
                let mut max = min.clone();
                c_records.iter().enumerate().for_each(|(i, (c, e))| {
                    let line = format!("{:6}: {}\n        {}\n", i, c, e);
                    f.write_all(line.as_bytes()).expect("cannot write c_records");

                    if (c.release_cause() == ReleaseCause::PassiveClose || c.release_cause() == ReleaseCause::ActiveClose)
                        && c.states().last().unwrap() == &TcpState::Closed
                    {
                        completed_count += 1
                    }
                    if c.get_first_stamp().unwrap_or(u64::max_value()) < min.get_first_stamp().unwrap_or(u64::max_value()) {
                        min = c.clone()
                    }
                    if c.get_last_stamp().unwrap_or(0) > max.get_last_stamp().unwrap_or(0) {
                        max = c.clone()
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
                assert_eq!(
                    completed_count,
                    tcp_counters_s.get(&p).unwrap()[TcpStatistics::SentSyn]
                        + tcp_counters_c.get(&p).unwrap()[TcpStatistics::SentSyn]
                );
            }
        }

        f.flush().expect("cannot flush BufWriter");

        assert_eq!(configuration.test_size.unwrap(), completed_count_c);
        assert_eq!(configuration.test_size.unwrap(), completed_count_s);
    }

    for (p, counters) in tcp_counters_s {
        assert_eq!(counters[TcpStatistics::SentSyn], counters[TcpStatistics::SentSynAck2]);
        assert_eq!(counters[TcpStatistics::SentSynAck2], counters[TcpStatistics::RecvSynAck]);
        assert_eq!(
            counters[TcpStatistics::RecvFin] + counters[TcpStatistics::RecvFinPssv],
            tcp_counters_c.get(&p).unwrap()[TcpStatistics::RecvFinPssv]
                + tcp_counters_c.get(&p).unwrap()[TcpStatistics::RecvFin]
        );
        assert!(
            tcp_counters_c.get(&p).unwrap()[TcpStatistics::SentFin]
                + tcp_counters_c.get(&p).unwrap()[TcpStatistics::SentFinPssv]
                <= tcp_counters_c.get(&p).unwrap()[TcpStatistics::RecvAck4Fin]
        );
        assert!(
            counters[TcpStatistics::SentFin] + counters[TcpStatistics::SentFinPssv] <= counters[TcpStatistics::RecvAck4Fin]
        );
        if configuration.test_size.unwrap() <= 9 {
            // otherwise the payload bytes are difficult to count
            assert_eq!(counters[TcpStatistics::RecvPayload], counters[TcpStatistics::SentSyn] * 17);
            assert_eq!(
                tcp_counters_c.get(&p).unwrap()[TcpStatistics::RecvPayload],
                tcp_counters_c.get(&p).unwrap()[TcpStatistics::RecvSyn] * 7
            );
        }
    }

    mtx.send(MessageFrom::Exit).unwrap();
    thread::sleep(Duration::from_millis(2000));

    info!("terminating ProxyEngine ...");
    println!("\nPASSED\n");
    std::process::exit(0);
}
