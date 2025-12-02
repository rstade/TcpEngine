extern crate ctrlc;
extern crate e2d2;
extern crate ipnet;
extern crate bincode;

use std::arch::x86_64::_rdtsc;
use std::time::Duration;
use std::thread;
use std::net::{SocketAddr, SocketAddrV4, TcpStream, Shutdown, Ipv4Addr};
use std::io::{Read, Write, BufWriter};
use std::fs::File;
use std::process;

use e2d2::interface::{FlowSteeringMode};

use separator::Separatable;
use crate::netfcts::conrecord::HasTcpState;
#[cfg(feature = "profiling")]
use netfcts::io::print_rx_tx_counters;

use {crate::get_tcp_generator_nfg, crate::install_pipelines_for_all_cores};
use {crate::CData};
use crate::netfcts::comm::MessageFrom;
use {crate::initialize_engine, crate::ReleaseCause};
use {crate::TcpState, crate::TcpStatistics};
use crate::analysis::collect_from_main_reply;


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TestType {
    Client,
    Server,
}

// we use this function for the integration tests
pub fn run_test(test_type: TestType) {
    let (mut runtime, _mode, _running) = initialize_engine(true);
    debug!("*** run_test logging is in debug mode ***");

    let run_configuration = runtime.run_configuration.clone();
    let configuration = &run_configuration.engine_configuration;
    let run_configuration_cloned = run_configuration.clone();

    if configuration.test_size.is_none() {
        error!(
            "missing parameter 'test_size' in configuration file {}",
            runtime.toml_filename()
        );
        process::exit(1);
    };

    // number of payloads sent, after which the connection is closed
    #[cfg(any(test, feature = "test-support"))]
    let fin_by_client = configuration.engine.fin_by_client.unwrap_or(1000);

    runtime.start_schedulers().expect("cannot start schedulers");

    install_pipelines_for_all_cores(&mut runtime, run_configuration_cloned, get_tcp_generator_nfg())
        .expect("cannot install pipelines");


    let mut pci = None;
    let mut kni = None;

    for port in runtime
        .context()
        .expect("no context")
        .ports
        .values()
        .filter(|p| p.is_physical() && p.flow_steering_mode().is_some())
    {
        // note down pci and kni ifaces
        if pci.is_some() {
            error!("the test may not work with more than one physical dpdk port");
        } else {
            pci = Some(port.clone());
            kni = Some(
                runtime
                    .context()
                    .unwrap()
                    .ports
                    .get(port.kni_name().unwrap())
                    .unwrap()
                    .clone(),
            );
            assert!(kni.is_some());
        }
    }

    // this is quick and dirty and just for testing purposes:
    let port_mask = u16::from_be(
        run_configuration.netbricks_configuration.ports[0]
            .fdir_conf
            .unwrap()
            .mask
            .dst_port_mask,
    );
    let rx_queues = pci.as_ref().unwrap().rx_cores.as_ref().unwrap().len() as u16;
    let rfs_mode = pci.as_ref().unwrap().flow_steering_mode().unwrap_or(FlowSteeringMode::Port);
    let cores = runtime.context().unwrap().active_cores.clone();
    debug!("rx_queues = { }, port mask = 0x{:x}", rx_queues, port_mask);

    // start the controller
    runtime.start();

    // give threads some time to do initialization work
    thread::sleep(Duration::from_millis(1000u64));

    if test_type == TestType::Client {
        // set up local test servers (only when test-support is enabled)
        #[cfg(any(test, feature = "test-support"))]
        {
            use crate::test_support::spawn_test_servers;
            let _handles = spawn_test_servers(
                fin_by_client,
                run_configuration.engine_configuration.targets.clone(),
            );
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            warn!(
                "feature 'test-support' not enabled; skipping local servers for Client test"
            );
        }

        thread::sleep(Duration::from_millis(1000u64)); // wait for the servers
    }
    // start generator

    let (mtx, reply_mrx) = runtime.get_main_channel().expect("cannot get main channel");
    mtx.send(MessageFrom::StartEngine).unwrap();
    thread::sleep(Duration::from_millis(2000u64));

    if test_type == TestType::Server {
        let timeout = Duration::from_millis(1000u64);
        for ntry in 0..run_configuration.engine_configuration.test_size.unwrap() as u16 {
            let target_socket;
            if rfs_mode == FlowSteeringMode::Port {
                let target_port = 0xFFFF - (!port_mask + 1) * (ntry % rx_queues);
                target_socket = SocketAddr::from((kni.as_ref().unwrap().ip_addr().unwrap(), target_port));
                debug!("try {}: connecting to port 0x{:x}", ntry, target_port);
            } else {
                let target_ip =
                    Ipv4Addr::from(u32::from(kni.as_ref().unwrap().ip_addr().unwrap()) + (ntry % rx_queues) as u32 + 1);
                target_socket = SocketAddr::from((target_ip, 0xFFFF));
            }

            match TcpStream::connect_timeout(&target_socket, timeout) {
                Ok(mut stream) => {
                    debug!("test connection {}: TCP connect to engine successful", ntry);
                    stream.set_write_timeout(Some(timeout)).unwrap();
                    stream.set_read_timeout(Some(timeout)).unwrap();
                    let cdata = CData::new(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080), 0xFFFF, unsafe {
                        _rdtsc()
                    });
                    //let json_string = serde_json::to_string(&cdata).expect("cannot serialize cdata");
                    //stream.write(json_string.as_bytes()).expect("cannot write to stream");
                    let bin_vec = bincode::serialize(&cdata).expect("cannot serialize cdata");
                    stream.write(&bin_vec).expect("cannot write to stream");
                    let mut buffer = [0u8; 1500];
                    stream
                        .read(&mut buffer[..])
                        .expect("did not receive reply from server to cdata");
                    match stream.write(&format!("{} stars", ntry).to_string().into_bytes()) {
                        Ok(_) => {
                            debug!("successfully send {} stars", ntry);
                        }
                        _ => {
                            panic!("error when writing to test connection {}", ntry);
                        }
                    }
                    stream
                        .read(&mut buffer[..])
                        .expect("did not receive reply from server to my stars");
                    stream.shutdown(Shutdown::Both).unwrap();
                }
                _ => {
                    panic!("test connection {}: 3-way handshake with proxy failed", ntry);
                }
            }
        }
    }

    thread::sleep(Duration::from_millis(1000u64));
    mtx.send(MessageFrom::PrintPerformance(cores)).unwrap();
    thread::sleep(Duration::from_millis(100u64));


    mtx.send(MessageFrom::FetchCounter).unwrap();
    if run_configuration
        .engine_configuration
        .engine
        .detailed_records
        .unwrap_or(false)
    {
        mtx.send(MessageFrom::FetchCRecords).unwrap();
    }


    let collected = collect_from_main_reply(&reply_mrx, 1000);
    let tcp_counters_to = collected.tcp_counters_to;
    let tcp_counters_from = collected.tcp_counters_from;
    let con_records = collected.con_records;

    if run_configuration
        .engine_configuration
        .engine
        .detailed_records
        .unwrap_or(false)
    {
        let file = match File::create("c_records.txt") {
            Err(why) => panic!("couldn't create c_records.txt: {}", why),
            Ok(file) => file,
        };
        let mut f = BufWriter::new(file);

        assert_ne!(con_records.len(), 0);
        if test_type == TestType::Server {
            for (p, (_, c_records)) in &con_records {
                match c_records {
                    Some(c_records) if c_records.len() > 0 => {
                        let mut completed_count = 0;
                        let mut min = c_records.iter().last().unwrap().0;
                        let mut max = min;
                        c_records.iter().enumerate().for_each(|(i, c)| {
                            let line = format!("{:6}: {}\n", i, c.0);
                            f.write_all(line.as_bytes()).expect("cannot write c_records");
                            if c.0.states().last().unwrap() == &TcpState::Closed {
                                completed_count += 1
                            }
                            if c.0.get_first_stamp().unwrap_or(u64::MAX) < min.get_first_stamp().unwrap_or(u64::MAX) {
                                min = c.0
                            }
                            if c.0.get_last_stamp().unwrap_or(0) > max.get_last_stamp().unwrap_or(0) {
                                max = c.0
                            }
                            if i == (c_records.len() - 1)
                                && min.get_first_stamp().is_some()
                                && max.get_last_stamp().is_some()
                            {
                                let total = max.get_last_stamp().unwrap() - min.get_first_stamp().unwrap();
                                info!(
                                    "total used cycles= {}, per connection = {}",
                                    total.separated_string(),
                                    (total / (i as u64 + 1)).separated_string()
                                );
                            }
                        });
                        println!("{} completed connections = {}", p, completed_count);
                        assert_eq!(completed_count, tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvSyn]);
                    }
                    _ => (),
                }
            }
        }

        if test_type == TestType::Client {
            for (p, (c_records, _)) in &con_records {
                let mut completed_count = 0;
                info!("Pipeline {}:", p);
                f.write_all(format!("Pipeline {}:\n", p).as_bytes())
                    .expect("cannot write c_records");
                c_records.as_ref().unwrap().iter().enumerate().for_each(|(i, c)| {
                    let line = format!("{:6}: {}\n", i, c.0);
                    f.write_all(line.as_bytes()).expect("cannot write c_records");
                    if (c.0.release_cause() == ReleaseCause::PassiveClose
                        || c.0.release_cause() == ReleaseCause::ActiveClose)
                        && c.0.states().last().unwrap() == &TcpState::Closed
                    {
                        completed_count += 1
                    };
                });
                println!("{} completed connections = {}", p, completed_count);
                assert_eq!(completed_count, tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentSyn]);
            }
        }

        f.flush().expect("cannot flush BufWriter");
    }
    if test_type == TestType::Server {
        for (p, _) in &tcp_counters_from {
            assert_eq!(
                tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvSyn],
                tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentSynAck]
            );
            assert_eq!(
                tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentSynAck],
                tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvSynAck2]
            );
            assert!(
                tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvFin]
                    + tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvFinPssv]
                    <= tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentAck4Fin]
            );
            assert!(
                tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentFinPssv]
                    + tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentFin]
                    <= tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvAck4Fin]
            );
        }
    } else {
        for (p, _) in &tcp_counters_to {
            assert_eq!(
                tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentSyn],
                tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentSynAck2]
            );
            assert_eq!(
                tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentSynAck2],
                tcp_counters_to.get(&p).unwrap()[TcpStatistics::RecvSynAck]
            );
            assert!(
                tcp_counters_to.get(&p).unwrap()[TcpStatistics::RecvFin]
                    + tcp_counters_to.get(&p).unwrap()[TcpStatistics::RecvFinPssv]
                    <= tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentAck4Fin]
            );
            assert!(
                tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentFinPssv]
                    + tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentFin]
                    <= tcp_counters_to.get(&p).unwrap()[TcpStatistics::RecvAck4Fin]
            );
        }
    }
    mtx.send(MessageFrom::Exit).unwrap();
    thread::sleep(Duration::from_millis(2000));
    println!("*** *** PASSED *** ***");
    debug!("terminating TcpEngine");
    process::exit(0);
}
