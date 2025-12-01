extern crate ctrlc;
extern crate e2d2;
extern crate env_logger;
extern crate eui48;
extern crate ipnet;
extern crate separator;
extern crate bincode;
extern crate rustyline;
extern crate tcp_lib;
extern crate clap;
extern crate rand;
#[macro_use]
extern crate serde_derive;

pub mod netfcts;

// Logging
#[macro_use]
extern crate log;
extern crate uuid;
extern crate serde;

use e2d2::interface::{PmdPort, Pdu, HeaderStack};
use e2d2::scheduler::StandaloneScheduler;

use tcp_lib::netfcts::comm::{MessageFrom, MessageTo, PipelineId};
use tcp_lib::netfcts::io::print_tcp_counters;
use tcp_lib::netfcts::conrecord::{ConRecord, HasTcpState, HasConData};
#[cfg(feature = "profiling")]
use tcp_lib::netfcts::io::print_rx_tx_counters;
use tcp_lib::netfcts::recstore::{Extension, Store64};

use tcp_lib::{setup_pipelines, Connection, EngineMode, get_tcp_generator_nfg, get_delayed_tcp_proxy_nfg, initialize_engine, get_simple_tcp_proxy_nfg};
use tcp_lib::netfcts::tcp_common::ReleaseCause;
use tcp_lib::netfcts::tcp_common::TcpState;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::RecvTimeoutError;
use std::thread;
use std::time::Duration;
use std::io::{Write, BufWriter};
use std::fs::File;
use std::net::{SocketAddrV4, Ipv4Addr};
use std::mem;
use std::cmp;

use separator::Separatable;
use rustyline::Editor;
use rustyline::error::ReadlineError;
use clap::{Command, Arg, ArgAction};
use e2d2::native::zcsi::rte_ethdev_api::{rte_eth_stats_get, rte_eth_stats};

fn print_performance_from_stamps(cpu_clock: u64, nr_connections: usize, start_stop_stamps: HashMap<PipelineId, (u64, u64)>) {
    println!("\nperformance data derived from time stamps sent by pipelines:");
    let mut min_t: u64 = 0;
    let mut max_t: u64 = 0;
    for (p, (t_start, t_stop)) in &start_stop_stamps {
        if min_t == 0 {
            min_t = *t_start
        } else {
            min_t = cmp::min(min_t, *t_start)
        }
        if max_t == 0 {
            max_t = *t_stop
        } else {
            max_t = cmp::max(max_t, *t_stop)
        }
        let per_connection = (*t_stop - *t_start) / nr_connections as u64;
        let cps = cpu_clock / per_connection;
        println!(
            "{} cycles used= {}, per connection = {}, cps= {}",
            p,
            (t_stop - t_start).separated_string(),
            per_connection,
            cps
        );
    }

    let mut stats = rte_eth_stats::new();
    let retval;
    unsafe {
        retval = rte_eth_stats_get(1u16, &mut stats);
    }
    if retval != 0 {
        panic!("rte_eth_stats_get failed");
    }

    let per_connection = (max_t - min_t) / nr_connections as u64 / start_stop_stamps.len() as u64;
    let per_packet = (max_t - min_t) / (stats.ipackets + stats.opackets);
    println!(
        "cyles over all pipes = {}, per connection = {}, cps = {}, pps= {}",
        (max_t - min_t).separated_string(),
        per_connection,
        cpu_clock / per_connection,
        cpu_clock / per_packet,
    );
}

fn evaluate_records(
    con_records_c: &mut Vec<(PipelineId, Store64<Extension>)>,
    con_records_s: &mut Vec<(PipelineId, Store64<Extension>)>,
    cpu_clock: u64,
) {
    println!("\nperformance data derived from connection records:");
    let file = match File::create("c_records.txt") {
        Err(why) => panic!("couldn't create c_records.txt: {}", why),
        Ok(file) => file,
    };
    let mut f = BufWriter::new(file);

    //we are searching for the most extreme time stamps over all pipes
    let mut min_total;
    let mut max_total;
    let mut total_connections = 0;
    {
        let cc = (con_records_c[0].1).iter().last().unwrap();
        min_total = (cc.0.clone(), cc.1.clone());
        max_total = min_total.clone();
    }

    // a hash map of all server side records by uuid
    let mut by_uuid = HashMap::with_capacity(con_records_s[0].1.len() * con_records_s.len());
    let mut completed_count_s = 0;
    for (_p, c_records_server) in con_records_s {
        c_records_server.iter().enumerate().for_each(|(_i, c)| {
            if c.0.release_cause() == ReleaseCause::ActiveClose && c.0.states().last().unwrap() == &TcpState::Closed {
                completed_count_s += 1
            };
            by_uuid.insert(c.0.uid(), c.0);
        });
    }

    for (p, c_records_client) in con_records_c {
        f.write_all(format!("Pipeline {}:\n", p).as_bytes())
            .expect("cannot write c_records");
        let mut completed_count_c = 0;
        c_records_client.sort_0_by(|a, b| a.port().cmp(&b.port()));
        if c_records_client.len() > 0 {
            total_connections += c_records_client.len();
            let mut min = c_records_client.iter().last().unwrap();
            let mut max = min;
            c_records_client.iter().enumerate().for_each(|(i, c)| {
                let uuid = c.0.uid();
                let c_server = by_uuid.remove(&uuid);
                let line = format!("{:6}: {}\n", i, c.0);
                f.write_all(line.as_bytes()).expect("cannot write c_records");
                if c_server.is_some() {
                    let c_server = c_server.unwrap();
                    let line = format!(
                        "        ({:?}, {:21}, {:6}, {:3}, {:7}, {:7}, {:?}, {:?}, +{}, {:?})\n",
                        c_server.role(),
                        if c_server.sock().0 != 0 {
                            let s = c_server.sock();
                            SocketAddrV4::new(Ipv4Addr::from(s.0), s.1).to_string()
                        } else {
                            "none".to_string()
                        },
                        c_server.port(),
                        c_server.server_index(),
                        c_server.sent_payload_packets(),
                        c_server.recv_payload_packets(),
                        c_server.states(),
                        c_server.release_cause(),
                        (c_server.get_first_stamp().unwrap() - c.0.get_first_stamp().unwrap()).separated_string(),
                        c_server
                            .deltas_to_base_stamp()
                            .iter()
                            .map(|u| u.separated_string())
                            .collect::<Vec<_>>(),
                    );
                    f.write_all(line.as_bytes()).expect("cannot write c_records");
                }
                if (c.0.release_cause() == ReleaseCause::PassiveClose || c.0.release_cause() == ReleaseCause::ActiveClose)
                    && c.0.states().last().unwrap() == &TcpState::Closed
                {
                    completed_count_c += 1
                }
                if c.0.get_first_stamp().unwrap_or(u64::MAX) < min.0.get_first_stamp().unwrap_or(u64::MAX) {
                    min = c
                }
                if c.0.get_last_stamp().unwrap_or(0) > max.0.get_last_stamp().unwrap_or(0) {
                    max = c
                }
                if i == (c_records_client.len() - 1) && min.0.get_first_stamp().is_some() && max.0.get_last_stamp().is_some()
                {
                    let total = max.0.get_last_stamp().unwrap() - min.0.get_first_stamp().unwrap();
                    println!(
                        "{} total used cycles = {}, per connection = {}",
                        p,
                        total.separated_string(),
                        (total / (i as u64 + 1)).separated_string()
                    );
                }
            });
            if min.0.get_first_stamp().unwrap_or(u64::MAX) < min_total.0.get_first_stamp().unwrap_or(u64::MAX) {
                min_total = (min.0.clone(), min.1.clone())
            }
            if max.0.get_last_stamp().unwrap_or(0) > max_total.0.get_last_stamp().unwrap_or(0) {
                max_total = (max.0.clone(), max.1.clone())
            }
        }

        println!("{} completed client connections = {}", p, completed_count_c);
    }

    println!("total completed server connections = {}", completed_count_s);

    println!("unbound server-side connections = {}", by_uuid.len());
    by_uuid.iter().enumerate().for_each(|(i, (_, c))| {
        debug!("{:6}: {}", i, c);
    });


    if min_total.0.get_first_stamp().is_some() && max_total.0.get_last_stamp().is_some() {
        let total = max_total.0.get_last_stamp().unwrap() - min_total.0.get_first_stamp().unwrap();
        println!(
            "max used cycles over all pipelines = {}, per connection = {} ({} cps)",
            total.separated_string(),
            (total / (total_connections as u64)).separated_string(),
            cpu_clock / (total / (total_connections as u64 + 1)),
        );
    }

    f.flush().expect("cannot flush BufWriter");
}


pub fn main() {
    let (mut runtime, mode, running) = initialize_engine(false);

    let run_configuration = runtime.run_configuration.clone();
    let run_configuration_cloned = run_configuration.clone();
    let nr_connections = run_configuration.engine_configuration.test_size.unwrap_or(128);

    runtime.start_schedulers().expect("cannot start schedulers");


    match mode {
        EngineMode::TrafficGenerator => {
            runtime
                .install_pipeline_on_cores(Box::new(
                    move |core: i32, pmd_ports: HashMap<String, Arc<PmdPort>>, s: &mut StandaloneScheduler| {
                        setup_pipelines(
                            core,
                            pmd_ports,
                            s,
                            run_configuration_cloned.clone(),
                            &get_tcp_generator_nfg().clone(),
                        );
                    },
                ))
                .expect("cannot install pipelines for TrafficGenerator");
        }
        EngineMode::DelayedProxy => {
            runtime
                .install_pipeline_on_cores(Box::new(
                    move |core: i32, pmd_ports: HashMap<String, Arc<PmdPort>>, s: &mut StandaloneScheduler| {
                        setup_pipelines(
                            core,
                            pmd_ports,
                            s,
                            run_configuration_cloned.clone(),
                            &get_delayed_tcp_proxy_nfg(None).clone(),
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
                .expect("cannot install pipelines for DelayedProxy");
        }
    };

    let cores = runtime.context().unwrap().active_cores.clone();

    // start the run_time
    runtime.start();

    // give threads some time to do initialization work
    thread::sleep(Duration::from_millis(1000 as u64));

    let (mtx, reply_mrx) = runtime.get_main_channel().expect("cannot get main channel");
    // start generator by setting all tasks on scheduler threads to ready state
    mtx.send(MessageFrom::StartEngine).unwrap();

    //main loop
    if run_configuration.b_interactive {
        let cmd_print = Command::new("print")
            .arg(
                Arg::new("performance")
                    .long("performance")
                    .short('p')
                    .help("performance data of pipeline components")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("rxtx")
                    .long("rxtx")
                    .help(" rxtx of pipeline components")
                    .action(ArgAction::SetTrue),
            );
        let cmd_quit = Command::new("quit");
        let shim_cmd = Command::new(":").subcommand(cmd_print).subcommand(cmd_quit);
        let mut rl = Editor::<()>::new().unwrap();
        println!("enter commands or press ctrl-c to terminate TcpEngine ...");
        loop {
            let readline = rl.readline(">> ");
            match readline {
                Ok(line) => {
                    rl.add_history_entry(line.as_str());
                    let shim_line = ": ".to_owned() + &line;
                    let matches = shim_cmd.clone().try_get_matches_from(shim_line.split_whitespace());
                    if let Err(err) = matches {
                        println!("{}", err);
                        continue;
                    }
                    let matches = matches.unwrap();
                    let sub_matches = matches.subcommand_matches("print");
                    match sub_matches {
                        Some(arg_matches) => {
                            if arg_matches.get_flag("performance") {
                                // request performance data
                                mtx.send(MessageFrom::PrintPerformance(cores.clone())).unwrap();
                                thread::sleep(Duration::from_millis(100 as u64));
                            }
                            if arg_matches.get_flag("rxtx") {
                                mtx.send(MessageFrom::PrintPerformance(cores.clone())).unwrap();
                                thread::sleep(Duration::from_millis(100 as u64));
                            }
                        }
                        None => break,
                    }
                    let sub_matches = matches.subcommand_matches("quit");
                    match sub_matches {
                        Some(_) => break,
                        None => continue,
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!("CTRL-C");
                    break;
                }
                Err(ReadlineError::Eof) => {
                    println!("CTRL-D");
                    break;
                }
                Err(err) => {
                    println!("Error: {:?}", err);
                    break;
                }
            }
        }
    } else {
        println!("press ctrl-c to terminate TcpEngine ...");
        while running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(200 as u64)); // Sleep for a bit
        }
    }

    // request performance data
    mtx.send(MessageFrom::PrintPerformance(cores)).unwrap();
    thread::sleep(Duration::from_millis(100 as u64));
    // request counters
    mtx.send(MessageFrom::FetchCounter).unwrap();
    // request connection records
    if run_configuration
        .engine_configuration
        .engine
        .detailed_records
        .unwrap_or(false)
    {
        mtx.send(MessageFrom::FetchCRecords).unwrap();
    }

    let mut tcp_counters_to = HashMap::new();
    let mut tcp_counters_from = HashMap::new();
    let mut start_stop_stamps: HashMap<PipelineId, (u64, u64)> = HashMap::new();
    let mut con_records_s = Vec::with_capacity(64);
    let mut con_records_c = Vec::with_capacity(64);

    // loop for replies
    loop {
        match reply_mrx.recv_timeout(Duration::from_millis(1000)) {
            Ok(MessageTo::Counter(pipeline_id, tcp_counter_to, tcp_counter_from, _rx_tx_stats)) => {
                print_tcp_counters(&pipeline_id, &tcp_counter_to, &tcp_counter_from);
                #[cfg(feature = "profiling")]
                print_rx_tx_counters(&pipeline_id, &_rx_tx_stats.unwrap());
                tcp_counters_to.insert(pipeline_id.clone(), tcp_counter_to);
                tcp_counters_from.insert(pipeline_id, tcp_counter_from);
            }
            Ok(MessageTo::CRecords(pipeline_id, Some(c_records_client), Some(c_records_server))) => {
                con_records_c.push((pipeline_id.clone(), c_records_client));
                con_records_s.push((pipeline_id, c_records_server));
            }
            Ok(MessageTo::TimeStamps(p, t_start, t_stop)) => {
                start_stop_stamps.insert(p.clone(), (t_start, t_stop));
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

    info!(
        "Connection record sizes = {} + {}",
        mem::size_of::<Connection>(),
        mem::size_of::<ConRecord>()
    );

    info!(
        "Pdu size = {}, HeaderStack size = {}",
        mem::size_of::<Pdu>(),
        mem::size_of::<HeaderStack>(),
    );

    if start_stop_stamps.len() > 0 {
        print_performance_from_stamps(run_configuration.system_data.cpu_clock, nr_connections, start_stop_stamps);
    }

    if run_configuration
        .engine_configuration
        .engine
        .detailed_records
        .unwrap_or(false)
    {
        evaluate_records(
            &mut con_records_c,
            &mut con_records_s,
            run_configuration.system_data.cpu_clock,
        );
    }

    // stop and exit all scheduler threads and finally the run_time thread
    mtx.send(MessageFrom::Exit).unwrap();

    thread::sleep(Duration::from_millis(200 as u64)); // Sleep for a bit
    std::process::exit(0);
}
