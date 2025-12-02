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

use e2d2::interface::{Pdu, HeaderStack};

use tcp_lib::netfcts::comm::{MessageFrom, PipelineId};
use tcp_lib::netfcts::conrecord::ConRecord;
#[cfg(feature = "profiling")]
use tcp_lib::netfcts::io::print_rx_tx_counters;

use tcp_lib::{Connection, EngineMode, get_tcp_generator_nfg, get_delayed_tcp_proxy_nfg, initialize_engine, get_simple_tcp_proxy_nfg, install_pipelines_for_all_cores};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use rustyline::Editor;
use rustyline::error::ReadlineError;
use clap::{Command, Arg, ArgAction};

// Use shared analysis helpers moved to the library module
use tcp_lib::analysis::{evaluate_records, print_performance_from_stamps, collect_from_main_reply};
use tcp_lib::netfcts::recstore::{Store64, Extension};

// Removed local helper implementations; now provided by tcp_lib::analysis


pub fn main() {
    let (mut runtime, mode, running) = initialize_engine(false);

    let run_configuration = runtime.run_configuration.clone();
    let run_configuration_cloned = run_configuration.clone();
    let nr_connections = run_configuration.engine_configuration.test_size.unwrap_or(128);

    runtime.start_schedulers().expect("cannot start schedulers");

    match mode {
        EngineMode::TrafficGenerator => {
            install_pipelines_for_all_cores(&mut runtime, run_configuration_cloned, get_tcp_generator_nfg())
                .expect("cannot install pipelines for TrafficGenerator");
        }
        EngineMode::DelayedProxy => {
            install_pipelines_for_all_cores(&mut runtime, run_configuration_cloned, get_delayed_tcp_proxy_nfg(None))
                .expect("cannot install pipelines for DelayedProxy");
        }
        EngineMode::SimpleProxy => {
            install_pipelines_for_all_cores(&mut runtime, run_configuration_cloned, get_simple_tcp_proxy_nfg(None))
                .expect("cannot install pipelines for DelayedProxy");
        }
    };

    let cores = runtime.context().unwrap().active_cores.clone();

    // start the run_time
    runtime.start();

    // give threads some time to do initialization work
    thread::sleep(Duration::from_millis(1000u64));

    let (mtx, reply_mrx) = runtime.get_main_channel().expect("cannot get main channel");
    // start the engine by setting all tasks on scheduler threads to ready state
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
                                thread::sleep(Duration::from_millis(100u64));
                            }
                            if arg_matches.get_flag("rxtx") {
                                mtx.send(MessageFrom::PrintPerformance(cores.clone())).unwrap();
                                thread::sleep(Duration::from_millis(100u64));
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
            thread::sleep(Duration::from_millis(200u64)); // Sleep for a bit
        }
    }

    // request performance data
    mtx.send(MessageFrom::PrintPerformance(cores)).unwrap();
    thread::sleep(Duration::from_millis(100u64));
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

    let collected = collect_from_main_reply(&reply_mrx, 1000);
    let start_stop_stamps: HashMap<PipelineId, (u64, u64)> = collected.start_stop_stamps;
    let mut con_records_s: Vec<(PipelineId, Store64<Extension>)> = Vec::with_capacity(64);
    let mut con_records_c: Vec<(PipelineId, Store64<Extension>)> = Vec::with_capacity(64);
    for (pid, (c_opt, s_opt)) in collected.con_records.into_iter() {
        if let (Some(c), Some(s)) = (c_opt, s_opt) {
            con_records_c.push((pid.clone(), c));
            con_records_s.push((pid, s));
        }
    }

    info!(
        "Connection record sizes = {} + {}",
        size_of::<Connection>(),
        size_of::<ConRecord>()
    );

    info!(
        "Pdu size = {}, HeaderStack size = {}",
        size_of::<Pdu>(),
        size_of::<HeaderStack>(),
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

    thread::sleep(Duration::from_millis(200u64)); // Sleep for a bit
    std::process::exit(0);
}
