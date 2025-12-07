use e2d2::interface::{Pdu, HeaderStack};
use tcp_lib::netfcts::comm::{MessageFrom, PipelineId};
use tcp_lib::netfcts::conrecord::ConRecord;
use tcp_lib::{Connection, EngineMode, get_tcp_generator_nfg, get_delayed_tcp_proxy_nfg, initialize_engine, get_simple_tcp_proxy_nfg, install_pipelines_for_all_cores};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};
use rustyline::Editor;
use rustyline::error::ReadlineError;
use clap::{Command, Arg, ArgAction};
use log::info;
use tcp_lib::analysis::{evaluate_records, print_performance_from_stamps, collect_from_main_reply};
use tcp_lib::netfcts::recstore::{Store64, Extension};
use std::mem::size_of;
use std::sync::mpsc::{TryRecvError, channel};

const STARTUP_DELAY_MS: u64 = 1000;
const PRINT_DELAY_MS: u64 = 100;
const SLEEP_CTRLC_LOOP_MS: u64 = 200;
const REPLY_TIMEOUT_MS: u64 = 1000;
const SHUTDOWN_POLL_MS: u64 = 100;
const SHUTDOWN_MAX_WAIT_MS: u64 = 1000;
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
                .expect("cannot install pipelines for SimpleProxy");
        }
    };

    let cores = runtime.context().unwrap().active_cores.clone();

    // start the run_time
    runtime.start();

    // give threads some time to do initialization work

    thread::sleep(Duration::from_millis(STARTUP_DELAY_MS));

    // Get exit notification receiver to detect early runtime thread termination
    let mut exit_rx = runtime.take_exit_receiver().expect("no exit receiver available");

    let (mtx, reply_mrx) = runtime.get_main_channel().expect("cannot get main channel");
    // start the engine by setting all tasks on scheduler threads to ready state
    mtx.send(MessageFrom::StartEngine).unwrap();

    // flag to detect if runtime exited early so we can skip post-loop requests
    let mut runtime_exited_early = false;
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
                    .help("rxtx of pipeline components")
                    .action(ArgAction::SetTrue),
            );
        let cmd_quit = Command::new("quit");
        let shim_cmd = Command::new(":").subcommand(cmd_print).subcommand(cmd_quit);
        // Spawn a dedicated thread for blocking readline, communicate via channel
        let (cmd_tx, cmd_rx) = channel::<Result<String, ReadlineError>>();
        thread::spawn(move || {
            let mut rl = Editor::<()>::new().unwrap();
            println!("enter commands or press ctrl-c to terminate TcpEngine ...");
            loop {
                let res = rl.readline(">> ");
                // keep some history if we got a line
                if let Ok(ref line) = res {
                    rl.add_history_entry(line.as_str());
                }
                if cmd_tx.send(res).is_err() {
                    // receiver dropped, exit thread
                    break;
                }
            }
        });

        // Main interactive loop: poll for either runtime exit or user input
        loop {
            // Detect early runtime termination
            match exit_rx.try_recv() {
                Ok(tcp_lib::netfcts::RuntimeExit::Ok) => {
                    info!("Runtime thread exited normally (early). Initiating shutdown.");
                    runtime_exited_early = true;
                    break;
                }
                Ok(tcp_lib::netfcts::RuntimeExit::Err(msg)) => {
                    info!("Runtime thread exited with error: {}. Initiating shutdown.", msg);
                    runtime_exited_early = true;
                    break;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    info!("Runtime exit channel disconnected. Initiating shutdown.");
                    runtime_exited_early = true;
                    break;
                }
            }

            match cmd_rx.try_recv() {
                Ok(Ok(line)) => {
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
                                thread::sleep(Duration::from_millis(PRINT_DELAY_MS));
                            }
                            if arg_matches.get_flag("rxtx") {
                                mtx.send(MessageFrom::PrintPerformance(cores.clone())).unwrap();
                                thread::sleep(Duration::from_millis(PRINT_DELAY_MS));
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
                Ok(Err(ReadlineError::Interrupted)) => {
                    println!("CTRL-C");
                    break;
                }
                Ok(Err(ReadlineError::Eof)) => {
                    println!("CTRL-D");
                    break;
                }
                Ok(Err(err)) => {
                    println!("Error: {:?}", err);
                    break;
                }
                Err(TryRecvError::Empty) => {
                    // nothing to do right now, avoid busy loop
                    thread::sleep(Duration::from_millis(20));
                }
                Err(TryRecvError::Disconnected) => {
                    // input thread ended, just continue shutdown path
                    break;
                }
            }
        }
    } else {
        println!("press ctrl-c to terminate TcpEngine ...");
        while running.load(Ordering::SeqCst) {
            // Detect early runtime termination
            match exit_rx.try_recv() {
                Ok(tcp_lib::netfcts::RuntimeExit::Ok) => {
                    info!("Runtime thread exited normally (early). Initiating shutdown.");
                    runtime_exited_early = true;
                    break;
                }
                Ok(tcp_lib::netfcts::RuntimeExit::Err(msg)) => {
                    info!("Runtime thread exited with error: {}. Initiating shutdown.", msg);
                    runtime_exited_early = true;
                    break;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    info!("Runtime exit channel disconnected. Initiating shutdown.");
                    runtime_exited_early = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(SLEEP_CTRLC_LOOP_MS)); // Sleep for a bit
        }
    }

    if !runtime_exited_early {
        // request performance data
        mtx.send(MessageFrom::PrintPerformance(cores)).unwrap();
        thread::sleep(Duration::from_millis(PRINT_DELAY_MS));
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
    }

    let collected = if !runtime_exited_early {
        collect_from_main_reply(&reply_mrx, REPLY_TIMEOUT_MS)
    } else {
        // empty collected data if runtime already exited
        tcp_lib::analysis::CollectedData::new()
    };
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

    // Request graceful shutdown of all scheduler threads and the runtime thread
    info!("Shutdown: requesting engine exit (MessageFrom::Exit)");
    match mtx.send(MessageFrom::Exit) {
        Ok(_) => {}
        Err(e) => {
            info!("Shutdown: could not send Exit to runtime (likely already exited): {}", e);
        }
    }
    // Drop our sender to help the runtime thread observe channel closure once done
    drop(mtx);
    info!("Shutdown: dropped main sender (mtx)");
    // Drop our clone of run_configuration to release its Sender<MessageTo<_>> on main side
    drop(run_configuration);
    info!("Shutdown: dropped run_configuration (reply sender clone on main side released)");
    // Note: run_configuration_cloned was moved into install_pipelines_for_all_cores earlier.
    // Also drop runtime to release the local sender clone held in run_configuration
    drop(runtime);
    info!("Shutdown: dropped runtime (remaining local sender clone released)");
    // Wait bounded time for the runtime thread to terminate by observing the reply channel closing
    info!(
        "Shutdown: waiting up to {} ms for runtime thread to terminate ...",
        SHUTDOWN_MAX_WAIT_MS
    );
    let start_wait = Instant::now();
    let deadline = start_wait + Duration::from_millis(SHUTDOWN_MAX_WAIT_MS);
    let mut terminated = false;
    loop {
        // observe exit channel first to react to early exit
        match exit_rx.try_recv() {
            Ok(tcp_lib::netfcts::RuntimeExit::Ok) => {
                info!("Shutdown: runtime exit signal received (Ok)");
                terminated = true;
                break;
            }
            Ok(tcp_lib::netfcts::RuntimeExit::Err(msg)) => {
                info!("Shutdown: runtime exit signal received with error: {}", msg);
                terminated = true;
                break;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                info!("Shutdown: runtime exit channel disconnected");
                terminated = true;
                break;
            }
        }
        match reply_mrx.recv_timeout(Duration::from_millis(SHUTDOWN_POLL_MS)) {
            // runtime thread has exited and dropped its senders
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                terminated = true;
                info!(
                    "Shutdown: runtime thread terminated; reply channel closed after {} ms",
                    start_wait.elapsed().as_millis()
                );
                break;
            }
            // ignore any late messages while shutting down
            Ok(_msg) => {}
            // still waiting
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline { break; }
            }
        }
    }
    if !terminated {
        info!(
            "Shutdown: timeout reached ({} ms) while waiting for runtime termination; proceeding",
            SHUTDOWN_MAX_WAIT_MS
        );
    }
    // return from main after graceful shutdown
}
