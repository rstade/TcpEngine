use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use e2d2::common::errors::Result as E2d2Result;
use e2d2::interface::PmdPort;
use e2d2::scheduler::{SchedulerCommand, SchedulerReply, StandaloneScheduler};
use netfcts::comm::{MessageFrom, MessageTo, PipelineId};
use netfcts::recstore::SimpleStore;
use netfcts::{setup_kernel_interfaces, RuntimeExit};
use netfcts::io::print_hard_statistics;
use netfcts::tasks::TaskType;
use separator::Separatable;
use uuid::Uuid;
use crate::netfcts::{RunConfiguration, RunTime};
use crate::{Configuration, FnNetworkFunctionGraph, RunConfigType, RunTimeType};
use crate::netfcts::recstore::{Store64, Extension};
use crate::setup_pipelines;

/// Install the provided Network Function Graph (NFG) on all active cores.
///
/// This factors the duplicated `install_pipeline_on_cores` closures used in
/// `bin.rs` and `run_test.rs`.
pub fn install_pipelines_for_all_cores<NFG>(
    runtime: &mut RunTimeType,
    run_configuration: RunConfigType,
    nfg: NFG,
) -> E2d2Result<()>
where
    NFG: FnNetworkFunctionGraph,
{
    let run_configuration_cloned = run_configuration.clone();
    runtime.install_pipeline_on_cores(Box::new(
        move |core: i32, pmd_ports: HashMap<String, Arc<PmdPort>>, s: &mut StandaloneScheduler| {
            setup_pipelines(core, pmd_ports, s, run_configuration_cloned.clone(), &nfg.clone());
        },
    ))
}


pub struct RunTimeThread<T:Sized + Clone + Send, TStore: SimpleStore + Clone + 'static> {
    pub runtime: RunTime<T, MessageFrom<TStore>, MessageTo<TStore>, MessageFrom<TStore>>,
}
/// start spawns_run_time_thread and consumes self.context and self.local_receiver (thread needs static lifetime)

impl<T:Sized + Clone + Send, TStore: SimpleStore + Clone> RunTimeThread<T, TStore> {
    pub fn start(&mut self) {
        let mut context = self.runtime.context.take().unwrap();
        let reply_to_main = self.runtime.rt_sender_tm.clone();
        let rt_receiver_fm = self.runtime.rt_receiver_fm.take().unwrap();

        // create exit notification channel and keep receiver for main
        let (exit_tx, exit_rx) = channel::<RuntimeExit>();
        self.runtime.exit_receiver = Some(exit_rx);



        let handle = thread::spawn(move || {
            use std::panic::{catch_unwind, AssertUnwindSafe};
            let mut senders = HashMap::new();
            let mut tasks: Vec<Vec<(PipelineId, Uuid)>> = Vec::with_capacity(TaskType::NoTaskTypes as usize);
            for _t in 0..TaskType::NoTaskTypes as usize {
                tasks.push(Vec::<(PipelineId, Uuid)>::with_capacity(16));
            }

            // start execution of pipelines, but does not change task state of pipelines (e.g. sets them into ready state)
            // the latter happens with message StartEngine (see below)
            let result = catch_unwind(AssertUnwindSafe(|| {
                context.execute_schedulers();
                setup_kernel_interfaces(&context);
                // communicate with schedulers and main thread:
                loop {
                    match rt_receiver_fm.recv_timeout(Duration::from_millis(10)) {
                        Ok(MessageFrom::StartEngine) => {
                            debug!("starting generator tasks");
                            for s in &context.scheduler_channels {
                                s.1.send(SchedulerCommand::SetTaskStateAll(true)).unwrap();
                            }
                        }
                        Ok(MessageFrom::Channel(pipeline_id, sender)) => {
                            debug!("got sender from {}", pipeline_id);
                            senders.insert(pipeline_id, sender);
                        }
                        Ok(MessageFrom::PrintPerformance(indices)) => {
                            for i in &indices {
                                context
                                    .scheduler_channels
                                    .get(i)
                                    .unwrap()
                                    .send(SchedulerCommand::GetPerformance)
                                    .unwrap();
                                sleep(Duration::from_micros(200));
                            }
                        }
                        Ok(MessageFrom::Exit) => {
                            // stop all tasks on all schedulers
                            for s in context.scheduler_channels.values() {
                                s.send(SchedulerCommand::SetTaskStateAll(false)).unwrap();
                            }


                            for port in context.ports.values() {
                                println!("Port {}:{}", port.port_type(), port.port_id());
                                print_hard_statistics(port.port_id());
                                port.print_soft_statistics();
                            }
                            info!("terminating RunTime ...");
                            // drop all per-pipeline senders so the reply channel can close cleanly
                            senders.clear();
                            // Some error scenarios may already have torn down channels; protect stop() against panics
                            if let Err(_p) = std::panic::catch_unwind(AssertUnwindSafe(|| {
                                context.stop();
                            })) {
                                error!("context.stop() panicked during graceful exit; continuing shutdown");
                            }
                            break;
                        }
                        Ok(MessageFrom::Task(pipeline_id, uuid, task_type)) => {
                            debug!("{}: task uuid= {}, type={:?}", pipeline_id, uuid, task_type);
                            tasks[task_type as usize].push((pipeline_id, uuid));
                        }
                        Ok(MessageFrom::Counter(pipeline_id, tcp_counter_to, tcp_counter_from, tx_counter)) => {
                            debug!("{}: received Counter", pipeline_id);
                            reply_to_main
                                .send(MessageTo::Counter(pipeline_id, tcp_counter_to, tcp_counter_from, tx_counter))
                                .unwrap();
                        }
                        Ok(MessageFrom::FetchCounter) => {
                            for (_p, s) in &senders {
                                s.send(MessageTo::FetchCounter).unwrap();
                            }
                        }
                        Ok(MessageFrom::EtypeCnt(pipeline_id, etype_cnt)) => {
                            reply_to_main.send(MessageTo::EtypeCnt(pipeline_id, etype_cnt)).unwrap();
                        }
                        Ok(MessageFrom::CRecords(pipeline_id, c_records_client, c_records_server)) => {
                            reply_to_main
                                .send(MessageTo::CRecords(pipeline_id, c_records_client, c_records_server))
                                .unwrap();
                        }
                        Ok(MessageFrom::FetchCRecords) => {
                            for (_p, s) in &senders {
                                s.send(MessageTo::FetchCRecords).unwrap();
                            }
                        }
                        Ok(MessageFrom::TimeStamps(p, t0, t1)) => {
                            reply_to_main.send(MessageTo::TimeStamps(p, t0, t1)).unwrap();
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(e) => {
                            error!("error receiving from MessageFrom channel: {}", e);
                            // best-effort stop of all tasks and schedulers before exiting the runtime thread
                            for s in context.scheduler_channels.values() {
                                let _ = s.send(SchedulerCommand::SetTaskStateAll(false));
                            }
                            // drop all per-pipeline senders so the reply channel can close cleanly
                            senders.clear();
                            // Protect against panics if context is already partially torn down
                            if let Err(_p) = std::panic::catch_unwind(AssertUnwindSafe(|| {
                                context.stop();
                            })) {
                                error!("context.stop() panicked after MessageFrom error; continuing shutdown");
                            }
                            break;
                        }
                        Ok(_) => {}
                    };
                    match context
                        .reply_receiver
                        .as_ref()
                        .unwrap()
                        .recv_timeout(Duration::from_millis(10))
                    {
                        Ok(SchedulerReply::PerformanceData(core, map)) => {
                            let mut pairs = map.into_iter().collect::<Vec<_>>();
                            pairs.sort_by(|a, b| a.1.0.cmp(&b.1.0));
                            for (_, d) in pairs {
                                println!(
                                    "{:2}: {:20} {:>15} cycles, count= {:12}, queue length= {}",
                                    core,
                                    d.0,
                                    d.1.separated_string(),
                                    d.2.separated_string(),
                                    d.3
                                )
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(e) => {
                            error!("error receiving from SchedulerReply channel: {}", e);
                            // best-effort stop of all tasks and schedulers before exiting the runtime thread
                            for s in context.scheduler_channels.values() {
                                let _ = s.send(SchedulerCommand::SetTaskStateAll(false));
                            }
                            // drop all per-pipeline senders so the reply channel can close cleanly
                            senders.clear();
                            // Protect against panics if context is already partially torn down
                            if let Err(_p) = std::panic::catch_unwind(AssertUnwindSafe(|| {
                                context.stop();
                            })) {
                                error!("context.stop() panicked after SchedulerReply error; continuing shutdown");
                            }
                            break;
                        }
                    }
                }
                info!("exiting mrx recv thread of the RunTime ...");
            }));

            match result {
                Ok(_) => {
                    info!("RunTime: signaling RuntimeExit::Ok to main (exit_tx)");
                    if let Err(e) = exit_tx.send(RuntimeExit::Ok) {
                        error!("RunTime: failed to send RuntimeExit::Ok to main: {}", e);
                    }
                }
                Err(payload) => {
                    let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "panic in runtime thread (non-string payload)".to_string()
                    };
                    info!("RunTime: signaling RuntimeExit::Err to main (exit_tx): {}", msg);
                    if let Err(e) = exit_tx.send(RuntimeExit::Err(msg)) {
                        error!("RunTime: failed to send RuntimeExit::Err to main: {}", e);
                    }
                }
            }
        });

        self.runtime.handle = Some(handle);
    }
}
