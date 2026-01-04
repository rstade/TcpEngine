use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::sync::Arc;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::{env, thread};
use std::io::Read;
use std::net::Ipv4Addr;
use std::thread::sleep;
use std::time::Duration;
use e2d2::allocators::CacheAligned;
use e2d2::common::errors::Result as E2d2Result;
use e2d2::config::{basic_opts, read_matches};
use e2d2::interface::{FlowDirector, FlowSteeringMode, PmdPort, PortQueue, PortType};
use e2d2::native::zcsi::rte_ethdev_api::{rte_log_get_global_level, rte_log_get_level, rte_log_set_global_level, rte_log_set_level};
use e2d2::native::zcsi::{fdir_get_infos, RteLogLevel, RteLogtype};
use e2d2::scheduler::{initialize_system, NetBricksContext, SchedulerCommand, SchedulerReply, StandaloneScheduler};
use e2d2::common::ErrorKind as E2d2ErrorKind;
use netfcts::comm::{MessageFrom, MessageTo, PipelineId, RuntimeMessage};
use netfcts::recstore::SimpleStore;
use netfcts::{get_tcp_port_base, setup_kernel_interfaces};
use netfcts::io::print_hard_statistics;
use netfcts::system::SystemData;
use netfcts::tasks::TaskType;
use separator::Separatable;
use serde::de::DeserializeOwned;
use uuid::Uuid;
use crate::netfcts::{RunConfiguration};
use crate::{FnNetworkFunctionGraph, RunConfigType, RunTimeType};
use crate::setup_pipelines;

#[derive(Deserialize, Clone)]
struct Config<T: Sized + Clone> {
    engine: T,
}

#[derive(Debug, Clone)]
pub enum RuntimeExit {
    Ok,
    Err(String),
}


pub struct RunTime<T: Sized + Clone + Send, FM: RuntimeMessage, TM: RuntimeMessage, FW: RuntimeMessage> {
    pub run_configuration: RunConfiguration<T, FM, FW>,
    pub context: Option<NetBricksContext>,
    /// receiver in run_time thread for messages from all the pipelines running, and usually from main thread
    /// will be moved into the run_time thread
    pub rt_receiver_fm: Option<Receiver<FM>>,
    /// a single receiver instance for messages sent by run_time thread and pipelines, usually retrieved by main thread
    /// see also get_main_channel()
    main_receiver_tm: Option<Receiver<TM>>,
    pub rt_sender_tm: Sender<TM>,
    pub rt_receiver_fw: Receiver<FW>,
    toml_file: String,
    /// exit notification receiver: main/test can take this to learn when the runtime thread exits
    pub exit_receiver: Option<Receiver<RuntimeExit>>,
    /// Join handle of the runtime thread for optional joining
    pub handle: Option<thread::JoinHandle<()>>,
}

impl<T: Sized + Clone + Send, FM: RuntimeMessage, TM: RuntimeMessage, FW: RuntimeMessage> RunTime<T, FM, TM, FW>
where
    T: DeserializeOwned,
{
    fn read_config(filename: &str) -> E2d2Result<Config<T>> {
        let mut toml_str = String::new();
        if File::open(filename)
            .and_then(|mut f| f.read_to_string(&mut toml_str))
            .is_err()
        {
            return Err(E2d2ErrorKind::ConfigurationError(format!("Could not read file {}", filename)));
        }

        info!("toml configuration:\n {}", toml_str);

        let config: Config<T> = match toml::from_str(&toml_str) {
            Ok(value) => value,
            //Err(err) => return Err(err.into()),
            //the recent compiler generates a fake(?) error message about missing trait
            Err(err) => return Err(E2d2ErrorKind::ConfigParseError(format!("{}", err))),
        };

        Ok(config.clone())
    }

    fn check_system(context: NetBricksContext) -> e2d2::common::Result<NetBricksContext> {
        let num_pmd_ports = PmdPort::num_pmd_ports();
        for i in 0..num_pmd_ports {
            PmdPort::print_eth_dev_info(i as u16);
        }
        /*
        for port in context.ports.values() {
            if port.port_type() == &PortType::Physical {
                debug!("Supported filters on port {}:", port.port_id());
                for i in RteFilterType::RteEthFilterNone as i32 + 1..RteFilterType::RteEthFilterMax as i32 {
                    let result = unsafe { rte_eth_dev_filter_supported(port.port_id() as u16, RteFilterType::from(i)) };
                    debug!(
                        "{:<50}: {}(rc={})",
                        RteFilterType::from(i),
                        if result == 0 { "supported" } else { "not supported" },
                        result
                    );
                }
            }
        }
         */
        Ok(context)
    }

    fn initialize_flowdirector(port: &Arc<PmdPort>, kni: &Arc<PmdPort>) -> Option<FlowDirector> {
        info!("initialize flowdirector for port {} with kni = {}", port.name(), kni.name());
        if *port.port_type() == PortType::Physical && port.flow_steering_mode().is_some() {
            // initialize flow director on port, cannot do this in parallel from multiple threads
            let steering_mode = port.flow_steering_mode().clone().unwrap();
            let mut flowdir = FlowDirector::new(port.clone());
            assert!(kni.net_spec().is_some());
            let ip_addr_first = kni.net_spec().as_ref().unwrap().ip_net.as_ref().unwrap().addr();
            for (i, _core) in port.rx_cores.as_ref().unwrap().iter().enumerate() {
                match steering_mode {
                    FlowSteeringMode::Ip => {
                        let dst_ip = u32::from(ip_addr_first) + i as u32 + 1;
                        let dst_port = port.get_tcp_dst_port_mask();
                        info!(
                            "set fdir filter on dpdk port {} for dst-IP receive flow steering: queue= {}, ip= {}, port base = {:#X}",
                            port.port_id(),
                            i,
                            Ipv4Addr::from(dst_ip),
                            dst_port,
                        );
                        flowdir.add_tcp_flow_rule(i as u16, dst_ip, port.get_ipv4_dst_mask(), dst_port, dst_port);
                    }
                    FlowSteeringMode::Port => {
                        let dst_ip = u32::from(ip_addr_first);
                        let dst_port = get_tcp_port_base(port, i as u16);
                        info!(
                            "set fdir filter on dpdk port {} for dst-port receive flow steering: queue= {}, ip= {}, port base = {:#X}",
                            port.port_id(),
                            i,
                            Ipv4Addr::from(dst_ip),
                            dst_port,
                        );
                        flowdir.add_tcp_flow_rule(
                            i as u16,
                            dst_ip,
                            port.get_ipv4_dst_mask(),
                            dst_port,
                            port.get_tcp_dst_port_mask(),
                        );
                    }
                }
            }
            Some(flowdir)
        } else {
            error!("need a physical port with defined flow steering mode for flowdirector");
            None
        }
    }

    fn check_for_root_user() {
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
    }

    fn set_rte_log_level() {
        let log_level_rte = if log_enabled!(log::Level::Debug) {
            RteLogLevel::RteLogDebug
        } else {
            RteLogLevel::RteLogInfo
        };
        unsafe {
            rte_log_set_global_level(log_level_rte as u32);
            rte_log_set_level(RteLogtype::RteLogtypePmd as u32, log_level_rte as u32);
            info!("dpdk log global level: {}", rte_log_get_global_level());
            info!(
                "dpdk log level for PMD: {}",
                rte_log_get_level(RteLogtype::RteLogtypePmd as u32)
            );
        }
    }

    pub fn init_with_toml_file(args: &Vec<String>) -> E2d2Result<RunTime<T, FM, TM, FW>> {
        let opts = basic_opts();

        let matches = match opts.parse(&args[..]) {
            Ok(m) => m,
            Err(f) => panic!("{}", f.to_string()),
        };

        let toml_file = match matches.opt_str("f") {
            Some(toml_file) => toml_file,
            None => panic!("option -f <toml_file> not found"),
        };

        info!("toml file: {}", toml_file);
        info!("matched option interactive: {}", matches.opt_present("interactive"));

        let netbricks_configuration = read_matches(&matches, &opts);

        let config: Config<T> = RunTime::<T, FM, TM, FW>::read_config(&toml_file.trim())?;
        let engine_configuration = config.engine;

        // the channels from and to the main thread
        let (main_sender_fm, rt_receiver_fm) = channel::<FM>();
        let (rt_sender_tm, main_receiver_tm) = channel::<TM>();

        // the MPSC channel from worker threads, the return channel is created by the worker threads
        let (worker_sender_fw, rt_receiver_fw) = channel::<FW>();

        // this calls also DPDK EAL
        info!("initializing DPDK ...");
        match initialize_system(&netbricks_configuration)
            .map_err(|e| e.into())
            .and_then(|ctxt| RunTime::<T, FM, TM, FW>::check_system(ctxt))
        {
            Ok(context) => Ok(RunTime {
                run_configuration: RunConfiguration {
                    system_data: SystemData::detect(),
                    netbricks_configuration,
                    engine_configuration,
                    flowdirector_map: HashMap::new(),
                    main_sender_fm,
                    worker_sender_fw,
                    b_interactive: matches.opt_present("interactive"),
                },
                context: Some(context),
                rt_receiver_fm: Some(rt_receiver_fm),
                main_receiver_tm: Some(main_receiver_tm),
                rt_sender_tm,
                rt_receiver_fw,
                toml_file: toml_file.clone(),
                exit_receiver: None,
                handle: None,
            }),
            Err(e) => {
                error!("Error: {}", e);
                Err(e)
            }
        }
    }

    /// initializes with a toml-file whose name is in args[1]
    pub fn init() -> E2d2Result<RunTime<T, FM, TM, FW>> {
        Self::set_rte_log_level();
        Self::check_for_root_user();
        // read config file name from command line
        let mut args: Vec<String> = env::args().collect();
        let config_file;
        if args.len() > 1 {
            config_file = args[1].clone();
        } else {
            println!("try '{} <toml configuration file>'\n", args[0]);
            std::process::exit(1);
        }
        // adding the toml file name as "-f <toml file>" to the options
        args.append(&mut vec!["-f".to_string(), config_file.trim().to_string()]);
        RunTime::init_with_toml_file(&args)
    }

    /// initializes with a toml-file whose name is read from an indirection file
    pub fn init_indirectly(indirection_pathname: &str) -> E2d2Result<RunTime<T, FM, TM, FW>> {
        Self::set_rte_log_level();
        Self::check_for_root_user();
        let mut f = File::open(indirection_pathname).expect("file not found");
        let mut toml_file = String::new();
        f.read_to_string(&mut toml_file)
            .expect("something went wrong reading ./tests/toml_file.txt");
        //cut off white spaces at the end:
        toml_file.truncate(toml_file.trim_end().len());
        // adding the toml file name as "-f <toml file>" to the options
        let args = vec!["-f".to_string(), toml_file.trim().to_string()];
        RunTime::init_with_toml_file(&args)
    }

    pub fn toml_filename(&self) -> &String {
        &self.toml_file
    }

    /// this returns the communication channel to the run_time thread, only the first call returns the channel
    pub fn get_main_channel(&mut self) -> Option<(Sender<FM>, Receiver<TM>)> {
        if self.main_receiver_tm.is_some() {
            Some((
                self.run_configuration.main_sender_fm.clone(),
                self.main_receiver_tm.take().unwrap(),
            ))
        } else {
            None
        }
    }

    /// Returns the exit notification receiver. Only the first call returns it.
    pub fn take_exit_receiver(&mut self) -> Option<Receiver<RuntimeExit>> {
        self.exit_receiver.take()
    }

    fn context_mut(&mut self) -> E2d2Result<&mut NetBricksContext> {
        if self.context.is_none() {
            return Err(E2d2ErrorKind::RunTimeError(
                "context consumed by spawn_recv_thread already".to_string(),
            ));
        }
        Ok(self.context.as_mut().unwrap())
    }

    pub fn context(&self) -> E2d2Result<&NetBricksContext> {
        if self.context.is_none() {
            return Err(E2d2ErrorKind::RunTimeError(
                "context consumed by spawn_recv_thread already".to_string(),
            ));
        }
        Ok(self.context.as_ref().unwrap())
    }

    pub fn setup_flowdirector(&mut self) -> E2d2Result<()> {
        if self.context.is_none() {
            return Err(E2d2ErrorKind::RunTimeError(
                "context consumed by spawn_recv_thread already".to_string(),
            ));
        }
        for port in self
            .context
            .as_ref()
            .unwrap()
            .ports
            .values()
            .filter(|p| p.is_physical() && p.flow_steering_mode().is_some())
        {
            if port.kni_name().is_some() {
                let opt_kni = self.context.as_ref().unwrap().ports.get(*port.kni_name().as_ref().unwrap());
                if opt_kni.is_some() {
                    let kni = opt_kni.unwrap();
                    let flow_dir = RunTime::<T, FM, TM, FW>::initialize_flowdirector(port, kni);
                    if flow_dir.is_some() {
                        self.run_configuration
                            .flowdirector_map
                            .insert(port.port_id(), Arc::new(flow_dir.unwrap()));
                        unsafe {
                            fdir_get_infos(port.port_id());
                        }
                    }
                } else {
                    error!("kni {} for port {} not found", port.kni_name().as_ref().unwrap(), port.name());
                    return Err(E2d2ErrorKind::FailedToInitializeKni(port.name().to_string()));
                }
            } else {
                info!("port {} has no kni interface assigned", port.name());
                //return Err(E2d2ErrorKind::FailedToInitializeKni(port.name().to_string()));
            }
        }
        Ok(())
    }

    /// starts scheduler threads on the cores, but still does not execute pipelines
    pub fn start_schedulers(&mut self) -> E2d2Result<()> {
        self.context_mut()?.start_schedulers();
        Ok(())
    }

    pub fn install_pipeline_on_cores<P>(&mut self, run: Box<P>) -> E2d2Result<()>
    where
        P: Fn(i32, HashMap<String, Arc<PmdPort>>, &mut StandaloneScheduler) + Send + Clone + 'static,
    {
        self.context_mut()?.install_pipeline_on_cores(run);
        Ok(())
    }

    pub fn add_pipeline_to_run<P>(&mut self, run: Box<P>) -> E2d2Result<()>
    where
        P: Fn(i32, HashSet<CacheAligned<PortQueue>>, &mut StandaloneScheduler) + Send + Clone + 'static,
    {
        self.context_mut()?.add_pipeline_to_run(run);
        Ok(())
    }


    /// Join the runtime thread with a bounded timeout. Returns true if the thread
    /// terminated within the timeout, false on timeout or if there is no handle.
    pub fn join_with_timeout(&mut self, timeout_ms: u64) -> bool {
        use std::time::Duration;
        if let Some(handle) = self.handle.take() {
            let (tx, rx) = channel::<()>();
            thread::spawn(move || {
                let _ = handle.join();
                let _ = tx.send(());
            });
            match rx.recv_timeout(Duration::from_millis(timeout_ms)) {
                Ok(_) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }
}


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
