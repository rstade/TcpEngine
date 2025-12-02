use std::collections::HashMap;
use std::sync::Arc;

use e2d2::common::errors::Result as E2d2Result;
use e2d2::interface::PmdPort;
use e2d2::scheduler::StandaloneScheduler;

use crate::netfcts::{RunConfiguration, RunTime};
use crate::{Configuration, FnNetworkFunctionGraph};
use crate::netfcts::recstore::{Store64, Extension};
use crate::setup_pipelines;

/// Install the provided Network Function Graph (NFG) on all active cores.
///
/// This factors the duplicated `install_pipeline_on_cores` closures used in
/// `bin.rs` and `run_test.rs`.
pub fn install_pipelines_for_all_cores<NFG>(
    runtime: &mut RunTime<Configuration, Store64<Extension>>,
    run_configuration: RunConfiguration<Configuration, Store64<Extension>>,
    nfg: NFG,
) -> E2d2Result<()>
where
    NFG: FnNetworkFunctionGraph,
{
    let run_configuration_cloned = run_configuration.clone();
    runtime.install_pipeline_on_cores(Box::new(
        move |core: i32,
              pmd_ports: HashMap<String, Arc<PmdPort>>,
              s: &mut StandaloneScheduler| {
            setup_pipelines(
                core,
                pmd_ports,
                s,
                run_configuration_cloned.clone(),
                &nfg.clone(),
            );
        },
    ))
}
