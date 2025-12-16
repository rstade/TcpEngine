use std::cmp;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};

use e2d2::native::zcsi::rte_ethdev_api::{rte_eth_stats, rte_eth_stats_get};
use separator::Separatable;

use crate::netfcts::conrecord::{ConRecord, HasConData, HasTcpState};
use crate::netfcts::recstore::{Extension, Store64};
use crate::netfcts::tcp_common::{ReleaseCause, TcpState};
use crate::netfcts::comm::PipelineId;
use crate::netfcts::comm::MessageTo;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;
use crate::netfcts::io::print_tcp_counters;
#[cfg(feature = "profiling")]
use crate::netfcts::io::print_rx_tx_counters;
use crate::netfcts::tcp_common::TcpCounter;

/// Print performance information derived from start/stop stamps reported by pipelines.
pub fn print_performance_from_stamps(
    cpu_clock: u64,
    nr_connections: usize,
    start_stop_stamps: HashMap<PipelineId, (u64, u64)>,
) {
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

/// Evaluate and print connection record statistics for client/server stores.
pub fn evaluate_records(
    con_records_c: &mut Vec<(PipelineId, Store64<Extension>)>,
    con_records_s: &mut Vec<(PipelineId, Store64<Extension>)>,
    cpu_clock: u64,
) {
    println!("\nperformance data derived from connection records:");
    let mut f = BufWriter::new(File::create("c_records.txt").expect("couldn't create c_records.txt"));

    let mut min_total: Option<ConRecord> = None;
    let mut max_total: Option<ConRecord> = None;
    let mut total_connections = 0;

    // Build index of server records
    let (mut by_uuid, completed_count_s) = index_server_records(con_records_s);

    for (p, c_records_client) in con_records_c {
        f.write_all(format!("Pipeline {}:\n", p).as_bytes())
            .expect("cannot write c_records");

        c_records_client.sort_0_by(|a, b| a.port().cmp(&b.port()));

        let count = c_records_client.len();
        let mut completed_count_c = 0;

        if count > 0 {
            total_connections += count;
            let mut min_pipe = c_records_client.iter().last().unwrap().0.clone();
            let mut max_pipe = min_pipe.clone();

            c_records_client.iter().enumerate().for_each(|(i, c)| {
                let (client_rec, _) = c;
                let uuid = client_rec.uid();
                let server_rec_opt = by_uuid.remove(&uuid);

                f.write_all(format!("{:6}: {}\n", i, client_rec).as_bytes())
                    .expect("cannot write c_records");

                if let Some(server_rec) = server_rec_opt {
                    f.write_all(format_server_details(&server_rec, client_rec).as_bytes())
                        .expect("cannot write c_records");
                }

                if is_client_completed(client_rec) {
                    completed_count_c += 1
                }

                if client_rec.get_first_stamp().unwrap_or(u64::MAX) < min_pipe.get_first_stamp().unwrap_or(u64::MAX) {
                    min_pipe = client_rec.clone();
                }
                if client_rec.get_last_stamp().unwrap_or(0) > max_pipe.get_last_stamp().unwrap_or(0) {
                    max_pipe = client_rec.clone();
                }

                if i == (count - 1) && min_pipe.get_first_stamp().is_some() && max_pipe.get_last_stamp().is_some() {
                    let total = max_pipe.get_last_stamp().unwrap() - min_pipe.get_first_stamp().unwrap();
                    println!(
                        "{}: total used cycles = {}, per connection = {} ({} cps)",
                        p,
                        total.separated_string(),
                        (total / (i as u64 + 1)).separated_string(),
                        cpu_clock / (total / (i as u64 + 1))
                    );
                }
            });

            // Track min/max over all pipelines
            if min_total.is_none()
                || min_pipe.get_first_stamp().unwrap_or(u64::MAX)
                    < min_total.as_ref().unwrap().get_first_stamp().unwrap_or(u64::MAX)
            {
                min_total = Some(min_pipe);
            }
            if max_total.is_none()
                || max_pipe.get_last_stamp().unwrap_or(0) > max_total.as_ref().unwrap().get_last_stamp().unwrap_or(0)
            {
                max_total = Some(max_pipe);
            }

            println!(
                "{} completed client connections = {} (server completed = {})",
                p, completed_count_c, completed_count_s
            );
        }
    }

    if let (Some(min), Some(max)) = (min_total, max_total) {
        if min.get_first_stamp().is_some() && max.get_last_stamp().is_some() {
            let total = max.get_last_stamp().unwrap() - min.get_first_stamp().unwrap();
            println!(
                "max used cycles over all pipelines = {}, per connection = {} ({} cps)",
                total.separated_string(),
                (total / (total_connections as u64)).separated_string(),
                cpu_clock / (total / (total_connections as u64 + 1)),
            );
        }
    }
    f.flush().expect("cannot flush BufWriter");
}

fn index_server_records(con_records_s: &Vec<(PipelineId, Store64<Extension>)>) -> (HashMap<u64, ConRecord>, usize) {
    let total_capacity: usize = con_records_s.iter().map(|c| c.1.len()).sum();
    let mut by_uuid = HashMap::with_capacity(total_capacity);
    let mut completed_count_s = 0;

    for (_, c_records_server) in con_records_s {
        c_records_server.iter().for_each(|(crec, _ext)| {
            // Count only fully completed server-side connections
            if crec.release_cause() == ReleaseCause::ActiveClose && crec.states().last().unwrap() == &TcpState::Closed {
                completed_count_s += 1
            };
            by_uuid.insert(crec.uid(), crec.clone());
        });
    }
    (by_uuid, completed_count_s)
}

fn format_server_details(c_server: &ConRecord, c_client: &ConRecord) -> String {
    use std::net::{Ipv4Addr, SocketAddrV4};
    let sock_str = if c_server.sock().0 != 0 {
        let s = c_server.sock();
        SocketAddrV4::new(Ipv4Addr::from(s.0), s.1).to_string()
    } else {
        "none".to_string()
    };

    format!(
        "        ({:?}, {:21}, {:6}, {:3}, {:7}, {:7}, {:?}, {:?}, +{}, {:?})\n",
        c_server.role(),
        sock_str,
        c_server.port(),
        c_server.server_index(),
        c_server.sent_payload_packets(),
        c_server.recv_payload_packets(),
        c_server.states(),
        c_server.release_cause(),
        (c_server.get_first_stamp().unwrap() - c_client.get_first_stamp().unwrap()).separated_string(),
        c_server
            .deltas_to_base_stamp()
            .iter()
            .map(|u| u.separated_string())
            .collect::<Vec<_>>(),
    )
}

fn is_client_completed(c: &ConRecord) -> bool {
    (c.release_cause() == ReleaseCause::PassiveClose || c.release_cause() == ReleaseCause::ActiveClose)
        && c.states().last().unwrap() == &TcpState::Closed
}

/// Collected data returned from the reply channel gatherer
pub struct CollectedData {
    pub tcp_counters_to: HashMap<PipelineId, TcpCounter>,
    pub tcp_counters_from: HashMap<PipelineId, TcpCounter>,
    /// Map of pipeline -> (client records, server records)
    pub con_records: HashMap<PipelineId, (Option<Store64<Extension>>, Option<Store64<Extension>>)>,
    pub start_stop_stamps: HashMap<PipelineId, (u64, u64)>,
}

impl CollectedData {
    pub fn new() -> Self {
        Self {
            tcp_counters_to: HashMap::new(),
            tcp_counters_from: HashMap::new(),
            con_records: HashMap::new(),
            start_stop_stamps: HashMap::new(),
        }
    }
}

/// Collect replies from the main reply channel into convenient structures.
/// This unifies the duplicated receive loops in bin.rs and run_test.rs.
pub fn collect_from_main_reply(reply_mrx: &Receiver<MessageTo<Store64<Extension>>>, timeout_ms: u64) -> CollectedData {
    let mut data = CollectedData::new();

    loop {
        match reply_mrx.recv_timeout(Duration::from_millis(timeout_ms as u64)) {
            Ok(MessageTo::Counter(pipeline_id, tcp_counter_to, tcp_counter_from, _rx_tx_stats)) => {
                // Side-effect prints like before
                print_tcp_counters(&pipeline_id, &tcp_counter_to, &tcp_counter_from);
                #[cfg(feature = "profiling")]
                if let Some(stats) = _rx_tx_stats {
                    print_rx_tx_counters(&pipeline_id, &stats);
                }
                data.tcp_counters_to.insert(pipeline_id.clone(), tcp_counter_to);
                data.tcp_counters_from.insert(pipeline_id, tcp_counter_from);
            }
            Ok(MessageTo::CRecords(pipeline_id, c_records_client, c_records_server)) => {
                data.con_records.insert(pipeline_id, (c_records_client, c_records_server));
            }
            Ok(MessageTo::TimeStamps(p, t_start, t_stop)) => {
                data.start_stop_stamps.insert(p, (t_start, t_stop));
            }
            Ok(_m) => {
                error!("illegal MessageTo received from reply_to_main channel");
            }
            Err(RecvTimeoutError::Timeout) => {
                break;
            }
            Err(e) => {
                error!("error receiving from reply_to_main channel (reply_mrx): {}", e);
                break;
            }
        }
    }

    data
}
