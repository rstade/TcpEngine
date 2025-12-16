// Centralized profiling helper with cfg-gated no-op fallback.
//
// Purpose:
// - Provide a tiny facade (`Profiler`) for cycle-accurate timing buckets and RX/TX snapshot
//   sampling that all engines can use consistently.
// - Eliminate duplicated, feature-gated profiling code across engines.
//
// Behavior:
// - With `--features profiling`: records timing samples via `TimeAdder`, exposes
//   `start()`/`add_diff(..)` and an RX/TX sample buffer with change filtering.
// - Without the feature: provides the same API as zero-cost no-ops to keep call sites clean
//   and avoid conditional code at the use sites.

#[cfg(feature = "profiling")]
use std::arch::x86_64::_rdtsc;

#[cfg(feature = "profiling")]
use crate::netfcts::utils::TimeAdder;

#[cfg(feature = "profiling")]
pub struct Profiler {
    time_adders: Vec<TimeAdder>,
    rx_tx_stats: Vec<(u64, u64, u64)>,
}

#[cfg(feature = "profiling")]
impl Profiler {
    pub fn new(labels: &[&str], capacity: usize, warm_up: u64) -> Self {
        let cap = capacity as u64;
        let time_adders = labels.iter().map(|l| TimeAdder::new_with_warm_up(l, cap, warm_up)).collect();
        Self {
            time_adders,
            rx_tx_stats: Vec::with_capacity(capacity.min(100_000)),
        }
    }

    #[inline]
    pub fn start(&self) -> u64 {
        unsafe { _rdtsc() }
    }

    #[inline]
    pub fn add_diff(&mut self, label_idx: usize, start_tsc: u64) {
        if let Some(adder) = self.time_adders.get_mut(label_idx) {
            let now = unsafe { _rdtsc() };
            adder.add_diff(now - start_tsc);
        }
    }

    #[inline]
    pub fn record_rx_tx_if_changed(&mut self, now_tsc: u64, rx: u64, tx: u64) {
        if self
            .rx_tx_stats
            .last()
            .map(|(_, lr, lt)| *lr != rx || *lt != tx)
            .unwrap_or(true)
        {
            self.rx_tx_stats.push((now_tsc, rx, tx));
        }
    }

    #[inline]
    pub fn snapshot_rx_tx(&self) -> Option<&Vec<(u64, u64, u64)>> {
        Some(&self.rx_tx_stats)
    }

    #[inline]
    pub fn into_rx_tx(self) -> Option<Vec<(u64, u64, u64)>> {
        Some(self.rx_tx_stats)
    }
}

// ===================== No-op fallback (profiling disabled) =====================

#[cfg(not(feature = "profiling"))]
pub struct Profiler;

#[cfg(not(feature = "profiling"))]
impl Profiler {
    pub fn new(_labels: &[&str], _capacity: usize, _warm_up: u64) -> Self {
        Self
    }
    #[inline]
    pub fn start(&self) -> u64 {
        0
    }
    #[inline]
    pub fn add_diff(&mut self, _label_idx: usize, _start_tsc: u64) {}
    #[inline]
    pub fn record_rx_tx_if_changed(&mut self, _now_tsc: u64, _rx: u64, _tx: u64) {}
    pub fn snapshot_rx_tx(&self) -> Option<&Vec<(u64, u64, u64)>> {
        None
    }
    pub fn into_rx_tx(self) -> Option<Vec<(u64, u64, u64)>> {
        None
    }
}
