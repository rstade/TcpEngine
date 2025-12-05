### High‑level architecture (block diagram)

```
+-----------------------------------------------------------------------------------+
|                                     TcpEngine                                     |
|                                      (bin)                                        |
|                                                                                   |
|  - Parses config (TOML), selects EngineMode                                       |
|  - Boots runtime, installs pipelines, starts schedulers                           |
|  - Interactive CLI (optional): print perf, fetch counters/records, quit           |
|                                                                                   |
|      Control plane (channel)                         Data plane (packets)         |
|      ───────────────────────────                         ─────────────────         |
|                                                                                   |
|  +-----------------------------+       MessageFrom -->                            |
|  |         Main thread         |----------------------------+                     |
|  | (runtime owner + CLI loop)  |                             |                    |
|  +-----------------------------+                             |                    |
|             ^         |                                       v                   |
|             |         |                              +-------------------------+  |
|             |         |   MessageTo (perf, counters, |  NetBricks/e2d2 Runtime |  |
|             |         |   c-records, stamps)         |   + Schedulers per core |  |
|             |         +------------------------------|   + NIC/KNI integration  |  |
|             |                                        +-----------+-------------+  |
|             |                                                    |                |
|             |                                       install_pipelines_on_cores    |
|             |                                                    |                |
|  +----------+----------+                               +---------v----------+     |
|  |   analysis.rs       |<------ collects --------------| setup_pipelines()  |     |
|  | - collect_from_main |       and evaluates           |  (per core/port)   |     |
|  | - evaluate_records  |                               +---------+----------+     |
|  | - perf formatting   |                                         |                |
|  +----------+----------+                                         |                |
|             ^                                                    v                |
|             |                                        +-----------------------+    |
|             |                                        |  Network Function     |    |
|             |                                        |  Graph (NFG)          |    |
|             |                                        |  (per EngineMode)     |    |
|             |                                        |                       |    |
|             |                                        | - nftraffic (generator)|   |
|             |                                        | - nfdelayedproxy       |    |
|             |                                        | - nfsimpleproxy        |    |
|             |                                        +-----------+-----------+    |
|             |                                                    |                |
|             |                             per-connection state   | packets        |
|             |                                                    v                |
|   +---------v-----------+                         +----------------------------+  |
|   | tcpmanager.rs       |                         | proxymanager.rs            |  |
|   | (client/server conn |                         | (proxy connections,        |  |
|   |  state, payload)    |                         |  port management, timers)  |  |
|   +---------------------+                         +----------------------------+  |
|                                                                                   |
|  Supporting modules:                                                               |
|  - runtime_install.rs: install_pipelines_for_all_cores(...)                        |
|  - netfcts:: (RunTime, comm, tasks, recstore, tcp_common, io, flow director)      |
|  - recstore: Store64<Extension> (connection records)                               |
|  - test_support.rs (cfg test/feature): local echo servers for integration tests    |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Data flow at a glance
- Startup
  - `tcpengine` (bin) calls `initialize_engine()`, `start_schedulers()`, then `install_pipelines_for_all_cores()` with an NFG chosen by `EngineMode`.
  - `setup_pipelines()` adds Runnables to each core’s `StandaloneScheduler` for PCI/KNI queues.
- Run
  - Main sends `MessageFrom::StartEngine` to mark tasks ready; optional `PrintPerformance`, `FetchCounter`, `FetchCRecords`.
  - Schedulers run NFG stages (generator/proxy) on packet batches, using `tcpmanager`/`proxymanager` for per‑connection logic.
  - NIC ingress -> NFG -> NIC/KNI egress. Flow director and RX queue mapping are handled by `netfcts`/DPDK.
- Observe
  - Schedulers reply via `MessageTo` with counters, timestamps, and optional connection records.
  - `analysis::collect_from_main_reply(..)` aggregates replies; `evaluate_records(..)`/formatters summarize results.
- Shutdown
  - Main sends `MessageFrom::Exit` → tasks stopped, statistics printed, runtime halts.

### Key components and responsibilities
- Binary (`src/bin.rs`): user entrypoint, CLI, orchestration, printing.
- Library (`src/lib.rs`): exports NFGs, installers, analysis, and core engine types.
- Runtime install (`src/runtime_install.rs`): shared helper to install NFG across cores.
- NFGs (`src/nftraffic.rs`, `src/nfdelayedproxy.rs`, `src/nfsimpleproxy.rs`): build the pipeline per mode.
- Managers (`src/tcpmanager.rs`, `src/proxymanager.rs`): per‑connection state machines and payload/proxy logic.
- NetBricks glue (`src/netfcts/*`): `RunTime`, schedulers, DPDK port/queue handling, comm channels, counters/records.
- Analysis (`src/analysis.rs`): reply collection, record evaluation, performance formatting.
- Test support (`src/test_support.rs`): optional local servers for integration tests.

### Control/telemetry messages
- `MessageFrom`: `StartEngine`, `PrintPerformance(cores)`, `FetchCounter`, `FetchCRecords`, `Exit`.
- `MessageTo<Store64<Extension>>`: counters (to/from), connection records (client/server), start/stop timestamps.

### Environment and I/O
- Uses DPDK via NetBricks/e2d2. PCI `PmdPort` and optional `KNI` interface per NIC.
- Cargo config sets DPDK library search paths; `build.sh` exports the same for shell builds.

