### TcpEngine Threads and Communication

Generated: 2025-12-07 18:11 local time

This document illustrates the principal threads and message channels used by TcpEngine, based on the current implementation in:
- `src/netfcts/mod.rs` (RunTime, channels, scheduler orchestration)
- `src/bin.rs` (interactive main)
- `src/run_test.rs` (test harness main)

Legend:
- Main → RunTime (`mtx: Sender<MessageFrom>`): sends control messages, including `StartEngine`, `PrintPerformance`, `FetchCounter`, `FetchCRecords`, and `Exit`.
- RunTime → Main (`reply_mrx: Receiver<MessageTo>`): receives counters, connection records, and timestamps.
- RunTime ↔ Schedulers: `SchedulerCommand` to start/stop tasks and request performance; `SchedulerReply::PerformanceData` back.
- Pipelines register a per-pipeline `Sender<MessageTo>` via `MessageFrom::Channel`, enabling RunTime to broadcast fetch requests.

#### ASCII diagram

```
+------------------+                               +-------------------------------------+
|     Main         |                               |              RunTime                |
| (tcpengine main  |                               |        ("recv thread")              |
|  or run_test)    |                               |  spawned in RunTime::start()        |
|                  |                               |                                     |
| - installs NFG   |    MessageFrom<TStore>        | - owns NetBricksContext             |
| - starts scheds  |  (mtx: Sender)  ─────────────▶| - loops on mrx: Receiver<MessageFrom|
| - starts runtime |                               | - holds reply_to_main: Sender<MessageTo>
| - REPL / waits   |                               | - maintains per-pipeline senders    |
+------------------+                               +-------------------┬-----------------+
         ▲                                                         SchedulerCommand│
         │     MessageTo<TStore>                                   (control)       │
         │ (reply_mrx: Receiver) ◀──────────── reply_to_main: Sender<MessageTo>    │
         │                                                                         ▼
         │                                                              +---------------------------+
         │                                                              |    N StandaloneScheduler  |
         │                                                              |    threads (per active    |
         │                                                              |    core in config)        |
         │                                                              |                           |
         │   SchedulerReply                                             | - run pipelines/tasks     |
         │   (performance, etc.) ◀──────── context.reply_receiver ◀─────+ - expose channel per core |
         │                                                              |   in context.scheduler_   |
         │                                                              |   channels: Sender<SCmd>  |
         │                                                              +---------------------------+
         │                                                                              │
         │                         MessageFrom<TStore> via                              │ (internal to schedulers)
         │                         run_configuration.remote_sender                      │
         │                                                                              ▼
         │                                                              +---------------------------+
         │                                                              |  Pipelines & Tasks        |
         │                                                              |  (per core)               |
         │        MessageTo<TStore> per-pipeline sender stored in       |  - generate/forward TCP   |
         └───────── senders: HashMap<PipelineId, Sender<MessageTo>> ───▶|  - report counters,       |
                                                                        |    conn records, stamps   |
                                                                        +---------------------------+
```


#### Channels and message types
- Main → RunTime (mtx: `Sender<MessageFrom<TStore>>`)
    - `StartEngine` — set all tasks to ready (`SchedulerCommand::SetTaskStateAll(true)`)
    - `PrintPerformance(Vec<core_idx>)` — request per-core performance data
    - `FetchCounter` — ask pipelines to send counters
    - `FetchCRecords` — ask pipelines to send connection records
    - `Channel(PipelineId, Sender<MessageTo<TStore>>)` — pipelines register their reply channel to RunTime
    - `Task(pipeline_id, uuid, task_type)` — task registration/reporting
    - `Counter(...)` — counter data (can also come via pipelines → RunTime path)
    - `CRecords(...)` — connection records (can also come via pipelines → RunTime path)
    - `TimeStamps(p, t0, t1)` — start/stop stamps
    - `Exit` — graceful shutdown (RunTime stops tasks, prints stats, `context.stop()`, exits loop)

- RunTime → Main (`reply_to_main: Sender<MessageTo<TStore>>`, received on `reply_mrx` in main)
    - `Counter(...)` — per-pipeline TCP counters (to/from)
    - `CRecords(...)` — client/server connection records
    - `TimeStamps(p, t0, t1)` — performance timing stamps

- RunTime → Scheduler threads (`context.scheduler_channels: HashMap<core, Sender<SchedulerCommand>>`)
    - `SetTaskStateAll(true|false)` — start/stop all tasks on a scheduler
    - `GetPerformance` — trigger schedulers to report performance

- Scheduler threads → RunTime (`context.reply_receiver: Receiver<SchedulerReply>`)
    - `PerformanceData(core, map)` — performance snapshot printed by RunTime thread

- Pipelines/Tasks ↔ RunTime
    - Pipelines send `MessageFrom<TStore>` to RunTime via `run_configuration.remote_sender`.
    - RunTime receives `MessageFrom::Channel(pipeline_id, sender)` and stores per‑pipeline `Sender<MessageTo<TStore>>` in `senders` to broadcast `FetchCounter`/`FetchCRecords`.

#### Thread lifecycle summary
1. Main constructs `RunTime`, reads TOML, configures ports, starts schedulers (`start_schedulers()`), installs pipelines/NFGs, then calls `runtime.start()`.
2. `RunTime::start()` spawns the RunTime thread ("recv thread"):
    - Moves `context` and `local_receiver (mrx)` into the thread.
    - Calls `context.execute_schedulers()` so each scheduler thread starts running its task loop.
    - Handles messages from main/pipelines and forwards commands to schedulers.
3. Main obtains `(mtx, reply_mrx)` via `get_main_channel()` and begins control/remoting (REPL or test driver).
4. Shutdown (graceful in both `bin.rs` and `run_test.rs`):
    - Main sends `MessageFrom::Exit` over `mtx`.
    - Drops `mtx`, drops `run_configuration` (to release `Sender<MessageTo<_>>` clone), drops `runtime`.
    - Waits until `reply_mrx` reports `Disconnected` (RunTime thread has exited and dropped its senders), with a bounded timeout.

#### Where things live in code
- Thread spawn and RunTime loop: `src/netfcts/mod.rs` → `RunTime::start()`
- Main control path (interactive REPL and shutdown): `src/bin.rs`
- Test control path (server/client flows and shutdown): `src/run_test.rs`
- Scheduler API: `e2d2::scheduler::{StandaloneScheduler, SchedulerCommand, SchedulerReply}`
- Channels exposed on `RunConfiguration`:
    - `remote_sender: Sender<MessageFrom<TStore>>` (pipelines → RunTime)
    - `local_sender: Sender<MessageTo<TStore>>` (RunTime → Main)

#### Notes and implications
- The RunTime thread is the “hub” that:
    - Orchestrates scheduler threads (start/stop, performance requests)
    - Relays data between pipelines and main
- Pipelines/tasks execute within scheduler threads. They report back via the `remote_sender` and receive fetch requests via their per‑pipeline `Sender<MessageTo<TStore>>` registered with `MessageFrom::Channel`.
- The channel disconnect that main waits for at shutdown only occurs after all `Sender<MessageTo<_>>` clones (including the one held in `run_configuration` on the main side) are dropped; hence the shutdown order in `bin.rs`/`run_test.rs`.


#### Shutdown sequence (as implemented)
1. Main sends `MessageFrom::Exit` over `mtx`.
2. Main drops `mtx` (main → runtime channel), drops `run_configuration` (releasing a main‑side `Sender<MessageTo>` clone), then drops `runtime`.
3. Main waits until `reply_mrx` becomes `Disconnected`, indicating the RunTime thread has exited and dropped its senders. A bounded timeout prevents hangs.

This matches the logic in `src/bin.rs` and `src/run_test.rs`, and the `Exit` handling in `RunTime::start()` in `src/netfcts/mod.rs`.
