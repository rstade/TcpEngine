use std::fmt;
use std::sync::mpsc::Sender;
use crate::tasks::{TaskType, IDX_ETYPE_OTHER};
use crate::tcp_common::TcpCounter;
use uuid::Uuid;

#[derive(Clone, PartialEq, Eq, Hash, Default, Debug)]
pub struct PipelineId {
    pub core: u16,
    pub port_id: u16,
    pub rxq: u16,
}

impl fmt::Display for PipelineId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<c{}, p{}, rx{}>", self.core, self.port_id, self.rxq)
    }
}

pub trait RuntimeMessage {

}

#[derive(Debug)]
/// MessageFrom are messages which are sent either
/// a) from a pipeline (i.e. tasks of a pipeline) to the Runtime thread or
/// b) from the main thread to the Runtime thread
pub enum MessageFrom<T> {
    Channel(PipelineId, Sender<MessageTo<T>>),
    StartEngine,
    Task(PipelineId, Uuid, TaskType),
    PrintPerformance(Vec<i32>), // performance of tasks on cores selected by indices
    // counter client/to side, counter server/from side, sent_packets with time_stamps
    Counter(PipelineId, TcpCounter, TcpCounter, Option<Vec<(u64, usize, usize)>>),
    CRecords(PipelineId, Option<T>, Option<T>), // pipeline_id, client, server
    FetchCounter,                               // triggers fetching of counters from pipelines
    FetchCRecords,
    /// e.g. start and stop stamp
    TimeStamps(PipelineId, u64, u64),
    EtypeCnt(PipelineId, [u64; IDX_ETYPE_OTHER + 1]),
    Exit, // exit recv thread
}

/// MessageTo are messages which are sent by the Runtime either to pipelines or to the main thread
pub enum MessageTo<T> {
    FetchCounter, // fetch counters from pipeline
    FetchCRecords,
    Counter(PipelineId, TcpCounter, TcpCounter, Option<Vec<(u64, usize, usize)>>),
    CRecords(PipelineId, Option<T>, Option<T>),
    EtypeCnt(PipelineId, [u64; IDX_ETYPE_OTHER + 1]),
    StartGenerator,
    TimeStamps(PipelineId, u64, u64),
    Exit, // exit recv thread
}

impl<T> RuntimeMessage for MessageFrom<T> {

}

impl<T> RuntimeMessage for MessageTo<T> {

}
