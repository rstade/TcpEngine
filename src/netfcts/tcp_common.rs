use std::any::Any;
use std::convert;
use std::fmt;
use std::fmt::Write;
use std::net::SocketAddrV4;
use std::ops::{Index, IndexMut};
use e2d2::interface::{Pdu, NetSpec};
use e2d2::common;

use eui48::MacAddress;
use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum TcpState {
    Listen = 0,
    SynReceived,
    SynSent,
    Established,
    CloseWait,
    LastAck,
    FinWait1,
    Closing,
    FinWait2,
    Closed,
}

impl convert::From<u8> for TcpState {
    fn from(i: u8) -> TcpState {
        match i {
            0 => TcpState::Listen,
            1 => TcpState::SynReceived,
            2 => TcpState::SynSent,
            3 => TcpState::Established,
            4 => TcpState::CloseWait,
            5 => TcpState::LastAck,
            6 => TcpState::FinWait1,
            7 => TcpState::Closing,
            8 => TcpState::FinWait2,
            9 => TcpState::Closed,
            _ => TcpState::Listen,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpRole {
    Client = 0,
    Server,
}

impl convert::From<u8> for TcpRole {
    fn from(i: u8) -> TcpRole {
        match i {
            0 => TcpRole::Client,
            1 => TcpRole::Server,
            _ => TcpRole::Client,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpStatistics {
    SentSyn = 0,
    SentSynAck = 1,
    SentSynAck2 = 2,
    SentFin = 3,
    SentFinPssv = 4,
    SentAck4Fin = 5,
    SentAck = 6,
    RecvSyn = 7,
    RecvSynAck = 8,
    RecvSynAck2 = 9,
    RecvFin = 10,     //FIN of active close
    RecvFinPssv = 11, //FIN of passive close
    RecvAck4Fin = 12, //ACK for a FIN packet
    RecvAck = 13,
    RecvRst = 14,
    Unexpected = 15,
    RecvPayload = 16,
    SentPayload = 17,
    Count = 18,
}

impl convert::From<usize> for TcpStatistics {
    fn from(i: usize) -> TcpStatistics {
        match i {
            0 => TcpStatistics::SentSyn,
            1 => TcpStatistics::SentSynAck,
            2 => TcpStatistics::SentSynAck2,
            3 => TcpStatistics::SentFin,
            4 => TcpStatistics::SentFinPssv,
            5 => TcpStatistics::SentAck4Fin,
            6 => TcpStatistics::SentAck,
            7 => TcpStatistics::RecvSyn,
            8 => TcpStatistics::RecvSynAck,
            9 => TcpStatistics::RecvSynAck2,
            10 => TcpStatistics::RecvFin,
            11 => TcpStatistics::RecvFinPssv,
            12 => TcpStatistics::RecvAck4Fin,
            13 => TcpStatistics::RecvAck,
            14 => TcpStatistics::RecvRst,
            15 => TcpStatistics::Unexpected,
            16 => TcpStatistics::RecvPayload,
            17 => TcpStatistics::SentPayload,
            18 => TcpStatistics::Count,
            _ => TcpStatistics::Count,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReleaseCause {
    Unknown = 0,
    Timeout = 1,
    PassiveClose = 2,
    ActiveClose = 3,
    PassiveRst = 4,
    ActiveRst = 5,
    MaxCauses = 6,
}

impl convert::From<u8> for ReleaseCause {
    fn from(i: u8) -> ReleaseCause {
        match i {
            0 => ReleaseCause::Unknown,
            1 => ReleaseCause::Timeout,
            2 => ReleaseCause::PassiveClose,
            3 => ReleaseCause::ActiveClose,
            4 => ReleaseCause::PassiveRst,
            5 => ReleaseCause::ActiveRst,
            6 => ReleaseCause::MaxCauses,
            _ => ReleaseCause::Unknown,
        }
    }
}

#[inline]
pub fn tcp_start_state(role: TcpRole) -> TcpState {
    if role == TcpRole::Client {
        TcpState::Closed
    } else {
        TcpState::Listen
    }
}

impl fmt::Display for TcpStatistics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        write!(&mut output, "{:?}", self)?;
        write!(f, "{:12}", output)
    }
}

#[derive(Debug, Clone)]
pub struct TcpCounter([usize; TcpStatistics::Count as usize]);

impl TcpCounter {
    pub fn new() -> TcpCounter {
        TcpCounter([0; TcpStatistics::Count as usize])
    }
}

impl Index<TcpStatistics> for TcpCounter {
    type Output = usize;

    #[inline]
    fn index(&self, tcp_control: TcpStatistics) -> &usize {
        &self.0[tcp_control as usize]
    }
}

impl IndexMut<TcpStatistics> for TcpCounter {
    #[inline]
    fn index_mut(&mut self, tcp_control: TcpStatistics) -> &mut usize {
        &mut self.0[tcp_control as usize]
    }
}

impl fmt::Display for TcpCounter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Tcp Counters: ",)?;
        for i in 0..TcpStatistics::Count as usize {
            writeln!(f, "{:12} = {:6}", TcpStatistics::from(i), self.0[i])?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct L234Data {
    pub mac: MacAddress,
    pub ip: u32,
    pub port: u16,
    pub server_id: String,
    pub index: usize,
}

impl TryFrom<NetSpec> for L234Data {
    type Error = common::errors::ErrorKind;

    fn try_from(value: NetSpec) -> Result<Self, Self::Error> {
        if value.mac.is_none() || value.ip_net.is_none() {
            Err(common::errors::ErrorKind::TryFromNetSpecError)
        } else {
            Ok(L234Data {
                mac: value.mac.unwrap(),
                ip: u32::from(value.ip_net.unwrap().addr()),
                port: value.port.unwrap_or(0),
                server_id: "".to_string(),
                index: 0,
            })
        }
    }
}

pub trait UserData: Send + Sync + 'static {
    fn ref_userdata(&self) -> &dyn Any;
    fn mut_userdata(&mut self) -> &mut dyn Any;
    fn init(&mut self);
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CData {
    // connection data sent as first payload packet
    pub reply_socket: SocketAddrV4, // the socket on which the trafficengine expects the reply from the DUT
    pub client_port: u16,
    pub uuid: u64,
}

impl CData {
    #[inline]
    pub fn new(reply_socket: SocketAddrV4, client_port: u16, uuid: u64) -> CData {
        CData {
            reply_socket: reply_socket,
            client_port,
            uuid,
        }
    }
}

#[inline]
pub fn tcp_payload_size(p: &Pdu) -> usize {
    let iph = p.headers().ip(1);
    // payload size = ip total length - ip header length -tcp header length
    iph.length() as usize - (iph.ihl() as usize) * 4 - (p.headers().tcp(2).data_offset() as usize) * 4
}
