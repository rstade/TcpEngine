use std::arch::x86_64::_rdtsc;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

use separator::Separatable;

use crate::netfcts::tcp_common::{TcpRole, TcpState, ReleaseCause};
use crate::netfcts::recstore::Storable;
use crate::netfcts::tcp_common::tcp_start_state;

#[derive(Clone, Copy, Debug)]
//#[repr(align(64))]
pub struct ConRecord {
    base_stamp: u64,
    uid: u64,
    stamps: [u32; 6],
    sent_payload_packets: u16,
    recv_payload_packets: u16,
    client_ip: u32,
    client_port: u16,
    port: u16,
    state: [u8; 7],
    state_count: u8,
    server_index: u8,
    release_cause: u8,
    role: u8,
    server_state: u8,
}

// we map cycle differences from u64 to u32 to minimize record size in the cache (performance)
pub const TIME_STAMP_REDUCTION_FACTOR: u64 = 1000;

pub trait HasTcpState {
    fn push_state(&mut self, state: TcpState);
    fn last_state(&self) -> TcpState;
    fn states(&self) -> Vec<TcpState>;
    fn get_last_stamp(&self) -> Option<u64>;
    fn get_first_stamp(&self) -> Option<u64>;
    fn deltas_to_base_stamp(&self) -> Vec<u32>;
    fn release_cause(&self) -> ReleaseCause;
    fn set_release_cause(&mut self, cause: ReleaseCause);
}

pub trait HasConData {
    fn sock(&self) -> (u32, u16);
    fn set_sock(&mut self, s: (u32, u16));
    fn port(&self) -> u16;
    fn set_port(&mut self, port: u16);
    fn uid(&self) -> u64;
    fn set_uid(&mut self, new_uid: u64);
    fn server_index(&self) -> u8;
    fn set_server_index(&mut self, index: u8);
    fn sent_payload_packets(&self) -> u16;
    fn recv_payload_packets(&self) -> u16;
    fn inc_sent_payload_pkts(&mut self) -> u16;
    fn inc_recv_payload_pkts(&mut self) -> u16;
    fn server_state(&self) -> TcpState;
    fn set_server_state(&mut self, state: TcpState);
}

impl ConRecord {
    #[inline]
    pub fn init(&mut self, role: TcpRole, port: u16, sock: Option<(u32, u16)>) {
        self.state_count = 0;
        self.base_stamp = 0;
        self.sent_payload_packets = 0;
        self.recv_payload_packets = 0;
        self.uid = unsafe { _rdtsc() };
        self.server_index = 0;
        let s = sock.unwrap_or((0, 0));
        self.client_ip = s.0;
        self.client_port = s.1;
        self.role = role as u8;
        self.port = port;
        self.server_state = tcp_start_state(self.role()) as u8;
    }

    #[inline]
    pub fn role(&self) -> TcpRole {
        TcpRole::from(self.role)
    }

    #[inline]
    pub fn base_stamp(&self) -> u64 {
        self.base_stamp
    }
}

impl HasConData for ConRecord {
    #[inline]
    fn sock(&self) -> (u32, u16) {
        (self.client_ip, self.client_port)
    }

    #[inline]
    fn set_sock(&mut self, s: (u32, u16)) {
        self.client_ip = s.0;
        self.client_port = s.1;
    }

    #[inline]
    fn port(&self) -> u16 {
        self.port
    }

    #[inline]
    fn set_port(&mut self, port: u16) {
        self.port = port
    }

    #[inline]
    fn uid(&self) -> u64 {
        self.uid
    }

    #[inline]
    fn set_uid(&mut self, new_uid: u64) {
        self.uid = new_uid
    }

    #[inline]
    fn server_index(&self) -> u8 {
        self.server_index
    }

    #[inline]
    fn set_server_index(&mut self, index: u8) {
        self.server_index = index
    }

    #[inline]
    fn sent_payload_packets(&self) -> u16 {
        self.sent_payload_packets
    }

    #[inline]
    fn recv_payload_packets(&self) -> u16 {
        self.recv_payload_packets
    }

    #[inline]
    fn inc_sent_payload_pkts(&mut self) -> u16 {
        self.sent_payload_packets += 1;
        self.sent_payload_packets
    }

    #[inline]
    fn inc_recv_payload_pkts(&mut self) -> u16 {
        self.recv_payload_packets += 1;
        self.recv_payload_packets
    }

    #[inline]
    fn server_state(&self) -> TcpState {
        TcpState::from(self.server_state)
    }

    #[inline]
    fn set_server_state(&mut self, state: TcpState) {
        self.server_state = state as u8;
    }
}

impl HasTcpState for ConRecord {
    #[inline]
    fn push_state(&mut self, state: TcpState) {
        self.state[self.state_count as usize] = state as u8;
        if self.state_count == 0 {
            self.base_stamp = unsafe { _rdtsc() };
        } else {
            self.stamps[self.state_count as usize - 1] =
                ((unsafe { _rdtsc() } - self.base_stamp) / TIME_STAMP_REDUCTION_FACTOR) as u32;
        }
        self.state_count += 1;
    }

    #[inline]
    fn last_state(&self) -> TcpState {
        if self.state_count == 0 {
            tcp_start_state(self.role())
        } else {
            TcpState::from(self.state[self.state_count as usize - 1])
        }
    }

    #[inline]
    fn states(&self) -> Vec<TcpState> {
        let mut result = vec![tcp_start_state(self.role()); self.state_count as usize + 1];
        for i in 0..self.state_count as usize {
            result[i + 1] = TcpState::from(self.state[i]);
        }
        result
    }

    #[inline]
    fn get_last_stamp(&self) -> Option<u64> {
        match self.state_count {
            0 => None,
            1 => Some(self.base_stamp),
            _ => Some(self.base_stamp + self.stamps[self.state_count as usize - 2] as u64 * TIME_STAMP_REDUCTION_FACTOR),
        }
    }

    #[inline]
    fn get_first_stamp(&self) -> Option<u64> {
        if self.state_count > 0 {
            Some(self.base_stamp)
        } else {
            None
        }
    }

    fn deltas_to_base_stamp(&self) -> Vec<u32> {
        if self.state_count >= 2 {
            self.stamps[0..(self.state_count as usize - 1)].iter().map(|s| *s).collect()
        } else {
            vec![]
        }
    }

    #[inline]
    fn release_cause(&self) -> ReleaseCause {
        ReleaseCause::from(self.release_cause)
    }

    #[inline]
    fn set_release_cause(&mut self, cause: ReleaseCause) {
        self.release_cause = cause as u8;
    }
}

impl fmt::Display for ConRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "({:?}, {:21}, {:6}, {:3}, {:7}, {:7}, {:?}, {:?}, {}, {:?})",
            self.role(),
            if self.client_ip != 0 {
                SocketAddrV4::new(Ipv4Addr::from(self.client_ip), self.client_port).to_string()
            } else {
                "none".to_string()
            },
            self.port(),
            self.server_index,
            self.sent_payload_packets,
            self.recv_payload_packets,
            self.states(),
            self.release_cause(),
            self.base_stamp.separated_string(),
            self.deltas_to_base_stamp()
                .iter()
                .map(|u| u.separated_string())
                .collect::<Vec<_>>(),
        )
    }
}

impl Storable for ConRecord {
    #[inline]
    fn new() -> ConRecord {
        ConRecord {
            role: TcpRole::Client as u8,
            server_index: 0,
            release_cause: ReleaseCause::Unknown as u8,
            state_count: 0,
            base_stamp: 0,
            state: [TcpState::Closed as u8; 7],
            stamps: [0u32; 6],
            port: 0u16,
            client_ip: 0,
            client_port: 0,
            sent_payload_packets: 0,
            recv_payload_packets: 0,
            uid: 0,
            server_state: TcpState::Listen as u8,
        }
    }
}
