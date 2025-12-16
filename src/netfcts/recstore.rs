use std::fmt;
use std::slice::Iter;
use std::cmp;
use std::fmt::Display;
use std::cell::RefCell;
use std::rc::Rc;
use std::arch::x86_64::_rdtsc;
use crate::netfcts::conrecord::{ConRecord, HasConData, HasTcpState, TIME_STAMP_REDUCTION_FACTOR};
use crate::netfcts::tcp_common::ReleaseCause;
use crate::netfcts::tcp_common::TcpState;

use separator::Separatable;

//pub type TEngineStore = RecordStore<ConRecord>;

pub trait Storable: Sized + Send + Display + Clone {
    fn new() -> Self;
}

pub trait SimpleStore: Send {
    fn get(&self, slot: usize) -> &ConRecord;
    fn get_mut(&mut self, slot: usize) -> &mut ConRecord;
}
/*
#[derive(Clone)]
pub struct RecordStore<T: Storable> {
    store: Vec<T>,
    record_count: usize,
    overflow_count: usize,
}

impl<T: Storable> fmt::Debug for RecordStore<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.len() {
            write!(f, "{}\n", self.store[i])?;
        }
        Ok(())
    }
}

impl<T: Storable> RecordStore<T> {
    pub fn with_capacity(capacity: usize) -> RecordStore<T> {
        RecordStore {
            store: vec![T::new(); capacity],
            record_count: 0,
            overflow_count: 0,
        }
    }

    #[inline]
    pub fn get_next_slot(&mut self) -> usize {
        // changed to wrap around
        if self.record_count - self.overflow_count == self.store.len() {
            let wraps = self.record_count / self.store.len();
            warn!(
                "wrapping record storage after exceeding max size = {}, now {} wraps, record_count = {}",
                self.store.len(),
                wraps,
                self.record_count
            );
            self.overflow_count = self.record_count;
        }
        self.record_count += 1;
        self.record_count - 1 - self.overflow_count
    }

    /// the number of records which are stored (excluding overwritten records)
    #[inline]
    pub fn len(&self) -> usize {
        cmp::min(self.record_count, self.store.len())
    }

    #[inline]
    pub fn iter(&self) -> Iter<T> {
        self.store[0..self.len()].iter()
    }

    pub fn sort_by<F>(&mut self, compare: F)
    where
        F: FnMut(&T, &T) -> cmp::Ordering,
    {
        let len = self.len();
        self.store[0..len].sort_by(compare)
    }

    #[inline]
    pub fn get(&self, slot: usize) -> &T {
        &self.store[slot]
    }

    #[inline]
    pub fn get_mut(&mut self, slot: usize) -> &mut T {
        &mut self.store[slot]
    }
}

/// we need trait SimpleStore for the ConRecordOperations trait
impl SimpleStore for RecordStore<ConRecord> {
    #[inline]
    fn get(&self, slot: usize) -> &ConRecord {
        &self.store[slot]
    }

    #[inline]
    fn get_mut(&mut self, slot: usize) -> &mut ConRecord {
        &mut self.store[slot]
    }
}
*/

pub type ProxyRecStore = Store64<Extension>;

#[derive(Clone, Copy, Debug)]
#[repr(align(32))]
pub struct Extension {
    s_stamps: [u32; 7],
    s_state: [u8; 7],
    s_state_count: u8,
    s_release_cause: u8,
}

impl Extension {
    #[inline]
    pub fn states(&self) -> Vec<TcpState> {
        let mut result = vec![TcpState::Listen; self.s_state_count as usize + 1];
        for i in 0..self.s_state_count as usize {
            result[i + 1] = TcpState::from(self.s_state[i]);
        }
        result
    }

    #[inline]
    pub fn push_state(&mut self, state: TcpState, base_stamp: u64) {
        self.s_state[self.s_state_count as usize] = state as u8;
        self.s_stamps[self.s_state_count as usize] =
            ((unsafe { _rdtsc() } - base_stamp) / TIME_STAMP_REDUCTION_FACTOR) as u32;
        self.s_state_count += 1;
    }

    #[inline]
    pub fn release_cause(&self) -> ReleaseCause {
        ReleaseCause::from(self.s_release_cause)
    }

    #[inline]
    pub fn set_release_cause(&mut self, cause: ReleaseCause) {
        self.s_release_cause = cause as u8;
    }

    #[inline]
    pub fn init(&mut self) {
        self.s_state_count = 0;
    }

    #[inline]
    pub fn last_state(&self) -> TcpState {
        if self.s_state_count == 0 {
            TcpState::Listen
        } else {
            TcpState::from(self.s_state[self.s_state_count as usize - 1])
        }
    }

    #[inline]
    pub fn get_last_stamp(&self) -> Option<u64> {
        match self.s_state_count {
            0 => None,
            _ => Some(self.s_stamps[self.s_state_count as usize - 1] as u64 * TIME_STAMP_REDUCTION_FACTOR),
        }
    }

    #[inline]
    pub fn get_first_stamp(&self) -> Option<u64> {
        if self.s_state_count > 0 {
            Some(self.s_stamps[0] as u64 * TIME_STAMP_REDUCTION_FACTOR)
        } else {
            None
        }
    }

    fn deltas_to_base_stamp(&self) -> Vec<u32> {
        if self.s_state_count >= 1 {
            self.s_stamps[0..(self.s_state_count as usize)].iter().map(|s| *s).collect()
        } else {
            vec![]
        }
    }
}

impl Storable for Extension {
    fn new() -> Extension {
        Extension {
            s_state: [TcpState::Listen as u8; 7],
            s_stamps: [0u32; 7],
            s_release_cause: ReleaseCause::Unknown as u8,
            s_state_count: 0,
        }
    }
}

impl Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "(Server, {:?}, {:?}, {:?})",
            self.states(),
            self.release_cause(),
            self.deltas_to_base_stamp()
                .iter()
                .map(|u| u.separated_string())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone)]
pub struct Store64<T: Storable> {
    store_0: Vec<ConRecord>,
    store_1: Vec<T>,
    record_count: usize,
    overflow_count: usize,
}

impl<T: Storable> Store64<T> {
    pub fn with_capacity(capacity: usize) -> Store64<T> {
        Store64 {
            store_0: vec![ConRecord::new(); capacity],
            store_1: vec![T::new(); capacity],
            record_count: 0,
            overflow_count: 0,
        }
    }

    #[inline]
    pub fn get_next_slot(&mut self) -> usize {
        if self.record_count - self.overflow_count == self.store_0.len() {
            let wraps = self.record_count / self.store_0.len();
            warn!(
                "wrapping record storage after exceeding max size = {}, now {} wraps, record_count = {}",
                self.store_0.len(),
                wraps,
                self.record_count
            );
            self.overflow_count = self.record_count;
        }
        self.record_count += 1;
        self.record_count - 1 - self.overflow_count
    }

    #[inline]
    pub fn len(&self) -> usize {
        cmp::min(self.record_count, self.store_0.len())
    }

    #[inline]
    pub fn iter_0(&self) -> Iter<'_, ConRecord> {
        self.store_0[0..self.len()].iter()
    }

    #[inline]
    pub fn iter_1(&self) -> Iter<'_, T> {
        self.store_1[0..self.len()].iter()
    }

    pub fn iter(&self) -> std::iter::Zip<Iter<'_, ConRecord>, Iter<'_, T>> {
        self.iter_0().zip(self.iter_1())
    }

    #[inline]
    pub fn get_mut_1(&mut self, slot: usize) -> &mut T {
        &mut self.store_1[slot]
    }

    #[inline]
    pub fn get_1(&self, slot: usize) -> &T {
        &self.store_1[slot]
    }

    pub fn sort_0_by<F>(&mut self, compare: F)
    where
        F: FnMut(&ConRecord, &ConRecord) -> cmp::Ordering,
    {
        let n_records = self.len();
        self.store_0[0..n_records].sort_by(compare)
    }
}

impl<T: Storable> SimpleStore for Store64<T> {
    #[inline]
    fn get(&self, slot: usize) -> &ConRecord {
        &self.store_0[slot]
    }

    #[inline]
    fn get_mut(&mut self, slot: usize) -> &mut ConRecord {
        &mut self.store_0[slot]
    }
}

impl<T: Storable> fmt::Debug for Store64<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.len() - 1 {
            write!(f, "({}, {})", self.store_0[i], self.store_1[i])?;
        }
        Ok(())
    }
}

pub trait ConRecordOperations<S: SimpleStore> {
    /// return reference to reference counted pointer to store for the connection
    fn store(&self) -> &Rc<RefCell<S>>;

    /// return index of connection record in store
    fn con_rec(&self) -> usize;

    #[inline]
    fn port(&self) -> u16 {
        self.store().borrow().get(self.con_rec()).port()
    }

    fn in_use(&self) -> bool;

    #[inline]
    fn server_index(&self) -> usize {
        self.store().borrow().get(self.con_rec()).server_index() as usize
    }

    #[inline]
    fn set_server_index(&mut self, index: usize) {
        self.store()
            .borrow_mut()
            .get_mut(self.con_rec())
            .set_server_index(index as u8)
    }

    #[inline]
    fn sent_payload_pkts(&self) -> usize {
        self.store().borrow().get(self.con_rec()).sent_payload_packets() as usize
    }

    #[inline]
    fn recv_payload_pkts(&self) -> usize {
        self.store().borrow().get(self.con_rec()).recv_payload_packets() as usize
    }

    #[inline]
    fn inc_sent_payload_pkts(&self) -> usize {
        self.store().borrow_mut().get_mut(self.con_rec()).inc_sent_payload_pkts() as usize
    }

    #[inline]
    fn inc_recv_payload_pkts(&self) -> usize {
        self.store().borrow_mut().get_mut(self.con_rec()).inc_recv_payload_pkts() as usize
    }

    #[inline]
    fn states(&self) -> Vec<TcpState> {
        self.store().borrow().get(self.con_rec()).states()
    }

    #[inline]
    fn set_release_cause(&self, cause: ReleaseCause) {
        self.store().borrow_mut().get_mut(self.con_rec()).set_release_cause(cause)
    }

    #[inline]
    fn set_port(&mut self, port: u16) {
        self.store().borrow_mut().get_mut(self.con_rec()).set_port(port);
    }

    #[inline]
    fn sock(&self) -> Option<(u32, u16)> {
        let s = self.store().borrow().get(self.con_rec()).sock();
        if s.0 != 0 { Some(s) } else { None }
    }

    #[inline]
    fn set_sock(&mut self, sock: (u32, u16)) {
        self.store().borrow_mut().get_mut(self.con_rec()).set_sock(sock);
    }

    #[inline]
    fn set_uid(&mut self, uid: u64) {
        self.store().borrow_mut().get_mut(self.con_rec()).set_uid(uid);
    }

    #[inline]
    fn get_uid(&self) -> u64 {
        self.store().borrow().get(self.con_rec()).uid()
    }
}
