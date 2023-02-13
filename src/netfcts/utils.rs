use rand::thread_rng;
use rand::seq::SliceRandom;

#[derive(Deserialize, Clone)]
pub struct Timeouts {
    pub established: Option<u64>, // in millis
}

impl Default for Timeouts {
    fn default() -> Timeouts {
        Timeouts { established: Some(200) }
    }
}

impl Timeouts {
    pub fn default_or_some(timeouts: &Option<Timeouts>) -> Timeouts {
        let mut t = Timeouts::default();
        if timeouts.is_some() {
            let timeouts = timeouts.clone().unwrap();
            if timeouts.established.is_some() {
                t.established = timeouts.established;
            }
        }
        t
    }
}

pub struct TimeAdder {
    sum: u64,
    count: u64,
    name: String,
    sample_size: u64,
    warm_up: u64,
    start_time: u64,
}

impl TimeAdder {
    pub fn new_with_warm_up(name: &str, sample_size: u64, warm_up: u64) -> TimeAdder {
        TimeAdder {
            sum: 0,
            count: 0,
            name: name.to_string(),
            sample_size,
            warm_up,
            start_time: 0,
        }
    }

    pub fn new(name: &str, sample_size: u64) -> TimeAdder {
        TimeAdder {
            sum: 0,
            count: 0,
            name: name.to_string(),
            sample_size,
            warm_up: 0,
            start_time: 0,
        }
    }

    fn do_count(&mut self) {
        self.count += 1;
        if self.count == self.warm_up {
            // warm-up completed
            println!(
                "TimeAdder {:24}: sum = {:12}, count= {:9}, per count= {:6} (warm-up)",
                self.name,
                self.sum,
                self.count,
                self.sum / self.count
            );
            self.sum = 0;
        }

        if self.count > self.warm_up && (self.count - self.warm_up) % self.sample_size == 0 {
            println!(
                "TimeAdder {:24}: sum = {:12}, count= {:9}, per count= {:6}",
                self.name,
                self.sum,
                self.count,
                self.sum / (self.count - self.warm_up)
            );
        }
    }

    // takes absolute time-stamp and calculates difference to start_time
    pub fn add_stamp(&mut self, time_stamp: u64) {
        assert!(self.start_time > 0);
        self.sum += time_stamp - self.start_time;
        self.do_count();
    }
    // expects time differences
    pub fn add_diff(&mut self, time_diff: u64) {
        self.sum += time_diff;
        self.do_count();
    }

    pub fn start(&mut self, start_time: u64) {
        self.start_time = start_time;
    }
}

pub fn shuffle_ports(first_port: u16, last_port: u16) -> Vec<u16> {
    let mut vec: Vec<u16> = (first_port..last_port + 1).collect();
    {
        let slice: &mut [u16] = &mut vec;
        slice.shuffle(&mut thread_rng());
    }
    vec
}

use std::collections::{VecDeque, BTreeMap};
use std::ops::Shr;
use std::ops::BitAnd;

const CHUNK_BITS: usize = 8;
const CHUNK_SIZE: usize = 1usize << CHUNK_BITS;
const ROOT_SIZE: usize = 1usize << (16 - CHUNK_BITS);
const HEAP_SIZE: usize = 0x1000;

#[derive(Clone, Copy)]
struct Chunk<T>
where
    T: Copy,
{
    chunk: [T; CHUNK_SIZE],
    used_slots: usize,
    allocated: bool,
    ///indicates an empty slot
    empty: T,
}

impl<T: Copy + PartialEq> Chunk<T> {
    fn new(init: T) -> Chunk<T> {
        Chunk {
            chunk: [init; CHUNK_SIZE],
            allocated: false,
            used_slots: 0,
            empty: init,
        }
    }
    #[inline]
    fn remove(&mut self, ix: usize) -> Option<T> {
        let old = self.chunk[ix];
        if old != self.empty {
            self.chunk[ix] = self.empty;
            self.used_slots -= 1;
            Some(old)
        } else {
            None
        }
    }
    #[inline]
    fn insert(&mut self, ix: usize, item: T) -> Option<T> {
        let old = self.chunk[ix];
        self.chunk[ix] = item;
        if old != self.empty {
            Some(old)
        } else {
            self.used_slots += 1;
            None
        }
    }
}

struct ChunkHeap<T>
where
    T: Copy + PartialEq,
{
    heap: Vec<Chunk<T>>,
    free_chunks: VecDeque<usize>,
}

impl<T: Copy + PartialEq> ChunkHeap<T> {
    fn new(init: T) -> ChunkHeap<T> {
        ChunkHeap {
            heap: vec![Chunk::new(init); HEAP_SIZE],
            free_chunks: (1..HEAP_SIZE + 1).collect(),
        }
    }
    // index i must be > 0, as we use 0 for indicating unused slots
    #[inline]
    fn get(&self, i: usize) -> &Chunk<T> {
        &self.heap[i - 1]
    }
    #[inline]
    fn get_mut(&mut self, i: usize) -> &mut Chunk<T> {
        &mut self.heap[i - 1]
    }
    #[inline]
    fn allocate(&mut self) -> Option<usize> {
        let ix = self.free_chunks.pop_front();
        if ix.is_some() {
            self.get_mut(ix.unwrap()).allocated = true;
        }
        ix
    }
    fn values(&self, filter: fn(&&T) -> bool) -> Vec<T> {
        self.heap
            .iter()
            .filter(|chunk| (*chunk).allocated)
            .flat_map(|chunk| chunk.chunk.iter().filter(filter).map(|item| *item))
            .collect()
    }
}

struct PortMap {
    root: [u16; ROOT_SIZE],
}

impl PortMap {
    fn new() -> PortMap {
        PortMap { root: [0; ROOT_SIZE] }
    }
    #[inline]
    fn insert<T: Copy + PartialEq>(&mut self, chunk_heap: &mut ChunkHeap<T>, port: u16, item: T) {
        let high_p = port.shr(CHUNK_BITS as u16) as usize;
        let low_p = port.bitand(CHUNK_SIZE as u16 - 1) as usize;
        if self.root[high_p] == 0 {
            // allocate a chunk
            self.root[high_p] = chunk_heap.allocate().expect("out of chunks") as u16;
        }
        chunk_heap.get_mut(self.root[high_p] as usize).insert(low_p, item);
    }
    #[inline]
    fn get<'a, T: Copy + PartialEq>(&self, chunk_heap: &'a ChunkHeap<T>, port: u16) -> Option<&'a T> {
        let high_p = port.shr(CHUNK_BITS as u16) as usize;
        if self.root[high_p] == 0 {
            return None;
        } else {
            let low_p = port.bitand(CHUNK_SIZE as u16 - 1) as usize;
            Some(&chunk_heap.get(self.root[high_p] as usize).chunk[low_p])
        }
    }
    #[inline]
    fn remove<T: Copy + PartialEq>(&mut self, chunk_heap: &mut ChunkHeap<T>, port: u16) -> Option<T> {
        let high_p = port.shr(CHUNK_BITS as u16) as usize;
        if self.root[high_p] == 0 {
            return None;
        } else {
            let low_p = port.bitand(CHUNK_SIZE as u16 - 1) as usize;
            let chunk = chunk_heap.get_mut(self.root[high_p] as usize);
            chunk.remove(low_p)
        }
    }
}

pub struct Sock2Index {
    chunk_heap: ChunkHeap<u16>,
    sock_tree: BTreeMap<u32, PortMap>,
}

impl<'a> Sock2Index {
    pub fn new() -> Sock2Index {
        Sock2Index {
            chunk_heap: ChunkHeap::new(0),
            sock_tree: BTreeMap::new(),
        }
    }

    #[inline]
    pub fn get(&self, sock: &(u32, u16)) -> Option<&u16> {
        let ip = sock.0;
        let port = sock.1;
        assert!(port > 0);
        let port_map = self.sock_tree.get(&ip);
        match port_map {
            None => None,
            Some(port_map) => match port_map.get(&self.chunk_heap, port) {
                None => None,
                Some(0) => None,
                r => r,
            },
        }
    }

    #[inline]
    pub fn insert(&mut self, sock: (u32, u16), index: u16) {
        let ip = sock.0;
        {
            let port_map = self.sock_tree.get_mut(&ip);
            if port_map.is_some() {
                port_map.unwrap().insert(&mut self.chunk_heap, sock.1, index);
                return;
            }
        }
        self.sock_tree.insert(ip, PortMap::new());
        let port_map = self.sock_tree.get_mut(&ip);
        port_map.unwrap().insert(&mut self.chunk_heap, sock.1, index);
    }

    #[inline]
    pub fn remove(&mut self, sock: &(u32, u16)) -> Option<u16> {
        let port_map = self.sock_tree.get_mut(&sock.0);
        if port_map.is_none() {
            return None;
        } else {
            port_map.unwrap().remove(&mut self.chunk_heap, sock.1)
        }
    }

    #[inline]
    pub fn values(&self) -> Vec<u16> {
        self.chunk_heap.values(|ix| **ix != 0)
    }
}

#[test]
fn test_shuffling() {
    let vec = shuffle_ports(0, 100);
    let sum: u16 = vec.iter().sum();
    assert_eq!(sum, 5050);
    let h1: u16 = vec.iter().enumerate().filter(|(i, _x)| i < &50).map(|(_i, x)| x).sum();
    let h2: u16 = vec.iter().enumerate().filter(|(i, _x)| i >= &50).map(|(_i, x)| x).sum();
    println!("h1= {}, h2= {}", h1, h2);
    assert!((h1 as i32 - 2525).abs() < 500);
}

#[test]
fn test_chunk_heap() {
    let mut chunk_heap = ChunkHeap::<u16>::new(0);
    let mut port_map = PortMap::new();
    let item: u16 = 4321;
    port_map.insert(&mut chunk_heap, 1234, item);
    port_map.insert(&mut chunk_heap, 0, item + 1);
    port_map.insert(&mut chunk_heap, 0xFFFF, item + 2);
    {
        let val = port_map.get(&mut chunk_heap, 1234).unwrap();
        assert_eq!(*val, item);
    }
    {
        let val = port_map.get(&mut chunk_heap, 0).unwrap();
        assert_eq!(*val, item + 1);
    }
    {
        let val = port_map.get(&mut chunk_heap, 0xFFFF).unwrap();
        assert_eq!(*val, item + 2);
    }
    {
        // test for non-existent key
        let val = port_map.get(&mut chunk_heap, 0x1).unwrap();
        assert_eq!(*val, 0);
    }
    let mut values = chunk_heap.values(|ix| **ix != 0);
    values.sort_by(|a, b| a.cmp(b));
    for i in 0..3 {
        assert_eq!(values[i], item + i as u16);
    }
}

#[test]
fn test_sock2index() {
    let mut sock_map = Sock2Index::new();
    sock_map.insert((1, 2), 4711);
    {
        let not_existent = sock_map.get(&(1, 1));
        assert!(not_existent.is_none());
    }
    {
        let val = sock_map.get(&(1, 2)).unwrap();
        assert_eq!(*val, 4711);
    }
    {
        let values = sock_map.values();
        assert_eq!(values[0], 4711);
        assert_eq!(values.len(), 1);
    }
    {
        let val = sock_map.remove(&(1, 2)).unwrap();
        assert_eq!(val, 4711);
    }
    {
        let not_existent = sock_map.get(&(1, 2));
        assert!(not_existent.is_none());
    }
}
