//! Test support utilities for integration tests.
//!
//! This module is only compiled when running tests or when the
//! `test-support` feature is enabled.

#![cfg(any(test, feature = "test-support"))]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::thread::{self, JoinHandle};

use crate::netfcts::tcp_common::CData;
use crate::TargetConfig;

/// Spawn a simple TCP echo server per target specified in the configuration.
///
/// Each server:
/// - Accepts a connection
/// - Reads an initial `CData` blob (bincode), replies with "Thank you"
/// - Then performs `fin_by_client - 1` request/response exchanges
///
/// Returns the thread handles of the spawned servers.
pub fn spawn_test_servers(fin_by_client: usize, targets: Vec<TargetConfig>) -> Vec<JoinHandle<()>> {
    targets
        .into_iter()
        .map(|server| {
            let target_port = server.port;
            let target_ip: Ipv4Addr = server.ipnet.addr();
            let id = server.id;
            thread::spawn(move || match TcpListener::bind((target_ip, target_port)) {
                Ok(listener1) => {
                    debug!("bound server {} to {}:{}", id, target_ip, target_port);
                    for stream in listener1.incoming() {
                        let mut stream = stream.unwrap();
                        let mut buffer = [0u8; 256];
                        debug!("{} received connection from: {}", id, stream.peer_addr().unwrap());
                        let nr_bytes = stream
                            .read(&mut buffer[..])
                            .expect(&format!("cannot read from stream {}", stream.peer_addr().unwrap()));
                        let cdata: CData =
                            bincode::deserialize(&buffer[0..nr_bytes]).expect("cannot deserialize cdata");
                        debug!("{} received {:?} from: {}", id, cdata, stream.peer_addr().unwrap());
                        stream.write(&"Thank you".as_bytes()).expect("cannot write to stream");
                        for i in 1..fin_by_client {
                            stream
                                .read(&mut buffer[..])
                                .expect(&format!("cannot read from stream at try {}", i + 1));
                            stream
                                .write(&format!("Thank you, {} times", i + 1).as_bytes())
                                .expect("cannot write to stream");
                        }
                    }
                }
                _ => {
                    panic!(
                        "failed to bind server {} to {}:{}",
                        id, target_ip, target_port
                    );
                }
            })
        })
        .collect()
}
