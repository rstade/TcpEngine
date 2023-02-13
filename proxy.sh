#!/bin/bash
#we flush the ARP cache because outdated ARP entries may let proxy fail
sudo ip -s -s neigh flush all
export RUST_BACKTRACE=1
export RUST_LOG="tcp_proxy=info,proxy_engine=info,e2d2=info,netfcts=info"
executable=`cargo build $2 $3 $4 --message-format=json | jq -r 'select((.profile.test == false) and (.target.name == "proxy_engine")) | .filenames[]'`
echo $executable
sudo -E env "PATH=$PATH" perf stat -e L1-dcache-loads,L1-dcache-load-misses,L1-dcache-stores,L1-dcache-store-misses,LLC-loads,LLC-load-misses,cache-references,cache-misses $executable $1

