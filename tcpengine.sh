#!/bin/bash
#we flush the ARP cache because outdated ARP entries may let tests fail
#sudo ip -s -s neigh flush all
export RUST_BACKTRACE=1
export RUST_LOG="tcp_lib=info,tcpengine=info,e2d2=info,netfcts=info"

# Optionally add external shared library from NetBricks if present (same as in test.sh)
EXTRA_SO_REL="../NetBricks/target/native/libzcsi.so"
if [[ -f "$EXTRA_SO_REL" ]]; then
  # Resolve absolute path and prepend its directory to LD_LIBRARY_PATH
  EXTRA_SO_DIR="$(cd "$(dirname "$EXTRA_SO_REL")" && pwd -P)"
  EXTRA_SO_ABS="${EXTRA_SO_DIR}/$(basename "$EXTRA_SO_REL")"
  export LD_LIBRARY_PATH="${EXTRA_SO_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
  # Preload the library while preserving any existing LD_PRELOAD
  export LD_PRELOAD="${EXTRA_SO_ABS}${LD_PRELOAD:+:${LD_PRELOAD}}"
fi

executable=`cargo build $2 $3 $4 --message-format=json | jq -r 'select((.profile.test == false) and (.target.name == "tcpengine")) | .filenames[]'`
echo $executable
#sudo -E env "PATH=$PATH"  perf stat -e L1-dcache-loads,L1-dcache-load-misses,L1-dcache-stores,L1-dcache-store-misses,LLC-loads,LLC-load-misses,cache-references,cache-misses $executable $1
sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" "LD_PRELOAD=${LD_PRELOAD-}" $executable $1 --interactive