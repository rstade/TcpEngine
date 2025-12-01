#!/bin/bash
DPDK_LD_PATH="/usr/local/lib/x86_64-linux-gnu/"
export LIBRARY_PATH=${DPDK_LD_PATH}:${LIBRARY_PATH}
export LD_LIBRARY_PATH=${DPDK_LD_PATH}:${LD_LIBRARY_PATH}

cargo test $* --no-run
