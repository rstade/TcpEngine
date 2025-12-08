#!/bin/bash
set -euo pipefail
DPDK_LD_PATH="/usr/local/lib/x86_64-linux-gnu/"
# Prepend DPDK path without failing when vars are unset (due to set -u)
export LIBRARY_PATH="${DPDK_LD_PATH}${LIBRARY_PATH:+:${LIBRARY_PATH}}"
export LD_LIBRARY_PATH="${DPDK_LD_PATH}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

# Optionally add external shared library from NetBricks if present
EXTRA_SO_REL="../NetBricks/target/native/libzcsi.so"
if [[ -f "$EXTRA_SO_REL" ]]; then
  # Resolve absolute path and prepend its directory to LD_LIBRARY_PATH
  EXTRA_SO_DIR="$(cd "$(dirname "$EXTRA_SO_REL")" && pwd -P)"
  EXTRA_SO_ABS="${EXTRA_SO_DIR}/$(basename "$EXTRA_SO_REL")"
  export LD_LIBRARY_PATH="${EXTRA_SO_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
  # Preload the library while preserving any existing LD_PRELOAD
  export LD_PRELOAD="${EXTRA_SO_ABS}${LD_PRELOAD:+:${LD_PRELOAD}}"
fi

# we flush the ARP cache because outdated ARP entries may let tests fail
sudo ip -s -s neigh flush all

# Helper to build the selected test binary and run it with the given TOML and RUST_LOG
# Usage: build_and_run <test_name> <toml_path> <rust_log> [extra cargo args...]
build_and_run() {
  local test_name="$1"
  local toml_path="$2"
  local rust_log="$3"
  shift 3 || true

  export RUST_LOG="$rust_log"
  export RUST_BACKTRACE=1

  local filter
  filter="select((.profile.test == true) and (.target.name == \"${test_name}\")) | .filenames[]"

  local executable
  executable=$(cargo test "$@" --no-run --message-format=json --features test-support --test "${test_name}" | jq -r "$filter")

  echo "$executable"
  echo "$toml_path" > tests/toml_file.txt
  # Preserve PATH and LD_LIBRARY_PATH explicitly when invoking via sudo
  # Run the executable and propagate its exit code explicitly
  set +e
  sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" "LD_PRELOAD=${LD_PRELOAD-}" "$executable" --nocapture
  local rc=$?
  set -e
  return $rc
}

TASK=${1:-all}

case "$TASK" in
  # the following first targets are testing the TcpEngine as mode=DelayedProxyEngine or SimpleProxyEngine
  test_rfs_ip)
    build_and_run test_tcp_proxy ./tests/test_rfs_ip.toml "tcp_lib=info,test_tcp_proxy=debug,e2d2=info" "${@:2}"
    ;;
  test_rfs_ip.2)
    build_and_run test_tcp_proxy ./tests/test_rfs_ip.2.toml "tcp_lib=info,test_tcp_proxy=info,e2d2=info" "${@:2}"
    ;;
  test_rfs_ip.3)
    build_and_run test_tcp_proxy ./tests/test_rfs_ip.3.toml "tcp_lib=info,test_tcp_proxy=info,e2d2=info" "${@:2}"
    ;;
  test_rfs_port)
    build_and_run test_tcp_proxy ./tests/test_rfs_port.toml "tcp_lib=debug,test_tcp_proxy=debug,e2d2=info,netfcts=debug" "${@:2}"
    ;;
  test_rfs_port.3)
      build_and_run test_tcp_proxy ./tests/test_rfs_port.3.toml "tcp_lib=info,test_tcp_proxy=debug,e2d2=info,netfcts=info" "${@:2}"
      ;;
  timeout)
    build_and_run timeout ./tests/timeout.toml "tcp_lib=debug,timeout=debug,e2d2=info" "${@:2}"
    ;;
  timeout.2)
    build_and_run timeout ./tests/timeout.2.toml "tcp_lib=info,timeout=info,e2d2=info" "${@:2}"
    ;;
  client_syn_fin)
    build_and_run client_syn_fin ./tests/client_syn_fin.toml "tcp_lib=info,client_syn_fin=info,e2d2=info" "${@:2}"
    ;;
  client_syn_fin.2)
    build_and_run client_syn_fin ./tests/client_syn_fin.2.toml "tcp_lib=info,client_syn_fin=info,e2d2=info" "${@:2}"
    ;;
  client_syn_fin.3)
    build_and_run client_syn_fin ./tests/client_syn_fin.3.toml "tcp_lib=debug,client_syn_fin=debug,e2d2=info" "${@:2}"
    ;;
  ## the following targets are testing the TcpEngine as mode=TrafficEngine
  test_as_client)
    build_and_run test_as_client ./tests/test_gen.toml "tcp_lib=debug,e2d2=debug" "${@:2}"
    ;;
  test_as_server)
    build_and_run test_as_server ./tests/test_gen.toml "tcp_lib=info,e2d2=info" "${@:2}"
    ;;
  macswap)
    build_and_run macswap ./tests/macswap.toml "tcp_lib=info,macswap=info,e2d2=info" "${@:2}"
    ;;
  test_as_client.2)
    build_and_run test_as_client ./tests/test_gen.2.toml "tcp_lib=info,e2d2=info" "${@:2}"
    ;;
  test_as_client.3)
      build_and_run test_as_client ./tests/test_gen.3.toml "tcp_lib=info,e2d2=info" "${@:2}"
      ;;
  test_as_server.2)
    build_and_run test_as_server ./tests/test_gen.2.toml "tcp_lib=info,e2d2=info" "${@:2}"
    ;;
  test_as_server.3)
      build_and_run test_as_server ./tests/test_gen.3.toml "tcp_lib=info,e2d2=info" "${@:2}"
      ;;
  macswap.2)
    build_and_run macswap ./tests/macswap.2.toml "tcp_lib=info,macswap=info,e2d2=info" "${@:2}"
    ;;
  all)
    "$0" test_as_client "${@:2}"
    "$0" test_as_server "${@:2}"
    ;;
esac




