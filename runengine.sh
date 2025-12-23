#!/bin/bash
set -euo pipefail

#
# runengine.sh — build and start tcpengine
#
# Usage (new argument model):
#   ./runengine.sh <config> [<tcpengine_args> ...] [-- <cargo_build_args> ...]
#
# Rules:
# - The first positional argument is passed as the config to tcpengine.
# - Any arguments after the config and before a literal '--' are passed to tcpengine.
# - Any arguments after '--' are forwarded to 'cargo build'.
#
# Examples:
#   # Only config (no extra args)
#   ./runengine.sh proxy_run.toml
#
#   # Config plus extra tcpengine flags
#   ./runengine.sh proxy_run.toml --log-level debug --max-conns 50000
#
#   # Release build (args after -- go to cargo)
#   ./runengine.sh proxy_run.toml -- --release
#
#   # Both: tcpengine flags and cargo flags
#   ./runengine.sh proxy_run.toml --log-level debug -- --release --features "dpdk"
#
# Notes:
# - The script sets up LD_LIBRARY_PATH/LD_PRELOAD to include ../NetBricks/target/native/libzcsi.so if present.
# - It will use 'perf stat' if available; otherwise it runs the binary directly.
# - ARP cache flush is available but disabled by default; uncomment if needed.

# Determine script directory to resolve relative paths robustly
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# Optional: DPDK library path example (left as-is intentionally)
DPDK_LD_PATH="/usr/local/lib/x86_64-linux-gnu/"
export LIBRARY_PATH="${DPDK_LD_PATH}${LIBRARY_PATH:+:${LIBRARY_PATH}}"
export LD_LIBRARY_PATH="${DPDK_LD_PATH}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

# Optionally add external shared library from NetBricks if present
EXTRA_SO_ABS="${SCRIPT_DIR}/../NetBricks/target/native/libzcsi.so"
if [[ -f "$EXTRA_SO_ABS" ]]; then
  EXTRA_SO_DIR="$(dirname "$EXTRA_SO_ABS")"
  export LD_LIBRARY_PATH="${EXTRA_SO_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
  # Preload the library while preserving any existing LD_PRELOAD
  export LD_PRELOAD="${EXTRA_SO_ABS}${LD_PRELOAD:+:${LD_PRELOAD}}"
fi

# Basic argument check: require at least the config/first argument for the binary
if [[ $# -lt 1 ]]; then
  echo "Usage: $(basename "$0") <config> [<tcpengine_args> ...] [-- <cargo_build_args> ...]" >&2
  echo "  The first argument is the config for tcpengine; args before '--' go to tcpengine; args after '--' go to cargo build." >&2
  exit 1
fi

# We flush the ARP cache because outdated ARP entries may let proxy fail
# sudo ip -s -s neigh flush all

export RUST_BACKTRACE=1
export RUST_LOG="tcpengine=info,tcp_lib=info,e2d2=trace,netfcts=info"

# Parse arguments: first is CONFIG, then ENGINE_ARGS until '--', then BUILD_ARGS for cargo
CONFIG="$1"
shift || true
ENGINE_ARGS=()
BUILD_ARGS=()
sep_found=false
for arg in "$@"; do
  if [[ "$arg" == "--" ]]; then
    sep_found=true
    continue
  fi
  if [[ "$sep_found" == false ]]; then
    ENGINE_ARGS+=("$arg")
  else
    BUILD_ARGS+=("$arg")
  fi
done

# Prefer the single .executable field from cargo JSON; fall back to .filenames[]
executable=$(cargo build "${BUILD_ARGS[@]}" --message-format=json \
  | jq -r 'select(.profile.test==false and .target.name=="tcpengine" and .executable!=null) | .executable' \
  | tail -n1)

if [[ -z "${executable:-}" ]]; then
  executable=$(cargo build "${BUILD_ARGS[@]}" --message-format=json \
    | jq -r 'select(.profile.test==false and .target.name=="tcpengine") | .filenames[]' \
    | tail -n1)
fi

if [[ -z "${executable:-}" ]] || [[ ! -x "$executable" ]]; then
  echo "Error: could not locate built tcpengine executable" >&2
  exit 1
fi

echo "$executable"

# Run with perf if available; otherwise run directly
if command -v perf >/dev/null 2>&1; then
  sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" "LD_PRELOAD=${LD_PRELOAD-}" \
    perf stat -e L1-dcache-loads,L1-dcache-stores,L1-dcache-store-misses,LLC-loads,LLC-load-misses,cache-references,cache-misses -- \
    "$executable" "$CONFIG" "${ENGINE_ARGS[@]}"
else
  echo "Warning: 'perf' not found; running without performance counters" >&2
  sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" "LD_PRELOAD=${LD_PRELOAD-}" \
    "$executable" "$CONFIG" "${ENGINE_ARGS[@]}"
fi

