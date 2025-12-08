#!/usr/bin/env bash
# Run several tests silently and print their return codes. Suppress test output.

set -uo pipefail

tests=(
  "test_rfs_port.3"
  "test_rfs_ip.3"
  "client_syn_fin.3"
  "test_as_server.3"
  "test_as_client.3"
)

overall_rc=0

for t in "${tests[@]}"; do
  set +e
  ./test.sh "$t" >/dev/null 2>&1
  rc=$?
  set -e
  echo "$t return code: $rc"
  if [ "$rc" -ne 0 ]; then
    overall_rc=1
  fi
done

exit $overall_rc
