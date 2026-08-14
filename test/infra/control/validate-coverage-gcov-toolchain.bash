#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
dockerfile="${root}/test/infra/docker-base/Dockerfile"
runner="${root}/test/infra/control/run-tests-isolated.bash"
multi="${root}/test/infra/control/run-multi-group.bash"

rg -q '^[[:space:]]*gcc-11[[:space:]\\]*$' "${dockerfile}"
for file in "${runner}" "${multi}"; do
    # `-C` combines existing LCOV files and does not decode raw GCOV data.
    # Every other fastcov branch-coverage invocation must choose gcov-11.
    raw_fastcov_calls="$(rg -P -c 'fastcov -b(?!.* -C )' "${file}")"
    pinned_fastcov_calls="$(rg -c 'fastcov -b -g gcov-11' "${file}")"
    test "${raw_fastcov_calls}" -gt 0
    test "${raw_fastcov_calls}" -eq "${pinned_fastcov_calls}"
    rg -q 'command -v gcov-11' "${file}"
    rg -q 'gcov-11 is required to decode GCC 11 coverage data' "${file}"
done
