#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
dockerfile="${root}/test/infra/docker-base/Dockerfile"
runner="${root}/test/infra/control/run-tests-isolated.bash"
multi="${root}/test/infra/control/run-multi-group.bash"

! rg -q '^[[:space:]]*gcc-11[[:space:]\\]*$' "${dockerfile}"
for file in "${runner}" "${multi}"; do
    # `-C` combines existing LCOV files and does not decode raw GCOV data.
    # Every other fastcov branch-coverage invocation must use the image's
    # default gcov, which matches the compiler used by the build handoff.
    raw_fastcov_calls="$(rg -P -c 'fastcov -b(?!.* -C )' "${file}")"
    test "${raw_fastcov_calls}" -gt 0
    ! rg -q 'fastcov -b -g gcov-[0-9]+' "${file}"
done
rg -q -- '-s .*coverage_file' "${runner}"
rg -q -- '-s .*GROUP_INFO' "${multi}"
