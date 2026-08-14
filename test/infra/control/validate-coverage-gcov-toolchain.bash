#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
dockerfile="${root}/test/infra/docker-base/Dockerfile"
runner="${root}/test/infra/control/run-tests-isolated.bash"
multi="${root}/test/infra/control/run-multi-group.bash"

rg -q '^[[:space:]]*gcc-11[[:space:]\\]*$' "${dockerfile}"
test "$(rg -c 'fastcov -b -g gcov-11' "${runner}")" -eq 1
test "$(rg -c 'fastcov -b -g gcov-11' "${multi}")" -eq 1
