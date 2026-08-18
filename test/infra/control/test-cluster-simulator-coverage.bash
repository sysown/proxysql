#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
runner="${root}/test/infra/control/run-tests-isolated.bash"
builder="${root}/test/infra/control/cluster-simulator-ci.bash"
workflow="${root}/.github/workflows/CI-cluster-simulator.yml"
dump_helper="${root}/test/infra/control/dump-proxysql-gcov.bash"
status_helper="${root}/test/infra/control/coverage-exit-status.bash"

test -x "${dump_helper}"
test -f "${status_helper}"

source "${status_helper}"
coverage_exit_status 0 0
if coverage_exit_status 0 1; then
    echo "coverage failure must fail a successful TAP run" >&2
    exit 1
fi
if coverage_exit_status 7 0; then
    echo "TAP failure must preserve its original exit status" >&2
    exit 1
fi

grep -Fq 'make -C test/deps/cluster_simulator -j"$(nproc)" WITHGCOV=1 check' "${builder}"
dump_line=$(grep -nF 'dump-proxysql-gcov.bash' "${runner}" | cut -d: -f1)
decode_line=$(grep -nF 'fastcov -b' "${runner}" | head -n1 | cut -d: -f1)
test "${dump_line}" -lt "${decode_line}"
grep -Fq 'id: require-lcov' "${workflow}"
grep -Fq 'run: test -s ci_infra_logs/${{ env.INFRA_ID }}/coverage-report/${{ env.INFRA_ID }}.info' "${workflow}"
grep -Fq "if: always() && steps.require-lcov.outcome == 'success'" "${workflow}"

echo "cluster simulator coverage contract passed"
