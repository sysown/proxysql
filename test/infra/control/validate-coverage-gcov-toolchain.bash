#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
dockerfile="${root}/test/infra/docker-base/Dockerfile"
runner="${root}/test/infra/control/run-tests-isolated.bash"
multi="${root}/test/infra/control/run-multi-group.bash"
lint_workflow="${root}/.github/workflows/CI-lint-groups-json.yml"

if rg -q '^[[:space:]]*gcc-11[[:space:]\\]*$' "${dockerfile}"; then
    echo "coverage image must use the compiler's default GCOV reader" >&2
    exit 1
fi
for file in "${runner}" "${multi}"; do
    # `-C` combines existing LCOV files and does not decode raw GCOV data.
    # Every other fastcov branch-coverage invocation must use the image's
    # default gcov, which matches the compiler used by the build handoff.
    raw_fastcov_calls="$(rg -P -c 'fastcov -b(?!.* -C )' "${file}")"
    test "${raw_fastcov_calls}" -gt 0
    if rg -q 'fastcov -b -g gcov-[0-9]+' "${file}"; then
        echo "raw GCOV decoding must not force a versioned reader: ${file}" >&2
        exit 1
    fi
done
rg -q -- '-s .*coverage_file' "${runner}"
rg -q -- '-s .*GROUP_INFO' "${multi}"
rg -q 'validate-coverage-gcov-toolchain\.bash' "${lint_workflow}"

"${root}/test/infra/control/test-final-gcov-dump.bash"
