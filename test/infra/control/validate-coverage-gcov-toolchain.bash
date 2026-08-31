#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
dockerfile="${root}/test/infra/docker-base/Dockerfile"
runner="${root}/test/infra/control/run-tests-isolated.bash"
multi="${root}/test/infra/control/run-multi-group.bash"
lint_workflow="${root}/.github/workflows/CI-lint-groups-json.yml"
lint_runner="${root}/test/infra/control/run-ci-lint.bash"

if grep -Eq '^[[:space:]]*gcc-11[[:space:]\\]*$' "${dockerfile}"; then
    echo "coverage image must use the compiler's default GCOV reader" >&2
    exit 1
fi
for file in "${runner}" "${multi}"; do
    # `-C` combines existing LCOV files and does not decode raw GCOV data.
    # Every other fastcov branch-coverage invocation must use the image's
    # default gcov, which matches the compiler used by the build handoff.
    raw_fastcov_calls="$(awk '/fastcov -b/ && !/ -C / {count++} END {print count + 0}' "${file}")"
    test "${raw_fastcov_calls}" -gt 0
    if grep -Eq 'fastcov -b -g gcov-[0-9]+' "${file}"; then
        echo "raw GCOV decoding must not force a versioned reader: ${file}" >&2
        exit 1
    fi
done
grep -Eq -- '-s .*coverage_file' "${runner}"
grep -Eq -- '-s .*GROUP_INFO' "${multi}"
grep -Eq '^[[:space:]]*run:[[:space:]]+test/infra/control/run-ci-lint\.bash[[:space:]]*$' "${lint_workflow}"
awk '
	/^[[:space:]]*run_check[[:space:]]+"Check coverage collector invariants"[[:space:]]*\\[[:space:]]*$/ {
		getline
		if ($0 ~ /^[[:space:]]*test\/infra\/control\/validate-coverage-gcov-toolchain\.bash[[:space:]]*$/) {
			found = 1
		}
	}
	END { exit(found ? 0 : 1) }
' "${lint_runner}"

"${root}/test/infra/control/test-final-gcov-dump.bash"
