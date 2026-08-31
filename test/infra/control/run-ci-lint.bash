#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
cd "${repo_root}"

run_check() {
	local label="$1"
	shift
	echo ">>> ${label}"
	"$@"
}

run_check "Lint groups.json format" \
	python3 test/tap/groups/lint_groups_json.py
run_check "Check AI TAP shard split" \
	python3 test/tap/groups/test_ai_group_shards.py
run_check "Check TAP Makefile dependency graph" \
	python3 test/tap/groups/test_makefile_dependencies.py
run_check "Check binlog reader infrastructure contract" \
	python3 test/tap/groups/test_binlog_reader_infra.py
run_check "Check every TAP source is registered in groups.json" \
	python3 test/tap/groups/check_groups.py --source
run_check "Check cluster simulator coverage contract" \
	test/infra/control/test-cluster-simulator-coverage.bash
run_check "Check coverage collector invariants" \
	test/infra/control/validate-coverage-gcov-toolchain.bash
run_check "Check package CI verification hook" \
	test/infra/control/test-package-ci-verification.bash
run_check "Check package install verifier" \
	test/infra/control/test-verify-package-install.bash
run_check "Check group infra/workflow coverage (warn-only)" \
	python3 test/tap/groups/lint_group_coverage.py

echo ">>> CI lint suite: OK"
