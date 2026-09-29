#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"

if ! command -v envsubst >/dev/null 2>&1; then
	echo "CI lint prerequisite missing: envsubst (install gettext-base on Debian/Ubuntu or gettext on macOS)." >&2
	exit 1
fi

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
run_check "Check MySQLX unit group registration" \
	python3 test/tap/groups/test_mysqlx_group_registration.py
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
run_check "Check interface TAP disk-safety contract" \
	test/infra/control/validate-interface-tap-disk-safety.bash
run_check "Test interface TAP disk-safety validator" \
	test/infra/control/test-interface-tap-disk-safety.bash
run_check "Check pre-push lint hook contract" \
	test/infra/control/test-pre-push-lint-hook.bash
run_check "Check package CI verification hook" \
	test/infra/control/test-package-ci-verification.bash
run_check "Check package install verifier" \
	test/infra/control/test-verify-package-install.bash
run_check "Check system OpenSSL audit regressions" \
	test/infra/control/test-no-system-openssl-links-regressions.bash
run_check "Check RE2 platform and unit linker flags" \
	test/infra/control/test-re2-platform-link.bash
run_check "Check libusual incremental patch dependency" \
	test/infra/control/test-libusual-incremental.bash
run_check "Check vendored OpenSSL consumer flags" \
	test/infra/control/test-vendored-openssl-consumers.bash
# The fork isolation contract spans CI-builds.yml and CI-builds-fork.yml on this
# ref plus ci-builds.yml on GH-Actions, so it needs both refs fetched. The
# workflow fetches GH-Actions with a tolerated failure, so skip rather than fail
# the whole lint suite when it is momentarily unavailable.
if git rev-parse --verify --quiet origin/GH-Actions >/dev/null; then
	run_check "Check fork PR build isolation contract" \
		python3 test/infra/control/validate_fork_pr_builds.py HEAD origin/GH-Actions
	run_check "Test fork PR build isolation validator" \
		python3 -m unittest discover -s test/infra/control -p test_validate_fork_pr_builds.py
else
	echo ">>> Check fork PR build isolation contract: SKIPPED (origin/GH-Actions not fetched)"
fi
run_check "Check group infra/workflow coverage (warn-only)" \
	python3 test/tap/groups/lint_group_coverage.py
# tier-sweep.lst is the work list CI-tier-sweep reads at run time. Unlike
# lint_group_coverage.py (warn-only, advisory) this one FAILS: if a group is
# wired into regular CI and runnable on a downgrade tier but missing from the
# list, the merge-only sweep has silently stopped covering it. See
# test/infra/control/check_tier_sweep_groups.py for why that direction matters.
run_check "Check tier-sweep group list is in sync" \
	python3 test/infra/control/check_tier_sweep_groups.py

echo ">>> CI lint suite: OK"
