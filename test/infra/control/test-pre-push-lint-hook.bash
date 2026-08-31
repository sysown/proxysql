#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
hook="${repo_root}/.githooks/pre-push"
runner="${repo_root}/test/infra/control/run-ci-lint.bash"
workflow="${repo_root}/.github/workflows/CI-lint-groups-json.yml"

fail() {
	echo "pre-push lint hook contract: FAIL: $*" >&2
	exit 1
}

[[ -x "${hook}" ]] || fail "${hook} must exist and be executable"
[[ -x "${runner}" ]] || fail "${runner} must exist and be executable"
grep -Fq "test/infra/control/run-ci-lint.bash" "${workflow}" \
	|| fail "CI lint workflow must invoke the shared runner"

fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT
git -C "${fixture}" init -q
mkdir -p "${fixture}/.githooks" "${fixture}/test/infra/control" "${fixture}/nested"
cp "${hook}" "${fixture}/.githooks/pre-push"

cat > "${fixture}/test/infra/control/run-ci-lint.bash" <<'RUNNER'
#!/usr/bin/env bash
printf '%s\n' "${PWD}" > "${LINT_HOOK_PROBE}"
exit "${LINT_HOOK_STATUS}"
RUNNER
chmod +x "${fixture}/test/infra/control/run-ci-lint.bash"

probe="${fixture}/probe"
(
	cd "${fixture}/nested"
	LINT_HOOK_PROBE="${probe}" LINT_HOOK_STATUS=0 \
		"${fixture}/.githooks/pre-push" origin example.invalid
) || fail "hook must return success when the lint runner succeeds"
[[ "$(<"${probe}")" == "${fixture}" ]] \
	|| fail "hook must execute the lint runner from the worktree root"

if (
	cd "${fixture}/nested"
	LINT_HOOK_PROBE="${probe}" LINT_HOOK_STATUS=23 \
		"${fixture}/.githooks/pre-push" origin example.invalid
); then
	fail "hook must return non-zero when the lint runner fails"
fi

echo "pre-push lint hook contract: OK"
