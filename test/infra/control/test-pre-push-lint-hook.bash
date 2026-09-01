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

clear_git_local_environment() {
	while IFS= read -r variable_name; do
		unset "${variable_name}"
	done < <(git rev-parse --local-env-vars)
}

[[ -x "${hook}" ]] || fail "${hook} must exist and be executable"
[[ -x "${runner}" ]] || fail "${runner} must exist and be executable"
grep -Fq "test/infra/control/run-ci-lint.bash" "${workflow}" \
	|| fail "CI lint workflow must invoke the shared runner"
grep -Eq '^[[:space:]]*test/infra/control/test-pre-push-lint-hook\.bash([[:space:]]|$)' "${runner}" \
	|| fail "shared runner must execute the pre-push lint hook contract"

fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT

mkdir -p "${fixture}/missing-envsubst-bin"
ln -s "$(command -v dirname)" "${fixture}/missing-envsubst-bin/dirname"
if missing_envsubst_output="$(
	PATH="${fixture}/missing-envsubst-bin" /bin/bash "${runner}" 2>&1
)"; then
	fail "shared runner must fail when envsubst is unavailable"
fi
grep -Fq "envsubst" <<<"${missing_envsubst_output}" \
	|| fail "missing envsubst error must name the unavailable command"
grep -Eq 'gettext(-base)?' <<<"${missing_envsubst_output}" \
	|| fail "missing envsubst error must name the package to install"

clear_git_local_environment
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
	clear_git_local_environment
	cd "${fixture}/nested"
	LINT_HOOK_PROBE="${probe}" LINT_HOOK_STATUS=0 \
		"${fixture}/.githooks/pre-push" origin example.invalid
) || fail "hook must return success when the lint runner succeeds"
fixture_root="$(cd "${fixture}" && pwd -P)"
[[ "$(<"${probe}")" == "${fixture_root}" ]] \
	|| fail "hook must execute the lint runner from the worktree root"

if (
	clear_git_local_environment
	cd "${fixture}/nested"
	LINT_HOOK_PROBE="${probe}" LINT_HOOK_STATUS=23 \
		"${fixture}/.githooks/pre-push" origin example.invalid
); then
	fail "hook must return non-zero when the lint runner fails"
fi

echo "pre-push lint hook contract: OK"
