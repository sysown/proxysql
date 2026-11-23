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

# Regression: when pushing from a linked worktree git exports GIT_DIR (and
# can export GIT_WORK_TREE / GIT_INDEX_FILE) to the hook. The lint runner must
# not inherit them, or fixture `git init`/`commit` calls hit the real repo.
cat > "${fixture}/test/infra/control/run-ci-lint.bash" <<'RUNNER'
#!/usr/bin/env bash
env | grep -E '^GIT_(DIR|WORK_TREE|INDEX_FILE|OBJECT_DIRECTORY|COMMON_DIR)=' > "${LINT_HOOK_PROBE}" || true
exit 0
RUNNER
(
	clear_git_local_environment
	cd "${fixture}"
	GIT_DIR="${fixture}/.git" GIT_WORK_TREE="${fixture}" \
		GIT_INDEX_FILE="${fixture}/.git/index" LINT_HOOK_PROBE="${probe}" \
		"${fixture}/.githooks/pre-push" origin example.invalid
) || fail "hook must succeed when invoked with git-exported repository variables"
[[ ! -s "${probe}" ]] \
	|| fail "hook must clear repository-local GIT_* variables before running the lint runner (leaked: $(tr '\n' ' ' <"${probe}"))"

# The shared runner is also invoked outside the hook, so exercise the real
# runner directly with repository variables pointing at a sentinel repository.
# The runner calls resolve-ci-engine-ref.bash before its first check; a stub in
# its place records the environment the checks would inherit, builds a fixture
# repository the way the lint checks do, then stops the runner.
sentinel="${fixture}/sentinel"
(
	clear_git_local_environment
	git init -q "${sentinel}"
	git -C "${sentinel}" -c user.name=t -c user.email=t@example.invalid \
		commit -q --allow-empty -m sentinel
)
sentinel_head="$(clear_git_local_environment; git -C "${sentinel}" rev-parse HEAD)"
cp "${runner}" "${fixture}/test/infra/control/run-ci-lint.bash"
cat > "${fixture}/test/infra/control/resolve-ci-engine-ref.bash" <<'RESOLVER'
#!/usr/bin/env bash
env | grep -E '^GIT_(DIR|WORK_TREE|INDEX_FILE|OBJECT_DIRECTORY|COMMON_DIR)=' > "${LINT_RUNNER_PROBE}" || true
scratch="$(mktemp -d)"
git -C "${scratch}" init -q
git -C "${scratch}" -c user.name=t -c user.email=t@example.invalid \
	commit -q --allow-empty -m fixture
rm -rf "${scratch}"
exit 42
RESOLVER
chmod +x "${fixture}/test/infra/control/resolve-ci-engine-ref.bash"
runner_probe="${fixture}/runner-probe"
if (
	clear_git_local_environment
	cd "${fixture}"
	GIT_DIR="${sentinel}/.git" GIT_WORK_TREE="${sentinel}" \
		GIT_INDEX_FILE="${sentinel}/.git/index" LINT_RUNNER_PROBE="${runner_probe}" \
		"${fixture}/test/infra/control/run-ci-lint.bash" >/dev/null 2>&1
); then
	fail "shared runner must stop when resolve-ci-engine-ref.bash fails"
fi
[[ -e "${runner_probe}" ]] \
	|| fail "shared runner must call resolve-ci-engine-ref.bash before its first check"
[[ ! -s "${runner_probe}" ]] \
	|| fail "shared runner must clear repository-local GIT_* variables before running checks (leaked: $(tr '\n' ' ' <"${runner_probe}"))"
[[ "$(clear_git_local_environment; git -C "${sentinel}" rev-parse HEAD)" == "${sentinel_head}" ]] \
	|| fail "fixture git commands run by the shared runner must not modify the caller's repository"

echo "pre-push lint hook contract: OK"
