#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT

fail() {
    echo "no-infra source assets: FAIL: $*" >&2
    exit 1
}

mkdir -p "${fixture}/test/infra/control" "${fixture}/test/tap"
cp "${script_dir}/asan-detection.bash" "${fixture}/test/infra/control/"
cp "${repo_root}/test/tap/Makefile" "${fixture}/test/tap/"
cp "${repo_root}/.gitignore" "${fixture}/.gitignore"
# Exercise the runner's actual preparation code, stopping before any service,
# container, or database operation.
sed '/^# 1\. Determine Required Infras/,$d' \
    "${script_dir}/run-tests-isolated.bash" \
    > "${fixture}/test/infra/control/preflight.bash"
git -C "${fixture}" init -q
git -C "${fixture}" add .gitignore test/tap/Makefile
git -C "${fixture}" -c core.hooksPath=/dev/null \
    -c user.name=fixture -c user.email=fixture@example.invalid \
    commit -qm 'source assets'

asset_assertion() {
    WORKSPACE="${fixture}" python3 \
        "${repo_root}/tools/pgsql_user_sync/tests/test_pgsql_user_sync.py" \
        AssetTests.test_tap_assets_have_a_build_dependency_and_clean_output
}

preflight() {
    TAP_GROUP="${1:-no-infra-g1}" COVERAGE=0 \
        bash "${fixture}/test/infra/control/preflight.bash"
}

rm "${fixture}/.gitignore"
if asset_assertion > "${fixture}/before.log" 2>&1; then
    fail 'missing source asset must reproduce the original test error'
fi
grep -q 'FileNotFoundError' "${fixture}/before.log" \
    || fail 'fixture must fail because .gitignore is missing'
preflight
asset_assertion || fail 'runner must restore the missing tracked source asset'

printf '\n# local fixture edit\n' >> "${fixture}/.gitignore"
cp "${fixture}/.gitignore" "${fixture}/expected"
preflight
cmp "${fixture}/expected" "${fixture}/.gitignore" \
    || fail 'runner must preserve an existing .gitignore'

git -C "${fixture}" rm -qf .gitignore
git -C "${fixture}" -c core.hooksPath=/dev/null \
    -c user.name=fixture -c user.email=fixture@example.invalid \
    commit -qm 'missing tracked asset'
if preflight > "${fixture}/missing.log" 2>&1; then
    fail 'no-infra preparation must reject an asset missing from HEAD'
fi
grep -q 'no-infra-g1 requires .gitignore tracked at HEAD' "${fixture}/missing.log" \
    || fail 'missing tracked asset must have a clear preparation error'
[[ ! -e "${fixture}/.gitignore" ]] \
    || fail 'failed restoration must not create an empty asset'
preflight cluster_sim_aurora-g1
[[ ! -e "${fixture}/.gitignore" ]] \
    || fail 'other groups must not require the no-infra source asset'

echo 'no-infra source assets: OK'
