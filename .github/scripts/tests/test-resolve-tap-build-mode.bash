#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
resolver="$root_dir/resolve-tap-build-mode.bash"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

stub="$tmp_dir/gh"
cat >"$stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${GH_STUB_FAIL:-0}" == 1 ]]; then
    exit 1
fi
tr ' ' '\n' <<<"${GH_LABELS:-}"
EOF
chmod +x "$stub"

assert_mode() {
    local expected="$1"; shift
    local actual
    actual=$("$@")
    test "$actual" = "$expected" || {
        echo "expected $expected, got $actual" >&2
        exit 1
    }
}

pr_trigger='{"event":{"workflow_run":{"pull_requests":[{"number":42}]}}}'
non_pr_trigger='{"event":{"workflow_run":{"pull_requests":[]}}}'

assert_mode normal env TRUSTED=false TRIGGER_JSON="$pr_trigger" \
    GITHUB_REPOSITORY=sysown/proxysql GH_BIN="$stub" "$resolver"
assert_mode normal env TRUSTED=true GITHUB_REPOSITORY=sysown/proxysql \
    GH_BIN="$stub" "$resolver"
assert_mode normal env TRUSTED=true TRIGGER_JSON="$non_pr_trigger" \
    GITHUB_REPOSITORY=sysown/proxysql GH_BIN="$stub" "$resolver"
assert_mode normal env TRUSTED=true TRIGGER_JSON="$pr_trigger" GH_LABELS='bug' \
    GITHUB_REPOSITORY=sysown/proxysql GH_BIN="$stub" "$resolver"
assert_mode normal env TRUSTED=true TRIGGER_JSON="$pr_trigger" GH_LABELS='ci:asan-extra' \
    GITHUB_REPOSITORY=sysown/proxysql GH_BIN="$stub" "$resolver"
assert_mode asan env TRUSTED=true TRIGGER_JSON="$pr_trigger" GH_LABELS='bug ci:asan' \
    GITHUB_REPOSITORY=sysown/proxysql GH_BIN="$stub" "$resolver"

if env TRUSTED=true TRIGGER_JSON="$pr_trigger" GH_STUB_FAIL=1 \
    GITHUB_REPOSITORY=sysown/proxysql GH_BIN="$stub" "$resolver" >/dev/null; then
    echo 'expected trusted PR label lookup failure to be nonzero' >&2
    exit 1
fi

echo 'all resolver cases passed'
