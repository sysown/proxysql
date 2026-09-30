#!/usr/bin/env bash
# Tests for prune-tier-handoff.bash.
#
# Uses a synthetic groups.json rather than the repo's real one: this branch
# (GH-Actions) does not carry test/tap/groups/, and a synthetic fixture makes
# the expected survivor counts exactly derivable by hand.
#
# Not currently wired into any workflow -- same as the other tests in this
# directory. Run it by hand:  .github/scripts/tests/test-prune-tier-handoff.bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
pruner="$root_dir/prune-tier-handoff.bash"

test -x "$pruner" || { echo "not executable: $pruner" >&2; exit 1; }

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

# --- fixture ---------------------------------------------------------------
# 4 tests in tests/, 2 in tests/unit/, 1 in tests_with_deps/.
mkdir -p "$tmp_dir"/test/tap/groups "$tmp_dir"/test/tap/tests/unit \
         "$tmp_dir"/test/tap/tests_with_deps "$tmp_dir"/src
cat >"$tmp_dir/test/tap/groups/groups.json" <<'EOF'
{
  "always-t"          : [ "legacy-g1" ],
  "needs_31-t"        : [ "unit-tests-g1", "@proxysql_min_version:3.1" ],
  "needs_40-t"        : [ "ai-g1", "@proxysql_min_version:4.0" ],
  "needs_40_unit-t"   : [ "unit-tests-g1", "@proxysql_min_version:4.0" ],
  "with_deps-t"       : [ "legacy-g1" ]
}
EOF

make_tree() {
  rm -f "$tmp_dir"/test/tap/tests/*-t \
        "$tmp_dir"/test/tap/tests/unit/*-t \
        "$tmp_dir"/test/tap/tests_with_deps/*-t
  for f in "$tmp_dir/test/tap/tests/always-t" \
           "$tmp_dir/test/tap/tests/needs_31-t" \
           "$tmp_dir/test/tap/tests/needs_40-t" \
           "$tmp_dir/test/tap/tests/unit/needs_40_unit-t" \
           "$tmp_dir/test/tap/tests_with_deps/with_deps-t"; do
    printf '#!/bin/sh\nexit 0\n' >"$f"
    chmod +x "$f"
  done
}

# A stub "proxysql" that reports a fixed version.
stub_binary() {
  printf '#!/bin/sh\necho "ProxySQL version %s, codename TEST"\n' "$1" \
    >"$tmp_dir/src/proxysql"
  chmod +x "$tmp_dir/src/proxysql"
}

remaining() {
  find "$tmp_dir/test/tap/tests" "$tmp_dir/test/tap/tests_with_deps" \
       -type f -name '*-t' | wc -l | tr -d ' '
}

assert_remaining() {
  local expected="$1" what="$2" got
  got="$(remaining)"
  if [ "$got" != "$expected" ]; then
    echo "FAIL [$what]: expected $expected binaries left, got $got" >&2
    find "$tmp_dir" -name '*-t' >&2
    exit 1
  fi
  echo "ok   [$what] $expected binaries remain"
}

assert_contains() {
  local f="$1" what="$2"
  [ -e "$tmp_dir/test/tap/tests/$f" ] || [ -e "$tmp_dir/test/tap/tests/unit/$f" ] || {
    echo "FAIL [$what]: expected $f to be kept" >&2; exit 1; }
  echo "ok   [$what] $f kept"
}

assert_absent() {
  local f="$1" what="$2"
  if [ -e "$tmp_dir/test/tap/tests/$f" ] || [ -e "$tmp_dir/test/tap/tests/unit/$f" ]; then
    echo "FAIL [$what]: expected $f to be dropped" >&2
    exit 1
  fi
  echo "ok   [$what] $f dropped"
}

run_pruner() {
  ( cd "$tmp_dir" && "$pruner" --binary src/proxysql \
      --groups test/tap/groups/groups.json ) 2>&1
}

# --- v4.0: nothing is gated out, so nothing is dropped ----------------------
make_tree; stub_binary 4.0.11
out="$(run_pruner)"
echo "$out" | grep -q 'dropped 0' || {
  echo "FAIL [v40 drops nothing]: $out" >&2; exit 1; }
assert_remaining 5 "v40 drops nothing"
assert_contains needs_40-t "v40"
assert_contains needs_31-t "v40"

# --- v3.1: only the 4.0-gated tests go --------------------------------------
make_tree; stub_binary 3.1.11
out="$(run_pruner)"
echo "$out" | grep -q 'dropped 2' || {
  echo "FAIL [v31 drops the two 4.0-gated tests]: $out" >&2; exit 1; }
assert_remaining 3 "v31"
assert_contains needs_31-t "v31"
assert_absent needs_40-t "v31"
assert_absent needs_40_unit-t "v31"

# --- v3.0: the 3.1-gated test goes too --------------------------------------
make_tree; stub_binary 3.0.11
out="$(run_pruner)"
echo "$out" | grep -q 'dropped 3' || {
  echo "FAIL [v30 drops the 3.1- and 4.0-gated tests]: $out" >&2; exit 1; }
assert_remaining 2 "v30"
assert_absent needs_31-t "v30"
assert_contains always-t "v30"

# --- numeric version compare, not lexicographic: 3.10 > 3.9 ----------------
# 3.10.0 must NOT be treated as older than a 3.9 requirement. The fixture has
# no 3.9 tag, so assert via a separate groups file.
cat >"$tmp_dir/test/tap/groups/nine.json" <<'EOF'
{ "needs_31-t": [ "unit-tests-g1", "@proxysql_min_version:3.9" ] }
EOF
make_tree; stub_binary 3.10.0
( cd "$tmp_dir" && "$pruner" --binary src/proxysql --groups test/tap/groups/nine.json ) >/dev/null 2>&1
assert_contains needs_31-t "3.10 >= 3.9 (numeric compare)"
assert_remaining 5 "3.10 keeps a 3.9-gated test"

# --- an unregistered binary is preserved and warned about -------------------
make_tree; stub_binary 3.0.11
printf '#!/bin/sh\nexit 0\n' >"$tmp_dir/test/tap/tests/stray-t"; chmod +x "$tmp_dir/test/tap/tests/stray-t"
out="$(run_pruner)"
echo "$out" | grep -q 'stray-t is not registered' || {
  echo "FAIL [unregistered binary warned about]: $out" >&2; exit 1; }
assert_contains stray-t "unregistered binary is not deleted"

# --- determinism: two runs agree (guards the grep-q/pipefail SIGPIPE bug) ---
for i in 1 2 3; do
  make_tree; stub_binary 3.1.11
  a="$(run_pruner | grep 'kept ')"
  make_tree; stub_binary 3.1.11
  b="$(run_pruner | grep 'kept ')"
  [ "$a" = "$b" ] || { echo "FAIL [determinism]: '$a' != '$b'" >&2; exit 1; }
done
echo "ok   [determinism] repeated runs agree"

# --- negative: undetectable version must abort without deleting -------------
# NOTE: the pruner is EXPECTED to exit non-zero here, so capture its output
# with `|| true` rather than piping it. Under `set -o pipefail` a genuinely
# failing command in a pipeline makes the whole `if` condition false, which
# would invert the assertion.
make_tree; stub_binary 4.0.11
printf '#!/bin/sh\necho "no version here"\n' >"$tmp_dir/src/proxysql"
chmod +x "$tmp_dir/src/proxysql"
out="$(run_pruner || true)"
if grep -q 'could not determine the ProxySQL version' <<<"$out"; then
  echo "ok   [bad version] aborts"
else
  echo "FAIL [bad version]: expected a version-detection error, got: $out" >&2
  exit 1
fi
assert_remaining 5 "bad version deletes nothing"

# --- host loader failure: probe in the build ABI before pruning -------------
mkdir -p "$tmp_dir/bin"
cat >"$tmp_dir/bin/docker" <<'EOF'
#!/bin/bash
printf '%s\n' "$@" > "$DOCKER_ARGS"
if [ "${DOCKER_FAIL:-0}" = 1 ]; then
  echo 'container loader failed' >&2
  exit 1
fi
printf 'ProxySQL version %s, codename TEST\n' "$DOCKER_VERSION"
EOF
chmod +x "$tmp_dir/bin/docker"
export PATH="$tmp_dir/bin:$PATH" DOCKER_ARGS="$tmp_dir/docker.args"
for tier in 3.0.12 3.1.12; do
  make_tree
  printf '#!/bin/sh\necho "host GLIBC_2.38 not found" >&2\nexit 1\n' >"$tmp_dir/src/proxysql"
  export DOCKER_VERSION="$tier"
  out="$(run_pruner)" || { echo "FAIL [host ABI fallback]: $out" >&2; exit 1; }
  grep -Fxq 'proxysql/packaging:build-ubuntu24-v4.0.0' "$DOCKER_ARGS" || {
    echo "FAIL [fallback image]: unexpected Docker arguments" >&2; cat "$DOCKER_ARGS" >&2; exit 1; }
  grep -Fxq '/opt/proxysql/src/proxysql' "$DOCKER_ARGS" || {
    echo "FAIL [fallback binary]: unexpected Docker arguments" >&2; cat "$DOCKER_ARGS" >&2; exit 1; }
  grep -Fxq "$tmp_dir:/opt/proxysql:ro" "$DOCKER_ARGS" || {
    echo "FAIL [read-only mount]: unexpected Docker arguments" >&2; cat "$DOCKER_ARGS" >&2; exit 1; }
  if [ "$tier" = 3.0.12 ]; then
    assert_remaining 2 "v30 container probe"
  else
    assert_remaining 3 "v31 container probe"
  fi
done
make_tree
export DOCKER_FAIL=1
if out="$(run_pruner)"; then
  echo 'FAIL [both probes fail]: unexpectedly succeeded' >&2; exit 1
fi
grep -q 'host GLIBC_2.38 not found' <<<"$out" || {
  echo "FAIL [host error preserved]: $out" >&2; exit 1; }
grep -q 'container loader failed' <<<"$out" || {
  echo "FAIL [container error preserved]: $out" >&2; exit 1; }
assert_remaining 5 "failed probes delete nothing"
unset DOCKER_FAIL

# --- negative: missing groups.json must abort -------------------------------
out="$( cd "$tmp_dir" && "$pruner" --binary src/proxysql \
        --groups test/tap/groups/nope.json 2>&1 || true )"
if grep -q 'ERROR' <<<"$out"; then
  echo "ok   [missing groups.json] aborts"
else
  echo "FAIL [missing groups.json]: should have errored, got: $out" >&2
  exit 1
fi

# --- negative: missing --binary arg must abort ------------------------------
out="$( cd "$tmp_dir" && "$pruner" --groups test/tap/groups/groups.json 2>&1 || true )"
if grep -q 'ERROR' <<<"$out"; then
  echo "ok   [missing --binary] aborts"
else
  echo "FAIL [missing --binary]: should have errored, got: $out" >&2
  exit 1
fi

echo ""
echo "ALL TESTS PASSED"
