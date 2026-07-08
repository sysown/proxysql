#!/usr/bin/env bash
#
# run-unit-tests-asan-coverage.bash — runs every executable under
# test/tap/tests/unit/ and captures an LCOV+HTML coverage report.
#
# Designed to be invoked INSIDE the ubuntu24_dbg_build container that
# `make ubuntu24-tap` produces (or any container with the ProxySQL
# build toolchain + the source bind-mounted at /opt/proxysql). The
# CI workflow `.github/workflows/CI-unit-tests-asan-coverage.yml` is
# a thin wrapper that does:
#
#   docker compose run --rm --entrypoint bash ubuntu24_dbg_build \
#     -lc 'cd /opt/proxysql && \
#          test/infra/control/run-unit-tests-asan-coverage.bash'
#
# Local repro is the same command — both paths share this script as
# the single source of truth.
#
# Preconditions:
#   * cwd is the repository root (the script cd's there from $0 if not).
#   * lib/, src/, and test/tap/tests/unit/ have been built with
#     WITHASAN=1 WITHGCOV=1 NOJEMALLOC=1 PROXYSQL40=1 (the make
#     target `ubuntu24-tap` does this when invoked with those flags).
#   * The container has apt — we install lcov + libprotobuf-dev on
#     demand if missing (the build image is package-build-focused
#     and ships neither). libprotobuf provides the runtime
#     libprotobuf.so.32 the chassis-tier *-t binaries dlopen.
#
# Outputs (under cwd, visible on the host via the bind mount):
#   * coverage/lcov.info       — merged + filtered LCOV report
#   * coverage/html/           — genhtml-rendered HTML report
#   * unit-test-logs/<name>.log — stdout+stderr per failed test
#
# Exit status: 0 if all unit tests passed, 1 otherwise. Coverage
# capture runs regardless.

set -eu

# Ensure cwd is repo root no matter where we were invoked from.
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/../../.." && pwd )"
cd "${REPO_ROOT}"

# ASAN_OPTIONS: caller can override (e.g. tighter halt_on_error). The
# default mirrors the values the CI workflow passes through and the
# values include/makefiles_vars.mk's WASAN block was tuned against.
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1:symbolize=1:print_stacktrace=1:halt_on_error=1}"

# Install runtime deps only if missing — keeps the script idempotent
# for repeated local runs and skips the apt round-trip when re-running
# inside an already-prepared container.
if ! command -v lcov >/dev/null 2>&1 || ! command -v genhtml >/dev/null 2>&1 \
   || ! ldconfig -p | grep -q libprotobuf\\.so; then
    echo "==> Installing missing runtime deps (lcov, libprotobuf-dev)"
    apt-get update -qq
    apt-get install -y --no-install-recommends lcov libprotobuf-dev
fi

mkdir -p coverage unit-test-logs

echo "==> Capturing baseline coverage snapshot (--initial)"
# A baseline pass over all .gcno files seeds the report with zero
# coverage for every instrumented source line, so unrun code paths
# show as 0% in the merged report (rather than being absent
# entirely).
#
# Capture from lib/ only. src/ contains the proxysql binary's
# main.cpp and a small number of helpers; unit tests link only
# against libproxysql.a (from lib/) so there is never a .gcda in
# src/ from this workflow. Keeping `--directory src` here makes
# lcov 2.x abort with "no .gcda files found in src" (an `empty`-
# class error, not covered by --ignore-errors gcov,source), which
# wipes the output file and breaks the whole capture chain.
#
# `empty` is added to --ignore-errors as belt-and-suspenders so a
# future test reorganisation that produces a partially-empty
# directory tree doesn't recur the same silent failure.
lcov --quiet --capture --initial \
     --directory lib \
     --output-file coverage/lcov-base.info \
     --ignore-errors gcov,source,empty || true

echo "==> Running unit tests under ASAN"
# Iterate every executable under test/tap/tests/unit/. We
# deliberately do NOT use run-tests-isolated.bash here: its
# dual-directory test discovery (test/tap/tests/ in addition to
# .../unit/) picks up integration tests misclassified as unit tests
# in groups.json (e.g. unit-strip_schema_from_query-t). Using the
# directory listing keeps the test set scoped to actual unit tests.
FAILED=()
PASSED=0
shopt -s nullglob
pushd test/tap/tests/unit >/dev/null
for t in *-t; do
    [ -x "./${t}" ] || continue
    log="${REPO_ROOT}/unit-test-logs/${t}.log"
    echo "::group::${t}"
    if ./"${t}" > "${log}" 2>&1; then
        PASSED=$((PASSED + 1))
        echo "PASS: ${t}"
    else
        rc=$?
        FAILED+=("${t} (rc=${rc})")
        echo "FAIL: ${t} (rc=${rc})"
        tail -n 80 "${log}"
    fi
    echo "::endgroup::"
done
popd >/dev/null

echo
echo "===================================================================="
echo "Unit test summary: ${PASSED} passed, ${#FAILED[@]} failed"
echo "===================================================================="
test_rc=0
if [ ${#FAILED[@]} -gt 0 ]; then
    printf "  %s\n" "${FAILED[@]}"
    test_rc=1
fi

echo "==> Capturing post-test coverage"
# Mirror the baseline-capture scope above: lib/ only, empty added to
# --ignore-errors. See the baseline-capture comment for the full
# rationale.
lcov --quiet --capture \
     --directory lib \
     --output-file coverage/lcov-tests.info \
     --ignore-errors gcov,source,mismatch,empty || true

if [ -s coverage/lcov-base.info ] && [ -s coverage/lcov-tests.info ]; then
    lcov --quiet \
         --add-tracefile coverage/lcov-base.info \
         --add-tracefile coverage/lcov-tests.info \
         --output-file coverage/lcov.info \
         --ignore-errors mismatch || true
elif [ -s coverage/lcov-tests.info ]; then
    cp coverage/lcov-tests.info coverage/lcov.info
fi

if [ -s coverage/lcov.info ]; then
    # Filter out third-party / generated paths so the report stays
    # focused on ProxySQL's own lib/ and src/.
    lcov --quiet --remove coverage/lcov.info \
         "/usr/*" "*/deps/*" "*/test/*" \
         --output-file coverage/lcov.info \
         --ignore-errors unused || true

    genhtml --quiet \
            --output-directory coverage/html \
            --title "ProxySQL unit tests coverage" \
            --demangle-cpp \
            --legend \
            coverage/lcov.info \
            --ignore-errors source,category || true

    echo "==> Coverage summary"
    lcov --summary coverage/lcov.info || true
fi

exit "${test_rc}"
