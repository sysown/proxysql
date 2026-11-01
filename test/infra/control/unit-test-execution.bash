#!/usr/bin/env bash
# Shared execution boundary for the directory and group-based unit runners.
UNIT_TEST_TIMEOUT_SECONDS="${UNIT_TEST_TIMEOUT_SECONDS:-300}"
if ! [[ "${UNIT_TEST_TIMEOUT_SECONDS}" =~ ^[1-9][0-9]*$ ]]; then
    echo "UNIT_TEST_TIMEOUT_SECONDS must be a positive integer" >&2
    return 1
fi
if command -v timeout >/dev/null 2>&1; then
    UNIT_TEST_TIMEOUT_COMMAND=timeout
elif command -v gtimeout >/dev/null 2>&1; then
    UNIT_TEST_TIMEOUT_COMMAND=gtimeout # Homebrew coreutils on macOS.
else
    echo "The unit runner requires GNU timeout (gtimeout on macOS)" >&2
    return 1
fi
export TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=1:exitcode=66}"

proxysql_run_unit_test() {
    local log="$1"
    local binary="$2"
    local rc=0
    # Supervise the logger as well as the test: a descendant can keep its
    # inherited output pipe open after the test parent accepts TERM. Catch
    # TERM in the supervisor (so tests retain their normal signal disposition)
    # and ignore it only in tee, keeping the KILL deadline active until EOF.
    "${UNIT_TEST_TIMEOUT_COMMAND}" --signal=TERM --kill-after=10s "${UNIT_TEST_TIMEOUT_SECONDS}s" \
        bash -c '
            trap : TERM
            "$1" 2>&1 | (trap "" TERM; exec tee "$2")
            execution_status=("${PIPESTATUS[@]}")
            rc=${execution_status[0]}
            if [ "$rc" -eq 0 ] && [ "${execution_status[1]}" -ne 0 ]; then
                rc=${execution_status[1]}
            fi
            exit "$rc"
        ' unit-test "${binary}" "${log}"
    rc=$?
    # TAP can return success despite diagnostics, and callers can configure a
    # sanitizer's exit code as zero. Such reports must still fail the suite.
    if [ "${rc}" -eq 0 ] && grep -Eq \
        '(WARNING|FATAL|SUMMARY): ThreadSanitizer:|ERROR: (AddressSanitizer|LeakSanitizer):|runtime error:' "${log}"; then
        rc=1
    fi
    if [ "${rc}" -eq 124 ] || [ "${rc}" -eq 137 ]; then
        echo "TIMEOUT: $(basename "${binary}") after ${UNIT_TEST_TIMEOUT_SECONDS}s (rc=${rc})"
    fi
    return "${rc}"
}
