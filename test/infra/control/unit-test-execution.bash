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
    local -a execution_status
    # Retain live CI output and a complete per-binary diagnostic log. A second
    # deadline kills the process group if a test or its children ignore TERM.
    "${UNIT_TEST_TIMEOUT_COMMAND}" --signal=TERM --kill-after=10s "${UNIT_TEST_TIMEOUT_SECONDS}s" \
        "${binary}" 2>&1 | tee "${log}"
    execution_status=("${PIPESTATUS[@]}")
    rc=${execution_status[0]}
    if [ "${rc}" -eq 0 ] && [ "${execution_status[1]}" -ne 0 ]; then
        rc=${execution_status[1]}
    fi
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
