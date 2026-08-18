#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
subject="${script_dir}/dump-proxysql-gcov.bash"
fake_mysql="${script_dir}/fixtures/record-mysql-argv.bash"
runner="${script_dir}/run-tests-isolated.bash"
tester="${script_dir}/../../scripts/bin/proxysql-tester.py"
status_helper="${script_dir}/coverage-exit-status.bash"
record_file="$(mktemp)"
trap 'rm -f "${record_file}"' EXIT

MYSQL_CLIENT_BIN="${fake_mysql}" MYSQL_RECORD_FILE="${record_file}" "${subject}"

expected=(
    -uradmin
    -pradmin
    -hproxysql
    -P6032
    --batch
    --skip-column-names
    -e
    "PROXYSQL GCOV DUMP"
)
mapfile -t actual < "${record_file}"

if [ "${#actual[@]}" -ne "${#expected[@]}" ]; then
    echo "expected ${#expected[@]} mysql arguments, got ${#actual[@]}" >&2
    exit 1
fi
for i in "${!expected[@]}"; do
    if [ "${actual[$i]}" != "${expected[$i]}" ]; then
        echo "mysql argument ${i}: expected '${expected[$i]}', got '${actual[$i]}'" >&2
        exit 1
    fi
done

TAP_ADMINUSERNAME="ci-admin" TAP_ADMINPASSWORD="ci-secret" \
    TAP_ADMINHOST="proxy-under-test" TAP_ADMINPORT="16032" \
    MYSQL_CLIENT_BIN="${fake_mysql}" MYSQL_RECORD_FILE="${record_file}" "${subject}"
mapfile -t actual < "${record_file}"
expected=(
    -uci-admin
    -pci-secret
    -hproxy-under-test
    -P16032
    --batch
    --skip-column-names
    -e
    "PROXYSQL GCOV DUMP"
)
for i in "${!expected[@]}"; do
    if [ "${actual[$i]}" != "${expected[$i]}" ]; then
        echo "custom mysql argument ${i}: expected '${expected[$i]}', got '${actual[$i]}'" >&2
        exit 1
    fi
done

set +e
MYSQL_CLIENT_BIN="${fake_mysql}" MYSQL_RECORD_FILE="${record_file}" MYSQL_EXIT_CODE=23 "${subject}"
dump_exit=$?
set -e
if [ "${dump_exit}" -ne 23 ]; then
    echo "expected mysql failure 23 to propagate, got ${dump_exit}" >&2
    exit 1
fi

set +e
MYSQL_CLIENT_BIN="${fake_mysql}" MYSQL_RECORD_FILE="${record_file}" \
    MYSQL_DELAY_SECONDS=2 GCOV_DUMP_TIMEOUT_SECONDS=0.1 "${subject}"
timeout_exit=$?
set -e
if [ "${timeout_exit}" -ne 124 ]; then
    echo "expected bounded mysql call to exit 124, got ${timeout_exit}" >&2
    exit 1
fi

set +e
MYSQL_CLIENT_BIN="${fake_mysql}" MYSQL_RECORD_FILE="${record_file}" \
    GCOV_DUMP_TIMEOUT_SECONDS=0 "${subject}" 2>/dev/null
zero_timeout_exit=$?
set -e
if [ "${zero_timeout_exit}" -ne 64 ]; then
    echo "expected zero timeout to be rejected with exit 64, got ${zero_timeout_exit}" >&2
    exit 1
fi

helper_calls=$(grep -Fc 'dump-proxysql-gcov.bash' "${runner}")
if [ "${helper_calls}" -ne 1 ]; then
    echo "expected one final dump invocation in isolated runner, got ${helper_calls}" >&2
    exit 1
fi
dump_line=$(grep -nF 'dump-proxysql-gcov.bash' "${runner}" | cut -d: -f1)
decode_line=$(grep -nF 'fastcov -b' "${runner}" | head -n1 | cut -d: -f1)
if [ "${dump_line}" -ge "${decode_line}" ]; then
    echo "final daemon dump must run before GCDA decoding" >&2
    exit 1
fi
if grep -qF 'self.padmin_command("PROXYSQL GCOV DUMP")' "${tester}"; then
    echo "per-test GCOV dumps must remain disabled" >&2
    exit 1
fi
status_calls=$(grep -Fc 'coverage_exit_status' "${runner}")
if [ "${status_calls}" -ne 1 ]; then
    echo "coverage trap must resolve the final exit status exactly once" >&2
    exit 1
fi

assert_final_exit() {
    local test_exit="$1"
    local coverage_exit="$2"
    local expected_status="$3"
    local actual

    set +e
    bash -c 'source "$1"; coverage_exit_status "$2" "$3"' \
        bash "${status_helper}" "${test_exit}" "${coverage_exit}"
    actual=$?
    set -e
    if [ "${actual}" -ne "${expected_status}" ]; then
        echo "test exit ${test_exit}, coverage exit ${coverage_exit}: expected ${expected_status}, got ${actual}" >&2
        exit 1
    fi
}

assert_final_exit 0 0 0
assert_final_exit 0 1 1
assert_final_exit 7 0 7
assert_final_exit 7 1 7

echo "final GCOV dump helper tests passed"
