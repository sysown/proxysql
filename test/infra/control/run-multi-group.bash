#!/bin/bash
set -euo pipefail
#
# Run Multiple TAP Groups in Parallel
# Usage:
#   RUN_ID="abc123" \
#   TAP_GROUPS="legacy-g1 legacy-g2 ai-g1 mysql84-g1" \
#   ./run-multi-group.bash
#
# Optional environment variables:
#   PARALLEL_JOBS=4        # Max parallel groups (default: unlimited)
#   TIMEOUT_MINUTES=60     # Hard timeout per group (default: 60)
#   EXIT_ON_FIRST_FAIL=0   # Stop on first failure (default: 0)
#   AUTO_CLEANUP=0         # Auto cleanup successful groups (default: 0)
#   SKIP_CLUSTER_START=1   # Skip ProxySQL cluster initialization (default: 0)
#   COVERAGE=1             # Enable code coverage collection (default: 0)
#
# Coverage notes:
#   - Requires ProxySQL to be compiled with COVERAGE=1 (adds --coverage flags)
#   - Requires fastcov and genhtml to be available in containers
#   - Coverage is collected regardless of test success/failure/timeout
#   - Individual reports: ci_infra_logs/{INFRA_ID}/coverage-report/
#   - Combined report: ci_infra_logs/multi-group-{RUN_ID}/coverage-report/
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Configuration
export WORKSPACE="${WORKSPACE:-${REPO_ROOT}}"
RUN_ID="${RUN_ID:-$(date +%s)}"
TAP_GROUPS="${TAP_GROUPS:-}"
PARALLEL_JOBS="${PARALLEL_JOBS:-2}"  # Default: 2 parallel groups
TIMEOUT_MINUTES="${TIMEOUT_MINUTES:-60}"
EXIT_ON_FIRST_FAIL="${EXIT_ON_FIRST_FAIL:-0}"
AUTO_CLEANUP="${AUTO_CLEANUP:-0}"
SKIP_CLUSTER_START="${SKIP_CLUSTER_START:-0}"
COVERAGE="${COVERAGE:-0}"

# Validate required variables
if [ -z "${TAP_GROUPS}" ]; then
    echo "ERROR: TAP_GROUPS is not set."
    echo "Usage: RUN_ID=<id> TAP_GROUPS='group1 group2' ${0}"
    exit 1
fi

# Count groups
TOTAL_GROUPS=0
for _ in ${TAP_GROUPS}; do
    TOTAL_GROUPS=$((TOTAL_GROUPS + 1))
done

if [ "${TOTAL_GROUPS}" -eq 0 ]; then
    echo "ERROR: No TAP groups specified."
    exit 1
fi

echo "=========================================="
echo "Parallel TAP Group Execution"
echo "=========================================="
echo "RUN_ID: ${RUN_ID}"
echo "TAP_GROUPS: ${TAP_GROUPS}"
echo "PARALLEL_JOBS: ${PARALLEL_JOBS}"
echo "TIMEOUT_MINUTES: ${TIMEOUT_MINUTES}"
echo "EXIT_ON_FIRST_FAIL: ${EXIT_ON_FIRST_FAIL}"
echo "AUTO_CLEANUP: ${AUTO_CLEANUP}"
echo "SKIP_CLUSTER_START: ${SKIP_CLUSTER_START}"
echo "COVERAGE: ${COVERAGE}"
echo "=========================================="

# Create results directory
RESULTS_DIR="${WORKSPACE}/ci_infra_logs/multi-group-${RUN_ID}"
mkdir -p "${RESULTS_DIR}"

# Arrays to track job PIDs and their associated groups
declare -a JOB_PIDS=()
declare -A GROUP_FOR_PID
declare -A PID_FOR_GROUP
declare -A EXIT_CODES
declare -A START_TIMES
declare -A END_TIMES

# Cleanup function for interrupted runs
cleanup_on_interrupt() {
    echo ""
    echo ">>> INTERRUPT received - cleaning up running jobs..."
    for pid in "${JOB_PIDS[@]}"; do
        kill -TERM "${pid}" 2>/dev/null || true
    done
    sleep 2
    for pid in "${JOB_PIDS[@]}"; do
        kill -KILL "${pid}" 2>/dev/null || true
    done
    exit 130
}
trap cleanup_on_interrupt INT TERM

# Function to run a single group
run_single_group() {
    local group="${1}"
    local infra_id="${group}-${RUN_ID}"
    local log_file="${RESULTS_DIR}/${group}.log"
    local start_time end_time duration

    # Add random delay (1-20 seconds) to stagger infrastructure startup
    # This prevents resource contention when running multiple groups in parallel
    local delay=$((RANDOM % 20 + 1))
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${group}: Waiting ${delay}s to stagger startup..." | tee -a "${log_file}"
    sleep "${delay}"

    start_time=$(date +%s)
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] STARTING: ${group} (INFRA_ID: ${infra_id})" | tee -a "${log_file}"

    # Export variables for the child process
    export INFRA_ID="${infra_id}"
    export TAP_GROUP="${group}"

    # Run ensure-infras + run-tests-isolated with timeout
    # Note: We don't run cleanup here - let the user decide when to destroy
    local exit_code=0

    # Run tests with timeout - capture exit code properly
    local cmd_exit_code=0
    # Export variables for the subshell
    export INFRA_ID="${infra_id}"
    export TAP_GROUP="${group}"
    export SKIP_CLUSTER_START="${SKIP_CLUSTER_START}"
    export COVERAGE="${COVERAGE}"

    timeout "${TIMEOUT_MINUTES}m" bash <<INNERSHELL || cmd_exit_code=$?
        set -uo pipefail

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Setting up infrastructure..." | tee -a "${log_file}"
        if ! "${SCRIPT_DIR}/ensure-infras.bash" >> "${log_file}" 2>&1; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Failed to set up infrastructure" | tee -a "${log_file}"
            exit 1
        fi

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running tests..." | tee -a "${log_file}"
        # Note: run-tests-isolated.bash handles coverage collection regardless of exit code
        "${SCRIPT_DIR}/run-tests-isolated.bash" >> "${log_file}" 2>&1
        inner_exit_code=$?
        if [ \${inner_exit_code} -ne 0 ]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: Tests failed with exit code \${inner_exit_code}" | tee -a "${log_file}"
            # Coverage is still collected in run-tests-isolated.bash even on failure
            exit \${inner_exit_code}
        fi

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Tests completed successfully" | tee -a "${log_file}"
INNERSHELL

    # Process exit code
    if [ "${cmd_exit_code}" -eq 0 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS: ${group}" | tee -a "${log_file}"
        exit_code=0
    elif [ "${cmd_exit_code}" -eq 124 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] TIMEOUT: ${group} after ${TIMEOUT_MINUTES} minutes" | tee -a "${log_file}"
        exit_code=124
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] FAILED: ${group} (exit code: ${cmd_exit_code})" | tee -a "${log_file}"
        exit_code="${cmd_exit_code}"
    fi

    end_time=$(date +%s)
    duration=$((end_time - start_time))

    # Write result file
    cat > "${RESULTS_DIR}/${group}.result" << EOF
GROUP=${group}
INFRA_ID=${infra_id}
EXIT_CODE=${exit_code}
DURATION=${duration}
START_TIME=${start_time}
END_TIME=${end_time}
LOG_FILE=${log_file}
EOF

    # Auto-cleanup successful runs if enabled
    if [ "${exit_code}" -eq 0 ] && [ "${AUTO_CLEANUP}" -eq 1 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Auto-cleanup: ${group}" | tee -a "${log_file}"
        INFRA_ID="${infra_id}" TAP_GROUP="${group}" "${SCRIPT_DIR}/stop-proxysql-isolated.bash" >> "${log_file}" 2>&1 || true
        INFRA_ID="${infra_id}" TAP_GROUP="${group}" "${SCRIPT_DIR}/destroy-infras.bash" >> "${log_file}" 2>&1 || true
    fi

    return "${exit_code}"
}

# Main execution
echo ">>> Starting parallel execution of ${TOTAL_GROUPS} groups..."
START_TIME=$(date +%s)

# Track overall status
OVERALL_FAILED=0
JOBS_RUNNING=0

# Launch jobs
for group in ${TAP_GROUPS}; do
    # Check if we should stop due to previous failure
    if [ "${EXIT_ON_FIRST_FAIL}" -eq 1 ] && [ "${OVERALL_FAILED}" -ne 0 ]; then
        echo ">>> Skipping ${group} due to previous failure"
        continue
    fi

    # If PARALLEL_JOBS is set and we're at the limit, wait for a job to finish
    if [ "${PARALLEL_JOBS}" -gt 0 ] && [ "${JOBS_RUNNING}" -ge "${PARALLEL_JOBS}" ]; then
        echo ">>> Waiting for a job to finish (max ${PARALLEL_JOBS} parallel)..."
        wait -n || true
        JOBS_RUNNING=$((JOBS_RUNNING - 1))
    fi

    # Start the job
    echo ">>> Launching: ${group}"
    run_single_group "${group}" &
    local_pid=$!
    JOB_PIDS+=("${local_pid}")
    GROUP_FOR_PID["${local_pid}"]="${group}"
    PID_FOR_GROUP["${group}"]="${local_pid}"
    JOBS_RUNNING=$((JOBS_RUNNING + 1))
done

# Wait for all jobs to complete
echo ">>> Waiting for all jobs to complete..."
for pid in "${JOB_PIDS[@]}"; do
    group="${GROUP_FOR_PID[${pid}]}"
    if wait "${pid}"; then
        EXIT_CODES["${group}"]=0
    else
        EXIT_CODES["${group}"]=$?
        OVERALL_FAILED=1
    fi
done

END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))

# Generate summary report
echo ""
echo "=========================================="
echo "           EXECUTION SUMMARY              "
echo "=========================================="
printf "%-25s %10s %12s\n" "Group" "Duration" "Status"
echo "------------------------------------------"

for group in ${TAP_GROUPS}; do
    exit_code="${EXIT_CODES[${group}]:-1}"
    result_file="${RESULTS_DIR}/${group}.result"

    if [ -f "${result_file}" ]; then
        duration=$(grep "^DURATION=" "${result_file}" | cut -d= -f2)
        duration_min=$((duration / 60))
        duration_sec=$((duration % 60))
        duration_str="${duration_min}m${duration_sec}s"
    else
        duration_str="N/A"
    fi

    if [ "${exit_code}" -eq 0 ]; then
        status="✓ PASS"
    elif [ "${exit_code}" -eq 124 ]; then
        status="✗ TIMEOUT"
    else
        status="✗ FAIL"
    fi

    printf "%-25s %10s %12s\n" "${group}" "${duration_str}" "${status}"
done

echo "------------------------------------------"
echo "TOTAL TIME: $((TOTAL_DURATION / 60))m$((TOTAL_DURATION % 60))s"
echo "=========================================="

# Summary of results
PASS_COUNT=0
FAIL_COUNT=0
TIMEOUT_COUNT=0

for group in ${TAP_GROUPS}; do
    exit_code="${EXIT_CODES[${group}]:-1}"
    if [ "${exit_code}" -eq 0 ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    elif [ "${exit_code}" -eq 124 ]; then
        TIMEOUT_COUNT=$((TIMEOUT_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done

echo ""
echo "PASSED:  ${PASS_COUNT}/${TOTAL_GROUPS}"
echo "FAILED:  ${FAIL_COUNT}/${TOTAL_GROUPS}"
echo "TIMEOUT: ${TIMEOUT_COUNT}/${TOTAL_GROUPS}"
echo ""
echo "Results directory: ${RESULTS_DIR}"
echo ""

# Print log locations for failed groups
if [ "${FAIL_COUNT}" -gt 0 ] || [ "${TIMEOUT_COUNT}" -gt 0 ]; then
    echo "Failed/Timed out group logs:"
    for group in ${TAP_GROUPS}; do
        exit_code="${EXIT_CODES[${group}]:-1}"
        if [ "${exit_code}" -ne 0 ]; then
            echo "  ${group}: ${RESULTS_DIR}/${group}.log"
        fi
    done
    echo ""
fi

# Combine coverage reports if coverage mode is enabled
if [ "${COVERAGE}" -eq 1 ]; then
    echo ""
    echo "=========================================="
    echo "       COMBINING COVERAGE REPORTS         "
    echo "=========================================="

    COMBINED_COVERAGE_DIR="${RESULTS_DIR}/coverage-report"
    mkdir -p "${COMBINED_COVERAGE_DIR}"

    # Find all individual coverage info files from each group
    COVERAGE_FILES=""
    for group in ${TAP_GROUPS}; do
        infra_id="${group}-${RUN_ID}"
        group_coverage_dir="${WORKSPACE}/ci_infra_logs/${infra_id}/coverage-report"
        if [ -d "${group_coverage_dir}" ]; then
            for info_file in "${group_coverage_dir}"/*.info; do
                if [ -f "${info_file}" ]; then
                    COVERAGE_FILES="${COVERAGE_FILES} ${info_file}"
                    echo ">>> Found coverage: ${info_file}"
                fi
            done
        fi
    done

    if [ -n "${COVERAGE_FILES}" ]; then
        # Check if fastcov is available
        if command -v fastcov >/dev/null 2>&1; then
            COMBINED_INFO="${COMBINED_COVERAGE_DIR}/combined-coverage.info"
            echo ">>> Combining coverage reports into: ${COMBINED_INFO}"
            # shellcheck disable=SC2086
            fastcov -b -l -C ${COVERAGE_FILES} -o "${COMBINED_INFO}" 2>/dev/null || {
                echo ">>> WARNING: fastcov combine failed, trying lcov..."
                # Fallback to lcov if fastcov fails
                if command -v lcov >/dev/null 2>&1; then
                    FIRST_FILE=true
                    for info_file in ${COVERAGE_FILES}; do
                        if [ "${FIRST_FILE}" = true ]; then
                            cp "${info_file}" "${COMBINED_INFO}"
                            FIRST_FILE=false
                        else
                            lcov -a "${COMBINED_INFO}" -a "${info_file}" -o "${COMBINED_INFO}".tmp 2>/dev/null && \
                                mv "${COMBINED_INFO}".tmp "${COMBINED_INFO}"
                        fi
                    done
                fi
            }

            if [ -f "${COMBINED_INFO}" ]; then
                echo ">>> Combined coverage report: ${COMBINED_INFO}"

                # Generate HTML report
                if command -v genhtml >/dev/null 2>&1; then
                    COMBINED_HTML="${COMBINED_COVERAGE_DIR}/html"
                    mkdir -p "${COMBINED_HTML}"
                    genhtml --branch-coverage "${COMBINED_INFO}" --output-directory "${COMBINED_HTML}" 2>/dev/null || \
                        echo ">>> WARNING: HTML generation failed"
                    [ -f "${COMBINED_HTML}/index.html" ] && echo ">>> Combined HTML report: ${COMBINED_HTML}/index.html"
                fi
            else
                echo ">>> WARNING: Failed to generate combined coverage report"
            fi
        else
            echo ">>> WARNING: fastcov/lcov not found, skipping coverage combination"
            echo ">>> Individual coverage files are available at:"
            for group in ${TAP_GROUPS}; do
                infra_id="${group}-${RUN_ID}"
                echo "  ${group}: ${WORKSPACE}/ci_infra_logs/${infra_id}/coverage-report/"
            done
        fi
    else
        echo ">>> No coverage files found to combine"
    fi
    echo ""
fi

# Exit with appropriate code
if [ "${OVERALL_FAILED}" -eq 0 ]; then
    echo ">>> All groups passed!"
    exit 0
else
    echo ">>> Some groups failed. Check logs above."
    exit 1
fi
