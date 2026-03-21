#!/bin/bash
set -e
set -o pipefail
#
# Run Tests in Isolated Environment
#
# Usage:
#   INFRA_ID="my-test" \
#   TAP_GROUP="legacy-g1" \
#   ./run-tests-isolated.bash
#
# Optional environment variables:
#   COVERAGE=1             # Enable code coverage collection (default: 0)
#
# Coverage notes:
#   - Requires ProxySQL to be compiled with COVERAGE=1 (adds --coverage flags)
#   - Requires fastcov and genhtml to be available in the test-runner container
#   - Coverage is collected regardless of test success/failure
#   - Reports saved to: ci_infra_logs/{INFRA_ID}/coverage-report/
#

# Derive Workspace relative to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

# Default INFRA_ID if not provided
export INFRA_ID="${INFRA_ID:-dev-$USER}"

# Coverage mode detection
COVERAGE_MODE="${COVERAGE:-0}"
COVERAGE_REPORT_DIR="${WORKSPACE}/ci_infra_logs/${INFRA_ID}/coverage-report"
if [ "${COVERAGE_MODE}" = "1" ]; then
    echo ">>> Code coverage enabled - reports will be saved to ${COVERAGE_REPORT_DIR}"
    mkdir -p "${COVERAGE_REPORT_DIR}"
fi

# 1. Determine Required Infras
INFRAS_TO_CHECK=""
BASE_GROUP=$(echo "${TAP_GROUP}" | sed -E "s/[-_]g[0-9]+.*//") # Strip -g1, -g2, _g1, _g2 etc.

if [ -n "${TAP_GROUP}" ]; then
    if [ -f "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst" ]; then
        INFRAS_TO_CHECK=$(cat "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst")
    elif [ -f "${WORKSPACE}/test/tap/groups/${BASE_GROUP}/infras.lst" ]; then
        INFRAS_TO_CHECK=$(cat "${WORKSPACE}/test/tap/groups/${BASE_GROUP}/infras.lst")
    fi
fi

# If no list found, use INFRA_TYPE as single requirement
if [ -z "${INFRAS_TO_CHECK}" ]; then
    INFRAS_TO_CHECK="${INFRA_TYPE}"
fi

# 2. Automatically derive DEFAULT_MYSQL_INFRA and DEFAULT_PGSQL_INFRA
# We take the first compatible infrastructure found in the list.
if [ -n "${INFRAS_TO_CHECK}" ]; then
    for INFRA in ${INFRAS_TO_CHECK}; do
        if [[ "${INFRA}" == *mysql* ]] || [[ "${INFRA}" == *mariadb* ]]; then
            export DEFAULT_MYSQL_INFRA="${DEFAULT_MYSQL_INFRA:-${INFRA}}"
        fi
        if [[ "${INFRA}" == *pgsql* ]] || [[ "${INFRA}" == *pgdb* ]]; then
            export DEFAULT_PGSQL_INFRA="${DEFAULT_PGSQL_INFRA:-${INFRA}}"
        fi
    done
fi

export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)
NETWORK_NAME="${INFRA_ID}_backend"
TEST_CONTAINER="test-runner.${INFRA_ID}"
INFRA_LOGS_PATH="${WORKSPACE}/ci_infra_logs"
PROXY_DATA_DIR_HOST="${INFRA_LOGS_PATH}/${INFRA_ID}/proxysql"



# VERIFICATION: Verify ProxySQL is running
PROXY_CONTAINER="proxysql.${INFRA_ID}"
echo ">>> Verifying ProxySQL container: ${PROXY_CONTAINER}"
if ! docker ps --format '{{.Names}}' | grep -q "^${PROXY_CONTAINER}$"; then
    echo "ERROR: ProxySQL container ${PROXY_CONTAINER} is NOT running!"
    exit 1
fi

# VERIFICATION: Verify all required backend containers are running
for INFRA_NAME in ${INFRAS_TO_CHECK}; do
    echo ">>> Verifying Backend: ${INFRA_NAME}"
    # Extract container names from the infra's docker-compose.yml
    if [ -f "${WORKSPACE}/test/infra/${INFRA_NAME}/docker-compose.yml" ]; then
        # Project name used by init script
        COMPOSE_PROJECT="${INFRA_NAME}-${INFRA_ID}"
        # Get all services for this project
        RUNNING_CONTAINERS=$(docker ps --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" --format '{{.Names}}')
        if [ -z "${RUNNING_CONTAINERS}" ]; then
            if [ -f "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst" ]; then LST_PATH="${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst"; else LST_PATH="${WORKSPACE}/test/tap/groups/${BASE_GROUP}/infras.lst"; fi
            echo "ERROR: Required infrastructure '${INFRA_NAME}' is NOT running."
            if [ -f "${LST_PATH}" ]; then
                echo "According to '${LST_PATH}', this infrastructure is mandatory for the '${TAP_GROUP}' group."
            fi
            echo "Please run initialization for '${INFRA_NAME}' first (e.g. cd test/infra/${INFRA_NAME} && ./docker-compose-init.bash)."
            exit 1
        fi
        echo "Found running containers: ${RUNNING_CONTAINERS//$'\n'/ }"
    else
        echo "ERROR: Infrastructure directory ${INFRA_NAME} not found!"
        exit 1
    fi
done

echo ">>> INFRASTRUCTURE VERIFIED. LAUNCHING TEST RUNNER..."

# Cleanup old test runner if exists
docker rm -f "${TEST_CONTAINER}" >/dev/null 2>&1 || true

# Prepare logs path
TESTS_LOGS_PATH_HOST="${INFRA_LOGS_PATH}/${INFRA_ID}/tests"
mkdir -p "${TESTS_LOGS_PATH_HOST}"
chmod 777 "${TESTS_LOGS_PATH_HOST}"

# Find binaries
MYSQL_BINLOG_BIN=$(find "${WORKSPACE}" -path "${WORKSPACE}/ci_infra_logs" -prune -o -path "${WORKSPACE}/.git" -prune -o -name "mysqlbinlog" -type f -executable -print | head -n 1)
BINLOG_READER_BIN=$(find "${WORKSPACE}" -path "${WORKSPACE}/ci_infra_logs" -prune -o -path "${WORKSPACE}/.git" -prune -o -name "test_binlog_reader-t" -type f -executable -print | head -n 1)

# Execution: run the container
docker run \
    --name "${TEST_CONTAINER}" \
    --network "${NETWORK_NAME}" \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_ADMIN \
    -v "${WORKSPACE}:${WORKSPACE}" \
        -v "${PROXY_DATA_DIR_HOST}:/var/lib/proxysql" \
    -e WORKSPACE="${WORKSPACE}" \
    -e INFRA_ID="${INFRA_ID}" \
    -e INFRA_TYPE="${INFRA_TYPE}" \
    -e DEFAULT_MYSQL_INFRA="${DEFAULT_MYSQL_INFRA}" \
    -e DEFAULT_PGSQL_INFRA="${DEFAULT_PGSQL_INFRA}" \
    -e ROOT_PASSWORD="${ROOT_PASSWORD}" \
    -e TEST_PY_TAP_INCL="${TEST_PY_TAP_INCL}" \
    -e TAP_GROUP="${TAP_GROUP}" \
    -e SKIP_CLUSTER_START="${SKIP_CLUSTER_START}" \
    -e PROXYSQL_CLUSTER_NODES="${PROXYSQL_CLUSTER_NODES}" \
    -e COVERAGE_MODE="${COVERAGE_MODE}" \
    -e COVERAGE_REPORT_DIR="${COVERAGE_REPORT_DIR}" \
    -e SCRIPT_DIR="${SCRIPT_DIR}" \
    -e MYSQL_BINLOG_BIN="${MYSQL_BINLOG_BIN}" \
    -e BINLOG_READER_BIN="${BINLOG_READER_BIN}" \
    proxysql-ci-base:latest \
    /bin/bash -c "
        set -e

        # Coverage collection trap - runs on exit regardless of success/failure/timeout
        collect_coverage() {
            local exit_code=\$?
            if [ \"\${COVERAGE_MODE}\" = \"1\" ]; then
                echo \">>> Collecting code coverage data (exit code was: \${exit_code})...\"
                if command -v fastcov >/dev/null 2>&1; then
                    mkdir -p \"\${COVERAGE_REPORT_DIR}\"
                    local coverage_file=\"\${COVERAGE_REPORT_DIR}/\${INFRA_ID}.info\"
                    echo \">>> Generating coverage report: \${coverage_file}\"
                    local nproc_val=\$(nproc)
                    cd \"\${WORKSPACE}\"
                    fastcov -b -j\"\${nproc_val}\" --process-gcno -l -e /usr/include/ -e test/tap/tests -e deps/ -d . -o \"\${coverage_file}\" 2>&1 || echo \">>> WARNING: Coverage generation failed\"
                    if [ -f \"\${coverage_file}\" ]; then
                        echo \">>> Coverage report generated: \${coverage_file}\"
                        # Generate HTML report
                        if command -v genhtml >/dev/null 2>&1; then
                            local html_dir=\"\${COVERAGE_REPORT_DIR}/html\"
                            mkdir -p \"\${html_dir}\"
                            genhtml --branch-coverage --ignore-errors negative,source --synthesize-missing \"\${coverage_file}\" --output-directory \"\${html_dir}\" 2>&1 || echo \">>> WARNING: HTML generation failed\"
                            [ -f \"\${html_dir}/index.html\" ] && echo \">>> HTML coverage report: \${html_dir}/index.html\"
                        fi
                    else
                        echo \">>> WARNING: Coverage info file not generated\"
                    fi
                else
                    echo \">>> WARNING: fastcov not found in container, skipping coverage collection\"
                fi
            fi
            exit \${exit_code}
        }
        trap collect_coverage EXIT

        git config --global --add safe.directory \"${WORKSPACE}\"

        # Redirection: Replace reference to legacy scripts with local infra control scripts
        find \"${WORKSPACE}/test/tap/groups\" -name \"*.bash\" | xargs -r sed -i \"s|\\\$JENKINS_SCRIPTS_PATH|${WORKSPACE}/test/infra/control|g\"

        # Cleanup legacy .env files inside container view
        find \"${WORKSPACE}/test/tap/tests\" -name \".env\" -o -name \"tests.env\" | while read f; do
            sed -i '/TAP_ROOT/d' \"\$f\"
            sed -i '/TAP_MYSQL/d' \"\$f\"
        done

        mkdir -p \"${WORKSPACE}/test-scripts/deps\"
        [ -n \"${MYSQL_BINLOG_BIN}\" ] && ln -sf \"${MYSQL_BINLOG_BIN}\" \"${WORKSPACE}/test-scripts/deps/mysqlbinlog\"
        [ -n \"${BINLOG_READER_BIN}\" ] && ln -sf \"${BINLOG_READER_BIN}\" \"${WORKSPACE}/test-scripts/deps/test_binlog_reader-t\"
        
        # Source the local isolated environment
        source ${SCRIPT_DIR}/env-isolated.bash

        # Dump ProxySQL configuration before running tests
        echo '================================================================================'
        echo 'ProxySQL Configuration Dump (BEFORE TESTS)'
        echo '================================================================================'

        # MySQL configuration
        echo '--- mysql_servers ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT hostgroup_id, hostname, port, status, comment FROM mysql_servers ORDER BY hostgroup_id, hostname' 2>/dev/null || echo 'ERROR: Failed to query mysql_servers'

        echo '--- mysql_users ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT username, password, active, default_hostgroup, transaction_persistent FROM mysql_users ORDER BY username' 2>/dev/null || echo 'ERROR: Failed to query mysql_users'

        echo '--- mysql_replication_hostgroups ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT writer_hostgroup, reader_hostgroup, comment FROM mysql_replication_hostgroups' 2>/dev/null || echo 'ERROR: Failed to query mysql_replication_hostgroups'

        echo '--- mysql_query_rules ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT rule_id, active, username, match_pattern, destination_hostgroup, apply, comment FROM mysql_query_rules ORDER BY rule_id' 2>/dev/null || echo 'ERROR: Failed to query mysql_query_rules (or empty)'

        echo '--- runtime_mysql_query_rules ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT rule_id, active, username, match_pattern, destination_hostgroup, apply, comment FROM runtime_mysql_query_rules ORDER BY rule_id' 2>/dev/null || echo 'ERROR: Failed to query runtime_mysql_query_rules (or empty)'

        # PgSQL configuration
        echo '--- pgsql_servers ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT hostgroup_id, hostname, port, status, comment FROM pgsql_servers ORDER BY hostgroup_id, hostname' 2>/dev/null || echo 'INFO: pgsql_servers not configured (or error)'

        echo '--- pgsql_users ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT username, password, active, default_hostgroup FROM pgsql_users ORDER BY username' 2>/dev/null || echo 'INFO: pgsql_users not configured (or error)'

        echo '--- pgsql_replication_hostgroups ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT writer_hostgroup, reader_hostgroup, comment FROM pgsql_replication_hostgroups' 2>/dev/null || echo 'INFO: pgsql_replication_hostgroups not configured (or error)'

        echo '--- pgsql_query_rules ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT rule_id, active, username, match_pattern, destination_hostgroup, apply, comment FROM pgsql_query_rules ORDER BY rule_id' 2>/dev/null || echo 'INFO: pgsql_query_rules not configured (or empty)'

        echo '================================================================================'

        # Execute the Python tester
        python3 "${WORKSPACE}/test/scripts/bin/proxysql-tester.py"
    "

# Execute group-specific pre-cleanup hook if it exists
# This runs before the test runner container is removed, allowing cleanup
# of ProxySQL-specific configuration while admin is still accessible
if [ -n "${TAP_GROUP}" ]; then
    PRE_CLEANUP_HOOK="${WORKSPACE}/test/tap/groups/${TAP_GROUP}/pre-cleanup.bash"
    if [ ! -f "${PRE_CLEANUP_HOOK}" ]; then
        PRE_CLEANUP_HOOK="${WORKSPACE}/test/tap/groups/${BASE_GROUP}/pre-cleanup.bash"
    fi

    if [ -f "${PRE_CLEANUP_HOOK}" ]; then
        echo ">>> Executing group pre-cleanup hook: ${PRE_CLEANUP_HOOK}"
        "${PRE_CLEANUP_HOOK}" || true  # Allow cleanup to fail
    fi
fi

# Capture code coverage data if enabled
# This runs regardless of test success/failure
if [ "${COVERAGE_MODE}" = "1" ]; then
    echo ">>> Collecting code coverage data..."

    # Check if fastcov is available in the container
    if docker exec "${TEST_CONTAINER}" which fastcov >/dev/null 2>&1; then
        COVERAGE_INFO_FILE="${COVERAGE_REPORT_DIR}/${TAP_GROUP:-test}-${INFRA_ID}.info"

        echo ">>> Generating coverage report: ${COVERAGE_INFO_FILE}"
        # Extract coverage data from container
        docker exec "${TEST_CONTAINER}" bash -c "
            cd '${WORKSPACE}' && \
            fastcov -b -j\$(nproc) --process-gcno -l \
                -e /usr/include/ -e test/tap/tests \
                -d . -i include -i lib -i src \
                -o '${COVERAGE_INFO_FILE}' 2>&1
        " || echo ">>> WARNING: Coverage generation failed"

        # Check if report was generated
        if [ -f "${COVERAGE_INFO_FILE}" ]; then
            echo ">>> Coverage report generated: ${COVERAGE_INFO_FILE}"
            # Generate HTML report
            if command -v genhtml >/dev/null 2>&1; then
                HTML_REPORT_DIR="${COVERAGE_REPORT_DIR}/html/${TAP_GROUP:-test}-${INFRA_ID}"
                mkdir -p "${HTML_REPORT_DIR}"
                genhtml --branch-coverage --ignore-errors negative,source --synthesize-missing "${COVERAGE_INFO_FILE}" --output-directory "${HTML_REPORT_DIR}" 2>/dev/null || \
                    echo ">>> WARNING: HTML report generation failed"
                [ -d "${HTML_REPORT_DIR}" ] && echo ">>> HTML report: ${HTML_REPORT_DIR}/index.html"
            fi
        else
            echo ">>> WARNING: Coverage info file not generated"
        fi
    else
        echo ">>> WARNING: fastcov not found in container, skipping coverage collection"
    fi
fi

# Clean up only the runner container
echo ">>> Cleaning up Test Runner container"
docker rm -f "${TEST_CONTAINER}" >/dev/null 2>&1 || true
