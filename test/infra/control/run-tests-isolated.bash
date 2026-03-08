#!/bin/bash
set -e

# Derive Workspace relative to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

# Default INFRA_ID if not provided
export INFRA_ID="${INFRA_ID:-dev-$USER}"

[ -z "${DEFAULT_MYSQL_INFRA}" ] && echo "WARNING: DEFAULT_MYSQL_INFRA is not set. Tests will target default MySQL version."
[ -z "${DEFAULT_PGSQL_INFRA}" ] && echo "WARNING: DEFAULT_PGSQL_INFRA is not set. Tests will target default PostgreSQL version."

export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)

NETWORK_NAME="${INFRA_ID}_backend"
TEST_CONTAINER="test-runner.${INFRA_ID}"
INFRA_LOGS_PATH="${WORKSPACE}/ci_infra_logs"
PROXY_DATA_DIR_HOST="${INFRA_LOGS_PATH}/${INFRA_ID}/proxysql"
LEGACY_SCRIPTS_PATH="/var/lib/jenkins/scripts"

cleanup() {
    echo ">>> Cleaning up Test Runner: ${TEST_CONTAINER}"
    docker rm -f "${TEST_CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT SIGINT SIGTERM

docker rm -f "${TEST_CONTAINER}" >/dev/null 2>&1 || true
TESTS_LOGS_PATH_HOST="${INFRA_LOGS_PATH}/${INFRA_ID}/tests"
mkdir -p "${TESTS_LOGS_PATH_HOST}"
chmod 777 "${TESTS_LOGS_PATH_HOST}"

MYSQL_BINLOG_BIN=$(find "${WORKSPACE}" -name "mysqlbinlog" -type f -executable | head -n 1)
BINLOG_READER_BIN=$(find "${WORKSPACE}" -name "test_binlog_reader-t" -type f -executable | head -n 1)

# Note: We still mount the external jenkins-build-scripts for now as they contain 
# the test-scripts/ directory which hasn't been migrated yet.
JENKINS_SCRIPTS_DIR="${HOME}/jenkins-build-scripts"

# CRITICAL: We MUST mount /var/run/docker.sock AND the docker binary 
# to allow the test-runner to execute docker commands (DooD - Docker-outside-of-Docker).
docker run     --name "${TEST_CONTAINER}"     --network "${NETWORK_NAME}"     --cap-add=NET_ADMIN     --cap-add=SYS_ADMIN     -v "/var/run/docker.sock:/var/run/docker.sock"     -v "/usr/bin/docker:/usr/bin/docker"     -v "${WORKSPACE}:${WORKSPACE}"     -v "${JENKINS_SCRIPTS_DIR}:${LEGACY_SCRIPTS_PATH}"     -v "${PROXY_DATA_DIR_HOST}:/var/lib/proxysql"     -e WORKSPACE="${WORKSPACE}"     -e INFRA_ID="${INFRA_ID}"     -e INFRA_TYPE="${INFRA_TYPE}"     -e DEFAULT_MYSQL_INFRA="${DEFAULT_MYSQL_INFRA}"     -e DEFAULT_PGSQL_INFRA="${DEFAULT_PGSQL_INFRA}"     -e ROOT_PASSWORD="${ROOT_PASSWORD}"     -e TEST_PY_TAP_INCL="${TEST_PY_TAP_INCL}"     -e TAP_GROUP="${TAP_GROUP}"     -e SKIP_CLUSTER_START="${SKIP_CLUSTER_START}"     -e PROXYSQL_CLUSTER_NODES="${PROXYSQL_CLUSTER_NODES}"     -e JENKINS_SCRIPTS_PATH="${LEGACY_SCRIPTS_PATH}"     -w "${LEGACY_SCRIPTS_PATH}"     proxysql-ci-base:latest     /bin/bash -c "
        set -e
        git config --global --add safe.directory \"${WORKSPACE}\"
        
        # Redirection: Replace reference to legacy scripts with local infra control scripts
        find \"${WORKSPACE}/test/tap/groups\" -name \"*.bash\" | xargs -r sed -i \"s|\\\$JENKINS_SCRIPTS_PATH|/test/infra/control|g\"

        # Cleanup legacy .env files
        find \"${WORKSPACE}/test/tap/tests\" -name \".env\" -o -name \"tests.env\" | while read f; do
            sed -i '/TAP_ROOT/d' \"\$f\"
            sed -i '/TAP_MYSQL/d' \"\$f\"
        done

        mkdir -p ./test-scripts/deps
        [ -n \"${MYSQL_BINLOG_BIN}\" ] && ln -sf \"${MYSQL_BINLOG_BIN}\" ./test-scripts/deps/mysqlbinlog
        [ -n \"${BINLOG_READER_BIN}\" ] && ln -sf \"${BINLOG_READER_BIN}\" ./test-scripts/deps/test_binlog_reader-t
        
        source ${SCRIPT_DIR}/env-isolated.bash
        
        # Ensure shared scripts directory exists and is populated
        for script_dir in reg_test_3838_scripts reg_test_3223_scripts load_data_local_datadir; do
            if [ -d \"${WORKSPACE}/test/tap/tests/\${script_dir}\" ]; then
                mkdir -p /var/lib/proxysql/\${script_dir}
                cp -r \"${WORKSPACE}/test/tap/tests/\${script_dir}/\"* /var/lib/proxysql/\${script_dir}/
                chmod -R 777 /var/lib/proxysql/\${script_dir}
            fi
        done
        
        python3 ./test-scripts/bin/proxysql-tester.py
    "
