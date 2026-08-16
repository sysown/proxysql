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
#   TAP_USE_NOISE=1        # Enable noise injection for race condition testing (default: 0)
#
# Noise injection notes:
#   - When enabled, tests that support noise injection will introduce random delays
#     and stress to help detect race conditions and deadlocks
#   - Tests check `cl.use_noise` and adjust their behavior accordingly
#   - See test/tap/NOISE_TESTING.md for more details
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
export INFRA="${INFRA:-${INFRA_TYPE}}"

expand_infra_list() {
    local list_path="$1"
    while IFS= read -r infra_name; do
        [ -n "${infra_name}" ] || continue
        eval "printf '%s\n' \"${infra_name}\""
    done < "${list_path}"
}

# Coverage mode detection
COVERAGE_MODE="${COVERAGE:-0}"
COVERAGE_REPORT_DIR="${WORKSPACE}/ci_infra_logs/${INFRA_ID}/coverage-report"
if [ "${COVERAGE_MODE}" = "1" ]; then
    echo ">>> Code coverage enabled - reports will be saved to ${COVERAGE_REPORT_DIR}"
    mkdir -p "${COVERAGE_REPORT_DIR}"

    # Coverage workflows use sparse checkout for source trees, so the tracked
    # root codecov.yml may not be materialized in the worktree even though it
    # exists at HEAD. codecov-action is explicitly pointed at this path; restore
    # just that file from the tested commit without broadening sparse checkout.
    if [ ! -f "${WORKSPACE}/codecov.yml" ]; then
        if git -C "${WORKSPACE}" cat-file -e HEAD:codecov.yml 2>/dev/null; then
            git -C "${WORKSPACE}" show HEAD:codecov.yml > "${WORKSPACE}/codecov.yml"
            echo ">>> Materialized codecov.yml from HEAD for coverage upload"
        else
            echo ">>> WARNING: codecov.yml is not tracked at HEAD"
        fi
    fi
fi

# 1. Determine Required Infras
INFRAS_TO_CHECK=""
BASE_GROUP=$(echo "${TAP_GROUP}" | sed -E "s/[-_]g[0-9]+.*//") # Strip -g1, -g2, _g1, _g2 etc.

# Source group env.sh to pick up SKIP_PROXYSQL and other group-level settings
if [ -f "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/env.sh" ]; then
    source "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/env.sh"
elif [ -f "${WORKSPACE}/test/tap/groups/${BASE_GROUP}/env.sh" ]; then
    source "${WORKSPACE}/test/tap/groups/${BASE_GROUP}/env.sh"
fi

if [ -n "${TAP_GROUP}" ]; then
    if [ -f "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst" ]; then
        INFRAS_TO_CHECK=$(expand_infra_list "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst")
    elif [ -f "${WORKSPACE}/test/tap/groups/${BASE_GROUP}/infras.lst" ]; then
        INFRAS_TO_CHECK=$(expand_infra_list "${WORKSPACE}/test/tap/groups/${BASE_GROUP}/infras.lst")
    fi
fi

# If no list found, use INFRA_TYPE as single requirement
if [ -z "${INFRAS_TO_CHECK}" ]; then
    INFRAS_TO_CHECK="${INFRA_TYPE}"
fi

# Derive INFRA_TYPE from TAP_GROUP if not set
# This is simple and deterministic - matches group naming convention
if [ -z "${INFRA_TYPE}" ]; then
    case "${TAP_GROUP}" in
        mysql56-single*) export INFRA_TYPE="${DEFAULT_MYSQL_INFRA:-infra-dbdeployer-mysql56-single}" ;;
        mysql84*)  export INFRA_TYPE=infra-mysql84 ;;
        mysql90*)  export INFRA_TYPE=infra-mysql90 ;;
        mysql93*)  export INFRA_TYPE=infra-mysql93 ;;
        mariadb*)  export INFRA_TYPE=infra-mariadb10 ;;
        legacy*)   export INFRA_TYPE=infra-mysql57 ;;
    esac
    if [ -n "${INFRA_TYPE}" ]; then
        echo ">>> Derived INFRA_TYPE from TAP_GROUP: ${INFRA_TYPE}"
    fi
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
COVERAGE_DATA_DIR_HOST="${INFRA_LOGS_PATH}/${INFRA_ID}/gcov"



if [ "${SKIP_PROXYSQL}" = "1" ]; then
    echo ">>> SKIP_PROXYSQL=1: Skipping ProxySQL and backend verification for group '${TAP_GROUP}'."
    echo ">>> Running unit tests directly (no infrastructure needed)."
else
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
fi

# SKIP_PROXYSQL path: run test binaries directly on the host, no Docker needed.
# We bypass proxysql-tester.py because it requires a ProxySQL admin connection
# and Docker-specific environment variables that don't exist in this mode.
if [ "${SKIP_PROXYSQL}" = "1" ]; then
    echo ">>> Running tests directly on the host (no Docker container)..."

    # Ensure transitive shared libs (e.g. libparser.so via libcpp_dotenv.so) are found.
    # RUNPATH in intermediate libraries may contain stale absolute paths from the
    # original build, so we add the known library directories explicitly.
    export LD_LIBRARY_PATH="${WORKSPACE}/test/tap/tap${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

    # Discover test binaries from groups.json for this TAP_GROUP
    GROUPS_JSON="${WORKSPACE}/test/tap/groups/groups.json"
    if [ ! -f "${GROUPS_JSON}" ]; then
        echo "ERROR: groups.json not found at ${GROUPS_JSON}"
        exit 1
    fi

    # Detect ProxySQL version for @proxysql_min_version filtering
    PROXYSQL_BIN="${WORKSPACE}/src/proxysql"
    PROXYSQL_VERSION=""
    if [ -x "${PROXYSQL_BIN}" ]; then
        PROXYSQL_VERSION=$(${PROXYSQL_BIN} --version 2>&1 | grep -oP 'ProxySQL version \K[0-9]+\.[0-9]+\.[0-9]+' || true)
        echo ">>> Detected ProxySQL version: ${PROXYSQL_VERSION}"
    else
        echo ">>> WARNING: ProxySQL binary not found at ${PROXYSQL_BIN}, skipping version filtering"
    fi

    # Extract test names belonging to this group, filtering by @proxysql_min_version
    TEST_NAMES=$(python3 -c "
import json, sys
from packaging import version
proxysql_ver = '${PROXYSQL_VERSION}'
with open('${GROUPS_JSON}') as f:
    groups = json.load(f)
for test_name, test_groups in sorted(groups.items()):
    if '${TAP_GROUP}' in test_groups:
        # Check @proxysql_min_version tag
        skip = False
        if proxysql_ver:
            for entry in test_groups:
                if isinstance(entry, str) and entry.startswith('@proxysql_min_version:'):
                    min_ver = entry.split(':', 1)[1]
                    if version.parse(proxysql_ver) < version.parse(min_ver):
                        print(f'SKIP ({test_name}): requires ProxySQL >= {min_ver}, have {proxysql_ver}', file=sys.stderr)
                        skip = True
                    break
        if not skip:
            print(test_name)
")

    if [ -z "${TEST_NAMES}" ]; then
        echo "ERROR: No tests found for group '${TAP_GROUP}' in groups.json"
        exit 1
    fi

    # Search for test binaries in known test directories
    TEST_DIRS="${WORKSPACE}/test/tap/tests/unit ${WORKSPACE}/test/tap/tests"

    TOTAL=0
    PASSED=0
    FAILED=0
    FAILED_TESTS=""

    for TEST_NAME in ${TEST_NAMES}; do
        TEST_BIN=""
        for DIR in ${TEST_DIRS}; do
            if [ -x "${DIR}/${TEST_NAME}" ]; then
                TEST_BIN="${DIR}/${TEST_NAME}"
                break
            fi
        done

        if [ -z "${TEST_BIN}" ]; then
            echo "WARNING: Test binary '${TEST_NAME}' not found in: ${TEST_DIRS}"
            TOTAL=$((TOTAL + 1))
            FAILED=$((FAILED + 1))
            FAILED_TESTS="${FAILED_TESTS} ${TEST_NAME}(not-found)"
            continue
        fi

        TOTAL=$((TOTAL + 1))
        echo ">>> Running: ${TEST_NAME}"
        if "${TEST_BIN}"; then
            PASSED=$((PASSED + 1))
            echo ">>> PASSED: ${TEST_NAME}"
        else
            FAILED=$((FAILED + 1))
            FAILED_TESTS="${FAILED_TESTS} ${TEST_NAME}"
            echo ">>> FAILED: ${TEST_NAME}"
        fi
    done

    echo ""
    echo "================================================================================"
    echo "Unit Test Summary: ${PASSED}/${TOTAL} passed, ${FAILED} failed"
    if [ -n "${FAILED_TESTS}" ]; then
        echo "Failed tests:${FAILED_TESTS}"
    fi
    echo "================================================================================"

    [ "${FAILED}" -eq 0 ]
    exit $?
fi

# Cleanup old test runner if exists
docker rm -f "${TEST_CONTAINER}" >/dev/null 2>&1 || true

# Prepare logs path
TESTS_LOGS_PATH_HOST="${INFRA_LOGS_PATH}/${INFRA_ID}/tests"
mkdir -p "${TESTS_LOGS_PATH_HOST}"
chmod 777 "${TESTS_LOGS_PATH_HOST}"

# Find binaries
#
# ci-builds.yml explicitly deletes test/deps/ from the cached workspace after
# the TAP binaries are built (see "Delete test/deps" block in ci-builds.yml).
# The libmariadbclient.a / libmysqlclient.a archives are statically linked
# into the *-t binaries, but the mysqlbinlog *executable* is invoked at
# runtime by test_com_binlog_dump_enables_fast_forward-t via system() and
# therefore is NOT carried in the cache. Fall back to whatever the runner
# container provides on PATH (test/infra/docker-base/Dockerfile installs
# mysql-client, which depends on mysql-server-core-8.0 and ships
# /usr/bin/mysqlbinlog) so the symlink at TEST_DEPS/mysqlbinlog resolves
# even when nothing in the workspace matches.
#
# See GH issue #6092 for the full failure trace.
MYSQL_BINLOG_BIN=$(find "${WORKSPACE}" -path "${WORKSPACE}/ci_infra_logs" -prune -o -path "${WORKSPACE}/.git" -prune -o -name "mysqlbinlog" -type f -executable -print | head -n 1)
if [ -z "${MYSQL_BINLOG_BIN}" ]; then
    MYSQL_BINLOG_BIN="$(command -v mysqlbinlog 2>/dev/null || true)"
fi

# Execution: run the container
docker run \
    --name "${TEST_CONTAINER}" \
    --hostname "test-runner" \
    --network "${NETWORK_NAME}" \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_ADMIN \
    -v "${WORKSPACE}:${WORKSPACE}" \
    -v "${WORKSPACE}:/opt/proxysql:ro" \
    -v "${PROXY_DATA_DIR_HOST}:/var/lib/proxysql" \
    -v "${COVERAGE_DATA_DIR_HOST}:/gcov" \
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
    -e TAP_USE_NOISE="${TAP_USE_NOISE:-0}" \
    -e TAP_PGSQL_SYNC_REPLICA_PORT="${TAP_PGSQL_SYNC_REPLICA_PORT:-}" \
    -e MULTI_GROUP="${MULTI_GROUP:-0}" \
    -e GCOV_PREFIX="/gcov/tap" \
    -e GCOV_PREFIX_STRIP="2" \
    proxysql-ci-base:latest \
    /bin/bash -c "
        set -e

        # Coverage collection trap - runs on exit regardless of success/failure/timeout
        #
        # Data layout in /gcov (per-INFRA_ID mount):
        #   /gcov/{lib,src}/obj/*.gcda            — ProxySQL daemon (GCOV_PREFIX=/gcov,     STRIP=2)
        #   /gcov/tap/{lib,src,test}/.../obj/*.gcda — TAP tests      (GCOV_PREFIX=/gcov/tap, STRIP=2)
        #
        # STRIP=2 strips opt/proxysql from the absolute path the .gcno embeds
        # (/opt/proxysql/{lib,src,test}/obj/X.gcno; the workspace is mounted at
        # /opt/proxysql in both the build and run containers per docker-compose
        # and the -v rule on the test-runner below). The remaining
        # {lib,src,test}/.../obj/ component is what the .gcno copy loop below
        # uses to copy the matching .gcno next to its .gcda before fastcov runs.
        #
        # This trap always copies .gcno files adjacent to .gcda so the data is
        # ready for fastcov. When MULTI_GROUP=1, fastcov runs centrally later;
        # when standalone, it runs here.
        collect_coverage() {
            local exit_code=\$?
            local coverage_exit=0
            trap - EXIT
            set +e
            if [ \"\${COVERAGE_MODE}\" = \"1\" ]; then
                (
                set -e
                coverage_failed=0
                echo \">>> Collecting code coverage data (exit code was: \${exit_code})...\"

                # ProxySQL is a long-running process, so its in-memory counters
                # are not guaranteed to reach the GCDA files during container
                # teardown. GCC 13 also ignores a second __gcov_dump call until
                # __gcov_reset is called. Do not dump inside the TAP loop; dump
                # once here after the group and before any GCDA decoding starts.
                echo \">>> Dumping ProxySQL GCOV counters after the test group...\"
                if ! \"${SCRIPT_DIR}/dump-proxysql-gcov.bash\"; then
                    echo \">>> ERROR: Failed to dump ProxySQL GCOV counters\" >&2
                    coverage_failed=1
                fi

                if [ -d \"/gcov\" ] && [ \"\$(ls -A /gcov 2>/dev/null)\" ]; then
                    # Match .gcno files to .gcda files by basename and copy
                    # adjacent so fastcov can find them.
                    #
                    # The previous algorithm tried to find a matching .gcno
                    # by stripping leading path components off the .gcda
                    # relative path and looking up \${WORKSPACE}/<stripped>.gcno
                    # -- which only works when the .gcda relative path is a
                    # path-suffix of the .gcno absolute path. For the
                    # ProxySQL daemon, GCOV_PREFIX_STRIP=3 eats
                    # /opt/proxysql/lib/ from /opt/proxysql/lib/obj/X.gcda,
                    # so the .gcda lands at /gcov/obj/X.gcda. The matching
                    # .gcno is at \${WORKSPACE}/lib/obj/X.gcno -- not a
                    # suffix of any strip of obj/X, so the lookup always
                    # missed and fastcov reported every .gcda as
                    # \"Missing 'current_working_directory'\" with an empty
                    # files list, producing a 0-byte .info report.
                    #
                    # Basename matching is robust to GCOV_PREFIX_STRIP and
                    # build CWD. ProxySQL doesn't reuse .cpp basenames
                    # across directories (verified by inspection of lib/
                    # and src/), so basename collision is not a concern.
                    echo \">>> Indexing .gcno files in \${WORKSPACE}...\"
                    GCNO_INDEX=\$(mktemp)
                    find \"\${WORKSPACE}\" -name '*.gcno' -type f -printf '%f %p\\n' 2>/dev/null \\
                        | sed 's/\\.gcno / /' > \"\${GCNO_INDEX}\"
                    echo \">>> Found \$(wc -l < \"\${GCNO_INDEX}\") .gcno files\"
                    echo \">>> Copying .gcno files adjacent to .gcda files in /gcov...\"
                    matched=0
                    unmatched=0
                    cd /gcov && find . -name '*.gcda' -type f | while read gcda; do
                        relpath=\"\${gcda#./}\"
                        base=\"\${relpath%.gcda}\"
                        bname=\$(basename \"\${base}\")
                        gcno_src=\$(awk -v k=\"\${bname}\" '\$1==k {print \$2; exit}' \"\${GCNO_INDEX}\")
                        if [ -n \"\${gcno_src}\" ]; then
                            target=\"/gcov/\${base}.gcno\"
                            mkdir -p \"\$(dirname \"\${target}\")\"
                            cp -f \"\${gcno_src}\" \"\${target}\"
                            matched=\$((matched + 1))
                        else
                            unmatched=\$((unmatched + 1))
                        fi
                    done
                    rm -f \"\${GCNO_INDEX}\"
                    echo \">>> .gcno copy: matched=\${matched} unmatched=\${unmatched}\"

                    if [ \"\${MULTI_GROUP}\" = \"1\" ]; then
                        # Multi-group mode: data is ready in /gcov for centralized collection
                        echo \">>> MULTI_GROUP=1: skipping fastcov (will run centrally after all groups finish)\"
                    else
                        # Standalone mode: run fastcov + genhtml here
                        if command -v fastcov >/dev/null 2>&1; then
                            mkdir -p \"\${COVERAGE_REPORT_DIR}\"
                            local coverage_file=\"\${COVERAGE_REPORT_DIR}/\${INFRA_ID}.info\"
                            local coverage_log=\"\${COVERAGE_REPORT_DIR}/coverage-generation.log\"
                            echo \">>> Running fastcov on /gcov...\"
                            cd /gcov
                            fastcov -b -j\$(nproc) -l \
                                -e /usr deps \
                                -d . -o \"\${coverage_file}\" >> \"\${coverage_log}\" 2>&1
                            if [ ! -s \"\${coverage_file}\" ]; then
                                echo \">>> ERROR: fastcov produced an empty coverage report (see \${coverage_log})\" >&2
                                exit 1
                            fi

                            if [ -f \"\${coverage_file}\" ]; then
                                echo \">>> Coverage report generated: \${coverage_file}\"

                                # Normalize SF: paths to repo-root-relative form so TAP
                                # coverage merges with unit-tests on Codecov.
                                # fastcov emits a mix of:
                                #   SF:/opt/proxysql/include/X.h   (absolute container path)
                                #   SF:/gcov/proxysql/lib/Y.cpp    (GCOV_PREFIX layout)
                                #   SF:lib/Y.cpp                   (relative to /opt/proxysql)
                                #   SF:proxysql/src/Z.cpp          (legacy prefixed form)
                                # Unit-tests upload SF:lib/... (repo-root). Emitting the
                                # same shape here is required: the old proxysql/ prefix
                                # created a phantom namespace that never merged, leaving
                                # lib/MySQL_Monitor.cpp at 0% despite real TAP hits.
                                # NB to future editors: this whole script body is the
                                # argument to an outer bash -c that is wrapped in
                                # DOUBLE QUOTES. Comments must avoid backticks and bare
                                # double-quote characters.
                                sed -i \
                                    -e 's|^SF:/opt/proxysql/|SF:|' \
                                    -e 's|^SF:/gcov/proxysql/|SF:|' \
                                    -e 's|^SF:proxysql/|SF:|' \
                                    \"\${coverage_file}\"

                                if command -v genhtml >/dev/null 2>&1; then
                                    local html_dir=\"\${COVERAGE_REPORT_DIR}/html\"
                                    mkdir -p \"\${html_dir}\"
                                    echo \">>> Generating HTML coverage report...\"
                                    genhtml --branch-coverage --ignore-errors negative,source --synthesize-missing \"\${coverage_file}\" --output-directory \"\${html_dir}\" >> \"\${coverage_log}\" 2>&1 || echo \">>> WARNING: HTML generation failed (see \${coverage_log})\"
                                    [ -f \"\${html_dir}/index.html\" ] && echo \">>> HTML coverage report: \${html_dir}/index.html\"
                                fi
                            else
                                echo \">>> WARNING: Coverage info file not generated (see \${coverage_log})\"
                            fi
                        else
                            echo \">>> WARNING: fastcov not found in container, skipping coverage collection\"
                        fi
                    fi
                else
                    echo \">>> WARNING: /gcov directory is empty or missing, skipping coverage\"
                fi
                exit \${coverage_failed}
                )
                coverage_exit=\$?
            fi
            source "${SCRIPT_DIR}/coverage-exit-status.bash"
            coverage_exit_status \"\${exit_code}\" \"\${coverage_exit}\"
            exit \$?
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

        # Source group environment first (sets TEST_PY_* flags etc.)
        if [ -n \"${TAP_GROUP}\" ]; then
            BASE_GROUP=\$(echo \"${TAP_GROUP}\" | sed -E 's/[-_]g[0-9]+.*//')
            if [ -f \"${WORKSPACE}/test/tap/groups/${TAP_GROUP}/env.sh\" ]; then
                source \"${WORKSPACE}/test/tap/groups/${TAP_GROUP}/env.sh\"
            elif [ -f \"${WORKSPACE}/test/tap/groups/\${BASE_GROUP}/env.sh\" ]; then
                source \"${WORKSPACE}/test/tap/groups/\${BASE_GROUP}/env.sh\"
            fi
        fi

        # Source the local isolated environment (defaults for unset vars)
        source ${SCRIPT_DIR}/env-isolated.bash

        # Wait for ProxySQL to be reachable from this container
        # Docker DNS resolution can take a few seconds on newly created containers
        echo -n '>>> Waiting for ProxySQL admin (proxysql:6032) ...'
        WAIT_COUNT=0
        WAIT_MAX=30
        while [ \$WAIT_COUNT -lt \$WAIT_MAX ]; do
            if mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT 1' >/dev/null 2>&1; then
                echo ' OK.'
                break
            fi
            echo -n '.'
            sleep 1
            WAIT_COUNT=\$((WAIT_COUNT + 1))
        done
        if [ \$WAIT_COUNT -ge \$WAIT_MAX ]; then
            echo ' FAILED after \${WAIT_MAX}s'
            echo 'ERROR: Cannot reach ProxySQL admin from test-runner container.'
            echo 'DNS resolution test:'
            getent hosts proxysql || echo 'DNS lookup failed for proxysql'
            exit 1
        fi

        # Dump ProxySQL configuration before running tests
        echo '================================================================================'
        echo 'ProxySQL Configuration Dump (BEFORE TESTS)'
        echo '================================================================================'

        # MySQL configuration
        echo '--- mysql_servers ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT hostgroup_id, hostname, port, status, comment FROM mysql_servers ORDER BY hostgroup_id, hostname'

        echo '--- mysql_users ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT username, password, active, default_hostgroup, transaction_persistent FROM mysql_users ORDER BY username'

        echo '--- mysql_replication_hostgroups ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT writer_hostgroup, reader_hostgroup, comment FROM mysql_replication_hostgroups'

        echo '--- mysql_query_rules ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT rule_id, active, username, match_pattern, destination_hostgroup, apply, comment FROM mysql_query_rules ORDER BY rule_id'

        echo '--- runtime_mysql_query_rules ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT rule_id, active, username, match_pattern, destination_hostgroup, apply, comment FROM runtime_mysql_query_rules ORDER BY rule_id'

        # PgSQL configuration
        echo '--- pgsql_servers ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT hostgroup_id, hostname, port, status, comment FROM pgsql_servers ORDER BY hostgroup_id, hostname'

        echo '--- pgsql_users ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT username, password, active, default_hostgroup FROM pgsql_users ORDER BY username'

        echo '--- pgsql_replication_hostgroups ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT writer_hostgroup, reader_hostgroup, comment FROM pgsql_replication_hostgroups'

        echo '--- pgsql_query_rules ---'
        mysql -uradmin -pradmin -hproxysql -P6032 -e 'SELECT rule_id, active, username, match_pattern, destination_hostgroup, apply, comment FROM pgsql_query_rules ORDER BY rule_id'

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

# Clean up only the runner container
echo ">>> Cleaning up Test Runner container"
docker rm -f "${TEST_CONTAINER}" >/dev/null 2>&1 || true
