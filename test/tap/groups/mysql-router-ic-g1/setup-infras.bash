#!/usr/bin/env bash
set -euo pipefail

: "${INFRA_ID:?INFRA_ID must be set}"
: "${WORKSPACE:?WORKSPACE must be set}"

PROXY_CONTAINER="proxysql.${INFRA_ID}"
BACKEND_CONTAINER="infra-mysql-router-ic-${INFRA_ID}-dbdeployer1-1"
BACKEND_HOST="dbdeployer1.infra-mysql-router-ic"
ROOT_PASSWORD=${ROOT_PASSWORD:-$(printf '%s' "${INFRA_ID}" | sha256sum | head -c 10)}
RESULT_DIR="${WORKSPACE}/ci_infra_logs/${INFRA_ID}/mysql-router"
PROXY_DATA_DIR="${WORKSPACE}/ci_infra_logs/${INFRA_ID}/proxysql"
PLUGIN="${WORKSPACE}/plugins/mysql_router/proxysql_mysql_router.so"
CONFIG="${WORKSPACE}/test/tap/groups/mysql-router-ic-g1/proxysql-ci.cnf"
SETUP_COMPLETE=0
PASSFILE=""

cleanup_setup() {
    local rc=$?
    trap - EXIT
    if [ -n "${PASSFILE}" ]; then
        rm -f "${PASSFILE}"
    fi
    if [ "${rc}" -ne 0 ] && [ "${SETUP_COMPLETE}" -eq 0 ]; then
        docker start "${PROXY_CONTAINER}" >/dev/null 2>&1 || true
        INFRA_ID="${INFRA_ID}" WORKSPACE="${WORKSPACE}" ROOT_PASSWORD="${ROOT_PASSWORD}" \
            "${WORKSPACE}/test/tap/groups/mysql-router-ic-g1/pre-cleanup.bash" || true
    fi
    exit "${rc}"
}
trap cleanup_setup EXIT

mkdir -p "${RESULT_DIR}"
chmod 777 "${RESULT_DIR}"

run_mysqlsh() {
    local script=$1
    docker exec \
        -e MYSQL_ROUTER_IC_HOST="${BACKEND_HOST}" \
        -e MYSQL_ROUTER_IC_PASSWORD="${ROOT_PASSWORD}" \
        -e MYSQL_ROUTER_SHELL_ROUTER="${MYSQL_ROUTER_SHELL_ROUTER:-}" \
        "${BACKEND_CONTAINER}" mysqlsh --no-wizard --js --file "${script}"
}

SETUP_OUTPUT="${RESULT_DIR}/innodb_cluster_setup.log"
run_mysqlsh "${WORKSPACE}/test/tap/tests/mysql_router/innodb_cluster_setup.js" \
    | tee "${SETUP_OUTPUT}"
grep '^MYSQL_ROUTER_FIXTURE=' "${SETUP_OUTPUT}" | tail -1 \
    | sed 's/^MYSQL_ROUTER_FIXTURE=//' > "${RESULT_DIR}/fixture.json"
test -s "${RESULT_DIR}/fixture.json"

docker exec -i "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 <<SQL
INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,comment)
VALUES
    (77,'${BACKEND_HOST}',3306,'ONLINE','mysql-router-e2e-operator'),
    (77,'${BACKEND_HOST}',3307,'ONLINE','mysql-router-e2e-operator'),
    (77,'${BACKEND_HOST}',3308,'ONLINE','mysql-router-e2e-operator');
INSERT INTO mysql_users(username,password,active,default_hostgroup,frontend,backend,comment)
VALUES('operator_user','operator-password',1,77,1,1,'mysql-router-e2e-operator');
INSERT INTO mysql_query_rules(rule_id,active,username,destination_hostgroup,apply,comment)
VALUES(777001,1,'operator_user',77,1,'mysql-router-e2e-operator');
LOAD MYSQL SERVERS TO RUNTIME;
LOAD MYSQL USERS TO RUNTIME;
LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;
SAVE MYSQL USERS TO DISK;
SAVE MYSQL QUERY RULES TO DISK;
SQL

umask 077
PASSFILE="${RESULT_DIR}/bootstrap.password"
printf '%s\n' "${ROOT_PASSWORD}" > "${PASSFILE}"

docker stop "${PROXY_CONTAINER}" >/dev/null
BOOTSTRAP_LOG="${RESULT_DIR}/bootstrap.log"
set +e
docker run --rm \
    --name "mysql-router-bootstrap.${INFRA_ID}" \
    --hostname proxysql-e2e \
    --network "${INFRA_ID}_backend" \
    -v "${WORKSPACE}/src/proxysql:/usr/bin/proxysql:ro" \
    -v "${PLUGIN}:/usr/lib/proxysql/plugins/proxysql_mysql_router.so:ro" \
    -v "${CONFIG}:/etc/proxysql.cnf:ro" \
    -v "${PROXY_DATA_DIR}:/var/lib/proxysql" \
    -v "${PASSFILE}:/run/secrets/bootstrap_password:ro" \
    proxysql-ci-base:latest /bin/bash -c '
        exec 9</run/secrets/bootstrap_password
        /usr/bin/proxysql --idle-threads -f -c /etc/proxysql.cnf -D /var/lib/proxysql \
            --plugin-dir=/usr/lib/proxysql/plugins --load-plugin=mysql_router \
            --bootstrap root@dbdeployer1.infra-mysql-router-ic:3306 \
            --bootstrap-password-fd 9 --router-name proxysql-e2e \
            --ssl-mode=DISABLED &
        pid=$!
        tr "\0" " " < "/proc/${pid}/cmdline" > /var/lib/proxysql/bootstrap.cmdline
        wait "${pid}"
    ' >"${BOOTSTRAP_LOG}" 2>&1
BOOTSTRAP_RC=$?
set -e
rm -f "${PASSFILE}"
if [ "${BOOTSTRAP_RC}" -ne 0 ]; then
	if grep -Fq "${ROOT_PASSWORD}" "${BOOTSTRAP_LOG}" "${PROXY_DATA_DIR}/bootstrap.cmdline"; then
		echo "ERROR: bootstrap credential appeared in captured bootstrap output" >&2
		exit 1
	fi
	cat "${BOOTSTRAP_LOG}" >&2
    exit "${BOOTSTRAP_RC}"
fi
if grep -Fq "${ROOT_PASSWORD}" "${BOOTSTRAP_LOG}" "${PROXY_DATA_DIR}/bootstrap.cmdline"; then
    echo "ERROR: bootstrap credential leaked to output or process arguments" >&2
    exit 1
fi

docker start "${PROXY_CONTAINER}" >/dev/null
for attempt in $(seq 1 60); do
    if docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 \
        -NBe 'SELECT 1' >/dev/null 2>&1; then
        break
    fi
    if [ "${attempt}" = 60 ]; then
        docker logs "${PROXY_CONTAINER}" >&2 || true
        exit 1
    fi
    sleep 1
done

for port in 6446 6447 6450; do
    for attempt in $(seq 1 60); do
        if docker exec "${PROXY_CONTAINER}" bash -c "exec 3<>/dev/tcp/127.0.0.1/${port}" 2>/dev/null; then
            break
        fi
        if [ "${attempt}" = 60 ]; then
            docker logs "${PROXY_CONTAINER}" >&2 || true
            echo "ERROR: Router endpoint ${port} did not open" >&2
            exit 1
        fi
        sleep 1
    done
done

MYSQL_ROUTER_SHELL_ROUTER=$(docker exec "${BACKEND_CONTAINER}" mysql \
	-h"${BACKEND_HOST}" -P3306 -uroot -p"${ROOT_PASSWORD}" -NBe \
    "SELECT CONCAT(address,'::',router_name) FROM mysql_innodb_cluster_metadata.v2_routers ORDER BY router_id DESC LIMIT 1")
export MYSQL_ROUTER_SHELL_ROUTER
printf '%s\n' "${MYSQL_ROUTER_SHELL_ROUTER}" > "${RESULT_DIR}/router-key"

SHELL_OUTPUT="${RESULT_DIR}/shell_contract.log"
run_mysqlsh "${WORKSPACE}/test/tap/tests/mysql_router/assert_shell_contract.js" \
    | tee "${SHELL_OUTPUT}"
grep '^MYSQL_ROUTER_SHELL_CONTRACT=' "${SHELL_OUTPUT}" | tail -1 \
    | sed 's/^MYSQL_ROUTER_SHELL_CONTRACT=//' > "${RESULT_DIR}/shell-contract.json"
test -s "${RESULT_DIR}/shell-contract.json"

docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 \
    -e 'MYSQL ROUTER RECONCILE' >/dev/null
SETUP_COMPLETE=1
