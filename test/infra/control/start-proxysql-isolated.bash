#!/bin/bash
set -e
set -o pipefail

# SUDO helper: empty if root
SUDO=""
if [ "$(id -u)" != "0" ]; then SUDO="sudo"; fi

# Derive Workspace relative to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

if [ -z "${INFRA_ID}" ]; then echo "Error: INFRA_ID is not set."; exit 1; fi

export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)

NETWORK_NAME="${INFRA_ID}_backend"
PROXY_CONTAINER="proxysql.${INFRA_ID}"
INFRA_LOGS_PATH="${WORKSPACE}/ci_infra_logs"
PROXY_DATA_DIR="${INFRA_LOGS_PATH}/${INFRA_ID}/proxysql"
GENERIC_CONFIG="${SCRIPT_DIR}/proxysql-ci.cnf"

# Per-group override: a TAP group may need a config that differs from
# the generic one (e.g. to declare a `plugins=("...")` line so the
# chassis loads the mysqlx plugin at Phase A). The env var
# PROXYSQL_CONFIG_OVERRIDE is set by the group's env.sh when needed.
if [ -n "${PROXYSQL_CONFIG_OVERRIDE:-}" ] && [ -f "${PROXYSQL_CONFIG_OVERRIDE}" ]; then
    GENERIC_CONFIG="${PROXYSQL_CONFIG_OVERRIDE}"
    echo ">>> Using per-group ProxySQL config override: ${GENERIC_CONFIG}"
fi

# Cluster configuration
NUM_NODES=${PROXYSQL_CLUSTER_NODES:-9}
if [[ "${SKIP_CLUSTER_START}" == "1" ]] || [[ "${SKIP_CLUSTER_START}" == "true" ]]; then
    NUM_NODES=0
fi

# Coverage data directory (separate per INFRA_ID to avoid parallel write conflicts)
COVERAGE_DATA_DIR="${INFRA_LOGS_PATH}/${INFRA_ID}/gcov"
mkdir -p "${COVERAGE_DATA_DIR}"

echo ">>> Setting up isolated network: ${NETWORK_NAME}"
docker network inspect ${NETWORK_NAME} >/dev/null 2>&1 || docker network create ${NETWORK_NAME}

echo ">>> Preparing ProxySQL data directory: ${PROXY_DATA_DIR}"
$SUDO mkdir -p "${PROXY_DATA_DIR}"
$SUDO chmod -R 777 "${INFRA_LOGS_PATH}/${INFRA_ID}"
$SUDO rm -f "${PROXY_DATA_DIR}/proxysql.db" "${PROXY_DATA_DIR}"/*.pem

docker rm -f "${PROXY_CONTAINER}" >/dev/null 2>&1 || true

# Build the startup command for the container.
# Primary ProxySQL runs in foreground. Cluster nodes (if any) run as
# background processes inside the same container, each with its own
# data directory and port pair.
#
# Port scheme:
#   Primary:     admin=6032, mysql=6033, pgsql=6133
#   proxy-node1: admin=6042, mysql=6043
#   proxy-node2: admin=6052, mysql=6053
#   ...
#   proxy-nodeN: admin=6032+(N*10), mysql=6033+(N*10)

STARTUP_CMD="
# Save GCOV env for the primary process
SAVED_GCOV_PREFIX=\${GCOV_PREFIX:-}
SAVED_GCOV_PREFIX_STRIP=\${GCOV_PREFIX_STRIP:-}

# Disable gcov for background cluster nodes to avoid concurrent .gcda writes
unset GCOV_PREFIX GCOV_PREFIX_STRIP

# Start cluster nodes as background processes
for i in \$(seq 1 ${NUM_NODES}); do
    ADMIN_PORT=\$((6032 + i * 10))
    MYSQL_PORT=\$((6033 + i * 10))
    NODE_DIR=/var/lib/proxysql-node\${i}
    mkdir -p \${NODE_DIR}

    PGSQL_PORT=\$((7133 + i * 10))
    PGSQL_ADMIN_PORT=\$((7132 + i * 10))
    SQLITE_PORT=\$((7030 + i * 10))
    cat > \${NODE_DIR}/proxysql-node.cnf <<NODECNF
admin_variables=
{
    admin_credentials=\"admin:admin;radmin:radmin;cluster1:secret1pass\"
    mysql_ifaces=\"0.0.0.0:\${ADMIN_PORT}\"
    pgsql_ifaces=\"0.0.0.0:\${PGSQL_ADMIN_PORT}\"
    cluster_username=\"cluster1\"
    cluster_password=\"secret1pass\"
}
mysql_variables=
{
    threads=4
    max_connections=2048
    interfaces=\"0.0.0.0:\${MYSQL_PORT}\"
}
pgsql_variables=
{
    interfaces=\"0.0.0.0:\${PGSQL_PORT}\"
}
sqliteserver_variables=
{
    mysql_ifaces=\"0.0.0.0:\${SQLITE_PORT}\"
}
NODECNF

    /usr/bin/proxysql --idle-threads -f -c \${NODE_DIR}/proxysql-node.cnf -D \${NODE_DIR} >> \${NODE_DIR}/proxysql.log 2>&1 &
    echo \"Started proxy-node\${i} (admin=\${ADMIN_PORT}, mysql=\${MYSQL_PORT})\"
done

# Restore GCOV env for the primary process
export GCOV_PREFIX=\${SAVED_GCOV_PREFIX}
export GCOV_PREFIX_STRIP=\${SAVED_GCOV_PREFIX_STRIP}

# Start primary ProxySQL in foreground
exec /usr/bin/proxysql --idle-threads --clickhouse-server --sqlite3-server -f -c /etc/proxysql.cnf -D /var/lib/proxysql 2>&1 | tee /var/lib/proxysql/proxysql.log
"

# Optional: mount the mysqlx plugin .so into the container when the
# group asked for it via PROXYSQL_LOAD_MYSQLX_PLUGIN=1. The .so must
# already exist on the host (built via `make` in plugins/mysqlx). The
# plugin path is exposed inside the container at a stable location;
# the per-group setup-infras.bash adds `plugins=("/usr/lib/proxysql/
# ProxySQL_MySQLX_Plugin.so")` to ProxySQL's runtime config before any
# admin command provisioning.
MYSQLX_PLUGIN_SRC="${WORKSPACE}/plugins/mysqlx/ProxySQL_MySQLX_Plugin.so"
MYSQLX_PLUGIN_MOUNT=""
if [ "${PROXYSQL_LOAD_MYSQLX_PLUGIN:-0}" = "1" ]; then
    if [ ! -f "${MYSQLX_PLUGIN_SRC}" ]; then
        echo "ERROR: PROXYSQL_LOAD_MYSQLX_PLUGIN=1 but plugin .so missing at ${MYSQLX_PLUGIN_SRC}" >&2
        echo "       Build it first: cd plugins/mysqlx && make (with PROXYSQL40=1 etc)" >&2
        exit 1
    fi
    MYSQLX_PLUGIN_MOUNT="-v ${MYSQLX_PLUGIN_SRC}:/usr/lib/proxysql/ProxySQL_MySQLX_Plugin.so:ro"
    echo ">>> Mounting mysqlx plugin .so into ProxySQL container"
fi

echo ">>> Starting ProxySQL container: ${PROXY_CONTAINER} (cluster nodes: ${NUM_NODES})"
docker run -d \
    --name "${PROXY_CONTAINER}" \
    --hostname "proxysql" \
    --network "${NETWORK_NAME}" \
    --network-alias "proxysql" \
    -v "${WORKSPACE}/src/proxysql:/usr/bin/proxysql" \
    -v "${GENERIC_CONFIG}:/etc/proxysql.cnf" \
    -v "${PROXY_DATA_DIR}:/var/lib/proxysql" \
    -v "${COVERAGE_DATA_DIR}:/gcov" \
    ${MYSQLX_PLUGIN_MOUNT} \
    -e GCOV_PREFIX="/gcov" \
    -e GCOV_PREFIX_STRIP="3" \
    proxysql-ci-base:latest \
    /bin/bash -c "${STARTUP_CMD}"

if [ -f /.dockerenv ]; then
    RUNNER_ID=$(hostname)
    docker network connect "${NETWORK_NAME}" "${RUNNER_ID}" || true
fi

# Wait for primary
echo -n "Waiting for ${PROXY_CONTAINER}:6032 "
MAX_WAIT=30
COUNT=0
while [ $COUNT -lt $MAX_WAIT ]; do
    if docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 -e 'SELECT 1' >/dev/null 2>&1; then
        docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 -e "
            SET clickhouse-mysql_ifaces='0.0.0.0:8000';
            LOAD CLICKHOUSE VARIABLES TO RUNTIME;
        " >/dev/null 2>&1 || true
        echo " Ready."
        break
    fi
    echo -n "."
    sleep 1
    COUNT=$((COUNT+1))
done
if [ $COUNT -ge $MAX_WAIT ]; then echo " TIMEOUT"; exit 1; fi

# Wait for cluster nodes
for i in $(seq 1 "${NUM_NODES}"); do
    ADMIN_PORT=$((6032 + i * 10))
    echo -n "Waiting for proxy-node${i} (port ${ADMIN_PORT}) "
    COUNT=0
    while [ $COUNT -lt $MAX_WAIT ]; do
        if docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P${ADMIN_PORT} -e 'SELECT 1' >/dev/null 2>&1; then
            echo " OK."
            break
        fi
        echo -n "."
        sleep 1
        COUNT=$((COUNT+1))
    done
    if [ $COUNT -ge $MAX_WAIT ]; then echo " TIMEOUT (node ${i})"; exit 1; fi
done

# Initialize cluster if nodes were started
if [ "${NUM_NODES}" -gt 0 ]; then
    echo ">>> Initializing ProxySQL Cluster (${NUM_NODES} nodes)..."

    MYSQL_CMD="docker exec -i ${PROXY_CONTAINER} mysql -uadmin -padmin -h127.0.0.1"

    # Build proxysql_servers entries: primary + up to first 3 nodes as core
    CORE_NODES=3
    if [ "${NUM_NODES}" -lt 3 ]; then CORE_NODES="${NUM_NODES}"; fi
    PROXYSQL_SERVERS_SQL="DELETE FROM proxysql_servers;"
    # Include the primary itself — if a node syncs proxysql_servers from the primary,
    # the primary must be in the list, otherwise the node drops its monitor thread
    # for the primary and never detects checksum changes again.
    PROXYSQL_SERVERS_SQL="${PROXYSQL_SERVERS_SQL} INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ('proxysql',6032,0,'primary');"
    for i in $(seq 1 "${CORE_NODES}"); do
        PORT=$((6032 + i * 10))
        PROXYSQL_SERVERS_SQL="${PROXYSQL_SERVERS_SQL} INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ('proxysql',${PORT},0,'core-node${i}');"
    done

    # Configure primary — set the same admin variables as nodes so checksums match
    ${MYSQL_CMD} -P6032 <<SQL
SET admin-admin_credentials="admin:admin;radmin:radmin;cluster1:secret1pass";
SET admin-cluster_username="cluster1";
SET admin-cluster_password="secret1pass";
SET admin-cluster_mysql_servers_sync_algorithm=3;
SET admin-restapi_enabled='true';
SET admin-debug='true';
UPDATE global_variables SET variable_value='false' WHERE variable_name='admin-hash_passwords';
${PROXYSQL_SERVERS_SQL}
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
LOAD PROXYSQL SERVERS TO RUNTIME;
SAVE PROXYSQL SERVERS TO DISK;
SQL

    # Configure each node
    for i in $(seq 1 "${NUM_NODES}"); do
        ADMIN_PORT=$((6032 + i * 10))
        RESTAPI_PORT=$((7070 + i))
        echo ">>> Configuring proxy-node${i} (port ${ADMIN_PORT})"

        ${MYSQL_CMD} -P${ADMIN_PORT} <<SQL
UPDATE global_variables SET variable_value='false' WHERE variable_name='admin-hash_passwords';
SET admin-cluster_mysql_servers_sync_algorithm=3;
SET admin-restapi_port=${RESTAPI_PORT};
SET admin-restapi_enabled='true';
SET admin-debug='true';
${PROXYSQL_SERVERS_SQL}
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
LOAD PROXYSQL SERVERS TO RUNTIME;
SAVE PROXYSQL SERVERS TO DISK;
SQL
    done

    # Install scheduler (check_all_nodes) on primary and core nodes
    echo ">>> Installing scheduler on cluster nodes..."
    SCHEDULER_SCRIPT="${SCRIPT_DIR}/check_all_nodes.bash"

    # Install on primary
    docker cp "${SCHEDULER_SCRIPT}" "${PROXY_CONTAINER}:/tmp/check_all_nodes.bash"
    docker exec "${PROXY_CONTAINER}" chmod +x /tmp/check_all_nodes.bash

    ${MYSQL_CMD} -P6032 <<SQL
INSERT OR REPLACE INTO scheduler (interval_ms, filename) VALUES (12000, '/tmp/check_all_nodes.bash');
LOAD SCHEDULER TO RUNTIME;
SAVE SCHEDULER TO DISK;
SQL

    # Install on core nodes
    for i in $(seq 1 "${CORE_NODES}"); do
        ADMIN_PORT=$((6032 + i * 10))
        ${MYSQL_CMD} -P${ADMIN_PORT} <<SQL
INSERT OR REPLACE INTO scheduler (interval_ms, filename) VALUES (12000, '/tmp/check_all_nodes.bash');
LOAD SCHEDULER TO RUNTIME;
SAVE SCHEDULER TO DISK;
SQL
    done

    echo ">>> ProxySQL Cluster initialized (${NUM_NODES} nodes in single container)."
fi

echo ">>> ProxySQL is UP."
