#!/bin/bash
set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default INFRA_ID if not provided
export INFRA_ID="${INFRA_ID:-dev-$USER}"

NUM_NODES=${PROXYSQL_CLUSTER_NODES:-9}
if [[ "${SKIP_CLUSTER_START}" == "1" ]] || [[ "${SKIP_CLUSTER_START}" == "true" ]] || [[ "${NUM_NODES}" == "0" ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Cluster init SKIPPED (SKIP_CLUSTER_START=${SKIP_CLUSTER_START}, Nodes=${NUM_NODES})"
    exit 0
fi

IS_HOST=false
if command -v docker &> /dev/null; then IS_HOST=true; fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Cluster check/init ..."

# Helper to run SQL
run_sql() {
    local node_name=$1
    shift
    if [ "$IS_HOST" = true ]; then
        local container="${node_name}.${INFRA_ID}"
        docker exec -i "${container}" mysql -uadmin -padmin -h127.0.0.1 -P6032 "$@"
    else
        mysql -uadmin -padmin -h "${node_name}" -P 6032 "$@"
    fi
}

# Check if already initialized
if run_sql "proxysql" -e "SELECT hostname FROM proxysql_servers" 2>/dev/null | grep -q "proxy-node1"; then
    echo ">>> Cluster already initialized. Skipping."
    exit 0
fi

if [ "$IS_HOST" = false ]; then
    echo ">>> No Docker detected. Assuming coordinator will handle initialization. Skipping."
    exit 0
fi

echo ">>> Initializing Cluster Topology from Host..."

# 1. Configure the Primary node
run_sql "proxysql" <<SQL
SET admin-admin_credentials="admin:admin;radmin:radmin;cluster1:secret1pass";
SET admin-cluster_username="cluster1";
SET admin-cluster_password="secret1pass";
UPDATE global_variables SET variable_value='false' WHERE variable_name='admin-hash_passwords';

DELETE FROM proxysql_servers;
INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ("proxy-node1",6032,0,"core-node");
INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ("proxy-node2",6032,0,"core-node");
INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ("proxy-node3",6032,0,"core-node");

LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
LOAD PROXYSQL SERVERS TO RUNTIME;
SAVE PROXYSQL SERVERS TO DISK;
SQL

# 2. Configure the nodes
NUM_NODES=${PROXYSQL_CLUSTER_NODES:-9}
for i in $(seq 1 "${NUM_NODES}"); do
    NODE="proxy-node${i}"
    echo ">>> Configuring Node: ${NODE}"
    
    run_sql "${NODE}" <<SQL
UPDATE global_variables SET variable_value='false' WHERE variable_name='admin-hash_passwords';
SET admin-restapi_port=$((6070 + i));
SET admin-restapi_enabled='true';
SET admin-debug='true';

DELETE FROM proxysql_servers;
-- Every node should know about the Primary
INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ("proxysql",6032,0,"primary");
-- And the 3 core nodes
INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ("proxy-node1",6032,0,"core");
INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ("proxy-node2",6032,0,"core");
INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ("proxy-node3",6032,0,"core");

LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
LOAD PROXYSQL SERVERS TO RUNTIME;
SAVE PROXYSQL SERVERS TO DISK;
SQL
done

"${SCRIPT_DIR}/cluster_install_scheduler.bash"
echo ">>> Cluster initialization COMPLETE."
