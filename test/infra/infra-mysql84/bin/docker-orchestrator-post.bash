#!/bin/bash
set -e
set -o pipefail
[ -f .env ] && . .env

# Ensure INFRA is set correctly
if [ -z "${INFRA}" ] || [ "${INFRA}" == "." ]; then
    export INFRA=$(basename $(cd $(dirname $0)/.. && pwd))
fi

PROXY_CONTAINER="proxysql.${INFRA_ID}"

echo ">>> Configuring Orchestrator via ${PROXY_CONTAINER} (Infra: ${INFRA})"

orc_exec() {
    docker exec -e ORCHESTRATOR_API="http://orc1.${INFRA}:3000/api" "${PROXY_CONTAINER}" orchestrator-client "$@"
}

echo -n "Waiting for Orchestrator API..."
MAX_WAIT=60
COUNT=0
while ! orc_exec -c clusters >/dev/null 2>&1; do
    echo -n "."
    sleep 2
    COUNT=$((COUNT+2))
    if [ $COUNT -gt $MAX_WAIT ]; then echo " FAILED"; exit 1; fi
done
echo " OK."

# Use -c discover and -i host:port
echo ">>> Triggering discovery of MySQL nodes..."
for i in 1 2 3; do
    HOST="mysql${i}.${INFRA}"
    orc_exec -c discover -i "${HOST}:3306" >/dev/null 2>&1 || true
done

echo ">>> Waiting for topology to settle..."
MAX_WAIT=30
COUNT=0
CLUSTER_NAME=""
while [ -z "$CLUSTER_NAME" ]; do
    # Try to find which cluster our primary belongs to
    CLUSTER_NAME=$(orc_exec -c which-cluster -i "mysql1.${INFRA}:3306" 2>/dev/null | head -n 1)
    
    # Fallback: Just take any cluster name if which-cluster fails but clusters is not empty
    if [ -z "$CLUSTER_NAME" ]; then
        CLUSTER_NAME=$(orc_exec -c clusters 2>/dev/null | head -n 1)
    fi

    if [ -n "$CLUSTER_NAME" ]; then break; fi
    echo -n "."
    sleep 2
    COUNT=$((COUNT+2))
    if [ $COUNT -gt $MAX_WAIT ]; then 
        echo " WARNING: Still waiting for cluster discovery after ${MAX_WAIT}s"
        break
    fi
done
echo " OK."

if [ -n "$CLUSTER_NAME" ]; then
    echo ">>> Verifying Replication Topology for Cluster: ${CLUSTER_NAME}"
    echo "--------------------------------------------------------------------------------"
    # We use -c topology -i to get the text diagram
    TOPOLOGY=$(orc_exec -c topology -i "${CLUSTER_NAME}")
    echo "$TOPOLOGY"
    echo "--------------------------------------------------------------------------------"

    # Check for replication issues (look for anything not [ok])
    # Note: Orchestrator topology output uses [ok] for healthy nodes
    ISSUES=$(echo "$TOPOLOGY" | grep -E "\[.*\]" | grep -v "\[ok\]" || true)
    if [ -n "$ISSUES" ]; then
        echo "WARNING: Potential replication issues detected in topology!"
        echo "$ISSUES"
    else
        echo "SUCCESS: Replication topology is healthy."
    fi
else
    echo "ERROR: Orchestrator failed to discover any cluster."
    exit 1
fi
