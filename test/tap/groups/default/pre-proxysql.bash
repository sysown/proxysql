#!/usr/bin/env bash
set -e
set -o pipefail
#
# Default pre-proxysql hook.
#
# Cluster startup is now handled by start-proxysql-isolated.bash
# (controlled by SKIP_CLUSTER_START and PROXYSQL_CLUSTER_NODES).
# This hook only needs to wait for the cluster to stabilize.
#

NUM_NODES=${PROXYSQL_CLUSTER_NODES:-9}
if [[ "${SKIP_CLUSTER_START}" == "1" ]] || [[ "${SKIP_CLUSTER_START}" == "true" ]] || [[ "${NUM_NODES}" == "0" ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Pre-proxysql: no cluster, nothing to do."
    exit 0
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Pre-proxysql: waiting for cluster to stabilize..."
sleep 10
