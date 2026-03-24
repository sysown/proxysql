#!/bin/bash
set -e
set -o pipefail
#
# Basictests setup hook
#
# The in-repo infra configures servers in hostgroup pairs like 1300/1301.
# The legacy test scripts (proxysql-tester.py benchmark) expect servers
# in hostgroups 0 and 1. This hook moves everything from the original
# pair to 0/1 and removes the originals to avoid monitor conflicts.
#

export INFRA_ID="${INFRA_ID:-dev-$USER}"
PROXY_CONTAINER="proxysql.${INFRA_ID}"

MYSQL_CMD="docker exec ${PROXY_CONTAINER} mysql -uradmin -pradmin -h127.0.0.1 -P6032 -NB"

# Find the first writer/reader hostgroup pair
PAIR=$(${MYSQL_CMD} -e "SELECT writer_hostgroup, reader_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup != 0 LIMIT 1;" 2>/dev/null)
if [ -z "${PAIR}" ]; then
    echo ">>> No non-zero replication hostgroups found. Skipping."
    exit 0
fi

WRITER_HG=$(echo "${PAIR}" | awk '{print $1}')
READER_HG=$(echo "${PAIR}" | awk '{print $2}')

echo ">>> Remapping hostgroup pair ${WRITER_HG}/${READER_HG} -> 0/1"

# Move servers: copy into target hostgroups with INSERT OR REPLACE, then remove originals.
# Cannot UPDATE in-place because hostgroup 0/1 may already have entries with the same
# hostname:port, causing a UNIQUE constraint violation.
${MYSQL_CMD} -e "INSERT OR REPLACE INTO mysql_servers (hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) SELECT 0, hostname, port, gtid_port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers WHERE hostgroup_id = ${WRITER_HG};"
${MYSQL_CMD} -e "INSERT OR REPLACE INTO mysql_servers (hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) SELECT 1, hostname, port, gtid_port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers WHERE hostgroup_id = ${READER_HG};"
${MYSQL_CMD} -e "DELETE FROM mysql_servers WHERE hostgroup_id = ${WRITER_HG};"
${MYSQL_CMD} -e "DELETE FROM mysql_servers WHERE hostgroup_id = ${READER_HG};"

# Replace replication hostgroup mapping
${MYSQL_CMD} -e "DELETE FROM mysql_replication_hostgroups WHERE writer_hostgroup = ${WRITER_HG};"
${MYSQL_CMD} -e "INSERT OR REPLACE INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, comment) VALUES (0, 1, 'basictests');"

# Update users
${MYSQL_CMD} -e "UPDATE mysql_users SET default_hostgroup = 0 WHERE default_hostgroup = ${WRITER_HG};"

# Update query rules
${MYSQL_CMD} -e "UPDATE mysql_query_rules SET destination_hostgroup = 0 WHERE destination_hostgroup = ${WRITER_HG};"
${MYSQL_CMD} -e "UPDATE mysql_query_rules SET destination_hostgroup = 1 WHERE destination_hostgroup = ${READER_HG};"

# Load all to runtime
${MYSQL_CMD} -e "LOAD MYSQL SERVERS TO RUNTIME;"
${MYSQL_CMD} -e "LOAD MYSQL USERS TO RUNTIME;"
${MYSQL_CMD} -e "LOAD MYSQL QUERY RULES TO RUNTIME;"

echo ">>> Hostgroup remapping done."
