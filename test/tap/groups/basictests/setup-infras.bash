#!/bin/bash
set -e
set -o pipefail
#
# Basictests setup hook
#
# The in-repo infra configures servers in hostgroup pairs like 1300/1301.
# The legacy test scripts (proxysql-tester.py benchmark) expect servers
# in hostgroups 0 and 1. This hook copies the first hostgroup pair into
# hostgroups 0/1 and remaps users/rules accordingly.
#

export INFRA_ID="${INFRA_ID:-dev-$USER}"
PROXY_CONTAINER="proxysql.${INFRA_ID}"

MYSQL_CMD="docker exec ${PROXY_CONTAINER} mysql -uradmin -pradmin -h127.0.0.1 -P6032 -NB"

# Find the first writer/reader hostgroup pair from mysql_replication_hostgroups
PAIR=$(${MYSQL_CMD} -e "SELECT writer_hostgroup, reader_hostgroup FROM mysql_replication_hostgroups LIMIT 1;" 2>/dev/null)
if [ -z "${PAIR}" ]; then
    echo ">>> No replication hostgroups found. Skipping hostgroup aliasing."
    exit 0
fi

WRITER_HG=$(echo "${PAIR}" | awk '{print $1}')
READER_HG=$(echo "${PAIR}" | awk '{print $2}')

if [ "${WRITER_HG}" = "0" ] && [ "${READER_HG}" = "1" ]; then
    echo ">>> Hostgroups already 0/1. Skipping aliasing."
    exit 0
fi

echo ">>> Aliasing hostgroup pair ${WRITER_HG}/${READER_HG} -> 0/1"

# Copy servers from the original hostgroups into 0/1
${MYSQL_CMD} -e "
    INSERT OR IGNORE INTO mysql_servers (hostgroup_id, hostname, port, max_connections, comment)
        SELECT 0, hostname, port, max_connections, comment
        FROM mysql_servers WHERE hostgroup_id = ${WRITER_HG};
    INSERT OR IGNORE INTO mysql_servers (hostgroup_id, hostname, port, max_connections, comment)
        SELECT 1, hostname, port, max_connections, comment
        FROM mysql_servers WHERE hostgroup_id = ${READER_HG};
    INSERT OR IGNORE INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, comment)
        VALUES (0, 1, 'basictests alias');
"

# Remap users, query rules, and replication hostgroups to 0/1
${MYSQL_CMD} -e "UPDATE mysql_users SET default_hostgroup = 0 WHERE default_hostgroup = ${WRITER_HG};"
${MYSQL_CMD} -e "UPDATE mysql_query_rules SET destination_hostgroup = 0 WHERE destination_hostgroup = ${WRITER_HG};"
${MYSQL_CMD} -e "UPDATE mysql_query_rules SET destination_hostgroup = 1 WHERE destination_hostgroup = ${READER_HG};"

# Load all changes to runtime
${MYSQL_CMD} -e "LOAD MYSQL SERVERS TO RUNTIME;"
${MYSQL_CMD} -e "LOAD MYSQL USERS TO RUNTIME;"
${MYSQL_CMD} -e "LOAD MYSQL QUERY RULES TO RUNTIME;"

echo ">>> Hostgroup aliasing done."
