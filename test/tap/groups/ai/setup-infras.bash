#!/usr/bin/env bash
set -euo pipefail
#
# AI TAP Group Post-Infrastructure Hook
# Executed by ensure-infras.bash after all backends are running
# Configures MCP and seeds test data
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check required environment variables
if [ -z "${INFRA_ID:-}" ]; then
    echo "ERROR: INFRA_ID is not set"
    exit 1
fi

if [ -z "${WORKSPACE:-}" ]; then
    echo "ERROR: WORKSPACE is not set"
    exit 1
fi

# Derive DEFAULT_MYSQL_INFRA and DEFAULT_PGSQL_INFRA from infras.lst if not set
if [ -z "${DEFAULT_MYSQL_INFRA:-}" ] || [ -z "${DEFAULT_PGSQL_INFRA:-}" ]; then
    INFRAS_LST="${SCRIPT_DIR}/infras.lst"
    if [ -f "${INFRAS_LST}" ]; then
        for INFRA_NAME in $(cat "${INFRAS_LST}"); do
            if [[ "${INFRA_NAME}" == *mysql* ]] || [[ "${INFRA_NAME}" == *mariadb* ]]; then
                DEFAULT_MYSQL_INFRA="${DEFAULT_MYSQL_INFRA:-${INFRA_NAME}}"
            fi
            if [[ "${INFRA_NAME}" == *pgsql* ]] || [[ "${INFRA_NAME}" == *pgdb* ]]; then
                DEFAULT_PGSQL_INFRA="${DEFAULT_PGSQL_INFRA:-${INFRA_NAME}}"
            fi
        done
    fi
fi

# Validate that required infrastructure names were resolved
if [ -z "${DEFAULT_MYSQL_INFRA:-}" ]; then
    echo "ERROR: Could not resolve DEFAULT_MYSQL_INFRA (check ${SCRIPT_DIR}/infras.lst)"
    exit 1
fi

if [ -z "${DEFAULT_PGSQL_INFRA:-}" ]; then
    echo "ERROR: Could not resolve DEFAULT_PGSQL_INFRA (check ${SCRIPT_DIR}/infras.lst)"
    exit 1
fi

export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)
PROXY_CONTAINER="proxysql.${INFRA_ID}"

# Wait for ProxySQL admin to be ready
echo ">>> AI post-infras hook: Waiting for ProxySQL admin..."
MAX_WAIT=30
COUNT=0
while [ $COUNT -lt $MAX_WAIT ]; do
    if docker exec "${PROXY_CONTAINER}" mysql -uradmin -pradmin -h127.0.0.1 -P6032 -e "SELECT 1" >/dev/null 2>&1; then
        echo ">>> ProxySQL admin is ready"
        break
    fi
    echo -n "."
    sleep 1
    COUNT=$((COUNT+1))
done

if [ $COUNT -ge $MAX_WAIT ]; then
    echo " TIMEOUT - ProxySQL admin not accessible"
    exit 1
fi

# Configure MCP
echo ">>> AI post-infras hook: Configuring MCP..."

# Set MCP-specific environment variables (with defaults)
export TAP_MCPPORT="${TAP_MCPPORT:-6071}"
export TAP_MCP_AUTH_TOKEN="${TAP_MCP_AUTH_TOKEN:-tap-mcp-token}"
export MCP_TARGET_ID="${MCP_TARGET_ID:-tap_mysql_default}"
export MCP_AUTH_PROFILE_ID="${MCP_AUTH_PROFILE_ID:-tap_mysql_auth}"
export MCP_PGSQL_TARGET_ID="${MCP_PGSQL_TARGET_ID:-tap_pgsql_default}"
export MCP_PGSQL_AUTH_PROFILE_ID="${MCP_PGSQL_AUTH_PROFILE_ID:-tap_pgsql_auth}"
export MCP_MYSQL_HOSTGROUP_ID="${MCP_MYSQL_HOSTGROUP_ID:-9100}"
export MCP_PGSQL_HOSTGROUP_ID="${MCP_PGSQL_HOSTGROUP_ID:-9200}"
export MYSQL_DATABASE="${MYSQL_DATABASE:-test}"
export PGSQL_DATABASE="${PGSQL_DATABASE:-postgres}"

# Set backend connection variables
export TAP_MYSQLHOST="mysql1.${DEFAULT_MYSQL_INFRA}"
export TAP_MYSQLPORT="3306"
export TAP_MYSQLUSERNAME="root"
export TAP_MYSQLPASSWORD="${ROOT_PASSWORD}"
export TAP_PGSQLSERVER_HOST="pgsql1.${DEFAULT_PGSQL_INFRA}"
export TAP_PGSQLSERVER_PORT="5432"
export TAP_PGSQLSERVER_USERNAME="postgres"
export TAP_PGSQLSERVER_PASSWORD="${ROOT_PASSWORD}"

# envsubst is a textual renderer, so publish a separate value that is safe
# inside a single-quoted Admin SQL literal. ProxySQL's Admin parser accepts
# doubled quotes and backslashes in the same form as the MySQL client API.
TAP_MCP_AUTH_TOKEN_SQL="${TAP_MCP_AUTH_TOKEN//\\/\\\\}"
TAP_MCP_AUTH_TOKEN_SQL="${TAP_MCP_AUTH_TOKEN_SQL//\'/\'\'}"
export TAP_MCP_AUTH_TOKEN_SQL

# Apply MCP configuration
MCP_CONFIG_SQL="${SCRIPT_DIR}/mcp-config.sql"
if [ -f "${MCP_CONFIG_SQL}" ]; then
    if command -v envsubst >/dev/null 2>&1; then
        envsubst < "${MCP_CONFIG_SQL}" | docker exec -i "${PROXY_CONTAINER}" mysql -uradmin -pradmin -h127.0.0.1 -P6032
    else
        # Fallback: use bash variable expansion
        bash -c "cat <<EOF
$(cat "${MCP_CONFIG_SQL}")
EOF" | docker exec -i "${PROXY_CONTAINER}" mysql -uradmin -pradmin -h127.0.0.1 -P6032
    fi
    echo ">>> MCP configuration completed"
else
    echo ">>> WARNING: MCP config SQL not found at ${MCP_CONFIG_SQL}"
fi

# Seed test data on MySQL
echo ">>> AI post-infras hook: Seeding MySQL test data..."
MYSQL_SEED_SQL="${SCRIPT_DIR}/seed-mysql.sql"
if [ -f "${MYSQL_SEED_SQL}" ]; then
    # Seed only mysql1 (replication will propagate to others)
    MYSQL1_CONTAINER="${DEFAULT_MYSQL_INFRA}-${INFRA_ID}-mysql1-1"
    docker exec -i "${MYSQL1_CONTAINER}" mysql -h127.0.0.1 -uroot -p"${ROOT_PASSWORD}" < "${MYSQL_SEED_SQL}" || echo ">>> WARNING: MySQL seed may have partially failed (data may already exist)"
    echo ">>> MySQL test data seeding completed"
else
    echo ">>> WARNING: MySQL seed SQL not found at ${MYSQL_SEED_SQL}"
fi

# Seed test data on PostgreSQL
echo ">>> AI post-infras hook: Seeding PostgreSQL test data..."
PGSQL_SEED_SQL="${SCRIPT_DIR}/seed-pgsql.sql"
if [ -f "${PGSQL_SEED_SQL}" ]; then
    PGSQL_CONTAINER="${DEFAULT_PGSQL_INFRA}-${INFRA_ID}-pgdb1-1"
    docker exec -i "${PGSQL_CONTAINER}" psql -X -Upostgres < "${PGSQL_SEED_SQL}" || echo ">>> WARNING: PostgreSQL seed may have partially failed (data may already exist)"
    echo ">>> PostgreSQL test data seeding completed"
else
    echo ">>> WARNING: PostgreSQL seed SQL not found at ${PGSQL_SEED_SQL}"
fi

echo ">>> AI post-infras hook completed"
