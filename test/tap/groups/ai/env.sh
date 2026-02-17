export TEST_PY_TAP_INCL="ai_.*-t anomaly_.*-t genai.*-t mcp.*-t nl2sql_.*-t test_mcp.*-t vector.*-t"

# Local AI group backend defaults (used by MCP TAP tests).
# These variables can be overridden by the runner environment.
export TAP_MYSQLHOST="${TAP_MYSQLHOST:-127.0.0.1}"
export TAP_MYSQLPORT="${TAP_MYSQLPORT:-13306}"
export TAP_MYSQLUSERNAME="${TAP_MYSQLUSERNAME:-root}"
export TAP_MYSQLPASSWORD="${TAP_MYSQLPASSWORD:-rootpass}"
export TEST_DB_NAME="${TEST_DB_NAME:-testdb}"
export TAP_MCPPORT="${TAP_MCPPORT:-6071}"
export MCP_TARGET_ID="${MCP_TARGET_ID:-tap_mysql_default}"
export MCP_PGSQL_TARGET_ID="${MCP_PGSQL_TARGET_ID:-tap_pgsql_default}"
