# AI-g2 Subgroup Environment Configuration
# Inherits from parent ai group - duplicated here for POSIX sh compatibility

export DEFAULT_MYSQL_INFRA="infra-mysql84"
export DEFAULT_PGSQL_INFRA="docker-pgsql16-single"

export TAP_MCP_PORT="${TAP_MCP_PORT:-${TAP_MCPPORT:-6071}}"
export TAP_MCPPORT="${TAP_MCP_PORT}"
export TAP_MCP_AUTH_TOKEN="${TAP_MCP_AUTH_TOKEN:-tap-mcp-token}"
export MCP_TARGET_ID="${MCP_TARGET_ID:-tap_mysql_default}"
export MCP_AUTH_PROFILE_ID="${MCP_AUTH_PROFILE_ID:-tap_mysql_auth}"
export MCP_PGSQL_TARGET_ID="${MCP_PGSQL_TARGET_ID:-tap_pgsql_default}"
export MCP_PGSQL_AUTH_PROFILE_ID="${MCP_PGSQL_AUTH_PROFILE_ID:-tap_pgsql_auth}"
export MCP_MYSQL_HOSTGROUP_ID="${MCP_MYSQL_HOSTGROUP_ID:-9100}"
export MCP_PGSQL_HOSTGROUP_ID="${MCP_PGSQL_HOSTGROUP_ID:-9200}"

export MYSQL_DATABASE="${MYSQL_DATABASE:-test}"
export PGSQL_DATABASE="${PGSQL_DATABASE:-postgres}"

# The GenAI/MCP/RAG/LLM features are supplied by plugins/genai/.
export PROXYSQL_LOAD_GENAI_PLUGIN=1
export PROXYSQL_CONFIG_OVERRIDE="${WORKSPACE}/test/tap/groups/ai/proxysql-ci.cnf"
