# AI-g1 Subgroup Environment Configuration
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

# Post-carve-out: GenAI/MCP/RAG/LLM all live in plugins/genai/.  The
# proxysql binary itself no longer ships those subsystems, so for the
# AI tests to have anything to talk to we (a) bind-mount the genai
# plugin .so into the ProxySQL container and (b) point ProxySQL at a
# per-group cnf that lists the plugin under `plugins=("...")`.
export PROXYSQL_LOAD_GENAI_PLUGIN=1
export PROXYSQL_CONFIG_OVERRIDE="${WORKSPACE}/test/tap/groups/ai/proxysql-ci.cnf"
