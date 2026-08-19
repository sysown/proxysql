# shellcheck shell=bash
# AI TAP Group Environment Configuration
# Defines the primary targets for AI/MCP tests using standard test/infra/ pattern

export DEFAULT_MYSQL_INFRA="infra-mysql84"
export DEFAULT_PGSQL_INFRA="docker-pgsql16-single"

# MCP-specific environment variables for AI tests.  C++ CommandLine consumes
# TAP_MCP_PORT while older shell tests consume TAP_MCPPORT; keep one canonical
# value visible through both names.
export TAP_MCP_PORT="${TAP_MCP_PORT:-${TAP_MCPPORT:-6071}}"
export TAP_MCPPORT="${TAP_MCP_PORT}"
export TAP_MCP_AUTH_TOKEN="${TAP_MCP_AUTH_TOKEN:-tap-mcp-token}"
export MCP_TARGET_ID="${MCP_TARGET_ID:-tap_mysql_default}"
export MCP_AUTH_PROFILE_ID="${MCP_AUTH_PROFILE_ID:-tap_mysql_auth}"
export MCP_PGSQL_TARGET_ID="${MCP_PGSQL_TARGET_ID:-tap_pgsql_default}"
export MCP_PGSQL_AUTH_PROFILE_ID="${MCP_PGSQL_AUTH_PROFILE_ID:-tap_pgsql_auth}"
export MCP_MYSQL_HOSTGROUP_ID="${MCP_MYSQL_HOSTGROUP_ID:-9100}"
export MCP_PGSQL_HOSTGROUP_ID="${MCP_PGSQL_HOSTGROUP_ID:-9200}"

# Test data database name
export MYSQL_DATABASE="${MYSQL_DATABASE:-test}"
export PGSQL_DATABASE="${PGSQL_DATABASE:-postgres}"
