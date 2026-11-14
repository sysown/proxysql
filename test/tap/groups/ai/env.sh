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

# CI validates the restored binary and its handoff metadata before setup. Read
# that version without executing an Ubuntu 24 binary on an Ubuntu 22 host.
# Local builds without a handoff still probe the executable directly.
if [ -f "${WORKSPACE}/src/ci-tier.json" ]; then
    _ai_product_version="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["version"])' \
        "${WORKSPACE}/src/ci-tier.json")" || return 1
else
    _ai_product_version="$("${WORKSPACE}/src/proxysql" --version)" || return 1
fi
_ai_product_major="$(printf '%s\n' "${_ai_product_version}" | sed -n 's/^ProxySQL version \([0-9][0-9]*\)\..*/\1/p')"
case "${_ai_product_major}" in
    ''|*[!0-9]*)
        echo "ERROR: Cannot determine the compiled ProxySQL version for AI setup" >&2
        return 1
        ;;
esac
if [ "${_ai_product_major}" -ge 4 ]; then
    export PROXYSQL_LOAD_GENAI_PLUGIN=1
    export PROXYSQL_CONFIG_OVERRIDE="${WORKSPACE}/test/tap/groups/ai/proxysql-ci.cnf"
else
    export PROXYSQL_LOAD_GENAI_PLUGIN=0
    export PROXYSQL_CONFIG_OVERRIDE="${WORKSPACE}/test/infra/control/proxysql-ci.cnf"
fi
unset _ai_product_version _ai_product_major
