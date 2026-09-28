#!/usr/bin/env bash
# Shared connection, TAP, and request helpers for MCP shell tests.

# ProxySQL admin connection.  The isolated runner exposes ProxySQL through its
# Docker DNS name; callers can override every field through the standard TAP
# environment.
PROXYSQL_ADMIN_HOST="${TAP_ADMINHOST:-${PROXYSQL_ADMIN_HOST:-proxysql}}"
PROXYSQL_ADMIN_PORT="${TAP_ADMINPORT:-${PROXYSQL_ADMIN_PORT:-6032}}"
PROXYSQL_ADMIN_USER="${TAP_ADMINUSERNAME:-${PROXYSQL_ADMIN_USER:-radmin}}"
PROXYSQL_ADMIN_PASSWORD="${TAP_ADMINPASSWORD:-${PROXYSQL_ADMIN_PASSWORD:-radmin}}"

# Backend connection used by discovery fixtures.
MYSQL_HOST="${TAP_MYSQLHOST:-${MYSQL_HOST:-mysql}}"
MYSQL_PORT="${TAP_MYSQLPORT:-${MYSQL_PORT:-3306}}"
MYSQL_USER="${TAP_MYSQLUSERNAME:-${MYSQL_USER:-root}}"
MYSQL_PASSWORD="${TAP_MYSQLPASSWORD:-${MYSQL_PASSWORD:-none}}"
MYSQL_DATABASE="${MYSQL_DATABASE:-${TEST_DB_NAME:-test}}"

# MCP uses the admin host by default because both listeners belong to the same
# ProxySQL instance.  TAP_MCP_PORT is canonical; TAP_MCPPORT remains supported
# for older callers.
MCP_HOST="${TAP_MCP_HOST:-${TAP_ADMINHOST:-${MCP_HOST:-proxysql}}}"
MCP_PORT="${TAP_MCP_PORT:-${TAP_MCPPORT:-${MCP_PORT:-6071}}}"
MCP_SCHEME="${TAP_MCP_SCHEME:-${MCP_SCHEME:-http}}"
MCP_AUTH_TOKEN="${TAP_MCP_AUTH_TOKEN:-${PROXYSQL_MCP_TOKEN:-}}"
MCP_TARGET_ID="${MCP_TARGET_ID:-tap_mysql_default}"
MCP_CONNECT_TIMEOUT="${TAP_MCP_CONNECT_TIMEOUT:-5}"
MCP_REQUEST_TIMEOUT="${TAP_MCP_REQUEST_TIMEOUT:-30}"
MCP_CA_CERT="${TAP_MCP_CA_CERT:-}"
MCP_TLS_INSECURE="${TAP_MCP_TLS_INSECURE:-0}"

PLAN="${PLAN:-0}"
DONE="${DONE:-0}"
FAIL="${FAIL:-0}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_test() { echo -e "${GREEN}[TEST]${NC} $*" >&2; }
log_verbose() { echo -e "${YELLOW}[VERBOSE]${NC} $*" >&2; }

tap_plan() {
    PLAN="$1"
    echo "msg: 1..${PLAN}"
}

tap_ok() {
    DONE=$((DONE + 1))
    echo "msg: ok ${DONE} - $1"
}

tap_not_ok() {
    DONE=$((DONE + 1))
    FAIL=$((FAIL + 1))
    echo "msg: not ok ${DONE} - $1"
    if [[ $# -gt 1 && -n "$2" ]]; then
        while IFS= read -r line; do
            echo "msg: # ${line}"
        done <<< "$2"
    fi
}

tap_skip() {
    DONE=$((DONE + 1))
    echo "msg: ok ${DONE} - $1 # SKIP $2"
}

tap_finish() {
    if [[ "${DONE}" -ne "${PLAN}" ]]; then
        echo "msg: # planned ${PLAN} assertions but ran ${DONE}"
        return 1
    fi
    if [[ "${FAIL}" -ne 0 ]]; then
        echo "msg: # FAILURES=${FAIL}/${PLAN}"
        return 1
    fi
    return 0
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "required command is unavailable: $1"
        return 1
    fi
}

require_mcp_prerequisites() {
    local failed=0
    local command_name
    for command_name in mysql curl jq; do
        require_command "${command_name}" || failed=1
    done
    if [[ -z "${MCP_AUTH_TOKEN}" ]]; then
        log_error "TAP_MCP_AUTH_TOKEN is required for the authenticated AI TAP groups"
        failed=1
    fi
    case "${MCP_SCHEME}" in
        http|https) ;;
        *)
            log_error "TAP_MCP_SCHEME must be http or https (got: ${MCP_SCHEME})"
            failed=1
            ;;
    esac
    if [[ "${MCP_SCHEME}" == "https" && "${MCP_TLS_INSECURE}" != "1" ]]; then
        if [[ -z "${MCP_CA_CERT}" || ! -f "${MCP_CA_CERT}" ]]; then
            log_error "TAP_MCP_CA_CERT must name a readable test CA for HTTPS (or set TAP_MCP_TLS_INSECURE=1 explicitly)"
            failed=1
        fi
    fi
    return "${failed}"
}

mysql_command() {
    local host="$1"
    local port="$2"
    local user="$3"
    local password="$4"
    local query="$5"
    shift 5

    local -a arguments=("$@" -h "${host}" -P "${port}" -u "${user}" -e "${query}")
    if [[ -z "${password}" || "${password}" == "none" ]]; then
        mysql "${arguments[@]}"
    else
        MYSQL_PWD="${password}" mysql "${arguments[@]}"
    fi
}

exec_admin() {
    mysql_command \
        "${PROXYSQL_ADMIN_HOST}" "${PROXYSQL_ADMIN_PORT}" \
        "${PROXYSQL_ADMIN_USER}" "${PROXYSQL_ADMIN_PASSWORD}" "$1"
}

exec_admin_silent() {
    local output
    local status
    if output="$(mysql_command \
        "${PROXYSQL_ADMIN_HOST}" "${PROXYSQL_ADMIN_PORT}" \
        "${PROXYSQL_ADMIN_USER}" "${PROXYSQL_ADMIN_PASSWORD}" "$1" -B -N 2>&1)"; then
        status=0
    else
        status=$?
    fi
    if [[ -n "${output}" ]]; then
        printf '%s\n' "${output}" | sed '/^mysql: \[Warning\].* insecure\.$/d'
    fi
    return "${status}"
}

exec_mysql() {
    local -a database_argument=()
    if [[ -n "${MYSQL_DATABASE}" ]]; then
        database_argument=(-D "${MYSQL_DATABASE}")
    fi
    mysql_command \
        "${MYSQL_HOST}" "${MYSQL_PORT}" "${MYSQL_USER}" "${MYSQL_PASSWORD}" \
        "$1" "${database_argument[@]}"
}

exec_mysql_silent() {
    local output
    local status
    local -a database_argument=()
    if [[ -n "${MYSQL_DATABASE}" ]]; then
        database_argument=(-D "${MYSQL_DATABASE}")
    fi
    if output="$(mysql_command \
        "${MYSQL_HOST}" "${MYSQL_PORT}" "${MYSQL_USER}" "${MYSQL_PASSWORD}" \
        "$1" -B -N "${database_argument[@]}" 2>&1)"; then
        status=0
    else
        status=$?
    fi
    if [[ -n "${output}" ]]; then
        printf '%s\n' "${output}" | sed '/^mysql: \[Warning\].* insecure\.$/d'
    fi
    return "${status}"
}

get_endpoint_url() {
    printf '%s://%s:%s/mcp/%s\n' "${MCP_SCHEME}" "${MCP_HOST}" "${MCP_PORT}" "$1"
}

mcp_request_url() {
    local url="$1"
    local payload="$2"
    local -a curl_arguments=(
        --silent --show-error --fail-with-body
        --connect-timeout "${MCP_CONNECT_TIMEOUT}"
        --max-time "${MCP_REQUEST_TIMEOUT}"
        --request POST "${url}"
        --header "Content-Type: application/json"
        --header "Authorization: Bearer ${MCP_AUTH_TOKEN}"
        --data "${payload}"
    )
    if [[ "${url}" == https://* ]]; then
        if [[ "${MCP_TLS_INSECURE}" == "1" ]]; then
            curl_arguments=(--insecure "${curl_arguments[@]}")
        elif [[ -n "${MCP_CA_CERT}" && -f "${MCP_CA_CERT}" ]]; then
            curl_arguments=(--cacert "${MCP_CA_CERT}" "${curl_arguments[@]}")
        else
            log_error "HTTPS MCP request requires TAP_MCP_CA_CERT or explicit TAP_MCP_TLS_INSECURE=1"
            return 2
        fi
    fi
    curl "${curl_arguments[@]}"
}

mcp_request() {
    mcp_request_url "$(get_endpoint_url "$1")" "$2"
}

check_proxysql_admin() {
    exec_admin_silent "SELECT 1" >/dev/null 2>&1
}

check_mcp_server() {
    local response
    response="$(mcp_request config '{"jsonrpc":"2.0","method":"ping","id":1}')" || return 1
    jq -e \
        '.jsonrpc == "2.0" and .id == 1 and has("result") and (has("error") | not)' \
        >/dev/null 2>&1 <<< "${response}"
}

check_mysql_backend() {
    exec_mysql_silent "SELECT 1" >/dev/null 2>&1
}

get_rule_hits() {
    exec_admin_silent "SELECT hits FROM stats_mcp_query_rules WHERE rule_id = $1;"
}

restore_mcp_group_baseline() {
    # LOAD ... FROM DISK is disk->memory only (issue #6171), so each one needs
    # its TO RUNTIME counterpart to actually restore the running module.
    exec_admin_silent \
        "LOAD MCP VARIABLES FROM DISK; LOAD MCP VARIABLES TO RUNTIME;
         LOAD MCP PROFILES FROM DISK; LOAD MCP PROFILES TO RUNTIME;
         LOAD MCP QUERY RULES FROM DISK; LOAD MCP QUERY RULES TO RUNTIME;" \
        >/dev/null
}

export PROXYSQL_ADMIN_HOST PROXYSQL_ADMIN_PORT PROXYSQL_ADMIN_USER PROXYSQL_ADMIN_PASSWORD
export MYSQL_HOST MYSQL_PORT MYSQL_USER MYSQL_PASSWORD MYSQL_DATABASE
export MCP_HOST MCP_PORT MCP_SCHEME MCP_AUTH_TOKEN MCP_TARGET_ID
export MCP_CONNECT_TIMEOUT MCP_REQUEST_TIMEOUT MCP_CA_CERT MCP_TLS_INSECURE
export -f log_info log_error log_test log_verbose
export -f tap_plan tap_ok tap_not_ok tap_skip tap_finish
export -f require_command require_mcp_prerequisites
export -f mysql_command exec_admin exec_admin_silent exec_mysql exec_mysql_silent
export -f get_endpoint_url mcp_request_url mcp_request check_proxysql_admin check_mcp_server check_mysql_backend
export -f get_rule_hits restore_mcp_group_baseline
