# MariaDB 10.11 Galera Test Group Environment
export DEFAULT_MYSQL_INFRA="infra-dbdeployer-mariadb10-galera"

# Source infra .env to export TAP test variables (TAP_REG_TEST_3549_AUTOCOMMIT_TRACKING___MYSQL_SERVER_HOSTGROUP, etc.)
# Uses WORKSPACE (always set in CI) to avoid shell-specific BASH_SOURCE
if [ -n "${WORKSPACE}" ]; then
    _INFRA_ENV="${WORKSPACE}/test/infra/${DEFAULT_MYSQL_INFRA}/.env"
    # Validate path is under the workspace before sourcing
    case "${_INFRA_ENV}" in
        "${WORKSPACE}/"*) [ -f "${_INFRA_ENV}" ] && . "${_INFRA_ENV}" ;;
        *) echo "WARNING: Infra env path outside workspace, skipping: ${_INFRA_ENV}" ;;
    esac
fi

# Path to RESTAPI test scripts inside ProxySQL container
export REGULAR_INFRA_DATADIR="/var/lib/proxysql"
