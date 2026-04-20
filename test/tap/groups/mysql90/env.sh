# MySQL 9.0 Test Group Environment

export DEFAULT_MYSQL_INFRA="infra-dbdeployer-mysql90"

# Source infra .env to export TAP test variables (TAP_MYSQL8_BACKEND_HG, etc.)
# Uses WORKSPACE (always set in CI) to avoid shell-specific BASH_SOURCE
if [ -n "${WORKSPACE}" ]; then
    _INFRA_ENV="${WORKSPACE}/test/infra/${DEFAULT_MYSQL_INFRA}/.env"
    [ -f "${_INFRA_ENV}" ] && . "${_INFRA_ENV}"
fi

# Path to RESTAPI test scripts inside ProxySQL container
# The setup-infras.bash hook copies scripts to the ProxySQL data directory
export REGULAR_INFRA_DATADIR="/var/lib/proxysql"
