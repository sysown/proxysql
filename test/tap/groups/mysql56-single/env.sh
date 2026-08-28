# MySQL 5.6 single-backend test group environment

export DEFAULT_MYSQL_INFRA="infra-dbdeployer-mysql56-single"

if [ -n "${WORKSPACE}" ]; then
    _INFRA_ENV="${WORKSPACE}/test/infra/${DEFAULT_MYSQL_INFRA}/.env"
    [ -f "${_INFRA_ENV}" ] && . "${_INFRA_ENV}"
fi

export REGULAR_INFRA_DATADIR="/var/lib/proxysql"
