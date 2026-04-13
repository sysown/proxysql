# Legacy Test Group Environment
# Defines the primary targets for tests that expect a generic MySQL or PGSQL backend.

export DEFAULT_MYSQL_INFRA="infra-dbdeployer-mysql57"
export DEFAULT_PGSQL_INFRA="docker-pgsql16-single"

# Path to RESTAPI test scripts inside ProxySQL container
# The setup-infras.bash hook copies scripts to the ProxySQL data directory
export REGULAR_INFRA_DATADIR="/var/lib/proxysql"
