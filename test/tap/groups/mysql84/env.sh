# Legacy Test Group Environment
# Defines the primary targets for tests that expect a generic MySQL or PGSQL backend.

export DEFAULT_MYSQL_INFRA="infra-mysql84"

# Path to RESTAPI test scripts inside ProxySQL container
# The setup-infras.bash hook copies scripts to the ProxySQL data directory
export REGULAR_INFRA_DATADIR="/var/lib/proxysql"
