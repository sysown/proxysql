# set_parser_algorithm_3 Test Group Environment
# Runs all SET-related tests with ParserSQL-based SET parser enabled
# for both MySQL and PostgreSQL protocols.

export DEFAULT_MYSQL_INFRA="infra-dbdeployer-mysql57"
export DEFAULT_PGSQL_INFRA="docker-pgsql16-single"

export REGULAR_INFRA_DATADIR="/var/lib/proxysql"
