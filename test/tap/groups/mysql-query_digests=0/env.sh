# MySQL query_digests=0 Test Group Environment
# Defines environment for tests with query digests disabled.

export DEFAULT_MYSQL_INFRA="infra-mysql57"
export DEFAULT_PGSQL_INFRA="docker-pgsql16-single"

# Path to test data directory for RESTAPI scripts (reg_test_3223)
export REGULAR_INFRA_DATADIR="${WORKSPACE}/test/tap/tests"
