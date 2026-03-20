# Legacy Test Group Environment
# Defines the primary targets for tests that expect a generic MySQL or PGSQL backend.

export DEFAULT_MYSQL_INFRA="infra-mysql84"
export DEFAULT_PGSQL_INFRA="docker-pgsql16-single"

# Path to test data directory for RESTAPI scripts (reg_test_3223)
export REGULAR_INFRA_DATADIR="${WORKSPACE}/test/tap/tests"
