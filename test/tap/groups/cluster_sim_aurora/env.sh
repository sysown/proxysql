# shellcheck shell=bash
# Aurora simulator TAP group environment

export CLUSTER_SIM_BINARY_PATH="${WORKSPACE}/test/deps/cluster_simulator/cluster_simulator"
export CLUSTER_SIM_TESTS_ROOT="${WORKSPACE}/test/deps/cluster_simulator/tests"
export CLUSTER_SIM_HOST_FILE="${WORKSPACE}/test/tap/groups/cluster_sim_aurora/add-hosts"

# Target ProxySQL's SQLite server via the docker-network alias; defaults for
# username/password match what enable_aurora_testing() inserts.
export AURORA_HOSTNAME=proxysql
export AURORA_PORT=3306
export PROXYSQL_READY_PORTS_EXTRA="3306"

# Skip the background cluster nodes: they are built without TEST_AURORA and
# their empty mysql_users sync back to the primary, wiping aurora1/2/3.
export SKIP_CLUSTER_START=1

# No backend infra: simulator drives ProxySQL directly through the admin port.
# Intentionally NOT setting DEFAULT_MYSQL_INFRA / DEFAULT_PGSQL_INFRA.
