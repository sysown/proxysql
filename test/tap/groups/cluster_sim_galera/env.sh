# shellcheck shell=bash
# Galera simulator TAP group environment

export CLUSTER_SIM_BINARY_PATH="${WORKSPACE}/test/deps/cluster_simulator/cluster_simulator"
export CLUSTER_SIM_TESTS_ROOT="${WORKSPACE}/test/deps/cluster_simulator/tests"

# Target ProxySQL's SQLite server via the docker-network alias; defaults for
# username/password match what enable_galera_testing() inserts (galera1/pass1).
export GALERA_HOSTNAME=proxysql
export GALERA_PORT=3306
export PROXYSQL_READY_PORTS_EXTRA="3306"

# Skip the background cluster nodes so their empty mysql_users do not sync
# back to the primary and wipe galera1/2/galera.
export SKIP_CLUSTER_START=1

# No backend infra: simulator drives ProxySQL directly through the admin port.
