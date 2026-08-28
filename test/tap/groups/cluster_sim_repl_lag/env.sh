# shellcheck shell=bash
# Replication-lag simulator TAP group environment

export CLUSTER_SIM_BINARY_PATH="${WORKSPACE}/test/deps/cluster_simulator/cluster_simulator"
export CLUSTER_SIM_TESTS_ROOT="${WORKSPACE}/test/deps/cluster_simulator/tests"

# Target ProxySQL's SQLite server via the docker-network alias. Simulator
# defaults for username/password are 'root/root' (provisioned by pre-proxysql.sql).
export REPL_LAG_HOSTNAME=proxysql
export REPL_LAG_PORT=3306
export PROXYSQL_READY_PORTS_EXTRA="3306"

# Skip the background cluster nodes so their empty mysql_users do not sync
# back to the primary and wipe the root user we inject.
export SKIP_CLUSTER_START=1

# No backend infra: simulator drives ProxySQL directly through the admin port.
