# shellcheck shell=bash
# AWS RDS BGD simulator TAP group environment

# Inject AWS-style endpoint aliases into the ProxySQL container.
export CLUSTER_SIM_HOST_FILE="${WORKSPACE}/test/tap/groups/cluster_sim_rds_bgd/add-hosts"
export PROXYSQL_READY_PORTS_EXTRA="3306"

# Skip background cluster nodes: the TAP test drives the primary ProxySQL's
# built-in SQLite3-server simulator directly.
export SKIP_CLUSTER_START=1

# No backend infra: the TAP test controls simulated backend state through the
# SQLite3 server. Intentionally NOT setting DEFAULT_MYSQL_INFRA / DEFAULT_PGSQL_INFRA.
