# duckdb-e2e-g1: ProxySQL with the duckdb plugin loaded, exercised
# end-to-end over real client sockets. The replica test also consumes a
# MySQL 8.4 GTID/ROW/FULL source supplied by infras.lst.
export DEFAULT_MYSQL_INFRA="infra-dbdeployer-mysql84-binlog"

# Tell start-proxysql-isolated.bash to bind-mount the duckdb plugin .so
# into the ProxySQL container.
export PROXYSQL_LOAD_DUCKDB_PLUGIN=1

# Tell start-proxysql-isolated.bash to use the per-group config that
# declares plugins=("...") at Phase A -- without it the chassis sees
# zero plugins to load even though the .so is mounted.
export PROXYSQL_CONFIG_OVERRIDE="${WORKSPACE}/test/tap/groups/duckdb-e2e/proxysql-ci.cnf"

# No ProxySQL cluster needed for this group; a single primary node is
# enough, and bringing up the cluster takes ~30s of CI time we don't need.
export SKIP_CLUSTER_START=1
