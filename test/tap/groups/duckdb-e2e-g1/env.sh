# duckdb-e2e-g1: ProxySQL with the duckdb plugin loaded, exercised
# end-to-end over a real client socket (no backend database -- the
# plugin owns an embedded DuckDB instance and answers queries itself).

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
