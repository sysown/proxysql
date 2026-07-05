# mysqlx-soak: ProxySQL with the mysqlx plugin loaded, against a real
# MySQL 8.4 backend. This group runs operational harness scripts —
# behavioral_validation.py and stress.py from test/scripts/mysqlx/ —
# rather than per-test TAP binaries.
#
# Distinct from the existing `mysqlx-e2e` group, which uses dbdeployer
# locally and skips ProxySQL: this group goes through the full
# isolated docker harness so the plugin is exercised end-to-end the
# way it would be in production.

# Tell start-proxysql-isolated.bash to bind-mount the mysqlx plugin .so
# into the ProxySQL container.
export PROXYSQL_LOAD_MYSQLX_PLUGIN=1

# Tell start-proxysql-isolated.bash to use the per-group config that
# declares plugins=("...") at Phase A — without it the chassis sees
# zero plugins to load even though the .so is mounted.
export PROXYSQL_CONFIG_OVERRIDE="${WORKSPACE}/test/tap/groups/mysqlx-soak/proxysql-ci.cnf"

# No ProxySQL cluster needed for this harness; a single primary node
# is enough, and bringing up the cluster takes ~30s of CI time we
# don't need.
export SKIP_CLUSTER_START=1

# Default mysqlx listener port that the per-group setup-infras.bash
# tells the plugin to bind on. Matches the harness's --proxysql-port
# default in test/scripts/mysqlx/{behavioral_validation,stress}.py.
export MYSQLX_PROXYSQL_PORT=6603

# Backend MySQL X protocol port. dbdeployer's port convention is
# classic-port + 10000, so port 3306 (classic) ↔ port 13306 (X
# protocol). Verified by inspecting `mysqlx-port` in the sandbox's
# my.sandbox.cnf:
#   docker exec ... bash -lc 'grep ^mysqlx-port .../my.sandbox.cnf'
#   mysqlx-port=13306
# The previous 23306 (classic + 20000) was wrong; the mysqlx plugin
# then tried to connect to a closed port for every backend session
# and every SELECT after auth failed.
export MYSQLX_BACKEND_HOST="dbdeployer1.${INFRA:-infra-dbdeployer-mysql84}"
export MYSQLX_BACKEND_MYSQL_PORT=3306
export MYSQLX_BACKEND_X_PORT=13306
