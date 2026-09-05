export PROXYSQL_LOAD_MYSQL_ROUTER_PLUGIN=1
export PROXYSQL_CONFIG_OVERRIDE="${WORKSPACE}/test/tap/groups/mysql-router-ic-g1/proxysql-ci.cnf"
export SKIP_CLUSTER_START=1
export DEFAULT_MYSQL_INFRA="infra-mysql-router-ic"
export TAP_USERNAME="app_writer"
export TAP_PASSWORD="router-app-password"
export TAP_PORT=6446
