# MySQLX E2E Test Group Environment
# Uses dbdeployer for backend provisioning (no Docker).
# MySQL 8.4 sandbox with X Protocol on port 33060.

export SKIP_PROXYSQL=1
export DEFAULT_MYSQL_INFRA="dbdeployer-mysqlx"
export MYSQLX_E2E_HOST=127.0.0.1
export MYSQLX_E2E_PORT=33060
export MYSQLX_E2E_USER=root
export MYSQLX_E2E_PASS=''
export MYSQLX_E2E_PROXYSQL_PORT=16603
