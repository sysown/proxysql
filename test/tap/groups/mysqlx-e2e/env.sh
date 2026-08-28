# MySQLX E2E Test Group Environment
# Uses dbdeployer for backend provisioning (no Docker), so this group does
# NOT use the standard test/infra/<name>/docker-compose-init.bash flow that
# every other group uses. There is no `infras.lst` and no `infra-mysqlx/`
# directory under `test/infra/` — those would be misleading. SKIP_PROXYSQL=1
# below makes test/infra/control/ensure-infras.bash short-circuit before it
# reaches the docker-compose loop, and CI-mysqlx.yml runs the dbdeployer
# setup inline (see .github/workflows/CI-mysqlx.yml's "Deploy MySQL 8.4
# sandbox" step). The dbdeployer-based setup-infras.bash + pre-cleanup.bash
# scripts in this directory remain for ad-hoc local use; they are NOT in
# the CI critical path today.
export SKIP_PROXYSQL=1
export DEFAULT_MYSQL_INFRA="dbdeployer-mysqlx"
export MYSQLX_E2E_HOST=127.0.0.1
export MYSQLX_E2E_PORT=33060
# Match the credentials provisioned by setup-infras.bash and CI-mysqlx.yml.
export MYSQLX_E2E_USER=mysqlx_test
export MYSQLX_E2E_PASS=mysqlx_test
export MYSQLX_E2E_PROXYSQL_PORT=16603
