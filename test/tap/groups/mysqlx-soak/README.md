# mysqlx-soak TAP group

This group brings up the mysqlx plugin end-to-end inside the docker
isolation harness — distinct from `mysqlx-e2e/` which runs plain TAP
tests against a dbdeployer-managed MySQL with `SKIP_PROXYSQL=1`.

## What this group provisions

1. `infra-dbdeployer-mysql84` (3-node MySQL 8.4 replication on the
   docker network, classic ports 3306-3308, X-protocol ports
   23306-23308 by dbdeployer convention).
2. ProxySQL container (`proxysql.${INFRA_ID}`) started by
   `test/infra/control/start-proxysql-isolated.bash` with two env-var
   knobs from `env.sh` honoured:
   - `PROXYSQL_LOAD_MYSQLX_PLUGIN=1` → bind-mounts
     `${WORKSPACE}/plugins/mysqlx/ProxySQL_MySQLX_Plugin.so` at
     `/usr/lib/proxysql/ProxySQL_MySQLX_Plugin.so`.
   - `PROXYSQL_CONFIG_OVERRIDE=...mysqlx-soak/proxysql-ci.cnf` →
     replaces the generic `proxysql-ci.cnf` with a per-group config
     that declares `plugins=("/usr/lib/proxysql/ProxySQL_MySQLX_Plugin.so")`
     so the chassis loads it at Phase A.
3. `setup-infras.bash` (the standard group-setup hook): waits for the
   `mysqlx_users` admin table to appear (proves the plugin loaded),
   provisions one route + one user + one endpoint via admin SQL,
   reloads to runtime, and verifies the listener bound on port
   `${MYSQLX_PROXYSQL_PORT}` (default 6603).

## What this group still needs (TODO)

The framework is wired but the actual harness invocation is not yet
hooked in. To complete the integration:

1. **Add `mysql-connector-python` to `proxysql-ci-base`.** The
   `test/infra/docker-base/Dockerfile` installs `python3-pymysql` and
   a few other Python packages but not the X DevAPI bindings. Add
   `pip3 install --break-system-packages mysql-connector-python` (or
   apt's `python3-mysql.connector` if the Ubuntu version ships one).
   Rebuild `proxysql-ci-base:latest` after.

2. **Add a TAP entry that invokes the harness scripts.** Two options:
   - Wrap each harness in a shell-test that returns 0/non-0 (e.g.
     `test_mysqlx_behavioral_validation-t` is a Bash script that runs
     `python3 ${WORKSPACE}/test/scripts/mysqlx/behavioral_validation.py
     --proxysql-host proxysql --proxysql-port 6603 --user alice
     --password alicepass`). Register in `groups.json` under
     `mysqlx-soak`.
   - Or convert the harness to a C++ TAP test that uses libprotobuf
     directly (the way `test_mysqlx_e2e_handshake-t` works). Larger
     surface but no Python dependency.

3. **Add `mysqlx-soak-g1` to `groups.json`.** Whatever TAP tests land
   in step 2 need entries.

4. **Wire CI.** Either extend `CI-mysqlx.yml` with a `soak-tests` job
   that invokes `ensure-infras.bash` + `run-tests-isolated.bash` with
   `TAP_GROUP=mysqlx-soak-g1`, or add the group to the existing
   `CI-taptests-groups.yml` matrix.

Until those four items land, the harness scripts at
`test/scripts/mysqlx/{behavioral_validation,stress}.py` remain
runnable manually against any properly-configured ProxySQL — but they
are not part of CI and not invoked by `run-tests-isolated.bash`.

## Local invocation (dev workflow)

After standing up the group manually:

```bash
# 0. Build proxysql + plugin first (PROXYSQLGENAI=1 implies PROXYSQL40=1)
make build_deps && PROXYSQLGENAI=1 make
cd plugins/mysqlx && PROXYSQL40=1 PROXYSQL31=1 PROXYSQLFFTO=1 \
    PROXYSQLTSDB=1 PROXYSQLGENAI=1 make
cd ../..

# 1. Build the CI base image once (per test/README.md)
docker build --network host -t proxysql-ci-base:latest test/infra/docker-base

# 2. Bring up the group's infrastructure + ProxySQL
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=mysqlx-soak \
    test/infra/control/ensure-infras.bash

# 3. Run the harness from the test-runner container
docker run --rm \
    --network "${INFRA_ID}_backend" \
    -v "$(pwd):/ws" -w /ws \
    proxysql-ci-base:latest \
    bash -c "pip3 install --break-system-packages -q mysql-connector-python && \
             python3 test/scripts/mysqlx/behavioral_validation.py \
                 --proxysql-host proxysql --proxysql-port 6603 \
                 --admin-host proxysql --admin-port 6032 \
                 --user alice --password alicepass --clients 5 \
                 --scenario all"

# 4. Tear down
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=mysqlx-soak \
    test/infra/control/destroy-infras.bash
```

## Why a separate group from `mysqlx-e2e`

`mysqlx-e2e` was set up early in the plugin's development with
`SKIP_PROXYSQL=1` so the existing `test_mysqlx_e2e_*-t` binaries
could speak directly to a MySQL X port via dbdeployer — they did not
yet have a ProxySQL with the chassis loaded to talk to. That group's
shape is preserved for those direct-protocol tests.

`mysqlx-soak` is the post-chassis equivalent: ProxySQL IS up, the
plugin IS loaded, and the harnesses speak X-Protocol *through* the
plugin to validate the routing/auth/compression paths under realistic
load.
