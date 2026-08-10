# PostgreSQL SP-2 — Polyglot Test-Harness Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a reusable, driver-driven PostgreSQL test foundation for ProxySQL — a Toxiproxy-fronted primary+2-replica backend, a pytest harness that reconfigures ProxySQL as a test primitive, a 6-target **differential engine** (proxy-vs-direct, both backend-protocol modes, text+binary) and a **`pg_stat_statements` routing oracle** — proven end-to-end with a Python reference driver (psycopg3 + asyncpg), and wired into CI as a nightly + label-gated job.

**Architecture:** A new backend infra (`infra-dbdeployer-pgsql17-repl`, primary + 2 replicas) exposes each backend through a **Toxiproxy** endpoint; ProxySQL's `pgsql_servers` point at the Toxiproxy ports and use the **automatic** `pgsql_replication_hostgroups` monitor path for read/write split. A new pytest suite under `test/pg-compat/` runs **inside a container joined to the `${INFRA_ID}_backend` docker network** (ProxySQL exposes no host ports), addressing services by DNS. All service endpoints are injected via environment variables so the harness is decoupled from the backend topology. The differential engine drops in SQL cases and asserts ProxySQL is byte-identical to a direct backend; the routing oracle reads `pg_stat_statements` on each backend to prove where queries landed.

**Tech Stack:** Python 3.11, pytest, psycopg3, asyncpg, Toxiproxy (+ `toxiproxy-python`), PostgreSQL 17, ProxySQL PG monitor (`pg_is_in_recovery()`), dbdeployer (ProxySQL fork v2.2.1) *or* native `postgres:17` Docker fallback, Docker Compose on the external `${INFRA_ID}_backend` network, GitHub Actions (two-branch caller/reusable).

## Global Constraints

- **Discovery-phase framing (spec §2.1):** first runs are expected to surface failures. The suite is **non-gating**; its deliverable is a **failure inventory**. Every known divergence is an **xfail entry** in `test/pg-compat/xfail.toml` with `reason` + `mode` + tracking ref; an xfail that starts passing (**xpass**) is reported. Do NOT loosen an assertion to make a real divergence green.
- **Backend-protocol axis (spec §2.2):** the proxy targets run under both `pgsql-use_native_backend_protocol` = `off` (libpq, default) and `on` (native, PR #5882). Native-path cases that are incomplete are marked xfail, not skipped.
- **No host ports.** ProxySQL and backends publish nothing to the host. The harness runs in a container on `${INFRA_ID}_backend` and reaches: ProxySQL PG frontend `proxysql:6133`, ProxySQL admin over PG protocol `proxysql:6132`, backends + Toxiproxy by their DNS aliases. All endpoints come from env vars (never hardcode).
- **Debug proxysql build** required for the isolated harness admin commands (per `CLAUDE.md`); build `PROXYSQL31=1 make debug` and re-run `start-proxysql-isolated.bash` after rebuilds.
- **Never manually manage Docker** — bring infra up via `test/infra/control/ensure-infras.bash`.
- **Automatic RW-split config** (from recon): put ALL servers (incl. primary) in the writer hostgroup, add a `pgsql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type, comment)` row with `check_type='read_only'`, and enable the monitor (`pgsql-monitor_enabled=true`, `monitor_username`/`monitor_password` matching a real PG role). The monitor runs `SELECT pg_is_in_recovery()` and moves replicas to the reader hostgroup.
- **`LOAD PGSQL VARIABLES/SERVERS/USERS/QUERY RULES TO RUNTIME`** is required after each admin config change; `pgsql_replication_hostgroups` loads with `LOAD PGSQL SERVERS TO RUNTIME`.

---

## Greenfield risk register (read before starting)

| Piece | Status | Mitigation in this plan |
|---|---|---|
| dbdeployer PostgreSQL topology | **Confirmed supported** by the maintainer (2026-07-08); exact PG deploy flags still to capture | **Task 1 captures the exact command** (no go/no-go gate); commit to the dbdeployer path (Task 2a). Native `postgres:17` (Task 2b) remains only an emergency fallback. |
| Toxiproxy | Greenfield (0 refs in repo) | Task 3 adds it as a sidecar container + a bootstrap script; harness reads its host via env. |
| `pg_stat_statements` | Greenfield | Task 2 bakes `shared_preload_libraries` into `postgresql.conf` + `CREATE EXTENSION` in post-provision. |
| Host-published ports | Greenfield (none exist) | Harness runs **in-container** on the infra network (Task 5); no host ports needed. |
| Nightly + label CI | Greenfield (no `schedule`/label workflow) | Task 10 uses the standard idiom + inline proxysql build (like `CI-3p-*`). |
| Auto `pgsql_replication_hostgroups` | Exists, unused by infra | Task 4 enables it (exact SQL below). |
| pytest (non-TAP) suite in CI | Partial precedent (`test/scripts/mysqlx/*.py`, `mysqlx-soak`) | Task 5/10 model the runner on it. |

---

## File Structure

**New infra (Task 2 — one of these two, per Task 1's decision):**
- `test/infra/infra-dbdeployer-pgsql17-repl/` — dbdeployer path: `docker/{Dockerfile,build.sh,entrypoint.sh}`, `bin/docker-pgsql-post.bash`, `bin/docker-proxy-post.bash`, `docker-compose.yml`, `docker-compose-init.bash`, `docker-compose-destroy.bash`, `.env`, `conf/proxysql/infra-config.sql`.
- *(fallback)* extend the native `test/infra/infra-pgsql17-repl/` pattern to a `-3node` variant.

**New harness (Tasks 5–9) under `test/pg-compat/`:**
- `conftest.py` — fixtures: proxysql admin (config primitive), the 6 differential targets, direct-backend + toxiproxy clients, per-test config snapshot/restore.
- `harness/proxysql.py` — admin-driven config mutation + `LOAD ... TO RUNTIME`; snapshot/restore.
- `harness/targets.py` — connection factories for the 6 differential targets.
- `harness/diff.py` — differential comparison engine.
- `harness/oracle.py` — `pg_stat_statements` routing oracle.
- `harness/toxi.py` — Toxiproxy wrapper (used by SP-4; a thin stub + wiring self-check here).
- `harness/xfail.py` — loads `xfail.toml`, applies xfail/xpass semantics.
- `drivers/python/adapter.py` — reference driver adapter (psycopg3 + asyncpg).
- `behaviors/` — driver-agnostic behavior modules: `connect.py`, `transactions.py`, `prepared.py`, `rw_split.py`, `session_isolation.py`.
- `cases/NNN_slug.sql` — drop-in differential cases.
- `xfail.toml` — the failure inventory.
- `requirements.txt`, `Dockerfile`, `run-pg-compat.bash`, `README.md`.

**New CI (Task 10):**
- `.github/workflows/CI-pg-compat.yml` (caller, `v3.0`) + `gh-actions-reusable/ci-pg-compat.yml` (reusable, lands on `GH-Actions`).

---

## Task 1: Capture the exact dbdeployer PostgreSQL deploy command

**dbdeployer PG support is confirmed** by the maintainer (2026-07-08), so this is no longer a go/no-go gate — it only captures the **exact** flags/ports for a PG primary+2-replica sandbox against the pinned fork (v2.2.1), which Task 2a needs verbatim. Commit to the dbdeployer path (Task 2a); native `postgres:17` (Task 2b) is retained only as an emergency fallback if the pinned fork misbehaves in CI.

**Files:**
- Create: `test/pg-compat/SPIKE-dbdeployer-pg.md` (findings + decision)

- [ ] **Step 1: Check the pinned dbdeployer fork for PG support**

```bash
docker run --rm --network=host ubuntu:22.04 bash -c '
  apt-get update -qq && apt-get install -y -qq curl xz-utils >/dev/null
  curl -fsSL "https://github.com/ProxySQL/dbdeployer/releases/download/v2.2.1/dbdeployer-2.2.1.linux_amd64.tar.gz" | tar -xz -C /usr/local/bin/
  chmod +x /usr/local/bin/dbdeployer*
  ln -sf /usr/local/bin/dbdeployer-2.2.1.linux_amd64 /usr/local/bin/dbdeployer
  echo "=== available flavors ==="; dbdeployer downloads list | grep -i -E "postgres|pg" || echo "NO postgres downloads"
  echo "=== deploy help (flavor/type flags) ==="; dbdeployer deploy replication --help 2>&1 | grep -i -E "flavor|type|postgres" || echo "NO postgres deploy flags"
'
```
Expected: either PG flavors/flags appear (dbdeployer path viable) or not (fallback).

- [ ] **Step 2: If PG appears, prototype a 3-node PG replication sandbox**

Inside the same container image, attempt (adjust flags per Step 1 output):
```bash
dbdeployer downloads get-unpack <postgres-17-tarball>     # or: dbdeployer unpack <tarball>
dbdeployer deploy replication 17 --topology=... --nodes=3 --bind-address=0.0.0.0 --base-port=5432
dbdeployer sandboxes    # confirm 3 nodes, note the ports
```
Record the exact working command and port scheme, or the error proving it's unsupported.

- [ ] **Step 3: Record the exact command**

Create `test/pg-compat/SPIKE-dbdeployer-pg.md` recording the working PG deploy command, the resulting node ports, and the sandbox dir name — Task 2a copies these verbatim. (Support is already confirmed; only the exact flags/ports are being captured.) If the pinned fork unexpectedly fails, note it and fall back to Task 2b.

- [ ] **Step 4: Commit**

```bash
git add test/pg-compat/SPIKE-dbdeployer-pg.md
git commit -m "spike(pg-compat): capture exact dbdeployer PostgreSQL deploy command + ports"
```

---

## Task 2: New primary + 2-replica infra (with pg_stat_statements)

Build the backend infra chosen in Task 1. Both variants must end at the same contract: three PG 17 servers (1 primary + 2 streaming replicas) reachable on the `${INFRA_ID}_backend` network, each with `pg_stat_statements` preloaded and the extension created, plus a `monitor` login role and `testuser`/`postgres` app roles. Do the variant your spike selected.

**Files (Task 2a — dbdeployer):**
- Create: `test/infra/infra-dbdeployer-pgsql17-repl/` (mirror `infra-dbdeployer-mysql84-gr/` layout).

**Files (Task 2b — native fallback):**
- Create: `test/infra/infra-pgsql17-repl-3node/` (mirror `infra-pgsql17-repl/`, add a third `pgdb3` service).

**Interfaces:**
- Produces (both variants): DNS aliases and ports consumed by later tasks, published as env vars in the infra's `env.sh` — a `_HOST`/`_PORT` **pair per node**: `PGCOMPAT_PRIMARY_HOST`/`PGCOMPAT_PRIMARY_PORT`, `PGCOMPAT_REPLICA1_HOST`/`PGCOMPAT_REPLICA1_PORT`, `PGCOMPAT_REPLICA2_HOST`/`PGCOMPAT_REPLICA2_PORT`. There is deliberately **no** single `PGCOMPAT_BACKEND_PORT`: the dbdeployer variant puts all three nodes in one container on three different ports, so a shared port var cannot address the replicas. (dbdeployer → one host, three ports; native → three hosts, each on 5432.)

- [ ] **Step 1: Scaffold the infra directory**

Copy the selected reference tree and rename. For **2b** (lower-risk fallback), start from the working PG infra:
```bash
cp -r test/infra/infra-pgsql17-repl test/infra/infra-pgsql17-repl-3node
```
For **2a**, copy the dbdeployer reference:
```bash
cp -r test/infra/infra-dbdeployer-mysql84-gr test/infra/infra-dbdeployer-pgsql17-repl
```

- [ ] **Step 2: Add the third replica (fallback 2b) or set the PG deploy (2a)**

**2b:** In `docker-compose.yml` add a `pgdb3` service cloned from `pgdb2` (new alias `pgsql3.${INFRA}`), add `conf/pgsql/pgsql3/{postgresql.conf,pg_hba.conf}` cloned from pgsql2, and give it its own replication slot (the primary's `init-replication.sh` already creates `replica_slot_2/3/4`, so assign `replica_slot_3` to pgdb3). Update `.env` (`WHG=00`, `RHG=01`).

**2a:** In `docker/entrypoint.sh` replace the MySQL `dbdeployer deploy replication` invocation with the PG command recorded in the Task 1 spike (`--nodes=3`, PG flavor), and in `docker/Dockerfile` replace the `dbdeployer downloads get-unpack mysql-...` line with the PG tarball. Update `docker/build.sh`'s default tag to `proxysql/ci-infra:dbdeployer-pgsql17-repl`.

- [ ] **Step 3: Enable pg_stat_statements in postgresql.conf (all nodes)**

Add to each node's `postgresql.conf` (2b: `conf/pgsql/pgsql{1,2,3}/postgresql.conf`; 2a: the dbdeployer per-node conf template or a `-c` flag in entrypoint):
```
shared_preload_libraries = 'pg_stat_statements'
pg_stat_statements.track = all
```
(Requires the server to start with it preloaded — it is a bake-in, not a runtime SET.)

- [ ] **Step 4: Create roles + extension in the post-provision script**

In `bin/docker-pgsql-post.bash` (modeled on `docker-pgsql16-single/bin/docker-pgsql-post.bash`), after the existing user loop, add the `monitor` role and the extension on every database, and ensure `testuser`/`postgres`:
```bash
# monitor role for automatic replication_hostgroups (must match pgsql-monitor_username/password)
docker exec "${CONTAINER}" psql -X -Upostgres -c "SET client_min_messages='error';" \
  -c "DROP USER IF EXISTS monitor;" -c "CREATE USER monitor WITH PASSWORD 'monitor';"
# pg_stat_statements extension (routing oracle) — create in each app DB
for DB in postgres testuser; do
  docker exec "${CONTAINER}" psql -X -Upostgres -d "$DB" -c "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;"
done
```
For 2b, run the extension create on the **primary** only (it propagates via SQL, but pg_stat_statements is per-node/local — create it on each node's post script, or run against pgsql1/2/3 individually). Confirm `SELECT * FROM pg_stat_statements LIMIT 1;` works on each node.

- [ ] **Step 5: Publish endpoints via env.sh**

Create `test/tap/groups/pg-compat/env.sh` (group dir) exporting the endpoints and infra selection:
```bash
export INFRA_TYPE="infra-pgsql17-repl-3node"   # or infra-dbdeployer-pgsql17-repl
export PGCOMPAT_PRIMARY_HOST="pgsql1.${INFRA_ID}"
export PGCOMPAT_PRIMARY_PORT="5432"
export PGCOMPAT_REPLICA1_HOST="pgsql2.${INFRA_ID}"
export PGCOMPAT_REPLICA1_PORT="5432"
export PGCOMPAT_REPLICA2_HOST="pgsql3.${INFRA_ID}"
export PGCOMPAT_REPLICA2_PORT="5432"
```
Each node carries its own port so the same contract covers the dbdeployer
variant, where all three nodes share `dbdeployer1` and differ only by port
(16710/16711/16712).
and `test/tap/groups/pg-compat/infras.lst` with the single infra name (per the `infras.lst` mechanism in `ensure-infras.bash`).

- [ ] **Step 6: Bring it up and verify replication + extension**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=pg-compat test/infra/control/ensure-infras.bash
# verify from a throwaway container on the network:
docker run --rm --network "dev-$USER_backend" postgres:17 bash -c '
  PGPASSWORD=testuser psql -h pgsql1.dev-'"$USER"' -U testuser -d testuser -c "SELECT pg_is_in_recovery();"   # f (primary)
  PGPASSWORD=testuser psql -h pgsql2.dev-'"$USER"' -U testuser -d testuser -c "SELECT pg_is_in_recovery();"   # t (replica)
  PGPASSWORD=testuser psql -h pgsql3.dev-'"$USER"' -U testuser -d testuser -c "SELECT pg_is_in_recovery();"   # t (replica)
'
```
Expected: primary `f`, both replicas `t`, and `pg_stat_statements` present on each.

- [ ] **Step 7: Commit**

```bash
git add test/infra/infra-pgsql17-repl-3node test/tap/groups/pg-compat   # (or the dbdeployer dir)
git commit -m "infra(pg-compat): primary + 2-replica PG17 infra with pg_stat_statements"
```

---

## Task 3: Toxiproxy sidecar + backend endpoint indirection

Insert Toxiproxy between ProxySQL and each PG backend so backends are individually degradable later (SP-4). ProxySQL will point at Toxiproxy; the differential engine's *direct* targets bypass Toxiproxy and hit PG directly.

**Files:**
- Modify: the infra `docker-compose.yml` (add a `toxiproxy` service)
- Create: `<infra>/bin/toxiproxy-bootstrap.sh` (create one proxy per backend)
- Modify: `<infra>/bin/docker-proxy-post.bash` (invoke the bootstrap before applying ProxySQL config)
- Modify: `test/tap/groups/pg-compat/env.sh` (export toxiproxy endpoints)

**Interfaces:**
- Produces: env vars `PGCOMPAT_TOXI_ADMIN` (`toxiproxy.${INFRA_ID}:8474`) and per-backend proxy listen addresses `PGCOMPAT_TOXI_PRIMARY` / `_REPLICA1` / `_REPLICA2` (e.g. `toxiproxy.${INFRA_ID}:6001/6002/6003`), consumed by Task 4's ProxySQL config and Task 6/7 self-checks.

- [ ] **Step 1: Add the toxiproxy service to docker-compose.yml**

```yaml
  toxiproxy:
    hostname: toxiproxy.${INFRA}
    image: ghcr.io/shopify/toxiproxy:2.9.0
    container_name: ${COMPOSE_PROJECT}-toxiproxy-1
    command: ["-host", "0.0.0.0"]
    networks:
      backend:
        aliases:
          - toxiproxy.${INFRA}
```

- [ ] **Step 2: Write the bootstrap script**

Create `<infra>/bin/toxiproxy-bootstrap.sh` — creates one passthrough proxy per backend via the Toxiproxy admin API (no toxics yet; SP-4 adds toxics):
```bash
#!/usr/bin/env bash
set -euo pipefail
TOXI="toxiproxy.${INFRA_ID}:8474"
mk() {  # name  listen_port  upstream_host
  curl -fsS -XPOST "http://${TOXI}/proxies" -d "{\"name\":\"$1\",\"listen\":\"0.0.0.0:$2\",\"upstream\":\"$3:5432\",\"enabled\":true}"
}
mk pg_primary  6001 "pgsql1.${INFRA_ID}"
mk pg_replica1 6002 "pgsql2.${INFRA_ID}"
mk pg_replica2 6003 "pgsql3.${INFRA_ID}"
```
Run it from a container on the network (add its invocation to `docker-proxy-post.bash` before the ProxySQL config step, using a `docker run --rm --network ${INFRA_ID}_backend curlimages/curl ...` or by `docker exec` into the toxiproxy container).

- [ ] **Step 3: Export toxiproxy endpoints in env.sh**

Append to `test/tap/groups/pg-compat/env.sh`:
```bash
export PGCOMPAT_TOXI_ADMIN="toxiproxy.${INFRA_ID}:8474"
export PGCOMPAT_TOXI_PRIMARY="toxiproxy.${INFRA_ID}:6001"
export PGCOMPAT_TOXI_REPLICA1="toxiproxy.${INFRA_ID}:6002"
export PGCOMPAT_TOXI_REPLICA2="toxiproxy.${INFRA_ID}:6003"
```

- [ ] **Step 4: Bring up + verify a query flows through Toxiproxy**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=pg-compat test/infra/control/start-proxysql-isolated.bash
docker run --rm --network "dev-$USER_backend" postgres:17 \
  bash -c 'PGPASSWORD=testuser psql -h toxiproxy.dev-'"$USER"' -p 6001 -U testuser -d testuser -c "SELECT 1"'
```
Expected: `1` — proving the primary is reachable through its Toxiproxy proxy.

- [ ] **Step 5: Commit**

```bash
git add test/infra/*/docker-compose.yml test/infra/*/bin/toxiproxy-bootstrap.sh test/infra/*/bin/docker-proxy-post.bash test/tap/groups/pg-compat/env.sh
git commit -m "infra(pg-compat): Toxiproxy sidecar with one proxy per backend"
```

---

## Task 4: ProxySQL config — automatic replication hostgroups via Toxiproxy

Point ProxySQL at the Toxiproxy endpoints and enable the automatic monitor-driven read/write split.

**Files:**
- Modify: `<infra>/conf/proxysql/infra-config.sql`

- [ ] **Step 1: Write infra-config.sql (all servers in WHG, via Toxiproxy, auto-split)**

Replace the static-split config with the automatic path. Note servers point at **Toxiproxy** host/ports (from Task 3), placed initially in the **writer** hostgroup; the monitor demotes replicas:
```sql
DELETE FROM pgsql_servers WHERE comment LIKE '%${INFRA}%';
-- All three backends in the WRITER hostgroup, addressed via Toxiproxy.
INSERT INTO pgsql_servers (hostgroup_id, hostname, port, max_connections, comment) VALUES
  (${WHG}, 'toxiproxy.${INFRA}', 6001, 200, 'pg_primary ${INFRA}'),
  (${WHG}, 'toxiproxy.${INFRA}', 6002, 200, 'pg_replica1 ${INFRA}'),
  (${WHG}, 'toxiproxy.${INFRA}', 6003, 200, 'pg_replica2 ${INFRA}');

-- Automatic writer/reader assignment via pg_is_in_recovery().
DELETE FROM pgsql_replication_hostgroups WHERE writer_hostgroup=${WHG};
INSERT INTO pgsql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type, comment)
  VALUES (${WHG}, ${RHG}, 'read_only', 'pg auto rw-split ${INFRA}');

LOAD PGSQL SERVERS TO RUNTIME;   -- loads replication_hostgroups too
SAVE PGSQL SERVERS TO DISK;

DELETE FROM pgsql_users WHERE comment LIKE '%${INFRA}%';
REPLACE INTO pgsql_users (username, password, active, default_hostgroup, comment) VALUES
  ('postgres', '${ROOT_PASSWORD}', 1, ${WHG}, '${INFRA}'),
  ('testuser', 'testuser',        1, ${WHG}, '${INFRA}');
LOAD PGSQL USERS TO RUNTIME;
SAVE PGSQL USERS TO DISK;

-- Read/write split query rules (route SELECTs to reader HG).
DELETE FROM pgsql_query_rules WHERE destination_hostgroup IN (${WHG}, ${RHG});
INSERT INTO pgsql_query_rules (rule_id, active, match_digest, destination_hostgroup, apply) VALUES
  (${WHG}01, 1, '^SELECT.*FOR UPDATE', ${WHG}, 1),
  (${RHG}01, 1, '^SELECT', ${RHG}, 1);
LOAD PGSQL QUERY RULES TO RUNTIME;
SAVE PGSQL QUERY RULES TO DISK;

-- Enable the monitor (drives the automatic split).
UPDATE global_variables SET variable_value='true'    WHERE variable_name='pgsql-monitor_enabled';
UPDATE global_variables SET variable_value='monitor'  WHERE variable_name IN ('pgsql-monitor_username','pgsql-monitor_password');
LOAD PGSQL VARIABLES TO RUNTIME;
SAVE PGSQL VARIABLES TO DISK;
```

- [ ] **Step 2: Apply + verify the monitor moved replicas to the reader HG**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=pg-compat test/infra/control/start-proxysql-isolated.bash
# after ~monitor_read_only_interval, check runtime hostgroups over the PG admin (port 6132):
docker exec proxysql.dev-$USER env PGPASSWORD=admin psql -h127.0.0.1 -p6132 -Uadmin -dadmin \
  -c "SELECT hostgroup_id, hostname, port FROM runtime_pgsql_servers ORDER BY hostgroup_id;"
```
Expected: exactly one server in `${WHG}` (the primary, port 6001) and two in `${RHG}` (replicas, 6002/6003) — the monitor demoted the read-only backends.

- [ ] **Step 3: Commit**

```bash
git add test/infra/*/conf/proxysql/infra-config.sql
git commit -m "config(pg-compat): automatic pgsql_replication_hostgroups via Toxiproxy"
```

---

## Task 5: pytest harness skeleton (in-container runner + config primitive)

Create the pytest suite and the container runner. Prove the wiring with one trivial test that connects through ProxySQL and reconfigures it via admin.

**Files:**
- Create: `test/pg-compat/{requirements.txt,Dockerfile,run-pg-compat.bash,conftest.py,pytest.ini,README.md}`
- Create: `test/pg-compat/harness/proxysql.py`
- Create: `test/pg-compat/tests/test_smoke.py`

**Interfaces:**
- Consumes: env vars from Task 2/3 (`PGCOMPAT_*`) + `INFRA_ID`.
- Produces: `harness.proxysql.Admin` (methods `set_var`, `load_vars`, `snapshot`, `restore`, `query`), and pytest fixtures `admin`, `proxy_conn` used by all later tests.

- [ ] **Step 1: requirements + container image + runner**

`test/pg-compat/requirements.txt`:
```
psycopg[binary]==3.2.*
asyncpg==0.30.*
pytest==8.*
tomli==2.*
```
`test/pg-compat/Dockerfile`:
```dockerfile
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 curl && rm -rf /var/lib/apt/lists/*
WORKDIR /pg-compat
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENTRYPOINT ["pytest", "-q"]
```
`test/pg-compat/run-pg-compat.bash` (mirrors `run-tests-isolated.bash:273` — runs pytest in a container joined to the infra network):
```bash
#!/usr/bin/env bash
set -euo pipefail
: "${INFRA_ID:?}"; : "${WORKSPACE:?}"
NETWORK="${INFRA_ID}_backend"
source "${WORKSPACE}/test/tap/groups/pg-compat/env.sh"
docker build -t proxysql-pg-compat:latest "${WORKSPACE}/test/pg-compat"
docker run --rm --network "${NETWORK}" \
  -e INFRA_ID -e PGCOMPAT_PRIMARY_HOST -e PGCOMPAT_PRIMARY_PORT \
  -e PGCOMPAT_REPLICA1_HOST -e PGCOMPAT_REPLICA1_PORT \
  -e PGCOMPAT_REPLICA2_HOST -e PGCOMPAT_REPLICA2_PORT \
  -e PGCOMPAT_TOXI_ADMIN -e PGCOMPAT_TOXI_PRIMARY \
  -e PGCOMPAT_TOXI_REPLICA1 -e PGCOMPAT_TOXI_REPLICA2 \
  -e PGCOMPAT_PROXY_HOST="proxysql" -e PGCOMPAT_PROXY_PORT="6133" \
  -e PGCOMPAT_ADMIN_HOST="proxysql" -e PGCOMPAT_ADMIN_PORT="6132" \
  proxysql-pg-compat:latest "$@"
```

- [ ] **Step 2: Write the admin config primitive**

`test/pg-compat/harness/proxysql.py`:
```python
import os
import psycopg

def _admin_dsn():
    host = os.environ["PGCOMPAT_ADMIN_HOST"]; port = os.environ["PGCOMPAT_ADMIN_PORT"]
    # ProxySQL admin speaks the PG protocol on 6132; user/pass = admin/admin.
    return f"host={host} port={port} user=admin password=admin dbname=admin sslmode=disable"

class Admin:
    def __init__(self):
        self.conn = psycopg.connect(_admin_dsn(), autocommit=True)

    def query(self, sql):
        with self.conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall() if cur.description else None

    def set_var(self, name, value):
        self.query(f"SET {name}={value!r}" if isinstance(value, str) else f"SET {name}={value}")

    def load_vars(self):
        self.query("LOAD PGSQL VARIABLES TO RUNTIME")

    def snapshot(self, var_names):
        rows = self.query(
            "SELECT variable_name, variable_value FROM global_variables WHERE variable_name IN (%s)"
            % ",".join(repr(v) for v in var_names))
        return dict(rows)

    def restore(self, saved):
        for name, value in saved.items():
            self.set_var(name, value)
        self.load_vars()
```

- [ ] **Step 3: conftest fixtures + smoke test**

`test/pg-compat/conftest.py`:
```python
import os
import psycopg
import pytest
from harness.proxysql import Admin

@pytest.fixture(scope="session")
def admin():
    return Admin()

def _proxy_dsn(dbname="testuser"):
    h = os.environ["PGCOMPAT_PROXY_HOST"]; p = os.environ["PGCOMPAT_PROXY_PORT"]
    return f"host={h} port={p} user=testuser password=testuser dbname={dbname} sslmode=disable"

@pytest.fixture
def proxy_conn():
    conn = psycopg.connect(_proxy_dsn(), autocommit=True)
    yield conn
    conn.close()
```
`test/pg-compat/tests/test_smoke.py`:
```python
def test_proxy_select_one(proxy_conn):
    with proxy_conn.cursor() as cur:
        cur.execute("SELECT 1")
        assert cur.fetchone()[0] == 1

def test_admin_reconfig_roundtrip(admin):
    saved = admin.snapshot(["pgsql-authentication_method"])
    admin.set_var("pgsql-authentication_method", 1); admin.load_vars()
    val = admin.query("SELECT variable_value FROM global_variables WHERE variable_name='pgsql-authentication_method'")
    assert val[0][0] == "1"
    admin.restore(saved)
```
`test/pg-compat/pytest.ini`:
```ini
[pytest]
testpaths = tests
```

- [ ] **Step 4: Run — expect PASS**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=pg-compat test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER test/pg-compat/run-pg-compat.bash tests/test_smoke.py
```
Expected: 2 passed. Proves in-container reachability of ProxySQL frontend (6133) and admin-over-PG (6132), and the config primitive.

- [ ] **Step 5: Commit**

```bash
git add test/pg-compat
git commit -m "test(pg-compat): pytest harness skeleton + admin config primitive + smoke"
```

---

## Task 6: Differential engine (6 targets) + first case + self-check

Run each SQL case against 6 targets and assert ProxySQL is byte-identical to a direct backend. Includes a self-check proving the engine detects divergence.

**Files:**
- Create: `test/pg-compat/harness/targets.py`, `harness/diff.py`
- Create: `test/pg-compat/cases/001_scalars.sql`, `cases/002_bytea_json_array.sql`
- Create: `test/pg-compat/tests/test_differential.py`, `tests/test_differential_selfcheck.py`

**Interfaces:**
- Consumes: `Admin` (to toggle `pgsql-use_native_backend_protocol`), env endpoints (proxy + `PGCOMPAT_PRIMARY_HOST`).
- Produces: `targets.all_targets()` → list of `Target(name, connect(), result_format)`; `diff.run_case(sql, targets)` → per-target `CaseResult` + a `compare(results)` returning `(ok, diff_text)`.

- [ ] **Step 1: Write the failing differential test**

`test/pg-compat/tests/test_differential.py`:
```python
import glob, os, pytest
from harness import targets, diff

CASE_FILES = sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "cases", "*.sql")))

@pytest.mark.parametrize("case_file", CASE_FILES, ids=[os.path.basename(f) for f in CASE_FILES])
def test_case_is_transparent(admin, case_file):
    tgts = targets.all_targets(admin)
    results = diff.run_case(case_file, tgts)
    ok, detail = diff.compare(results)
    assert ok, f"{os.path.basename(case_file)} diverged:\n{detail}"
```

- [ ] **Step 2: Implement targets.py (6 targets)**

`test/pg-compat/harness/targets.py`:
```python
import os
from dataclasses import dataclass
from typing import Callable
import psycopg

def _dsn(host, port, dbname="testuser", user="testuser", pw="testuser"):
    return f"host={host} port={port} user={user} password={pw} dbname={dbname} sslmode=disable"

def _proxy():   return _dsn(os.environ["PGCOMPAT_PROXY_HOST"], os.environ["PGCOMPAT_PROXY_PORT"])
def _direct():  return _dsn(os.environ["PGCOMPAT_PRIMARY_HOST"], os.environ["PGCOMPAT_PRIMARY_PORT"])

@dataclass
class Target:
    name: str
    dsn: str
    binary: bool
    native_backend: bool | None   # None = direct (not applicable)

def all_targets(admin):
    # proxy targets exist twice: native backend OFF and ON.
    return [
        Target("proxy_libpq_text",    _proxy(),  False, False),
        Target("proxy_libpq_binary",  _proxy(),  True,  False),
        Target("proxy_native_text",   _proxy(),  False, True),
        Target("proxy_native_binary", _proxy(),  True,  True),
        Target("direct_text",         _direct(), False, None),
        Target("direct_binary",       _direct(), True,  None),
    ]
```

- [ ] **Step 3: Implement diff.py**

`test/pg-compat/harness/diff.py` — parses case metadata, sets the backend mode per target, runs, and compares status tag + column names + type OIDs + rows:
```python
import re
from fnmatch import fnmatchcase

import psycopg

def _parse(case_file):
    sql = open(case_file).read()
    # Metadata regexes run on the ORIGINAL text, comment lines included.
    skip = set(re.findall(r"--\s*skip-targets:\s*(.+)", sql))
    only = set(re.findall(r"--\s*only-targets:\s*(.+)", sql))
    # Strip comment lines PER LINE *before* splitting on ";". Filtering
    # ";"-delimited chunks that start with "--" instead discards an ENTIRE case
    # whose first line is a metadata comment: with one trailing ";" the whole
    # file is a single chunk beginning with "--", so the comment AND the SQL are
    # thrown away together and zero statements run -- a vacuous pass. Every
    # shipped case starts with such a comment, so this is not a corner case.
    body = "\n".join(l for l in sql.splitlines() if not l.strip().startswith("--"))
    stmts = [s.strip() for s in body.split(";") if s.strip()]
    return stmts, (skip.pop().split() if skip else []), (only.pop().split() if only else [])

def _run_on(target, stmts, admin):
    if target.native_backend is not None:
        admin.set_var("pgsql-use_native_backend_protocol", "true" if target.native_backend else "false")
        admin.load_vars()
    out = []
    with psycopg.connect(target.dsn, autocommit=True) as conn:
        for s in stmts:
            with conn.cursor(binary=target.binary) as cur:
                cur.execute(s)
                cols = [(d.name, d.type_code) for d in (cur.description or [])]
                rows = cur.fetchall() if cur.description else None
                out.append((cur.statusmessage, cols, rows))
    return out

def run_case(case_file, targets, admin=None):
    stmts, skip, only = _parse(case_file)
    results = {}
    for t in targets:
        # Glob matching, so a documented pattern such as "proxy_native_*"
        # actually selects the native targets; a plain name with no
        # metacharacter still compares as an exact match.
        if any(fnmatchcase(t.name, p) for p in skip): continue
        if only and not any(fnmatchcase(t.name, p) for p in only): continue
        results[t.name] = _run_on(t, stmts, admin)
    return results

def compare(results):
    # Every proxy_* result must equal its format-matched direct_* baseline.
    def base(name): return "direct_binary" if name.endswith("binary") else "direct_text"
    diffs = []
    for name, res in results.items():
        if name.startswith("direct"): continue
        b = results.get(base(name))
        if res != b:
            diffs.append(f"{name} != {base(name)}\n  got:  {res}\n  base: {b}")
    return (not diffs, "\n".join(diffs))
```
Note: `diff.run_case` needs `admin` — thread it through the test (`diff.run_case(case_file, tgts, admin)`); update the Step 1 call to pass `admin`.

- [ ] **Step 4: First cases**

`test/pg-compat/cases/001_scalars.sql`:
```sql
-- transactional: false
SELECT true, 2147483647::int4, 9223372036854775807::int8, 1.5::float8, 12345.6789::numeric, 'héllo'::text;
```
`test/pg-compat/cases/002_bytea_json_array.sql`:
```sql
-- transactional: false
SELECT '\xdeadbeef'::bytea, '{"a":1}'::jsonb, ARRAY[1,2,3]::int4[], '192.168.0.1'::inet, '00000000-0000-0000-0000-000000000001'::uuid;
```

- [ ] **Step 5: Run — expect PASS (or recorded xfail per §2.1)**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER test/pg-compat/run-pg-compat.bash tests/test_differential.py
```
Expected: proxy targets match direct. Any real divergence (esp. on `proxy_native_*`, the young path) is recorded in `xfail.toml` (Task 9), NOT silenced.

- [ ] **Step 6: Self-check — a rewrite rule must make a case fail**

`test/pg-compat/tests/test_differential_selfcheck.py`:
```python
from harness import targets, diff

def test_engine_detects_divergence(admin):
    # Install a query rule that rewrites the result, making proxy != direct.
    admin.query("INSERT INTO pgsql_query_rules (rule_id,active,match_digest,replace_pattern,re_modifiers,apply) "
                "VALUES (990001,1,'SELECT 1 AS canary','SELECT 2 AS canary','CASELESS',1)")
    admin.query("LOAD PGSQL QUERY RULES TO RUNTIME")
    try:
        tgts = targets.all_targets(admin)
        results = diff.run_case_sql("SELECT 1 AS canary", tgts, admin)   # inline-SQL helper variant
        ok, _ = diff.compare(results)
        assert not ok, "differential engine FAILED to detect an injected rewrite divergence"
    finally:
        admin.query("DELETE FROM pgsql_query_rules WHERE rule_id=990001")
        admin.query("LOAD PGSQL QUERY RULES TO RUNTIME")
```
Add a small `run_case_sql(sql, targets, admin)` helper to `diff.py` (same as `run_case` but takes a SQL string instead of a file).

- [ ] **Step 7: Run self-check + commit**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER test/pg-compat/run-pg-compat.bash tests/test_differential_selfcheck.py
git add test/pg-compat/harness/targets.py test/pg-compat/harness/diff.py test/pg-compat/cases test/pg-compat/tests/test_differential.py test/pg-compat/tests/test_differential_selfcheck.py
git commit -m "test(pg-compat): 6-target differential engine + cases + divergence self-check"
```

---

## Task 7: Routing oracle (pg_stat_statements) + self-check

Prove *where* a query landed by reading `pg_stat_statements` per backend.

**Files:**
- Create: `test/pg-compat/harness/oracle.py`, `tests/test_routing_oracle.py`

**Interfaces:**
- Consumes: direct connections to each backend (`PGCOMPAT_PRIMARY_HOST`/`_REPLICA1`/`_REPLICA2`), the proxy connection.
- Produces: `oracle.reset_all()`, `oracle.calls_for(pattern)` → `{primary:int, replica1:int, replica2:int}`.

- [ ] **Step 1: Write the failing oracle test**

`test/pg-compat/tests/test_routing_oracle.py`:
```python
from harness import oracle

def test_select_lands_on_a_reader(proxy_conn):
    oracle.reset_all()
    for _ in range(20):
        with proxy_conn.cursor() as cur:
            cur.execute("SELECT 42 AS oracle_probe")
            cur.fetchone()
    counts = oracle.calls_for("%oracle_probe%")
    # read/write split: SELECTs must hit readers (replicas), not the primary/writer.
    assert counts["primary"] == 0, f"SELECT hit the primary: {counts}"
    assert counts["replica1"] + counts["replica2"] == 20, f"reads not on replicas: {counts}"
```

- [ ] **Step 2: Implement oracle.py**

```python
import os
import psycopg

def _c(host, port):
    return psycopg.connect(
        f"host={host} port={port} user=testuser password=testuser dbname=testuser sslmode=disable",
        autocommit=True)

# Each backend carries its own port: under dbdeployer all three share a host
# and differ only by port, so keying on host alone cannot reach the replicas.
_BACKENDS = {
    "primary":  ("PGCOMPAT_PRIMARY_HOST",  "PGCOMPAT_PRIMARY_PORT"),
    "replica1": ("PGCOMPAT_REPLICA1_HOST", "PGCOMPAT_REPLICA1_PORT"),
    "replica2": ("PGCOMPAT_REPLICA2_HOST", "PGCOMPAT_REPLICA2_PORT"),
}

def reset_all():
    for host_env, port_env in _BACKENDS.values():
        with _c(os.environ[host_env], os.environ[port_env]) as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_stat_statements_reset()")

def calls_for(pattern):
    out = {}
    for name, env in _BACKENDS.items():
        with _c(os.environ[env]) as conn, conn.cursor() as cur:
            cur.execute("SELECT COALESCE(SUM(calls),0) FROM pg_stat_statements WHERE query LIKE %s", (pattern,))
            out[name] = int(cur.fetchone()[0])
    return out
```

- [ ] **Step 3: Run — expect PASS**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER test/pg-compat/run-pg-compat.bash tests/test_routing_oracle.py
```
Expected: primary=0, replicas sum to 20. (If the monitor hasn't demoted replicas yet, the reads could land on the primary — that is a real config/monitor finding, recorded per §2.1, not silenced.)

- [ ] **Step 4: Self-check — a writer-pinned query shows 0 on replicas**

Append to `tests/test_routing_oracle.py`:
```python
def test_write_pins_to_primary(proxy_conn):
    oracle.reset_all()
    with proxy_conn.cursor() as cur:
        cur.execute("CREATE TEMP TABLE oracle_w (id int)")
        cur.execute("INSERT INTO oracle_w VALUES (1)")
    counts = oracle.calls_for("%oracle_w%")
    assert counts["replica1"] == 0 and counts["replica2"] == 0, f"write leaked to a replica: {counts}"
```

- [ ] **Step 5: Run + commit**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER test/pg-compat/run-pg-compat.bash tests/test_routing_oracle.py
git add test/pg-compat/harness/oracle.py test/pg-compat/tests/test_routing_oracle.py
git commit -m "test(pg-compat): pg_stat_statements routing oracle + write-pin self-check"
```

---

## Task 8: Shared behavior set + Python driver adapter

Encode the driver-agnostic behavior set once, behind a small adapter interface, so SP-3 can add Java/Go/Node adapters against the same behaviors.

**Files:**
- Create: `test/pg-compat/drivers/python/adapter.py`
- Create: `test/pg-compat/behaviors/{__init__.py,connect.py,transactions.py,prepared.py,session_isolation.py}`
- Create: `test/pg-compat/tests/test_behaviors.py`

**Interfaces:**
- Produces: adapter protocol `Adapter` with methods `connect()`, `exec_simple(sql)`, `exec_params(sql, params, binary)`, `prepare(name, sql)`, `exec_prepared(name, params)`, `begin()/commit()/rollback()`, `close()`. Each behavior is `def run(adapter) -> None` raising on failure.

- [ ] **Step 1: Write the failing behavior test**

`test/pg-compat/tests/test_behaviors.py`:
```python
import pytest
from drivers.python.adapter import PsycopgAdapter
from behaviors import connect, transactions, prepared, session_isolation

BEHAVIORS = [connect, transactions, prepared, session_isolation]

@pytest.mark.parametrize("behavior", BEHAVIORS, ids=[b.__name__.split(".")[-1] for b in BEHAVIORS])
def test_behavior_python(behavior):
    behavior.run(PsycopgAdapter)
```

- [ ] **Step 2: Implement the Python adapter**

`test/pg-compat/drivers/python/adapter.py`:
```python
import os
import psycopg

class PsycopgAdapter:
    def __init__(self, dbname="testuser"):
        h = os.environ["PGCOMPAT_PROXY_HOST"]; p = os.environ["PGCOMPAT_PROXY_PORT"]
        self.conn = psycopg.connect(
            f"host={h} port={p} user=testuser password=testuser dbname={dbname} sslmode=disable",
            autocommit=True)

    def exec_simple(self, sql):
        with self.conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall() if cur.description else None

    def exec_params(self, sql, params, binary=False):
        with self.conn.cursor(binary=binary) as cur:
            cur.execute(sql, params)
            return cur.fetchall() if cur.description else None

    def begin(self):    self.conn.autocommit = False
    def commit(self):   self.conn.commit(); self.conn.autocommit = True
    def rollback(self): self.conn.rollback(); self.conn.autocommit = True
    def close(self):    self.conn.close()
```

- [ ] **Step 3: Implement the behaviors**

`test/pg-compat/behaviors/connect.py`:
```python
def run(Adapter):
    a = Adapter()
    assert a.exec_simple("SELECT 1")[0][0] == 1
    a.close()
```
`test/pg-compat/behaviors/transactions.py`:
```python
def run(Adapter):
    a = Adapter()
    a.exec_simple("DROP TABLE IF EXISTS tx_t")
    a.exec_simple("CREATE TABLE tx_t (id int)")
    a.begin()
    a.exec_simple("INSERT INTO tx_t VALUES (1)")
    a.rollback()
    assert a.exec_simple("SELECT count(*) FROM tx_t")[0][0] == 0, "rollback did not discard the insert"
    a.begin(); a.exec_simple("INSERT INTO tx_t VALUES (2)"); a.commit()
    assert a.exec_simple("SELECT count(*) FROM tx_t")[0][0] == 1
    a.close()
```
`test/pg-compat/behaviors/prepared.py`:
```python
def run(Adapter):
    a = Adapter()
    # Reuse a parameterized statement many times across multiplexed backends.
    for i in range(50):
        r = a.exec_params("SELECT $1::int + $2::int", (i, 1))
        assert r[0][0] == i + 1
    a.close()
```
`test/pg-compat/behaviors/session_isolation.py`:
```python
def run(Adapter):
    a = Adapter()
    a.exec_simple("SET application_name = 'behavior_A'")
    assert a.exec_simple("SHOW application_name")[0][0] == "behavior_A"
    b = Adapter()
    assert b.exec_simple("SHOW application_name")[0][0] != "behavior_A", "session state leaked across connections"
    a.close(); b.close()
```
`test/pg-compat/behaviors/__init__.py`: empty.

- [ ] **Step 4: Run + commit**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER test/pg-compat/run-pg-compat.bash tests/test_behaviors.py
git add test/pg-compat/drivers test/pg-compat/behaviors test/pg-compat/tests/test_behaviors.py
git commit -m "test(pg-compat): shared behavior set + Python (psycopg3) driver adapter"
```

---

## Task 9: xfail catalogue (discovery-phase reporting)

Make expected failures first-class so the suite is a living failure inventory rather than red-on-divergence.

**Files:**
- Create: `test/pg-compat/xfail.toml`, `test/pg-compat/harness/xfail.py`
- Modify: `test/pg-compat/conftest.py` (apply xfail markers), `pytest.ini`

**Interfaces:**
- Produces: `xfail.load()` → list of `{test_id, mode, reason, ref}`; a pytest hook that marks matching test IDs xfail(strict=False) so xpass is reported.

- [ ] **Step 1: Define the catalogue format**

`test/pg-compat/xfail.toml`:
```toml
# Each entry documents a KNOWN divergence discovered in the discovery phase (spec §2.1).
# strict=false semantics: a listed test that starts PASSING is reported as xpass (fix landed).
[[xfail]]
test_id = "tests/test_differential.py::test_case_is_transparent[002_bytea_json_array.sql]"
mode = "native"          # libpq | native | both
reason = "proxy_native_binary bytea OID mismatch on the young native backend path"
ref = "PR #5882"
```
(Seed it empty except for whatever the first real runs surface.)

- [ ] **Step 2: Implement the loader + pytest hook**

`test/pg-compat/harness/xfail.py`:
```python
import os, tomli

def load():
    path = os.path.join(os.path.dirname(__file__), "..", "xfail.toml")
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        return tomli.load(f).get("xfail", [])
```
Append to `test/pg-compat/conftest.py`:
```python
import pytest
from harness import xfail as _xfail

_XFAILS = { e["test_id"]: e for e in _xfail.load() }

def pytest_collection_modifyitems(config, items):
    for item in items:
        rel = item.nodeid
        entry = _XFAILS.get(rel)
        if entry:
            item.add_marker(pytest.mark.xfail(reason=f'{entry["reason"]} ({entry["ref"]})', strict=False))
```

- [ ] **Step 3: Verify xfail/xpass semantics**

Add a temporary known-failing case, list it in `xfail.toml`, run, and confirm it reports `xfailed`; remove the injected failure and confirm it reports `xpassed`. Then delete the temporary case.
```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER test/pg-compat/run-pg-compat.bash -rxX
```
Expected: the summary shows `xfailed`/`xpassed` lines, not `failed`.

- [ ] **Step 4: Commit**

```bash
git add test/pg-compat/xfail.toml test/pg-compat/harness/xfail.py test/pg-compat/conftest.py
git commit -m "test(pg-compat): xfail catalogue with xpass reporting (discovery phase)"
```

---

## Task 10: CI workflow — nightly + label-gated, inline build

Wire the suite into CI as a non-gating nightly job that also runs on labeled PRs. It builds ProxySQL inline (like `CI-3p-*`) rather than chaining off `CI-builds`, and follows the two-branch caller/reusable split.

**Files:**
- Create: `.github/workflows/CI-pg-compat.yml` (caller, on `v3.0`)
- Create: `gh-actions-reusable/ci-pg-compat.yml` (reusable body; merge to `GH-Actions` FIRST per `doc/GH-Actions/README.md:816-828`)

**Interfaces:**
- Consumes: `ensure-infras.bash`, `run-pg-compat.bash`. Produces: a CI job publishing the pytest summary + xfail/xpass report as an artifact.

- [ ] **Step 1: Caller workflow (schedule + label gate)**

`.github/workflows/CI-pg-compat.yml`:
```yaml
name: CI-pg-compat
on:
  schedule:
    - cron: '0 3 * * *'
  pull_request:
    types: [opened, synchronize, reopened, labeled]
  workflow_dispatch:

jobs:
  pg-compat:
    if: >-
      github.event_name == 'schedule' ||
      github.event_name == 'workflow_dispatch' ||
      contains(github.event.pull_request.labels.*.name, 'pg-compat')
    permissions: write-all
    uses: sysown/proxysql/.github/workflows/ci-pg-compat.yml@GH-Actions
    secrets: inherit
    with:
      trigger: ${{ toJson(github) }}
```

- [ ] **Step 2: Reusable body (inline build + infra + pytest)**

`gh-actions-reusable/ci-pg-compat.yml` (lands on `GH-Actions`; models the `CI-3p-*` inline-build pattern + the `ci-legacy-g4` infra steps in `README.md:355-484`):
```yaml
name: CI-pg-compat
on:
  workflow_call:
    inputs:
      trigger: { required: false, type: string }

jobs:
  pg-compat:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - name: Build ProxySQL (debug, PROXYSQL31)
        run: PROXYSQL31=1 make -j$(nproc) debug
      - name: Stand up infra (backends + Toxiproxy + ProxySQL)
        env: { INFRA_ID: ci-${{ github.run_id }}, WORKSPACE: ${{ github.workspace }}, TAP_GROUP: pg-compat }
        run: test/infra/control/ensure-infras.bash
      - name: Run pg-compat suite (non-gating, discovery phase)
        env: { INFRA_ID: ci-${{ github.run_id }}, WORKSPACE: ${{ github.workspace }} }
        run: test/pg-compat/run-pg-compat.bash --junitxml=/tmp/pg-compat.xml -rxX || true   # non-gating
      - name: Publish report
        if: always()
        uses: actions/upload-artifact@v4
        with: { name: pg-compat-report, path: /tmp/pg-compat.xml }
```
Note the `|| true` — per §2.1 this job is **reporting, not gating**, during the discovery phase; promote to gating (drop `|| true`, tighten xfail) once green and stable.

- [ ] **Step 3: Validate locally (act or a manual dry run of the steps)**

Run the reusable steps by hand on a dev box (build → ensure-infras → run-pg-compat) to confirm the sequence works end to end, since `schedule`/label triggers can only be exercised on the branch.

- [ ] **Step 4: Commit (two commits, two branches)**

```bash
# reusable first, on GH-Actions:
git add gh-actions-reusable/ci-pg-compat.yml
git commit -m "ci(pg-compat): reusable workflow (inline build + infra + pytest, non-gating)"
# caller on v3.0:
git add .github/workflows/CI-pg-compat.yml
git commit -m "ci(pg-compat): nightly + pg-compat-label caller workflow"
```

---

## Self-Review

**Spec coverage (SP-2 items → tasks):**
- New dbdeployer PG infra (primary + 2 replicas) → Tasks 1–2 ✓ (with honest dbdeployer spike + native fallback; §Greenfield register).
- Toxiproxy fault layer → Task 3 ✓ (sidecar + per-backend proxies; toxics themselves are SP-4).
- Automatic `pgsql_replication_hostgroups` routing → Task 4 ✓ (exact SQL, verified via `runtime_pgsql_servers`).
- pytest shared behavior-set runner → Tasks 5, 8 ✓ (in-container runner + adapter interface for SP-3).
- 6-target differential engine → Task 6 ✓ (proxy-libpq/native × text/binary vs direct; divergence self-check).
- `pg_stat_statements` routing oracle → Task 7 ✓ (+ write-pin self-check).
- Config-as-primitive → Task 5 ✓ (`Admin` snapshot/restore + `LOAD ... TO RUNTIME`).
- Backend-mode axis (§2.2) → Task 6 threads `pgsql-use_native_backend_protocol` off/on into the target set.
- Discovery-phase xfail catalogue (§2.1) → Task 9 ✓; CI non-gating → Task 10 ✓.

**Placeholder scan:** No TBD/TODO. The genuinely-unknown pieces are concrete **spikes with commands and a decision gate** (Task 1 dbdeployer; Task 2's variant fork), not placeholders. Task 6 Step 3 flags one wiring detail (thread `admin` into `run_case`) explicitly with the fix.

**Type consistency:** `Admin` methods (`set_var`, `load_vars`, `snapshot`, `restore`, `query`) are used consistently in Tasks 5–9. `Target` fields (`name`, `dsn`, `binary`, `native_backend`) match between `targets.py` and `diff.py`. `oracle` API (`reset_all`, `calls_for`) matches its test. Adapter methods (`exec_simple`, `exec_params`, `begin/commit/rollback`, `close`) match `PsycopgAdapter` and the behaviors. Env-var names (`PGCOMPAT_*`) are identical across `env.sh`, `run-pg-compat.bash`, and the harness.

**Cross-plan dependency:** SP-2 is independent of SP-1 (different harness) but shares the `pgsql-use_native_backend_protocol` axis framing (spec §2.2) and the discovery-phase policy (§2.1). SP-3 (more drivers) and SP-4 (chaos) build directly on Tasks 3, 6, 8.

**Highest residual risk:** Task 1 (dbdeployer-PG). If the spike fails, Task 2b (native `postgres:17`, extending the proven `infra-pgsql17-repl`) keeps the entire rest of the plan unchanged — every downstream task consumes env-injected endpoints, not a specific topology. Surface the spike outcome to the maintainer before building Task 2.
