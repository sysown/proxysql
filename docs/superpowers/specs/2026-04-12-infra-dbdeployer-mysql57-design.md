# Design: infra-dbdeployer-mysql57 — Replace infra-mysql57 with dbdeployer

**Date:** 2026-04-12
**Branch:** v3.0-dbdeployer01
**Status:** Draft

## Goal

Replace the 6-container `infra-mysql57` (3 MySQL + 3 Orchestrator) with a single-container infra using [dbdeployer](https://github.com/ProxySQL/dbdeployer/) to run 3 MySQL 5.7 instances inside one Docker container. Orchestrator is dropped (unused by legacy tests).

## Why

- Reduce container count from 6 to 1 per MySQL infra
- Faster startup and lower resource usage in CI
- Orchestrator is not used by the `legacy` test group
- Paves the way for a MySQL 8.4 variant using the same pattern

## Scope

**In scope:**
- Docker image: Dockerfile with dbdeployer + MySQL 5.7 tarball pre-baked
- Infra directory: `test/infra/infra-dbdeployer-mysql57/` with docker-compose, init/destroy, post-scripts, ProxySQL config
- Self-contained: image build artifacts live inside the infra directory under `docker/`

**Out of scope:**
- Modifying existing test groups (swap happens later)
- Fixing test failures from hostname/port changes
- MySQL 8.4 variant (separate follow-up)

## Architecture

### Current: infra-mysql57

```
6 containers:
  mysql1 (mysql:5.7, port 3306, server-id=111, read_only=0)  -- writer
  mysql2 (mysql:5.7, port 3306, server-id=222, read_only=1)  -- replica
  mysql3 (mysql:5.7, port 3306, server-id=333, read_only=1)  -- replica
  orc1, orc2, orc3 (percona-orchestrator)                    -- unused by legacy tests

Hostnames: mysql1.infra-mysql57, mysql2.infra-mysql57, mysql3.infra-mysql57
All on port 3306.
```

### New: infra-dbdeployer-mysql57

```
1 container:
  dbdeployer1 (proxysql/ci-infra:dbdeployer-mysql57)
    mysqld node1: port 3306, writer
    mysqld node2: port 3307, replica
    mysqld node3: port 3308, replica

Hostname: dbdeployer1.infra-dbdeployer-mysql57
Three ports: 3306, 3307, 3308.
No orchestrator.
```

### Key change for tests

Tests currently see 3 hostnames on port 3306. After the swap, they see 1 hostname on 3 ports. ProxySQL config (`infra-config.sql`) is updated accordingly. Some tests that connect directly to backends using `cl.mysql_host`/`cl.mysql_port` may need future updates, but that is out of scope for this branch.

## Directory Structure

```
test/infra/infra-dbdeployer-mysql57/
├── docker/
│   ├── Dockerfile            # Ubuntu base + dbdeployer + MySQL 5.7 tarball
│   ├── build.sh              # Builds and tags proxysql/ci-infra:dbdeployer-mysql57
│   └── entrypoint.sh         # Deploys replication, creates users, keeps container alive
├── .env                      # MYSQL_VERSION=5.7, WHG=1300, RHG=1301, BHG=1302, OHG=1303
├── docker-compose.yml        # Single service: dbdeployer1
├── docker-compose-init.bash  # Common init pattern (no orchestrator patching)
├── docker-compose-destroy.bash
├── bin/
│   ├── docker-mysql-post.bash   # Waits for 3 ports, creates users if not done by entrypoint
│   └── docker-proxy-post.bash   # Registers backends in ProxySQL
└── conf/
    └── proxysql/
        └── infra-config.sql     # 1 hostname, 3 ports in mysql_servers
```

## Docker Image Design

### Dockerfile (`docker/Dockerfile`)

- **Base**: Ubuntu 22.04
- **System deps**: libaio1, libnuma1, mysql-client (for health checks)
- **dbdeployer**: Download release binary from ProxySQL/dbdeployer
- **MySQL 5.7 tarball**: Download and `dbdeployer unpack` at build time, so `/root/opt/mysql/5.7.x/` is ready
- **entrypoint.sh**: Copied into image, set as ENTRYPOINT

### Entrypoint (`docker/entrypoint.sh`)

Runs at container startup:

1. **Deploy replication** (exact MySQL minor version TBD based on available tarball, e.g. `5.7.44`):
   ```bash
   dbdeployer deploy replication 5.7.44 \
     --nodes=3 \
     --gtid \
     --bind-address=0.0.0.0 \
     --base-port=3306 \
     --my-cnf-options="log-bin,log-slave-updates,binlog_format=ROW,max_connections=500,innodb_buffer_pool_size=128M,innodb_log_file_size=32M,innodb_flush_log_at_trx_commit=2,sync_binlog=0" \
     --repl-crash-safe
   ```

2. **Wait for all 3 mysqld processes** to accept connections (poll with mysqladmin ping or SELECT 1).

3. **Create test users** on all 3 nodes (same users as current `docker-mysql-post.bash`):
   - `root@'%'` with `$ROOT_PASSWORD` (passed via env var)
   - `monitor@'%'` with password `monitor`
   - `testuser@'%'` with password `testuser`
   - `$INFRA@'%'` with password `$INFRA` (infra-specific user)
   - `sbtest1`-`sbtest10` with matching passwords
   - Databases: `sysbench`, `test`, `t1`, `jdbc_test`
   - Grants: same as current setup

4. **Collect SSL certs** into bundle (same as current script, if MySQL 5.7 generates self-signed certs).

5. **Stay alive**: `exec sleep infinity` (or `tail -f /dev/null`)

### Build Script (`docker/build.sh`)

```bash
#!/bin/bash
IMAGE_TAG="${1:-proxysql/ci-infra:dbdeployer-mysql57}"
docker build -t "${IMAGE_TAG}" -f Dockerfile .
```

## Infra Runtime

### `.env`

```
MYSQL_VERSION=5.7
WHG=1300
RHG=1301
BHG=1302
OHG=1303
```

Same hostgroup IDs as `infra-mysql57` for drop-in compatibility.

### `docker-compose.yml`

Single service, no orchestrator:

```yaml
services:
  dbdeployer1:
    hostname: dbdeployer1.${INFRA}
    image: proxysql/ci-infra:dbdeployer-mysql57
    container_name: ${COMPOSE_PROJECT}-dbdeployer1-1
    environment:
      - ROOT_PASSWORD=${ROOT_PASSWORD}
      - INFRA=${INFRA}
    networks:
      backend:
        aliases:
          - dbdeployer1.${INFRA}
          - dbdeployer1.infra-dbdeployer-mysql57

networks:
  backend:
    name: "${INFRA_ID}_backend"
    external: true
```

### `docker-compose-init.bash`

Same pattern as `infra-mysql57/docker-compose-init.bash` but:
- No orchestrator config patching (step 3 skipped)
- No orchestrator post-script invocation
- Calls `docker-mysql-post.bash` and `docker-proxy-post.bash`

### `docker-compose-destroy.bash`

Same as existing infras — `docker compose down`, cleanup log dirs.

### `bin/docker-mysql-post.bash`

Simplified compared to `infra-mysql57`:
- Connects to one container (`${COMPOSE_PROJECT}-dbdeployer1-1`)
- Waits for ports 3306, 3307, 3308 to accept connections
- User creation is done by the entrypoint (inside the container). This script's role is to **wait** for readiness and **collect SSL cert bundles** — not to create users. This avoids a race condition where docker-mysql-post.bash runs before the entrypoint finishes user creation.
- If the entrypoint signals readiness (e.g. via a marker file or healthy exit code), this script proceeds to SSL cert collection.

### `bin/docker-proxy-post.bash`

Same logic as `infra-mysql57`, but references the updated `infra-config.sql`.

### `conf/proxysql/infra-config.sql`

Key change — single hostname, 3 ports:

```sql
-- Writer: node1 on port 3306
INSERT INTO mysql_servers (hostgroup_id,hostname,port,...) VALUES (${WHG},'dbdeployer1.${INFRA}',3306,...);
INSERT INTO mysql_servers (hostgroup_id,hostname,port,...) VALUES (${RHG},'dbdeployer1.${INFRA}',3306,...);

-- Replicas: node2 on 3307, node3 on 3308
INSERT INTO mysql_servers (hostgroup_id,hostname,port,...) VALUES (${RHG},'dbdeployer1.${INFRA}',3307,...);
INSERT INTO mysql_servers (hostgroup_id,hostname,port,...) VALUES (${RHG},'dbdeployer1.${INFRA}',3308,...);
```

The rest of the SQL (users, query rules, debug filters, etc.) stays the same but with updated hostname references.

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| dbdeployer `--bind-address=0.0.0.0` may not work as expected | Test during image build; fall back to patching my.sandbox.cnf post-deploy |
| `--base-port=3306` may conflict with dbdeployer's reserved ports list | Use `dbdeployer defaults update reserved-ports ''` to clear reservations |
| MySQL 5.7 tarball URL may change | Pin exact version in Dockerfile, document update process |
| Tests that hardcode hostname patterns like `mysql1.*` will break | Out of scope — expected and acceptable, will fix when swapping groups |
| Single container = single point of failure (all 3 mysqld share fate) | Acceptable for CI testing; not a production topology |

## Future Work

- **MySQL 8.4 variant**: Same pattern, different tarball — `infra-dbdeployer84/`
- **Swap legacy group**: Update `test/tap/groups/legacy/infras.lst` and `env.sh` to point to `infra-dbdeployer-mysql57`
- **Fix test failures**: Address tests that assume separate hostnames per backend
