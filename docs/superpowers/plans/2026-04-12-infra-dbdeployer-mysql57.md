# infra-dbdeployer-mysql57 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create `test/infra/infra-dbdeployer-mysql57/` — a single-container replacement for `infra-mysql57` using dbdeployer to run 3 MySQL 5.7 instances inside one Docker container.

**Architecture:** One Docker image (`proxysql/ci-infra:dbdeployer-mysql57`) bundles dbdeployer v2.2.1 + a pre-unpacked MySQL 5.7 tarball. At container startup, the entrypoint runs `dbdeployer deploy replication` to create a 3-node master-slave topology on ports 3306/3307/3308, creates the test users, and stays alive. The infra directory wraps this with docker-compose, init/destroy scripts, and ProxySQL config — following the same patterns as existing infras.

**Tech Stack:** Docker, docker-compose, bash, dbdeployer v2.2.1, MySQL 5.7

**Worktree:** `.worktrees/v3.0-dbdeployer01` (branch `v3.0-dbdeployer01`)

**Reference files to study before starting:**
- `test/infra/infra-mysql57/docker-compose.yml` — the infra being replaced
- `test/infra/infra-mysql57/docker-compose-init.bash` — init script pattern
- `test/infra/infra-mysql57/docker-compose-destroy.bash` — destroy script pattern
- `test/infra/infra-mysql57/bin/docker-mysql-post.bash` — user creation and replication setup
- `test/infra/infra-mysql57/bin/docker-proxy-post.bash` — ProxySQL registration
- `test/infra/infra-mysql57/conf/proxysql/infra-config.sql` — ProxySQL server/user/rule config
- `test/infra/infra-mysql57/.env` — hostgroup IDs and env vars

---

## File Map

All files created under `test/infra/infra-dbdeployer-mysql57/`:

| File | Responsibility |
|------|---------------|
| `docker/Dockerfile` | Image: Ubuntu 22.04 + dbdeployer + MySQL 5.7 tarball pre-unpacked |
| `docker/entrypoint.sh` | Container startup: deploy replication, create users, stay alive |
| `docker/build.sh` | Build and tag the Docker image |
| `.env` | Hostgroup IDs (WHG/RHG/BHG/OHG), MYSQL_VERSION |
| `docker-compose.yml` | Single dbdeployer1 service |
| `docker-compose-init.bash` | Infra init (adapted from infra-mysql57, no orchestrator) |
| `docker-compose-destroy.bash` | Infra teardown |
| `bin/docker-mysql-post.bash` | Wait for MySQL readiness, collect SSL certs |
| `bin/docker-proxy-post.bash` | Register backends in ProxySQL |
| `conf/proxysql/infra-config.sql` | ProxySQL config: 1 hostname, 3 ports |

---

## Task 1: Create the Dockerfile

**Files:**
- Create: `test/infra/infra-dbdeployer-mysql57/docker/Dockerfile`

- [ ] **Step 1: Create directory structure**

```bash
cd .worktrees/v3.0-dbdeployer01
mkdir -p test/infra/infra-dbdeployer-mysql57/docker
```

- [ ] **Step 2: Write the Dockerfile**

Create `test/infra/infra-dbdeployer-mysql57/docker/Dockerfile`:

```dockerfile
FROM ubuntu:22.04

ARG DBDEPLOYER_VERSION=2.2.1
ARG MYSQL_TARBALL_URL=https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-5.7.44-linux-glibc2.12-x86_64.tar.gz

ENV DEBIAN_FRONTEND=noninteractive

# System dependencies required by MySQL 5.7
RUN apt-get update && apt-get install -y --no-install-recommends \
    libaio1 \
    libnuma1 \
    libncurses5 \
    perl \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install dbdeployer
RUN curl -fsSL "https://github.com/ProxySQL/dbdeployer/releases/download/v${DBDEPLOYER_VERSION}/dbdeployer-${DBDEPLOYER_VERSION}.linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin/ \
    && chmod +x /usr/local/bin/dbdeployer

# Download and unpack MySQL 5.7 tarball (pre-baked so no download at runtime)
RUN mkdir -p /root/downloads \
    && curl -fsSL -o /root/downloads/mysql-5.7.44.tar.gz "${MYSQL_TARBALL_URL}" \
    && dbdeployer unpack /root/downloads/mysql-5.7.44.tar.gz \
    && rm -f /root/downloads/mysql-5.7.44.tar.gz

# Clear reserved ports so dbdeployer allows 3306
RUN dbdeployer defaults update reserved-ports ''

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3306 3307 3308

ENTRYPOINT ["/entrypoint.sh"]
```

**Notes:**
- The MySQL 5.7.44 tarball URL points to the official MySQL download site. If this URL is unreliable, it can be replaced with an internal mirror.
- `dbdeployer unpack` places files at `~/opt/mysql/5.7.44/` (i.e. `/root/opt/mysql/5.7.44/`).
- We clear reserved ports because 3306 is reserved by default and dbdeployer would refuse to use it.

- [ ] **Step 3: Commit**

```bash
git add test/infra/infra-dbdeployer-mysql57/docker/Dockerfile
git commit -m "feat(infra): add Dockerfile for dbdeployer-mysql57 image

Ubuntu 22.04 base with dbdeployer v2.2.1 and pre-unpacked MySQL 5.7.44
tarball. Clears reserved ports to allow base-port 3306."
```

---

## Task 2: Create the entrypoint script

**Files:**
- Create: `test/infra/infra-dbdeployer-mysql57/docker/entrypoint.sh`

- [ ] **Step 1: Write the entrypoint script**

Create `test/infra/infra-dbdeployer-mysql57/docker/entrypoint.sh`:

```bash
#!/bin/bash
set -e
set -o pipefail

echo "========================================================================"
echo "dbdeployer entrypoint: deploying MySQL 5.7 replication (3 nodes)..."
echo "========================================================================"

# Detect the unpacked MySQL version
MYSQL_VERSION=$(ls /root/opt/mysql/ | head -1)
if [ -z "${MYSQL_VERSION}" ]; then
    echo "ERROR: No MySQL tarball found in /root/opt/mysql/"
    exit 1
fi
echo "Using MySQL version: ${MYSQL_VERSION}"

# Deploy 3-node replication with GTID
dbdeployer deploy replication "${MYSQL_VERSION}" \
    --nodes=3 \
    --gtid \
    --bind-address=0.0.0.0 \
    --base-port=3306 \
    --my-cnf-options="log-slave-updates,binlog_format=ROW,max_connections=500,innodb_buffer_pool_size=128M,innodb_log_file_size=32M,innodb_flush_log_at_trx_commit=2,sync_binlog=0,binlog_checksum=NONE,show_compatibility_56=ON" \
    --repl-crash-safe

echo "Replication deployed. Waiting for all nodes to be ready..."

# Determine the sandbox directory
SANDBOX_DIR=$(ls -d /root/sandboxes/rsandbox_* | head -1)
if [ -z "${SANDBOX_DIR}" ]; then
    echo "ERROR: Sandbox directory not found"
    exit 1
fi
echo "Sandbox directory: ${SANDBOX_DIR}"

# Wait for all 3 nodes to accept connections
for NODE_NUM in 1 2 3; do
    PORT=$((3305 + NODE_NUM))
    echo -n "Waiting for node${NODE_NUM} on port ${PORT}..."
    MAX_WAIT=60
    COUNT=0
    while ! "${SANDBOX_DIR}/node${NODE_NUM}/use" -e "SELECT 1" >/dev/null 2>&1; do
        if [ $COUNT -ge $MAX_WAIT ]; then
            echo " TIMEOUT"
            exit 1
        fi
        echo -n "."
        sleep 1
        COUNT=$((COUNT + 1))
    done
    echo " OK"
done

# Create test users on all 3 nodes
# ROOT_PASSWORD and INFRA are passed via environment variables
ROOT_PASSWORD="${ROOT_PASSWORD:-default_password}"
INFRA="${INFRA:-infra-dbdeployer-mysql57}"

echo "Creating test users on all nodes..."
for NODE_NUM in 1 2 3; do
    NODE_SCRIPT="${SANDBOX_DIR}/node${NODE_NUM}/use"
    echo "Configuring users on node${NODE_NUM}..."

    "${NODE_SCRIPT}" <<SQL
SET SQL_LOG_BIN=0;

-- root user with dynamic password
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASSWORD}';
ALTER USER 'root'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

-- Monitor user
CREATE USER IF NOT EXISTS 'monitor'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'monitor';
GRANT USAGE, REPLICATION CLIENT ON *.* TO 'monitor'@'%';

-- testuser
CREATE USER IF NOT EXISTS 'testuser'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'testuser';
GRANT ALL PRIVILEGES ON *.* TO 'testuser'@'%';

-- Cluster specific user
CREATE USER IF NOT EXISTS '${INFRA}'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${INFRA}';
GRANT ALL PRIVILEGES ON *.* TO '${INFRA}'@'%';

-- Databases
CREATE DATABASE IF NOT EXISTS sysbench;
CREATE DATABASE IF NOT EXISTS test;
CREATE DATABASE IF NOT EXISTS t1;
CREATE DATABASE IF NOT EXISTS jdbc_test;

-- sbtest users
$(for j in $(seq 1 10); do
    echo "CREATE USER IF NOT EXISTS 'sbtest${j}'@'%' IDENTIFIED BY 'sbtest${j}';"
    for db in sysbench test t1 jdbc_test; do
        echo "GRANT ALL PRIVILEGES ON ${db}.* TO 'sbtest${j}'@'%';"
    done
done)

-- ssluser
CREATE USER IF NOT EXISTS 'ssluser'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'ssluser';
GRANT ALL PRIVILEGES ON *.* TO 'ssluser'@'%';

-- user (generic)
CREATE USER IF NOT EXISTS 'user'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'user';
GRANT ALL PRIVILEGES ON *.* TO 'user'@'%';

FLUSH PRIVILEGES;
SQL
done

# Signal readiness via marker file (used by docker-mysql-post.bash)
touch /tmp/dbdeployer_ready

echo "========================================================================"
echo "dbdeployer MySQL 5.7 replication is ready."
echo "  Node 1 (writer): port 3306"
echo "  Node 2 (replica): port 3307"
echo "  Node 3 (replica): port 3308"
echo "========================================================================"

# Keep container alive
exec sleep infinity
```

- [ ] **Step 2: Commit**

```bash
git add test/infra/infra-dbdeployer-mysql57/docker/entrypoint.sh
git commit -m "feat(infra): add entrypoint script for dbdeployer-mysql57

Deploys 3-node GTID replication via dbdeployer, creates all test users
(root, monitor, testuser, sbtest1-10, ssluser, user, infra-specific),
creates test databases, signals readiness via marker file."
```

---

## Task 3: Create the build script

**Files:**
- Create: `test/infra/infra-dbdeployer-mysql57/docker/build.sh`

- [ ] **Step 1: Write the build script**

Create `test/infra/infra-dbdeployer-mysql57/docker/build.sh`:

```bash
#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="${1:-proxysql/ci-infra:dbdeployer-mysql57}"

echo "Building Docker image: ${IMAGE_TAG}"
docker build -t "${IMAGE_TAG}" -f "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}"
echo "Done: ${IMAGE_TAG}"
```

- [ ] **Step 2: Make it executable and commit**

```bash
chmod +x test/infra/infra-dbdeployer-mysql57/docker/build.sh
git add test/infra/infra-dbdeployer-mysql57/docker/build.sh
git commit -m "feat(infra): add build script for dbdeployer-mysql57 image"
```

---

## Task 4: Create .env and docker-compose.yml

**Files:**
- Create: `test/infra/infra-dbdeployer-mysql57/.env`
- Create: `test/infra/infra-dbdeployer-mysql57/docker-compose.yml`

- [ ] **Step 1: Write .env**

Create `test/infra/infra-dbdeployer-mysql57/.env`:

```
MYSQL_VERSION=5.7
WHG=1300
RHG=1301
BHG=1302
OHG=1303

# Export hostgroup for TAP tests that need it
export TAP_REG_TEST_3549_AUTOCOMMIT_TRACKING___MYSQL_SERVER_HOSTGROUP=${WHG}
```

This is identical to `infra-mysql57/.env` — same hostgroup IDs for drop-in compatibility.

- [ ] **Step 2: Write docker-compose.yml**

Create `test/infra/infra-dbdeployer-mysql57/docker-compose.yml`:

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

- [ ] **Step 3: Commit**

```bash
git add test/infra/infra-dbdeployer-mysql57/.env test/infra/infra-dbdeployer-mysql57/docker-compose.yml
git commit -m "feat(infra): add .env and docker-compose.yml for infra-dbdeployer-mysql57

Single service (dbdeployer1) replaces 6 containers (3 mysql + 3 orc).
Same hostgroup IDs as infra-mysql57 for compatibility."
```

---

## Task 5: Create docker-compose-init.bash

**Files:**
- Create: `test/infra/infra-dbdeployer-mysql57/docker-compose-init.bash`
- Reference: `test/infra/infra-mysql57/docker-compose-init.bash`

- [ ] **Step 1: Write the init script**

Create `test/infra/infra-dbdeployer-mysql57/docker-compose-init.bash`. This is adapted from `infra-mysql57/docker-compose-init.bash` with these changes:
- Remove orchestrator config patching (step 3 in the original)
- Remove SSL transient setup (step 4 — not needed, MySQL 5.7 in dbdeployer generates its own certs)
- Remove orchestrator post-script invocation

```bash
#!/bin/bash
# RELIABLY CAPTURE INFRA_ID FROM ENVIRONMENT OR DIRECTORY NAME
if [ -z "${INFRA_ID}" ]; then
    export INFRA_ID=$(basename $(dirname $(pwd)) | sed 's/infra-//; s/docker-//')
fi
# Final safety: if INFRA_ID is still empty or ".", use a default
if [ -z "${INFRA_ID}" ] || [ "${INFRA_ID}" = "." ]; then
    export INFRA_ID="dev-$USER"
fi

# Derive Workspace relative to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

set -e
set -o pipefail

# SUDO helper: empty if root
SUDO=""
if [ "$(id -u)" != "0" ]; then SUDO="sudo"; fi

# relaunch self with timeout
[[ $(ps -o command= $(ps -o ppid= $$)) =~ timeout ]] || exec timeout -v -s 9 ${TIMEOUT:-600} "${BASH_SOURCE}" "$@"

# make sure we have correct cwd
pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT

# Load .env but ensure INFRA_ID is preserved
if [ ! -f .env ]; then echo "Error: .env not found"; exit 1; fi
SAVED_INFRA_ID="${INFRA_ID}"
set -a; . .env; set +a
export INFRA_ID="${SAVED_INFRA_ID}"

# Docker Compose version helper - prefer plugin (v2)
COMPOSE_CMD="docker compose"
if ! $COMPOSE_CMD version &>/dev/null; then
    COMPOSE_CMD="docker-compose"
    if ! $COMPOSE_CMD version &>/dev/null; then
        echo "ERROR: Neither 'docker compose' nor 'docker-compose' found!"
        exit 1
    fi
fi

if [ -z "${INFRA_ID}" ]; then echo "Error: INFRA_ID must be set"; exit 1; fi

export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)
export INFRA=${PWD##*/}
export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"
export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${WORKSPACE}/ci_infra_logs}

echo "================================================================================"
echo "Initializing CI Infra '${INFRA}' (Project: ${COMPOSE_PROJECT}) ..."
echo "================================================================================"

# 1. VERIFY NO EXISTING CONTAINERS ARE RUNNING FOR THIS PROJECT
if [ -n "$($COMPOSE_CMD -p "${COMPOSE_PROJECT}" ps -q 2>/dev/null)" ]; then
    echo "ERROR: Containers for project ${COMPOSE_PROJECT} are already running."
    echo "Please run teardown first."
    exit 1
fi

# 2. Infrastructure-specific preparation (logs/data)
echo "Scanning for volumes in docker-compose.yml..."
MOUNTED_PATHS=$(grep -E '\$\{INFRA_LOGS_PATH\}|\./log/' docker-compose.yml | grep -vE "\.crt|\.key" | awk -F: '{print $1}' | sed 's/^[[:space:]-]*//' | sort -u || true)

for RAW_PATH in ${MOUNTED_PATHS}; do
    if [[ "${RAW_PATH}" == "./conf/"* ]]; then continue; fi
    eval "ACTUAL_PATH=${RAW_PATH}"
    if [ -d "${ACTUAL_PATH}" ] && [ "$(ls -A "${ACTUAL_PATH}" 2>/dev/null)" ]; then
        echo "ERROR: Directory '${ACTUAL_PATH}' is not empty."
        echo "Please run teardown/cleanup first."
        exit 1
    fi
    echo "Preparing directory: ${ACTUAL_PATH}"
    $SUDO mkdir -p "${ACTUAL_PATH}"
    $SUDO chmod -R 777 "${ACTUAL_PATH}"
done

# 3. Create a temporary env file for docker-compose
ENV_FILE=".env.isolated.${INFRA_ID}"
cat <<ENVEOF > "${ENV_FILE}"
INFRA_ID=${INFRA_ID}
ROOT_PASSWORD=${ROOT_PASSWORD}
INFRA=${INFRA}
COMPOSE_PROJECT=${COMPOSE_PROJECT}
INFRA_LOGS_PATH=${INFRA_LOGS_PATH}
ENVEOF

# 4. START CONTAINERS
if ! $COMPOSE_CMD --env-file .env --env-file "${ENV_FILE}" -p "${COMPOSE_PROJECT}" up -d; then
    echo "ERROR: Docker Compose failed"; rm -f "${ENV_FILE}"; exit 1
fi
rm -f "${ENV_FILE}"

# 5. VERIFY ALL CONTAINERS STARTED SUCCESSFULLY
echo "Verifying container health..."
PROJECT_CONTAINERS=$($COMPOSE_CMD -p "${COMPOSE_PROJECT}" ps --format '{{.Name}}')
for C in ${PROJECT_CONTAINERS}; do
    STATE=$(docker inspect -f '{{.State.Running}}' "${C}" 2>/dev/null || echo "false")
    if [ "${STATE}" != "true" ]; then
        echo -e "\nERROR: Container ${C} failed to start!"
        echo ">>> Container Logs:"
        docker logs "${C}" | tail -n 50
        exit 1
    fi
done

if [ -f /.dockerenv ]; then
    RUNNER_ID=$(hostname)
    docker network connect "${INFRA_ID}_backend" "${RUNNER_ID}" || true
fi

# 6. Run post-scripts
# Wait for dbdeployer entrypoint to finish MySQL deployment
CONTAINER="${COMPOSE_PROJECT}-dbdeployer1-1"
echo -n "Waiting for dbdeployer to finish deployment..."
MAX_WAIT=120
COUNT=0
while ! docker exec "${CONTAINER}" test -f /tmp/dbdeployer_ready 2>/dev/null; do
    if [ $COUNT -ge $MAX_WAIT ]; then
        echo " TIMEOUT"
        echo ">>> Container Logs:"
        docker logs "${CONTAINER}" | tail -n 50
        exit 1
    fi
    echo -n "."
    sleep 2
    COUNT=$((COUNT + 2))
done
echo " OK"

[ -f ./bin/docker-mysql-post.bash ] && ./bin/docker-mysql-post.bash
[ -f ./bin/docker-proxy-post.bash ] && ./bin/docker-proxy-post.bash "$1"

echo "================================================================================"
echo "Done."
echo "================================================================================"
```

- [ ] **Step 2: Make it executable and commit**

```bash
chmod +x test/infra/infra-dbdeployer-mysql57/docker-compose-init.bash
git add test/infra/infra-dbdeployer-mysql57/docker-compose-init.bash
git commit -m "feat(infra): add init script for infra-dbdeployer-mysql57

Adapted from infra-mysql57. Removes orchestrator patching and SSL setup.
Waits for dbdeployer readiness marker before running post-scripts."
```

---

## Task 6: Create docker-compose-destroy.bash

**Files:**
- Create: `test/infra/infra-dbdeployer-mysql57/docker-compose-destroy.bash`
- Reference: `test/infra/infra-mysql57/docker-compose-destroy.bash`

- [ ] **Step 1: Write the destroy script**

Create `test/infra/infra-dbdeployer-mysql57/docker-compose-destroy.bash`:

```bash
#!/bin/bash
set -e
set -o pipefail
pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT
set -a; . .env; set +a
export INFRA=${PWD##*/}
export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"

echo "Destroying CI Infra Cluster '${INFRA}' (Project: ${COMPOSE_PROJECT})..."
docker compose -p "${COMPOSE_PROJECT}" down -v
```

This is identical to the `infra-mysql57` version — the destroy pattern is generic.

- [ ] **Step 2: Make it executable and commit**

```bash
chmod +x test/infra/infra-dbdeployer-mysql57/docker-compose-destroy.bash
git add test/infra/infra-dbdeployer-mysql57/docker-compose-destroy.bash
git commit -m "feat(infra): add destroy script for infra-dbdeployer-mysql57"
```

---

## Task 7: Create bin/docker-mysql-post.bash

**Files:**
- Create: `test/infra/infra-dbdeployer-mysql57/bin/docker-mysql-post.bash`
- Reference: `test/infra/infra-mysql57/bin/docker-mysql-post.bash`

- [ ] **Step 1: Create directory and write the script**

```bash
mkdir -p test/infra/infra-dbdeployer-mysql57/bin
```

Create `test/infra/infra-dbdeployer-mysql57/bin/docker-mysql-post.bash`:

```bash
#!/bin/bash
set -e
set -o pipefail
[ -f .env ] && . .env

CONTAINER="${COMPOSE_PROJECT}-dbdeployer1-1"

# Prepare cert bundle directories
BUNDLE_DIR="${INFRA_LOGS_PATH}/${INFRA_ID}/proxysql"
sudo mkdir -p "${BUNDLE_DIR}"
sudo chmod 777 "${BUNDLE_DIR}"

DB_BUNDLE="${BUNDLE_DIR}/dbservers-cert-bundle.pem"
CA_BUNDLE="${BUNDLE_DIR}/caservers-cert-bundle.pem"
sudo rm -f "${DB_BUNDLE}" "${CA_BUNDLE}"

# Verify all 3 MySQL nodes are reachable
for PORT in 3306 3307 3308; do
    echo -n "Verifying MySQL on ${CONTAINER}:${PORT}..."
    MAX_WAIT=60
    COUNT=0
    while ! docker exec "${CONTAINER}" mysql -h127.0.0.1 -P${PORT} -uroot -p"${ROOT_PASSWORD}" -e "SELECT 1" >/dev/null 2>&1; do
        if [ $COUNT -ge $MAX_WAIT ]; then
            echo " TIMEOUT"
            exit 1
        fi
        echo -n "."
        sleep 2
        COUNT=$((COUNT + 2))
    done
    echo " OK"
done

# Verify replication is working on nodes 2 and 3
for PORT in 3307 3308; do
    echo -n "Checking replication on port ${PORT}..."
    SLAVE_STATUS=$(docker exec "${CONTAINER}" mysql -h127.0.0.1 -P${PORT} -uroot -p"${ROOT_PASSWORD}" -e "SHOW SLAVE STATUS\G" 2>/dev/null)
    IO_RUNNING=$(echo "${SLAVE_STATUS}" | grep "Slave_IO_Running:" | awk '{print $2}')
    SQL_RUNNING=$(echo "${SLAVE_STATUS}" | grep "Slave_SQL_Running:" | awk '{print $2}')
    if [ "${IO_RUNNING}" = "Yes" ] && [ "${SQL_RUNNING}" = "Yes" ]; then
        echo " OK (IO: Yes, SQL: Yes)"
    else
        echo " WARNING (IO: ${IO_RUNNING}, SQL: ${SQL_RUNNING})"
    fi
done

# Collect SSL certs from node1 (all nodes share the same datadir-generated certs)
# dbdeployer sandbox datadirs are at ~/sandboxes/rsandbox_*/node1/data/
DATADIR=$(docker exec "${CONTAINER}" bash -c 'ls -d /root/sandboxes/rsandbox_*/node1/data' 2>/dev/null)
if [ -n "${DATADIR}" ]; then
    if docker exec "${CONTAINER}" test -f "${DATADIR}/ca.pem"; then
        echo "Collecting CA cert from node1..."
        docker exec "${CONTAINER}" cat "${DATADIR}/ca.pem" | sudo tee -a "${DB_BUNDLE}" | sudo tee -a "${CA_BUNDLE}" > /dev/null
    else
        echo ">>> CA cert not found at ${DATADIR}/ca.pem. Skipping SSL collection."
    fi
fi
[ -f "${DB_BUNDLE}" ] && sudo chmod 666 "${DB_BUNDLE}" "${CA_BUNDLE}" || true

echo "docker-mysql-post.bash complete."
```

- [ ] **Step 2: Make it executable and commit**

```bash
chmod +x test/infra/infra-dbdeployer-mysql57/bin/docker-mysql-post.bash
git add test/infra/infra-dbdeployer-mysql57/bin/docker-mysql-post.bash
git commit -m "feat(infra): add docker-mysql-post for infra-dbdeployer-mysql57

Verifies all 3 MySQL nodes on ports 3306/3307/3308, checks replication
status, and collects SSL cert bundles. User creation is handled by
the container entrypoint."
```

---

## Task 8: Create conf/proxysql/infra-config.sql

**Files:**
- Create: `test/infra/infra-dbdeployer-mysql57/conf/proxysql/infra-config.sql`
- Reference: `test/infra/infra-mysql57/conf/proxysql/infra-config.sql`

- [ ] **Step 1: Create directory and write the SQL config**

```bash
mkdir -p test/infra/infra-dbdeployer-mysql57/conf/proxysql
```

Create `test/infra/infra-dbdeployer-mysql57/conf/proxysql/infra-config.sql`. This is adapted from infra-mysql57 — the key change is replacing 3 hostnames (mysql1/mysql2/mysql3) with 1 hostname (dbdeployer1) on 3 ports (3306/3307/3308):

```sql
UPDATE global_variables SET variable_value='false' WHERE variable_name='admin-hash_passwords';
SET admin-mysql_ifaces='0.0.0.0:6032;0.0.0.0:6031;/tmp/proxysql_admin.sock';
SET mysql-have_ssl='true';
SET mysql-have_compress='true';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

DELETE FROM mysql_servers WHERE comment LIKE 'test server';
DELETE FROM mysql_servers WHERE comment LIKE '%${INFRA}';
-- Writer (node1) in both WHG and RHG
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (${WHG},'dbdeployer1.${INFRA}',3306,180,500,'dbdeployer1.${INFRA}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (${RHG},'dbdeployer1.${INFRA}',3306,180,500,'dbdeployer1.${INFRA}');
-- Replicas (node2, node3) in RHG only
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (${RHG},'dbdeployer1.${INFRA}',3307,180,500,'dbdeployer1.${INFRA}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (${RHG},'dbdeployer1.${INFRA}',3308,180,500,'dbdeployer1.${INFRA}');

DELETE FROM mysql_replication_hostgroups WHERE comment LIKE '%${INFRA}';
INSERT INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup,comment) VALUES (${WHG},${RHG},'${INFRA}');

DELETE FROM mysql_group_replication_hostgroups WHERE comment LIKE '%${INFRA}';

DELETE FROM mysql_galera_hostgroups  WHERE comment LIKE '%${INFRA}';

DELETE FROM mysql_aws_aurora_hostgroups  WHERE comment LIKE '%${INFRA}';
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;

DELETE FROM mysql_users WHERE comment LIKE '%${INFRA}';
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('root','root',1,${WHG},'${INFRA}');
UPDATE mysql_users SET default_hostgroup=${WHG},comment='${INFRA}' WHERE username='root';
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('user','user',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('testuser','testuser',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest1','sbtest1',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest2','sbtest2',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest3','sbtest3',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest4','sbtest4',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest7','sbtest7',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest8','sbtest8',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('ssluser','ssluser',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('${INFRA}','${INFRA}',1,${WHG},'${INFRA}');
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;

DELETE FROM mysql_query_rules WHERE comment LIKE '%${INFRA}';
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,comment) VALUES (${PREFIX}00,1,'root','^SELECT.*FOR UPDATE',${WHG},1,'${INFRA}');
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,comment) VALUES (${PREFIX}01,1,'root','^SELECT',${RHG},1,'${INFRA}');
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,comment) VALUES (${PREFIX}03,1,'testuser','^SELECT.*FOR UPDATE',${WHG},1,'${INFRA}');
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,comment) VALUES (${PREFIX}04,1,'testuser','^SELECT',${RHG},1,'${INFRA}');
LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL QUERY RULES TO DISK;

DELETE FROM scheduler WHERE comment LIKE '%${INFRA}';
LOAD SCHEDULER TO RUNTIME;
SAVE SCHEDULER TO DISK;

SET mysql-eventslog_default_log=1;
SET mysql-eventslog_format=2;
SET mysql-eventslog_filename='query.log';
SET mysql-auditlog_filesize=104857600;
SET mysql-auditlog_filename='audit.log';
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;

# configure Prometheus
SET admin-restapi_enabled='true';
SET admin-restapi_port=6070;
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

# configure DEBUGDB_DISK
UPDATE global_variables SET variable_value='2' WHERE variable_name='admin-debug_output';
SET admin-debug='true';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
UPDATE debug_levels SET verbosity=7;
UPDATE debug_levels SET verbosity=0 WHERE module IN ('debug_pkt_array','debug_net');
REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'get_pkts_from_client');
REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler');
REPLACE INTO debug_filters VALUES ('ProxySQL_Admin.cpp',0,'save_mysql_servers_runtime_to_database');
REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'ping_handler');
REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'generic_handler');
REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler_again___verify_backend_user_schema');
REPLACE INTO debug_filters VALUES ('mysql_data_stream.cpp',0,'assign_fd_from_mysql_conn');
REPLACE INTO debug_filters VALUES ('mysql_data_stream.cpp',0,'setDSS_STATE_QUERY_SENT_NET');
REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'set_no_backslash_escapes');
REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler_again___verify_backend_session_track_gtids');
REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler_again___verify_backend_autocommit');
REPLACE INTO debug_filters VALUES ('MySQL_Thread.cpp',0,'tune_timeout_for_myds_needs_pause');
REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'handler');
REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'real_query_cont');
REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler_again___verify_multiple_variables');
REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'handler');
REPLACE INTO debug_filters VALUES ('PgSQL_Connection.cpp',0,'handler');
REPLACE INTO debug_filters VALUES ('Base_Thread.cpp',0,'tune_timeout_for_myds_needs_pause');
REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection');
REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection');
REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'handler_again___verify_backend_user_db');
REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'get_pkts_from_client');
REPLACE INTO debug_filters VALUES ('MySQL_HostGroups_Manager.cpp',0,'push_MyConn_to_pool');
REPLACE INTO debug_filters VALUES ('MySQL_HostGroups_Manager.cpp',0,'get_MyConn_from_pool');
REPLACE INTO debug_filters VALUES ('MySrvConnList.cpp',0,'get_random_MyConn');
REPLACE INTO debug_filters VALUES ('MyHGC.cpp',0,'get_random_MySrvC');
REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_S');
REPLACE INTO debug_filters VALUES ('PgSQL_HostGroups_Manager.cpp',0,'get_random_MySrvC');
REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'stmt_prepare_cont');
REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'stmt_execute_cont');
REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'event_loop');
REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'get_connection');
REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'put_connection');
REPLACE INTO debug_filters VALUES ('PgSQL_Monitor.cpp',0,'worker_thread');
REPLACE INTO debug_filters VALUES ('PgSQL_Data_Stream.cpp',0,'assign_fd_from_pgsql_conn');
LOAD DEBUG TO RUNTIME;
SAVE DEBUG TO DISK;

# configure SSLKEYLOG
UPDATE global_variables SET variable_value='proxysql_ssl.keylog' WHERE variable_name='admin-ssl_keylog_file';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
```

- [ ] **Step 2: Commit**

```bash
git add test/infra/infra-dbdeployer-mysql57/conf/proxysql/infra-config.sql
git commit -m "feat(infra): add ProxySQL config for infra-dbdeployer-mysql57

Adapted from infra-mysql57. Key change: single hostname (dbdeployer1)
with 3 ports (3306/3307/3308) instead of 3 hostnames on port 3306.
All other config (users, query rules, debug filters) unchanged."
```

---

## Task 9: Create bin/docker-proxy-post.bash

**Files:**
- Create: `test/infra/infra-dbdeployer-mysql57/bin/docker-proxy-post.bash`
- Reference: `test/infra/infra-mysql57/bin/docker-proxy-post.bash`

- [ ] **Step 1: Write the proxy post-script**

Create `test/infra/infra-dbdeployer-mysql57/bin/docker-proxy-post.bash`:

```bash
#!/bin/bash
set -e
set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "${SCRIPT_DIR}/../.env" ] && . "${SCRIPT_DIR}/../.env"
PROXY_CONTAINER="proxysql.${INFRA_ID}"

echo ">>> Configuring ProxySQL (${PROXY_CONTAINER}) for Cluster: ${INFRA}"

docker exec -i "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 <<SQL
$(eval "echo \"$(cat ./conf/proxysql/infra-config.sql)\"")

-- Clean up existing user records
DELETE FROM mysql_users WHERE username='root';
DELETE FROM mysql_users WHERE username='testuser';

-- Register root user (fast_forward=0 by default)
INSERT OR IGNORE INTO mysql_users (username, password, active, default_hostgroup, fast_forward, backend, frontend, comment)
VALUES ('root', '${ROOT_PASSWORD}', 1, ${WHG}, 0, 1, 1, 'dynamic-root-user');

-- Register testuser (fast_forward=0 by default)
INSERT OR IGNORE INTO mysql_users (username, password, active, default_hostgroup, fast_forward, backend, frontend, comment)
VALUES ('testuser', 'testuser', 1, ${WHG}, 0, 1, 1, 'universal-testuser');

-- Ensure cluster specific user is also correctly set
DELETE FROM mysql_users WHERE username='${INFRA}';
INSERT OR IGNORE INTO mysql_users (username, password, active, default_hostgroup, fast_forward, backend, frontend, comment)
VALUES ('${INFRA}', '${INFRA}', 1, ${WHG}, 0, 1, 1, '${INFRA}');

-- Synchronize monitor credentials
UPDATE global_variables SET variable_value='monitor' WHERE variable_name='mysql-monitor_username';
UPDATE global_variables SET variable_value='monitor' WHERE variable_name='mysql-monitor_password';

LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;
LOAD MYSQL VARIABLES TO RUNTIME;
-- Ensure hostgroup 0 and 1 exist if not already present
INSERT INTO mysql_servers (hostgroup_id, hostname, port, max_replication_lag, max_connections, comment)
SELECT 0, hostname, port, max_replication_lag, max_connections, 'fallback-hg0'
FROM mysql_servers WHERE hostgroup_id = ${WHG} AND NOT EXISTS (SELECT 1 FROM mysql_servers WHERE hostgroup_id = 0);

INSERT INTO mysql_servers (hostgroup_id, hostname, port, max_replication_lag, max_connections, comment)
SELECT 1, hostname, port, max_replication_lag, max_connections, 'fallback-hg1'
FROM mysql_servers WHERE hostgroup_id = ${RHG} AND NOT EXISTS (SELECT 1 FROM mysql_servers WHERE hostgroup_id = 1);

-- Ensure replication hostgroup 0/1 mapping exists
INSERT INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, comment)
SELECT 0, 1, 'fallback-repl-hg'
WHERE NOT EXISTS (SELECT 1 FROM mysql_replication_hostgroups WHERE writer_hostgroup = 0 AND reader_hostgroup = 1);

LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;
SAVE MYSQL VARIABLES TO DISK;
SQL

if [ $? -eq 0 ]; then echo "Cluster ${INFRA} registered in ProxySQL."; else echo "ERROR: ProxySQL configuration FAILED for ${INFRA}"; exit 1; fi
```

- [ ] **Step 2: Make it executable and commit**

```bash
chmod +x test/infra/infra-dbdeployer-mysql57/bin/docker-proxy-post.bash
git add test/infra/infra-dbdeployer-mysql57/bin/docker-proxy-post.bash
git commit -m "feat(infra): add docker-proxy-post for infra-dbdeployer-mysql57

Same logic as infra-mysql57: registers backends in ProxySQL, creates
fallback hostgroups 0/1, sets monitor credentials."
```

---

## Task 10: Build and smoke-test the Docker image

This task verifies the image builds and the entrypoint works.

- [ ] **Step 1: Build the image**

```bash
cd test/infra/infra-dbdeployer-mysql57
bash docker/build.sh
```

Expected: Image builds successfully, tagged `proxysql/ci-infra:dbdeployer-mysql57`.

- [ ] **Step 2: Smoke-test the container standalone**

```bash
docker run --rm -d --name dbdeployer-test \
    -e ROOT_PASSWORD=testpass \
    -e INFRA=infra-dbdeployer-mysql57 \
    proxysql/ci-infra:dbdeployer-mysql57

# Wait for readiness (up to 2 minutes)
echo -n "Waiting for dbdeployer..."
for i in $(seq 1 60); do
    if docker exec dbdeployer-test test -f /tmp/dbdeployer_ready 2>/dev/null; then
        echo " READY"
        break
    fi
    echo -n "."
    sleep 2
done

# Verify 3 MySQL nodes are reachable
for PORT in 3306 3307 3308; do
    echo -n "Port ${PORT}: "
    docker exec dbdeployer-test mysql -h127.0.0.1 -P${PORT} -uroot -ptestpass -e "SELECT @@server_id, @@read_only, @@gtid_mode" 2>/dev/null || echo "FAILED"
done

# Verify replication
docker exec dbdeployer-test mysql -h127.0.0.1 -P3307 -uroot -ptestpass -e "SHOW SLAVE STATUS\G" 2>/dev/null | grep -E "Slave_IO_Running|Slave_SQL_Running"

# Cleanup
docker stop dbdeployer-test
```

Expected output:
- Port 3306: server_id != server_id on 3307/3308, read_only=0, gtid_mode=ON
- Port 3307, 3308: read_only=1, gtid_mode=ON
- Replication: Slave_IO_Running: Yes, Slave_SQL_Running: Yes

- [ ] **Step 3: Fix any issues found and commit fixes**

If the smoke test reveals issues (e.g. `--bind-address` not working, port conflicts, user creation failures), fix the Dockerfile or entrypoint and commit the fixes.

- [ ] **Step 4: Commit success marker**

```bash
git add -A test/infra/infra-dbdeployer-mysql57/
git commit -m "feat(infra): infra-dbdeployer-mysql57 smoke-tested and working

Docker image builds, 3-node GTID replication deploys correctly,
all test users created, SSL certs available."
```

---

## Task 11: Test the full infra init/destroy cycle

This tests the complete docker-compose workflow as the CI would run it.

- [ ] **Step 1: Create the Docker network manually (simulating CI)**

```bash
export INFRA_ID="test-$(whoami)"
docker network create "${INFRA_ID}_backend" || true
```

- [ ] **Step 2: Run the init script**

```bash
cd test/infra/infra-dbdeployer-mysql57
INFRA_ID="${INFRA_ID}" bash docker-compose-init.bash
```

Expected: Container starts, dbdeployer deploys MySQL, post-scripts run, "Done." printed.

- [ ] **Step 3: Verify from outside the container**

```bash
CONTAINER="infra-dbdeployer-mysql57-${INFRA_ID}-dbdeployer1-1"
# Test connectivity to all 3 ports
for PORT in 3306 3307 3308; do
    docker exec "${CONTAINER}" mysql -h127.0.0.1 -P${PORT} -uroot -p"$(echo -n ${INFRA_ID} | sha256sum | head -c 10)" -e "SELECT @@server_id, @@read_only"
done
```

- [ ] **Step 4: Run the destroy script**

```bash
INFRA_ID="${INFRA_ID}" bash docker-compose-destroy.bash
docker network rm "${INFRA_ID}_backend" || true
```

Expected: Clean teardown, no orphaned containers.

- [ ] **Step 5: Commit any final fixes**

```bash
git add -A test/infra/infra-dbdeployer-mysql57/
git commit -m "fix(infra): address issues found during full init/destroy cycle"
```

Only commit this if there were actual fixes needed. Skip if everything worked.
