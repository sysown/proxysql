# ProxySQL Unified CI Infrastructure

This directory contains the self-contained infrastructure configurations and control scripts for the ProxySQL **Unified CI System**. It enables high-concurrency, isolated test environments using **Docker-outside-of-Docker (DooD)** and **Pure Network Isolation**.

---

## 1. Core Concepts

The Unified CI system is designed around three pillars:
1.  **Isolation**: Every test run uses a unique `INFRA_ID`. This ID namespaces all Docker containers and networks, allowing multiple developers or CI jobs to run on the same host without port collisions.
2.  **Parity**: The exact same scripts and configurations are used in Jenkins, local development, and by AI agents.
3.  **Automation**: Provisioning of backends (MySQL, MariaDB, etc.) and their registration into ProxySQL is fully scripted via dynamic SQL templates.

---

## 2. Manual Execution Guide

For developers and AI agents, the typical workflow follows these steps:

### Step 1: Global Setup
Define your unique environment ID and set up the base environment.
```bash
# Set your workspace to the repo root
export WORKSPACE=$(pwd)
export INFRA_ID="dev-$USER-$(date +%s)"

# (Optional) Source common environment variables
source test/infra/common/env.sh
```

### Step 2: Start ProxySQL
This starts the primary ProxySQL container.
```bash
./test/infra/control/start-proxysql-isolated.bash
```

### Step 3: (Optional) Start ProxySQL Cluster
To test ProxySQL Cluster synchronization and features, you can spin up multiple ProxySQL nodes.

```bash
# To start a standard 9-node cluster
./test/infra/control/cluster_start.bash
./test/infra/control/cluster_init.bash

# To start a cluster with a specific number of nodes
export PROXYSQL_CLUSTER_NODES=3
./test/infra/control/cluster_start.bash
./test/infra/control/cluster_init.bash
```

If `SKIP_CLUSTER_START=1` is set, these scripts will exit immediately without performing any action.

### Step 4: Initialize Backends
You can start one or more backend clusters. Each will automatically register itself with the running ProxySQL instance.
```bash
# Start MySQL 5.7 Cluster
cd test/infra/infra-mysql57 && ./docker-compose-init.bash && cd ../../../

# Start MariaDB 10 Cluster
cd test/infra/infra-mariadb10 && ./docker-compose-init.bash && cd ../../../

# Start PostgreSQL 16 Single Instance
cd test/infra/docker-pgsql16-single && ./docker-compose-init.bash && cd ../../../

# Start PostgreSQL 17 Replication Cluster
cd test/infra/infra-pgsql17-repl && ./docker-compose-init.bash && cd ../../../

# Start Clickhouse 23
cd test/infra/infra-clickhouse23 && ./docker-compose-init.bash && cd ../../../
```

### Step 5: Run TAP Tests
Execute tests using the isolated test runner script. This starts a temporary container that joins the isolated network and runs the ProxySQL tester.

```bash
# Example: Run a specific test
export TEST_PY_TAP_INCL="mysql-protocol_compression_level-t"
./test/infra/control/run-tests-isolated.bash

# Example: Run a specific test group defined in test/tap/groups/groups.json
export TAP_GROUP="default-g1"
./test/infra/control/run-tests-isolated.bash
```

**Tip:** In a separate terminal, watch the test assertions in real-time:
```bash
tail -f ci_infra_logs/${INFRA_ID}/tests/proxysql-tester.py/tests/*.log
```

### Step 6: Teardown
Always clean up your isolated containers and networks.
```bash
./test/infra/control/stop-proxysql-isolated.bash
```

---

## 3. Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `INFRA_ID` | `dev-$USER` | **Required**. Unique namespace for Docker containers/networks. |
| `WORKSPACE` | Repo Root | Root path of the ProxySQL repository. |
| `INFRA_LOGS_PATH` | `$WORKSPACE/ci_infra_logs` | Destination for container logs and test outputs. |
| `ROOT_PASSWORD` | (dynamic) | Derived from `sha256(INFRA_ID)`. Used for all root-level access. |
| `PROXYSQL_CLUSTER_NODES`| `9` | Number of additional ProxySQL nodes to start. |
| `SKIP_CLUSTER_START`| `0` | Set to `1` to bypass cluster startup for single-node runs. |
| `TAP_GROUP` | (none) | Run a specific group defined in `test/tap/groups/groups.json` (e.g., `default-g1`). |
| `TAP_ADMINUSERNAME` | `radmin` | Credentials used for ProxySQL Admin remote connections. |

---

## 4. Directory Structure

*   `common/`: Shared shell utilities and the base `env.sh` generator.
*   `control/`: Scripts to manage the lifecycle of the ProxySQL container.
*   `infra-mysql57/`, `infra-mysql84/`, `infra-mariadb10/`: MySQL and MariaDB backend definitions.
*   `docker-clickhouse/`, `infra-clickhouse23/`: Clickhouse backend definitions.
*   `docker-pgsql16-single/`, `infra-pgsql17-repl/`: PostgreSQL backend definitions.
    *   `docker-compose.yml`: Service definitions using environment variable interpolation.
    *   `docker-compose-init.bash`: Orchestrates the container startup and post-provisioning.
    *   `bin/docker-proxy-post.bash`: Configures the ProxySQL container to recognize these backends.
    *   `conf/proxysql/infra-config.sql`: Dynamic SQL template for backend registration.

---

## 5. Guidelines for AI Agents

When performing investigations or fixes within this infrastructure:
1.  **Always use `INFRA_ID`**: Never start containers without a unique ID. Check `docker ps` to ensure you aren't interfering with other runs.
2.  **Verify via `docker exec`**: To check ProxySQL state, use:
    `docker exec proxysql.${INFRA_ID} mysql -uadmin -padmin -h127.0.0.1 -P6032 -e "SELECT * FROM runtime_mysql_servers"`
3.  **Logs are Persistent**: Look into `ci_infra_logs/${INFRA_ID}/${CONTAINER_NAME}/` for backend engine logs.
4.  **Hostname Resolution**: Inside the isolated network, containers use aliases. `proxysql` is the alias for the ProxySQL container, and `mysql1.${INFRA}` is the alias for the first MySQL node.

---

## 6. Best Practices for Creating New Infras

To add a new database type or version (e.g., `infra-mysql90`):

1.  **Template Pattern**: Copy an existing folder like `mysql57`.
2.  **Network Configuration**: Ensure the `docker-compose.yml` uses:
    ```yaml
    networks:
      backend:
        name: ${INFRA_ID}_backend
        external: true
    ```
3.  **Naming Convention**: Use `${COMPOSE_PROJECT}` as a prefix for all container names to ensure `stop-proxysql-isolated.bash` can find them.
4.  **Post-Config Hook**:
    *   Create a `conf/proxysql/infra-config.sql` template.
    *   Use variables like `${WHG}` (Writer Hostgroup) and `${RHG}` (Reader Hostgroup) instead of hardcoding IDs.
    *   Update `bin/docker-proxy-post.bash` to `eval` this template and pipe it into the `proxysql.${INFRA_ID}` container.
5.  **Deterministic Passwords**: Use `${ROOT_PASSWORD}` for all administrative credentials to ensure the test runner can connect automatically.

---

## 7. Troubleshooting

*   **Network Collisions**: If `docker network create` fails, an old `INFRA_ID` might still be hanging. Use `stop-proxysql-isolated.bash` with that ID.
*   **Permission Denied**: Logs and data directories are often managed with `sudo` in CI. Scripts automatically use `sudo` where necessary for `mkdir` and `chmod`.
*   **ProxySQL Not Ready**: If `start-proxysql-isolated.bash` timeouts, check `ci_infra_logs/${INFRA_ID}/proxysql/proxysql.log` for initialization errors.
