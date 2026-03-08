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

The infrastructure management and test execution are strictly separated. You must manually start the required components before launching the tests.

### Step 1: Global Setup
```bash
export WORKSPACE=$(pwd)
export INFRA_ID="dev-$USER"
source test/infra/common/env.sh
```

### Step 2: Start ProxySQL
```bash
./test/infra/control/start-proxysql-isolated.bash
```

### Step 3: (Optional) Start ProxySQL Cluster
```bash
./test/infra/control/cluster_start.bash
./test/infra/control/cluster_init.bash
```

### Step 4: Initialize Required Backends
Launch the backends needed for your tests.
```bash
# For MySQL 5.7 tests
cd test/infra/infra-mysql57 && ./docker-compose-init.bash && cd ../../../

# For PGSQL Replication tests
cd test/infra/infra-pgsql17-repl && ./docker-compose-init.bash && cd ../../../
```

### Step 5: Run TAP Tests
The test runner script will **verify** that all required containers are running before starting. If anything is missing, it will exit with an error.

```bash
# Run a specific test group
export TAP_GROUP="pgsql17-repl"
./test/infra/control/run-tests-isolated.bash
```

### Step 6: Teardown
Manual cleanup of all components.
```bash
# Destroy backends
cd test/infra/infra-mysql57 && ./docker-compose-destroy.bash && cd ../../../

# Stop ProxySQL and all its nodes
./test/infra/control/stop-proxysql-isolated.bash
```

---

## 3. Test Runner & Infrastructure Verification

The `run-tests-isolated.bash` script acts as a validator and execution orchestrator.

### The `infras.lst` Mechanism
Every TAP test group (in `test/tap/groups/<group_name>`) can define its required backend environments using an `infras.lst` file.

*   **Who reads it?**: `test/infra/control/run-tests-isolated.bash` on the host.
*   **Verification**: The script checks if ProxySQL (`proxysql.${INFRA_ID}`) and all project-prefixed backend containers (e.g. `infra-mysql57-${INFRA_ID}-mysql1-1`) are active.
*   **Safety**: If a required infrastructure is missing, the test runner **fails immediately**. It outputs an explicit error message identifying the missing infrastructure and referencing the `infras.lst` file that defined the requirement.

### Orchestration Roles
1.  **Infrastructure Initialization**: Handled by the user or a wrapper. Responsible for container health and ProxySQL registration.
2.  **Host Orchestrator (`run-tests-isolated.bash`)**: Responsible for verifying environment state and launching the `test-runner` container.
3.  **Test Runner (`proxysql-tester.py` in container)**: Client-side execution of TAP tests. It does not manage Docker containers.

---

## 4. Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `INFRA_ID` | `dev-$USER` | **Required**. Unique namespace for Docker containers/networks. |
| `WORKSPACE` | Repo Root | Root path of the ProxySQL repository. |
| `INFRA_LOGS_PATH` | `$WORKSPACE/ci_infra_logs` | Destination for container logs and test outputs. |
| `ROOT_PASSWORD` | (dynamic) | Derived from `sha256(INFRA_ID)`. Used for all root-level access. |
| `PROXYSQL_CLUSTER_NODES`| `9` | Number of additional ProxySQL nodes to start. |
| `SKIP_CLUSTER_START`| `0` | Set to `1` to bypass cluster startup for single-node runs. |
| `TAP_GROUP` | (none) | Run a specific group defined in `test/tap/groups/groups.json` (e.g., `legacy-g1`). |
| `TAP_ADMINUSERNAME` | `radmin` | Credentials used for ProxySQL Admin remote connections. |

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

1.  **Template Pattern**: Copy an existing folder like `infra-mysql57`.
2.  **Network Configuration**: Ensure the `docker-compose.yml` uses:
    ```yaml
    networks:
      backend:
        name: ${INFRA_ID}_backend
        external: true
    ```
3.  **Naming Convention**: Use `${COMPOSE_PROJECT}` as a prefix for all container names to ensure the teardown script can find them.
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
