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

The infrastructure management and test execution are strictly separated.

### Step 1: Global Setup
```bash
export WORKSPACE=$(pwd)
export INFRA_ID="dev-$USER"
export TAP_GROUP="legacy-g1"  # Optional but recommended
source test/infra/common/env.sh
```

### Step 2: Start ProxySQL & Backends
You can use the helper script to automatically start all required components for a group:
```bash
./test/infra/control/ensure-infras.bash
```
*This script will start ProxySQL and then iterate through the `infras.lst` of the specified group.*

Alternatively, start them manually:
```bash
./test/infra/control/start-proxysql-isolated.bash
# Then start specific backends
cd test/infra/infra-mysql57 && ./docker-compose-init.bash && cd ../../../
```

### Step 3: Run TAP Tests
The test runner script will **verify** that all required containers are running before starting. If anything is missing, it will exit with an error.

```bash
./test/infra/control/run-tests-isolated.bash
```

### Step 4: Teardown
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
Every TAP test group (in `test/tap/groups/<group_name>`) defines its required backend environments using an `infras.lst` file.

*   **Who reads it?**: Both `ensure-infras.bash` (to start them) and `run-tests-isolated.bash` (to verify them).
*   **Order Importance**: In multi-infrastructure groups, the **order of entries is critical**. Shared ProxySQL users (e.g., `testuser`, `root`) are registered using `INSERT OR IGNORE`. The **first** infrastructure in the list that defines a shared user will set its `default_hostgroup`. Subsequent infrastructures will not overwrite this setting.
*   **Subgroups**: If a group has a suffix (e.g., `legacy-g1`), the system automatically strips it to find the base group definition (`legacy`).
*   **Safety**: If a required infrastructure is missing, the test runner **fails immediately**. It outputs an explicit error message identifying the missing infrastructure and referencing the `infras.lst` file.

### Safety-First Initialization
The `docker-compose-init.bash` scripts implement a strict **non-destructive policy**:
*   They will **refuse to start** if the target data or log directories on the host are not empty.
*   This prevents accidental data loss or inconsistent test states.
*   You must run `docker-compose-destroy.bash` or manually clean the `ci_infra_logs/${INFRA_ID}/` directory before re-initializing.

---

## 4. Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `INFRA_ID` | `dev-$USER` | **Required**. Unique namespace for Docker containers/networks. |
| `WORKSPACE` | Repo Root | Root path of the ProxySQL repository. |
| `INFRA_LOGS_PATH` | `$WORKSPACE/ci_infra_logs` | Destination for container logs and test outputs. |
| `ROOT_PASSWORD` | (dynamic) | Derived from `sha256(INFRA_ID)`. Used for all root-level access. |
| `TAP_GROUP` | (none) | Run a specific group defined in `test/tap/groups/groups.json` (e.g., `legacy-g1`). |
| `DEFAULT_MYSQL_INFRA` | (auto) | The primary MySQL-compatible target for the current group. |
| `DEFAULT_PGSQL_INFRA` | (auto) | The primary PostgreSQL-compatible target for the current group. |

---

## 5. Guidelines for AI Agents

When performing investigations or fixes within this infrastructure:
1.  **Always use `INFRA_ID`**: Never start containers without a unique ID. 
2.  **Verify via `docker exec`**: To check ProxySQL state, use:
    `docker exec proxysql.${INFRA_ID} mysql -uadmin -padmin -h127.0.0.1 -P6032 -e "SELECT * FROM runtime_mysql_servers"`
3.  **Logs are Persistent**: Look into `ci_infra_logs/${INFRA_ID}/${COMPOSE_PROJECT}/${CONTAINER_NAME}/` for backend engine logs.
4.  **Hostname Resolution**: Inside the isolated network, containers use aliases. `proxysql` is the alias for the ProxySQL container, and `mysql1.infra-mysql57` is an alias for a specific backend node.

---

## 6. Best Practices for Creating New Infras

1.  **Template Pattern**: Copy an existing folder like `infra-mysql57`.
2.  **Network Configuration**: Use the standard external network `${INFRA_ID}_backend`.
3.  **Naming Convention**: Use `${COMPOSE_PROJECT}` as a prefix for all container names.
4.  **Post-Config Hook**:
    *   Create a `conf/proxysql/infra-config.sql` template.
    *   Update `bin/docker-proxy-post.bash` to apply this template to the ProxySQL container.
5.  **Deterministic Passwords**: Use `${ROOT_PASSWORD}` for all root/admin credentials.

---

## 7. Troubleshooting

*   **Directory Not Empty**: If initialization fails with an "is not empty" error, run `docker-compose-destroy.bash` for that specific infra or manually clean the log directory.
*   **Permission Denied**: Logs and data directories are often managed with `sudo`. The scripts automatically use `sudo` where necessary.
*   **ProxySQL Not Ready**: Check `ci_infra_logs/${INFRA_ID}/proxysql/proxysql.log` for initialization errors.

---

## 8. ProxySQL Cluster Management

By default, the infrastructure starts a single ProxySQL node. For cluster-specific testing, you can enable additional nodes.

### Starting a Cluster
```bash
# 1. Start the main ProxySQL node
./test/infra/control/start-proxysql-isolated.bash

# 2. Start additional nodes (default: 9 nodes)
# Use PROXYSQL_CLUSTER_NODES to change the count
export PROXYSQL_CLUSTER_NODES=3
./test/infra/control/cluster_start.bash

# 3. Initialize the cluster (configure discovery and synchronization)
./test/infra/control/cluster_init.bash
```

### Skipping Cluster Startup
If you are running tests that do not require a cluster, you should disable it to save resources and speed up initialization:
```bash
export SKIP_CLUSTER_START=1
./test/infra/control/run-tests-isolated.bash
```
