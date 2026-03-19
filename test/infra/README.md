# ProxySQL Unified CI Infrastructure

This directory contains the self-contained infrastructure configurations and control scripts for the ProxySQL **Unified CI System**. It enables high-concurrency, isolated test environments using **Docker-outside-of-Docker (DooD)** and **Pure Network Isolation**.

---

## 0. Pre-requirement: Building the CI Base Image

The ProxySQL control plane and test runner use a standardized toolbelt image: `proxysql-ci-base:latest`. This image **must be built locally** before starting any infrastructure:

```bash
cd test/infra/docker-base
docker build --network host -t proxysql-ci-base:latest .
cd ../../../
```

**Note:** Using `--network host` is recommended if you encounter DNS resolution hangs during the build process.

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
export TAP_GROUP="mysql84-g1"
source test/infra/common/env.sh
```

### Step 2: Start ProxySQL & Backends
You can use the helper script to automatically start all required components for a group:
```bash
./test/infra/control/ensure-infras.bash
```
*This script will start ProxySQL and then iterate through the `infras.lst` of the specified group.*

### Step 3: Run TAP Tests
The test runner script will **verify** that all required containers are running before starting. 

```bash
./test/infra/control/run-tests-isolated.bash
```

### Step 4: Teardown
Manual cleanup of all components.
```bash
# Destroy backends for the current group
./test/infra/control/stop-proxysql-isolated.bash
```

---

## 3. Test Runner & Infrastructure Verification

The `run-tests-isolated.bash` script acts as a validator and execution orchestrator.

### The `infras.lst` Mechanism
Every TAP test group (in `test/tap/groups/<group_name>`) defines its required backend environments using an `infras.lst` file.

*   **Who reads it?**: Both `ensure-infras.bash` (to start them) and `run-tests-isolated.bash` (to verify them).
*   **Order Importance**: In multi-infrastructure groups, the **order of entries is critical**. Shared ProxySQL users (e.g., `testuser`, `root`) are registered using `INSERT OR IGNORE`. The **first** infrastructure in the list that defines a shared user will set its `default_hostgroup`.
*   **Subgroups**: If a group has a suffix (e.g., `legacy-g1`), the system automatically strips it to find the base group definition (`legacy`).

### Safety-First Initialization
The `docker-compose-init.bash` scripts implement a strict **non-destructive policy**:
*   They will **refuse to start** if the target data or log directories on the host are not empty.
*   This prevents accidental data loss or inconsistent test states.
*   You must run `docker-compose-destroy.bash` within the infra folder or manually clean `ci_infra_logs/${INFRA_ID}/` before re-initializing.

---

## 4. Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `INFRA_ID` | `dev-$USER` | **Required**. Unique namespace for Docker containers/networks. |
| `WORKSPACE` | Repo Root | Root path of the ProxySQL repository. |
| `TAP_GROUP` | (none) | Run a specific group defined in `test/tap/groups/groups.json`. |
| `TEST_PY_TAP_INCL` | (none) | Filter tests within the group (regex matching test names). |
| `SKIP_CLUSTER_START`| `0` | Set to `1` to bypass starting additional ProxySQL nodes. |
| `PROXY_DATA_DIR_HOST`| (dynamic) | Host path for ProxySQL persistent data. |

---

## 5. Examples & Use Cases

### Example 1: Run a single test in a MySQL 8.4 environment
If you are developing a fix and only want to run one specific test:
```bash
export INFRA_ID="fix-123"
export TAP_GROUP="mysql84-g1"
export TEST_PY_TAP_INCL="admin_various_commands-t"
export SKIP_CLUSTER_START=1

./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
```

### Example 2: Run all MariaDB 10 tests in parallel with another run
```bash
export INFRA_ID="mariadb-test"
export TAP_GROUP="mariadb10-g1"
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
```

### Example 3: Debugging a failing PostgreSQL test in the Legacy group
```bash
export INFRA_ID="debug-legacy"
export TAP_GROUP="legacy-g1"
export TEST_PY_TAP_INCL="pgsql-.*" # Run only PGSQL tests in legacy
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
```

---

## 6. Advanced: Custom Test Groups

For rapid iteration, you can create a temporary subgroup to target exactly the infrastructure and tests you need.

### How to create a custom subgroup (e.g., `mysql84-g5`)
1.  **Define Infrastructure**: The system will look for `test/tap/groups/mysql84/infras.lst` (because it strips the `-g5` suffix).
2.  **Add Tests to groups.json**: Add your specific tests to the new group in `test/tap/groups/groups.json`:
    ```json
    "my_new_test-t": [ "mysql84-g5" ]
    ```
3.  **Run**:
    ```bash
    export TAP_GROUP="mysql84-g5"
    ./test/infra/control/ensure-infras.bash
    ./test/infra/control/run-tests-isolated.bash
    ```

---

## 7. ProxySQL Cluster Management

By default, the infrastructure starts a single ProxySQL node. For cluster-specific testing, you can enable additional nodes.

### Starting a Cluster
```bash
# 1. Start the main ProxySQL node
./test/infra/control/start-proxysql-isolated.bash

# 2. Start additional nodes (default: 9 nodes)
export PROXYSQL_CLUSTER_NODES=3
./test/infra/control/cluster_start.bash

# 3. Initialize the cluster
./test/infra/control/cluster_init.bash
```

---

## 8. Troubleshooting

*   **"Directory Not Empty"**: Run `./test/infra/control/stop-proxysql-isolated.bash` with the same `INFRA_ID` to cleanup, or manually delete the folder in `ci_infra_logs/`.
*   **Permission Denied**: The system uses `sudo` for log directory management. Ensure your user has sudo privileges.
*   **Container Crash**: Check logs in `ci_infra_logs/${INFRA_ID}/${COMPOSE_PROJECT}/${CONTAINER_NAME}/`.
