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

## 0.1. Building ProxySQL (Debug Mode)

Some tests require ProxySQL to be compiled in debug mode (e.g., for `LOAD DEBUG FROM DISK` support). If you encounter errors like `near "LOAD": syntax error` when the test runner tries to execute `LOAD DEBUG FROM DISK`, you need to rebuild ProxySQL in debug mode:

```bash
export PROXYSQLGENAI=1
make -j$(nproc) build_deps && make -j$(nproc) debug && make -j$(nproc) build_deps && make -j$(nproc) build_tap_test_debug
```

This will:
1. Build all dependencies
2. Compile ProxySQL with debug symbols and the DEBUG module enabled
3. Rebuild dependencies (if needed for debug mode)
4. Build TAP test executables in debug mode

**Note:** After rebuilding, restart your infrastructure with a fresh `INFRA_ID` to use the new binary.

---

## 0.2. Simulator-backed TAP groups

Groups whose name starts with `cluster_sim_` exercise simulator-specific
ProxySQL paths gated by compile-time `#ifdef` flags. State is driven either by
the in-repo `test/deps/cluster_simulator` process or directly by TAP helpers
through SQLite3-server, as in RDS BGD. The ProxySQL binary **must** be built with
the matching flag or state mutations become no-ops and tests fail silently.

| Simulator group             | Required build target     |
|-----------------------------|---------------------------|
| `cluster_sim_aurora-g<N>`   | `make testaurora`         |
| `cluster_sim_galera-g<N>`   | `make testgalera`         |
| `cluster_sim_group_repl-g<N>` | `make testgrouprep`       |
| `cluster_sim_read_only-g<N>` | `make testreadonly`       |
| `cluster_sim_repl_lag-g<N>` | `make testreplicationlag` |
| `cluster_sim_rds_bgd-g<N>` | `make test_rds_bgd`        |

Each target sets the corresponding `-DTEST_<FAMILY>` flag on the ProxySQL src
and lib builds and builds the TAP artifacts. Targets backed by
`test/deps/cluster_simulator` build that process as well. A plain `make` is
**not sufficient** for these groups.

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

**IMPORTANT:** `INFRA_ID` must be unique for each test run to avoid conflicts. Use a timestamp to ensure uniqueness:

```bash
export WORKSPACE=$(pwd)
export INFRA_ID="test-$(date +%s)"   # Unique ID using timestamp
export TAP_GROUP="mysql84-g1"
source test/infra/common/env.sh
```

**Why unique INFRA_ID?**
- Prevents port collisions when multiple tests run on the same host
- Ensures clean isolation between test environments
- Avoids conflicts with existing Docker containers and networks

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
| `INFRA_ID` | `dev-$USER` | **Required**. Unique namespace for Docker containers/networks. **Must be unique** - use a timestamp for isolation: `export INFRA_ID="test-$(date +%s)"` |
| `WORKSPACE` | Repo Root | Root path of the ProxySQL repository. |
| `TAP_GROUP` | (none) | Run a specific group defined in `test/tap/groups/groups.json`. |
| `TEST_PY_TAP_INCL` | (none) | Filter tests within the group (regex matching test names). |
| `SKIP_CLUSTER_START`| `0` | Set to `1` to bypass starting additional ProxySQL nodes. |
| `SKIP_PROXYSQL` | `0` | Set to `1` in a group's `env.sh` to skip ProxySQL and all backend infrastructure. When enabled, `ensure-infras.bash` exits immediately and `run-tests-isolated.bash` runs tests directly on the host without Docker. Used by the `unit-tests` group. |
| `PROXY_DATA_DIR_HOST`| (dynamic) | Host path for ProxySQL persistent data. |
| `COVERAGE` | `0` | Enable code coverage collection. |
| `TAP_USE_NOISE` | `0` | Enable noise injection for race condition testing. |

---

## 5. Examples & Use Cases

### Example 1: Run a single test in a MySQL 8.4 environment
If you are developing a fix and only want to run one specific test:
```bash
export INFRA_ID="fix-123-$(date +%s)"  # Unique ID with timestamp
export TAP_GROUP="mysql84-g1"
export TEST_PY_TAP_INCL="admin_various_commands-t"
export SKIP_CLUSTER_START=1

./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
```

### Example 2: Run all MariaDB 10 tests in parallel with another run
```bash
export INFRA_ID="mariadb-test-$(date +%s)"  # Unique ID with timestamp
export TAP_GROUP="mariadb10-g1"
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
```

### Example 3: Debugging a failing PostgreSQL test in the Legacy group
```bash
export INFRA_ID="debug-legacy-$(date +%s)"  # Unique ID with timestamp
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

## 6.1. Infrastructure-Free Groups (Unit Tests)

Some test groups do not require ProxySQL or any backend infrastructure. These groups set `SKIP_PROXYSQL=1` in their `env.sh`, which causes:

- `ensure-infras.bash` to exit immediately (no Docker containers started)
- `run-tests-isolated.bash` to run tests directly on the host (no Docker test runner)

The `unit-tests` group is the primary example. Unit tests link against `libproxysql.a` with stub globals and run as standalone binaries.

### Running Unit Tests

```bash
# Build unit tests
cd test/tap/tests/unit && make && cd -

# Run via the multi-group runner (recommended)
TAP_GROUPS="unit-tests-g1" ./test/infra/control/run-multi-group.bash

# Or run directly
export TAP_GROUP="unit-tests-g1"
./test/infra/control/ensure-infras.bash   # exits immediately (SKIP_PROXYSQL=1)
./test/infra/control/run-tests-isolated.bash
```

### Creating Your Own Infrastructure-Free Group

1. Create a group directory: `test/tap/groups/my-group/`
2. Add `env.sh` with `export SKIP_PROXYSQL=1`
3. Add your tests to `groups.json` under `my-group-g1`
4. No `infras.lst` needed

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

## 8. Multi-Group Parallel Execution

The `run-multi-group.bash` script enables running multiple TAP groups in parallel with proper isolation and resource management.

### Basic Usage
```bash
RUN_ID="test-$(date +%s)" \
TAP_GROUPS="legacy-g1 legacy-g2 legacy-g3 mysql84-g1" \
./test/infra/control/run-multi-group.bash
```

### Configuration Options

| Variable | Default | Description |
| :--- | :--- | :--- |
| `RUN_ID` | (timestamp) | Unique identifier for the multi-group run. |
| `TAP_GROUPS` | (required) | Space-separated list of TAP groups to run. |
| `PARALLEL_JOBS` | `2` | Maximum number of groups running in parallel. |
| `TIMEOUT_MINUTES` | `60` | Hard timeout per group in minutes. |
| `EXIT_ON_FIRST_FAIL` | `0` | Stop all groups on first failure if set to `1`. |
| `AUTO_CLEANUP` | `0` | Automatically cleanup successful groups if set to `1`. |
| `STAGGER_DELAY` | `5` | Seconds between group startups to prevent resource contention. |
| `COVERAGE` | `0` | Enable code coverage collection if set to `1`. |
| `TAP_USE_NOISE` | `0` | Enable noise injection for race condition testing if set to `1`. |

### Output Location
- Individual group logs: `ci_infra_logs/multi-group-{RUN_ID}/{group}.log`
- Combined coverage report: `ci_infra_logs/multi-group-{RUN_ID}/coverage-report/`

---

## 9. Code Coverage Collection

When running tests with `COVERAGE=1`, the system collects code coverage data from ProxySQL.

### Requirements
- ProxySQL must be compiled with `COVERAGE=1` (adds `--coverage` flags)
- `fastcov` and `genhtml` must be available in the `proxysql-ci-base` container

### Usage
```bash
# Single group with coverage
COVERAGE=1 ./test/infra/control/run-tests-isolated.bash

# Multi-group with coverage (reports are combined)
COVERAGE=1 RUN_ID="cov-$(date +%s)" TAP_GROUPS="legacy-g1 legacy-g2" ./test/infra/control/run-multi-group.bash
```

### Output
- Individual reports: `ci_infra_logs/{INFRA_ID}/coverage-report/`
- Combined report: `ci_infra_logs/multi-group-{RUN_ID}/coverage-report/`

---

## 10. Noise Injection Testing

Noise injection helps detect race conditions and deadlocks by introducing random delays and stress during test execution.

### Usage
```bash
# Enable noise injection for a single group
TAP_USE_NOISE=1 ./test/infra/control/run-tests-isolated.bash

# Enable noise injection for multi-group run
TAP_USE_NOISE=1 RUN_ID="noise-$(date +%s)" TAP_GROUPS="legacy-g1 legacy-g2" ./test/infra/control/run-multi-group.bash
```

For more details, see `test/tap/NOISE_TESTING.md`.

---

## 11. Troubleshooting

*   **"Directory Not Empty"**: Run `./test/infra/control/stop-proxysql-isolated.bash` with the same `INFRA_ID` to cleanup, or manually delete the folder in `ci_infra_logs/`.
*   **Permission Denied**: The system uses `sudo` for log directory management. Ensure your user has sudo privileges.
*   **Container Crash**: Check logs in `ci_infra_logs/${INFRA_ID}/${COMPOSE_PROJECT}/${CONTAINER_NAME}/`.
