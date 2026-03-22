# ProxySQL Test Suite

This directory contains the ProxySQL test suite, including TAP tests and infrastructure for running them.

## Quick Start: Running Tests Locally

To run tests using the local CI infrastructure (Docker-based isolation):

```bash
# 1. Set up environment
export WORKSPACE=$(pwd)
export INFRA_ID="test-$(date +%s)"   # Unique ID using timestamp
export TAP_GROUP="mysql84-g1"        # Or another group like "legacy-g1"
export TEST_PY_TAP_INCL="test_name-t"  # Optional: filter to specific test
export SKIP_CLUSTER_START=1          # Skip cluster nodes for single-node tests
source test/infra/common/env.sh

# 2. Start ProxySQL and backends
./test/infra/control/ensure-infras.bash

# 3. Run the tests
./test/infra/control/run-tests-isolated.bash

# 4. Cleanup when done
./test/infra/control/stop-proxysql-isolated.bash
```

## Documentation

- **[infra/README.md](infra/README.md)** - Complete documentation for the Unified CI infrastructure
- **[tap/groups/groups.json](tap/groups/groups.json)** - Test group definitions

## Available Test Groups

Common test groups (defined in `tap/groups/groups.json`):

| Group | Description |
|-------|-------------|
| `unit-tests-g1` | Unit tests (no ProxySQL or backends needed) |
| `mysql84-g1` | MySQL 8.4 tests |
| `mysql57-g1` | MySQL 5.7 tests |
| `mariadb10-g1` | MariaDB 10 tests |
| `legacy-g1` | Legacy tests (MySQL 5.7, MariaDB 10, PostgreSQL, ClickHouse) |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `INFRA_ID` | **Required**. Unique namespace for Docker containers. Use timestamp: `test-$(date +%s)` |
| `TAP_GROUP` | Test group to run (e.g., `mysql84-g1`) |
| `TEST_PY_TAP_INCL` | Regex to filter tests within the group |
| `SKIP_CLUSTER_START` | Set to `1` to skip starting additional ProxySQL nodes |
| `SKIP_PROXYSQL` | Set to `1` in a group's `env.sh` to skip ProxySQL and all backend infrastructure (used by `unit-tests`) |

## Prerequisites

1. Build the CI base image (one-time setup):
   ```bash
   cd test/infra/docker-base
   docker build --network host -t proxysql-ci-base:latest .
   cd ../../../
   ```

2. Build ProxySQL and TAP tests:
   ```bash
   make -j$(nproc) && make -j$(nproc) build_tap_test
   ```

## Troubleshooting

- **"Directory Not Empty"**: Run `./test/infra/control/stop-proxysql-isolated.bash` with the same `INFRA_ID`
- **Container issues**: Check logs in `ci_infra_logs/${INFRA_ID}/`
- **Test failures**: Check logs in `ci_infra_logs/${INFRA_ID}/tests/`
