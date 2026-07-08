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

1. Obtain the CI base image (one-time setup):

   Pull from GHCR if available:
   ```bash
   docker pull ghcr.io/sysown/proxysql-ci-base:latest
   docker tag ghcr.io/sysown/proxysql-ci-base:latest proxysql-ci-base:latest
   ```

   Or build locally:
   ```bash
   cd test/infra/docker-base
   docker build --network host -t proxysql-ci-base:latest .
   cd ../../../
   ```

2. Build ProxySQL and TAP tests in debug mode:
   ```bash
   make debug -j$(nproc) && make -j$(nproc) build_tap_test_debug
   ```

## Where logs actually live after a run

Once a run finishes (passed or failed), everything it produced lives under
`ci_infra_logs/${INFRA_ID}/`. The layout is:

```text
ci_infra_logs/${INFRA_ID}/
├── infra-mysql57/                      # per-backend logs (mysql, mariadb, pgsql, ...)
│   └── mysql1/
│       ├── error.log
│       └── general.log
├── infra-mariadb10/
│   └── ...
├── proxysql/                           # ProxySQL side
│   ├── proxysql.log
│   └── proxysql_audit.log
└── tests/
    └── proxysql-tester.py/
        └── tests/
            ├── test_flush_logs-t.log.gz             # per-test captured stdout+stderr
            ├── test_flush_logs-t.proxysql.log.gz    # ProxySQL log during that test
            ├── pgsql-servers_ssl_params-t.log.gz
            └── ...                                  # one .log.gz per test attempt
```

**All the per-test `.log.gz` files are gzipped** to save space — read them with
`zcat` or `zless`, not `cat`:

```bash
# Read the captured TAP output of a specific test
zless ci_infra_logs/${INFRA_ID}/tests/proxysql-tester.py/tests/test_flush_logs-t.log.gz

# Or the ProxySQL server log captured during that test
zless ci_infra_logs/${INFRA_ID}/tests/proxysql-tester.py/tests/test_flush_logs-t.proxysql.log.gz

# Grep across every test's TAP output for a pattern
zgrep -H 'not ok\|FAIL' ci_infra_logs/${INFRA_ID}/tests/proxysql-tester.py/tests/*.log.gz
```

## Debugging a flaky test

A test that passes locally but fails intermittently on CI is usually racing
against a timeout or a slow backend. The recipe to reproduce and stress-test
it locally is:

```bash
# Bring infra up once, run the same test N times back-to-back against the
# same running ProxySQL, capture each attempt's log under a separate subdir.
export WORKSPACE=$(pwd)
export TAP_GROUP="legacy-g3"
export TEST_PY_TAP_INCL="test_flush_logs-t"     # regex of the test(s) to focus on
export SKIP_CLUSTER_START=1
source test/infra/common/env.sh

# One infra lifecycle, many test runs:
export INFRA_ID="flake-$(date +%s)"
./test/infra/control/ensure-infras.bash

for i in $(seq 1 20); do
    echo "===== attempt $i ====="
    ./test/infra/control/run-tests-isolated.bash 2>&1 | tee /tmp/flake-$i.log
    # stash the per-test log before the next attempt overwrites it
    mkdir -p /tmp/flake-runs/$i
    cp -a ci_infra_logs/${INFRA_ID}/tests/proxysql-tester.py/tests/ /tmp/flake-runs/$i/
done

./test/infra/control/stop-proxysql-isolated.bash
```

Then inspect which attempts failed and diff their per-test logs:

```bash
# Which attempts had any failure? Matches both the TAP "not ok" marker and
# proxysql-tester.py's own "FAIL N/M" summary line, so we don't miss a test
# that failed at the TAP level but didn't produce a non-zero FAIL count in
# the summary (e.g. when the test binary itself crashes).
grep -lE 'not ok|FAIL [1-9]' /tmp/flake-*.log

# Compare the TAP output of a failing attempt against a passing one
zdiff /tmp/flake-runs/3/tests/test_flush_logs-t.log.gz \
      /tmp/flake-runs/7/tests/test_flush_logs-t.log.gz
```

If 20 attempts all pass locally but CI still fails, the race is probably
CI-runner-specific (slow I/O on the shared runner, docker volume consistency
delays, etc.) rather than a bug in the test or the code. That diagnosis is
useful information even if it doesn't point at a fix.

## Troubleshooting

- **"Directory Not Empty"**: Run `./test/infra/control/stop-proxysql-isolated.bash` with the same `INFRA_ID` that was used when you started the infra. If you lost the ID, `docker network ls` will show you active `*_backend` networks — each one is a stuck infra; the name before `_backend` is the `INFRA_ID`.
- **Container issues**: Check logs in `ci_infra_logs/${INFRA_ID}/infra-*/` (per-backend) and `ci_infra_logs/${INFRA_ID}/proxysql/` (ProxySQL side).
- **Test failures**: Read the per-test `.log.gz` files under `ci_infra_logs/${INFRA_ID}/tests/proxysql-tester.py/tests/` with `zless` or `zcat` — see the "Where logs actually live" section above for the full layout.
- **Stale docker state**: `docker ps -a | grep "${INFRA_ID}"` shows any leftover containers; prefer targeted cleanup of just this infra's network with `docker network rm "${INFRA_ID}_backend"` over the global `docker network prune`, which would also wipe unrelated project networks on the same host.
