# ProxySQL Test Infrastructure - Agent Skill Guide

This guide provides step-by-step instructions for agents to run ProxySQL tests using the Unified CI infrastructure.

## Prerequisites

Before running tests, ensure:
1. Docker is installed and running
2. The `proxysql-ci-base` image is built (see README.md section 0)
3. You have sudo access for log directory management

## Quick Start - Run a Specific Test Group

```bash
# 1. Set required environment variables
export INFRA_ID="dev-$USER"
export TAP_GROUP="legacy-binlog-g1"  # or your target group
export INFRA_TYPE="infra-mysql57-binlog"  # optional, inferred from group

# 2. Run the full pipeline (starts infra + runs tests)
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
```

## Step-by-Step Manual Execution

Use this approach when you need more control or want to debug infrastructure issues.

### Step 1: Environment Setup

```bash
export WORKSPACE=$(pwd)
export INFRA_ID="dev-$USER"  # Unique namespace for isolation
export TAP_GROUP="legacy-binlog-g1"
source test/infra/common/env.sh
```

**Critical Environment Variables:**
- `INFRA_ID` - **Required**. Unique namespace for containers/networks
- `TAP_GROUP` - The test group from `test/tap/groups/groups.json`
- `ROOT_PASSWORD` - Auto-derived from INFRA_ID hash if not set

### Step 2: Start Infrastructure

```bash
# Option A: Use the helper (recommended)
./test/infra/control/ensure-infras.bash

# Option B: Manual per-infrastructure startup
cd test/infra/infra-mysql57-binlog
export INFRA_ID="dev-$USER"
./docker-compose-init.bash
cd ../../../
```

### Step 3: Start ProxySQL

```bash
export INFRA_ID="dev-$USER"
./test/infra/control/start-proxysql-isolated.bash
```

Wait for "Ready." message. If it crashes, check logs:
```bash
docker logs proxysql.${INFRA_ID}
```

### Step 4: Configure ProxySQL Backend

```bash
cd test/infra/infra-mysql57-binlog
export INFRA_ID="dev-$USER"
./bin/docker-proxy-post.bash
```

**Verify configuration:**
```bash
docker exec proxysql.${INFRA_ID} mysql -uradmin -pradmin -h127.0.0.1 -P6032 \
  -e "SELECT hostgroup_id, hostname, port, gtid_port, status FROM mysql_servers;"
```

### Step 5: Run Tests

```bash
export INFRA_ID="dev-$USER"
export TAP_GROUP="legacy-binlog-g1"
./test/infra/control/run-tests-isolated.bash
```

**Run only specific tests:**
```bash
export TEST_PY_TAP_INCL="test_binlog.*"
./test/infra/control/run-tests-isolated.bash
```

## Common Issues and Solutions

### Issue: "Directory Not Empty" Error

**Cause:** Previous infrastructure data exists.

**Solution:**
```bash
# Destroy existing infrastructure first
cd test/infra/infra-mysql57-binlog
export INFRA_ID="dev-$USER"
./docker-compose-destroy.bash
sudo rm -rf ./logs/infra-mysql57-binlog-${INFRA_ID}
sudo rm -rf ../../ci_infra_logs/${INFRA_ID}
```

### Issue: "Access denied for user 'root'"

**Cause:** ROOT_PASSWORD not set or empty in ProxySQL.

**Solution:**
1. Ensure `.env` defines ROOT_PASSWORD:
   ```
   ROOT_PASSWORD=${ROOT_PASSWORD:-$(echo -n "${INFRA_ID:-dev}" | sha256sum | head -c 10)}
   ```
2. Re-run `docker-proxy-post.bash` after setting INFRA_ID
3. Verify: `docker exec proxysql.${INFRA_ID} mysql -uradmin -pradmin -h127.0.0.1 -P6032 -e "SELECT username, password FROM mysql_users;"`

### Issue: "Max connect timeout reached while reaching hostgroup"

**Cause:** MySQL containers not running or misconfigured.

**Solution:**
```bash
# Check container status
docker ps --format "table {{.Names}}\t{{.Status}}" | grep infra-mysql57-binlog

# Check network aliases
docker network inspect ${INFRA_ID}_backend

# Restart infrastructure if needed
```

### Issue: "GTID: failed to connect to ProxySQL binlog reader on port 6020"

**Cause:** Reader containers not running or gtid_port misconfigured.

**Solution:**
1. Verify reader containers are running:
   ```bash
   docker ps | grep reader
   ```
2. Check mysql_servers has gtid_port set:
   ```bash
   docker exec proxysql.${INFRA_ID} mysql -uradmin -pradmin -h127.0.0.1 -P6032 \
     -e "SELECT hostname, gtid_port FROM mysql_servers;"
   ```

### Issue: Test runs but no queries executed (act_queries: 0)

**Cause:** Connection pool not initialized or query routing issue.

**Solution:**
1. Check mysql_users exist
2. Verify mysql_query_rules loaded
3. Check stats_mysql_connection_pool for connections
4. Try running test individually after infrastructure warms up

## Test Results Location

After tests complete, logs are in:
```
ci_infra_logs/${INFRA_ID}/
├── proxysql/                    # ProxySQL logs
│   ├── proxysql.log
│   └── proxysql.db
└── tests/proxysql-tester.py/
    ├── tap_tests.log            # Test runner log
    └── tests/
        ├── test_name-t.log      # Individual test output
        └── test_name-t.proxysql.log  # ProxySQL log during test
```

**Check test results:**
```bash
# Find test exit code
grep "RC:" ci_infra_logs/${INFRA_ID}/tests/proxysql-tester.py/tests/test_name-t.log

# View compressed logs
zcat ci_infra_logs/${INFRA_ID}/tests/proxysql-tester.py/tests/test_name-t.log.gz
```

## Debugging Tips

### 1. Check Container Connectivity

```bash
# From ProxySQL container, test MySQL connection
docker exec -it proxysql.${INFRA_ID} bash
mysql -h mysql1.infra-mysql57-binlog -P 3306 -u root -p

# Test reader connection
telnet mysql1.infra-mysql57-binlog 6020
```

### 2. Monitor ProxySQL Runtime

```bash
# Watch connection pool
docker exec proxysql.${INFRA_ID} mysql -uradmin -pradmin -h127.0.0.1 -P6032 \
  -e "SELECT * FROM stats_mysql_connection_pool;" -t

# Watch query stats
docker exec proxysql.${INFRA_ID} mysql -uradmin -pradmin -h127.0.0.1 -P6032 \
  -e "SELECT * FROM stats_mysql_query_digest;" -t | head -20
```

### 3. Infrastructure Verification Script

```bash
# Check all required containers are running
docker ps --format "{{.Names}}" | grep ${INFRA_ID}

# Verify network
docker network ls | grep ${INFRA_ID}

# Check logs for errors
docker logs proxysql.${INFRA_ID} 2>&1 | grep -i error | tail -20
```

## Cleanup

```bash
# Stop test runner (if still running)
docker rm -f test-runner.${INFRA_ID}

# Stop ProxySQL
./test/infra/control/stop-proxysql-isolated.bash

# Destroy infrastructure
cd test/infra/infra-mysql57-binlog
export INFRA_ID="dev-$USER"
./docker-compose-destroy.bash

# Clean up logs (optional)
sudo rm -rf ci_infra_logs/${INFRA_ID}
```

## Testing Different Configurations

### Run a Single Test
```bash
export INFRA_ID="single-test"
export TAP_GROUP="legacy-binlog-g1"
export TEST_PY_TAP_INCL="test_binlog_reader-t"
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
```

### Test with Different INFRA_ID (parallel runs)
```bash
# Terminal 1
export INFRA_ID="test-a"
export TAP_GROUP="legacy-binlog-g1"
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash

# Terminal 2 (completely isolated)
export INFRA_ID="test-b"
export TAP_GROUP="legacy-binlog-g1"
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
```

## Agent Checklist

Before asking user about test failures:

- [ ] `INFRA_ID` is set and consistent across all commands
- [ ] `TAP_GROUP` is defined in `test/tap/groups/groups.json`
- [ ] Infrastructure containers are running (`docker ps`)
- [ ] ProxySQL container is running and healthy
- [ ] MySQL servers registered in ProxySQL (`SELECT * FROM mysql_servers`)
- [ ] mysql_users exist with correct passwords
- [ ] Test logs exist in `ci_infra_logs/${INFRA_ID}/tests/`
- [ ] Checked test log for specific error messages
- [ ] Checked ProxySQL log for crashes or errors
