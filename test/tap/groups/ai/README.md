# AI TAP Group

This group runs AI/MCP TAP tests using the **Unified CI Infrastructure** pattern, with isolated Docker network and automated infrastructure management.

## Architecture

The AI group uses the standard `test/infra/` pattern:

- **MySQL Backend**: `infra-mysql84` (3-node MySQL 8.4 cluster with replication)
- **PostgreSQL Backend**: `docker-pgsql16-single` (single PostgreSQL 16 instance)
- **MCP Server**: Configured on port 6071 with MySQL and PostgreSQL targets
- **Network**: Isolated Docker network `${INFRA_ID}_backend`

## Group Structure

The `ai` group follows the **supergroup/subgroup** pattern:
- `ai` is the supergroup (defines infrastructure and shared configuration)
- `ai-g1`, `ai-g2`, etc. are subgroups (define specific test sets in `groups.json`)

When running with `TAP_GROUP=ai-g1`, the system:
1. Looks for `test/tap/groups/ai/infras.lst` (infrastructure requirements)
2. Looks for `test/tap/groups/ai/env.sh` (environment configuration)
3. Runs only tests tagged with `ai-g1` in `groups.json`

## Infrastructure Files

| File | Purpose |
|------|---------|
| `infras.lst` | Lists required infrastructures (`infra-mysql84`, `docker-pgsql16-single`) |
| `env.sh` | Environment variables for MCP configuration |
| `mcp-config.sql` | SQL template for MCP setup (variables substituted at runtime) |
| `cleanup.sql` | SQL template for MCP cleanup after tests |
| `seed-mysql.sql` | Test data for MySQL (seeded on mysql1, replicated to others) |
| `seed-pgsql.sql` | Test data for PostgreSQL |
| `setup-infras.bash` | **Group hook**: Configures MCP and seeds test data after infrastructure is ready |
| `pre-cleanup.bash` | **Group hook**: Removes MCP configuration before test runner cleanup |

## MCP Configuration

The MCP (Model Context Protocol) is automatically configured with:

- **MySQL Target**: `tap_mysql_default` (hostgroup 9100)
- **PostgreSQL Target**: `tap_pgsql_default` (hostgroup 9200)
- **Port**: 6071 (SSL enabled)

Test data includes:
- MySQL: `test.tap_mysql_static_customers`, `test.tap_mysql_static_orders`
- PostgreSQL: `public.tap_pgsql_static_accounts`, `public.tap_pgsql_static_events`

## Usage

### Running the Full AI Group

```bash
# Set unique INFRA_ID to avoid conflicts with other runs
export INFRA_ID="ai-test-$(date +%s)"
export TAP_GROUP="ai-g1"
export WORKSPACE=$(pwd)

# Source common environment
source test/infra/common/env.sh

# Start infrastructure (ProxySQL + MySQL + PostgreSQL)
./test/infra/control/ensure-infras.bash

# Run tests
./test/infra/control/run-tests-isolated.bash

# Cleanup
./test/infra/control/stop-proxysql-isolated.bash
./test/infra/control/destroy-infras.bash
```

### Running a Single Test

```bash
export INFRA_ID="ai-single-$(date +%s)"
export TAP_GROUP="ai-g1"
export TEST_PY_TAP_INCL="mcp_module-t"
export WORKSPACE=$(pwd)

source test/infra/common/env.sh
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
./test/infra/control/stop-proxysql-isolated.bash
./test/infra/control/destroy-infras.bash
```

### Running Specific MCP Test Suites

**MCP Static Harvest (MySQL + PostgreSQL):**
```bash
export INFRA_ID="ai-harvest-$(date +%s)"
export TAP_GROUP="ai-g1"
export TEST_PY_TAP_INCL="test_mcp_static_harvest-t"
export WORKSPACE=$(pwd)

source test/infra/common/env.sh
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
./test/infra/control/stop-proxysql-isolated.bash
./test/infra/control/destroy-infras.bash
```

**MCP Discovery Phase B:**
```bash
export INFRA_ID="ai-discovery-$(date +%s)"
export TAP_GROUP="ai-g1"
export TEST_PY_TAP_INCL="test_mcp_llm_discovery_phaseb-t"
export WORKSPACE=$(pwd)

source test/infra/common/env.sh
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
./test/infra/control/stop-proxysql-isolated.bash
./test/infra/control/destroy-infras.bash
```

**Claude Headless Flow:**
```bash
export INFRA_ID="ai-claude-$(date +%s)"
export TAP_GROUP="ai-g1"
export TEST_PY_TAP_INCL="test_mcp_claude_headless_flow-t"
export WORKSPACE=$(pwd)

source test/infra/common/env.sh
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
./test/infra/control/stop-proxysql-isolated.bash
./test/infra/control/destroy-infras.bash

# Optional: Run with real Claude execution
# export TAP_RUN_REAL_CLAUDE=1
# export TAP_CLAUDE_MCP_CONFIG=./scripts/mcp/DiscoveryAgent/ClaudeCode_Headless/mcp_config.json
```

## Test Categories

Tests included in the AI group (defined in `groups.json`):

- **AI Module Tests**: `ai_validation-t`, `ai_error_handling_edge_cases-t`, `ai_llm_retry_scenarios-t`
- **Anomaly Detection**: `anomaly_detection-t`, `anomaly_detector_unit-t`, `anomaly_detection_integration-t`
- **GenAI Tests**: `genai_module-t`
- **MCP Tests**: `mcp_module-t`, `mcp_query_rules-t`, `mcp_stats_refresh-t`, `mcp_semantic_lifecycle-t`, etc.
- **NL2SQL Tests**: `nl2sql_integration-t`, `nl2sql_prompt_builder-t`, `nl2sql_model_selection-t`, etc.
- **Vector Tests**: `vector_features-t`, `vector_db_performance-t`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TAP_MCPPORT` | 6071 | MCP server port |
| `MCP_TARGET_ID` | tap_mysql_default | MySQL MCP target ID |
| `MCP_PGSQL_TARGET_ID` | tap_pgsql_default | PostgreSQL MCP target ID |
| `MCP_MYSQL_HOSTGROUP_ID` | 9100 | MySQL hostgroup for MCP |
| `MCP_PGSQL_HOSTGROUP_ID` | 9200 | PostgreSQL hostgroup for MCP |
| `TEST_PY_TAP_INCL` | (see env.sh) | Test filter pattern |

## Notes

- All containers run on an isolated Docker network (`${INFRA_ID}_backend`)
- MySQL replication automatically propagates seed data from mysql1 to mysql2/mysql3
- MCP configuration is applied by the group-specific `setup-infras.bash` hook and cleaned up by `pre-cleanup.bash`
- The `INFRA_ID` must be unique for each test run to avoid conflicts

## Group-Specific Hooks

The AI group uses the generic hook system provided by the Unified CI Infrastructure:

| Hook | Executed By | Purpose |
|------|-------------|---------|
| `setup-infras.bash` | `ensure-infras.bash` after backends start | Configures MCP, seeds test data |
| `pre-cleanup.bash` | `run-tests-isolated.bash` before cleanup | Removes MCP configuration |

These hooks are group-specific and live in the `test/tap/groups/ai/` directory. They are discovered and executed automatically by the infrastructure scripts based on `TAP_GROUP`.
