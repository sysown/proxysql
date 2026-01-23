# MCP Query Rules Test Plan

## Overview

This test plan covers the MCP Query Rules feature added in the last 7 commits. The feature allows filtering and modifying MCP tool calls based on rule evaluation, similar to MySQL query rules.

### Feature Design Summary

Actions are inferred from rule properties (like MySQL/PostgreSQL query rules):
- `error_msg != NULL` → **block**
- `replace_pattern != NULL` → **rewrite**
- `timeout_ms > 0` → **timeout**
- `OK_msg != NULL` → return OK message
- otherwise → **allow**

Actions are NOT mutually exclusive - a single rule can perform multiple actions simultaneously.

### Tables Involved

| Table | Purpose |
|-------|---------|
| `mcp_query_rules` | Admin table for defining rules |
| `runtime_mcp_query_rules` | In-memory state of active rules |
| `stats_mcp_query_rules` | Hit counters per rule |
| `stats_mcp_query_digest` | Query tracking statistics |

### Existing Test Infrastructure

1. **TAP Test**: `test/tap/tests/mcp_module-t.cpp` - Tests LOAD/SAVE commands for MCP variables
2. **Shell Test**: `scripts/mcp/test_mcp_query_rules_block.sh` - Tests block action
3. **SQL Rules**: `scripts/mcp/rules/block_rule.sql` - Sample block rules

---

## Test Plan

### Phase 1: Rule Management Tests (CREATE/READ/UPDATE/DELETE)

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| T1.1 | Create a basic rule with match_pattern | Rule inserted into `mcp_query_rules` |
| T1.2 | Create rule with all action types | Rule with error_msg, replace_pattern, OK_msg, timeout_ms |
| T1.3 | Create rule with username filter | Rule filters by specific user |
| T1.4 | Create rule with schemaname filter | Rule filters by specific schema |
| T1.5 | Create rule with tool_name filter | Rule filters by specific tool |
| T1.6 | Update existing rule | Rule properties modified |
| T1.7 | Delete rule | Rule removed from table |
| T1.8 | Create rule with flagIN/flagOUT | Rule chaining setup |

### Phase 2: LOAD/SAVE Commands Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| T2.1 | `LOAD MCP QUERY RULES TO MEMORY` | Rules loaded from disk to memory table |
| T2.2 | `LOAD MCP QUERY RULES FROM MEMORY` | Rules copied from memory to... |
| T2.3 | `LOAD MCP QUERY RULES TO RUNTIME` | Rules become active for evaluation |
| T2.4 | `SAVE MCP QUERY RULES TO DISK` | Rules persisted to disk |
| T2.5 | `SAVE MCP QUERY RULES TO MEMORY` | Rules saved to memory table |
| T2.6 | `SAVE MCP QUERY RULES FROM RUNTIME` | Runtime rules saved to memory |

### Phase 3: Runtime Table Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| T3.1 | Query `runtime_mcp_query_rules` | Returns active rules from memory |
| T3.2 | Verify rules match runtime after LOAD | Runtime table reflects loaded rules |
| T3.3 | Verify active flag filtering | Only active=1 rules are in runtime |
| T3.4 | Check rule order in runtime | Rules ordered by rule_id |

### Phase 4: Statistics Table Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| T4.1 | Query `stats_mcp_query_rules` | Returns rule_id and hits count |
| T4.2 | Verify hit counter increments on match | hits counter increases when rule matches |
| T4.3 | Verify hit counter persists across queries | Counter accumulates across multiple matches |
| T4.4 | Check hit counter for non-matching rule | Counter stays at 0 for unmatched rules |

### Phase 5: Query Digest Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| T5.1 | Query `stats_mcp_query_digest` | Returns tool_name, digest, count_star, etc. |
| T5.2 | Verify query tracked in digest | New query appears in digest table |
| T5.3 | Verify count_star increments | Repeated queries increment counter |
| T5.4 | Verify digest_text contains SQL | SQL query text is stored |
| T5.5 | Test `stats_mcp_query_digest_reset` | Reset table clears and returns current stats |

### Phase 6: Rule Evaluation Tests - Block Action

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| T6.1 | Block query with error_msg | Query rejected, error returned |
| T6.2 | Block with case-sensitive match | Pattern matching respects re_modifiers |
| T6.3 | Block with negate_match_pattern=1 | Inverts the match logic |
| T6.4 | Block specific username | Only queries from user are blocked |
| T6.5 | Block specific schema | Only queries in schema are blocked |
| T6.6 | Block specific tool_name | Only calls to tool are blocked |

### Phase 7: Rule Evaluation Tests - Rewrite Action

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| T7.1 | Rewrite SQL with replace_pattern | SQL modified before execution |
| T7.2 | Rewrite with capture groups | Pattern substitution works |
| T7.3 | Rewrite with regex modifiers | CASELESS/EXTENDED modifiers work |

### Phase 8: Rule Evaluation Tests - Timeout Action

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| T8.1 | Query with timeout_ms | Query times out after specified ms |
| T8.2 | Verify timeout error message | Appropriate error returned |

TODO: There is a limitation for testing this feature. MCP connection gets killed and becomes unusable after
'timeout' takes place. This should be fixed before continuing this testing phase.

### Phase 9: Rule Evaluation Tests - OK Message Action

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| T9.1 | Query with OK_msg | Query returns OK message without execution |
| T9.2 | Verify success response | Success response contains OK_msg |

### Phase 10: Rule Chaining Tests (flagIN/flagOUT)

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| T10.1 | Create rules with flagIN=0, flagOUT=100 | First rule sets flag to 100 |
| T10.2 | Create rule with flagIN=100 | Second rule only evaluates if flag=100 |
| T10.3 | Verify rule chaining order | Rules evaluated in flagIN/flagOUT order |
| T10.4 | Test multiple flagOUT values | Complex chaining scenarios |

### Phase 11: Integration Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| T11.1 | Multiple actions in single rule | Block + rewrite together |
| T11.2 | Multiple matching rules | First matching rule wins (or all?) |
| T11.3 | Load rules and verify immediately | Rules active after LOAD TO RUNTIME |
| T11.4 | Modify rule and reload | Updated behavior after reload |

---

## Implementation Approach

### Option A: Extend Existing Shell Test Script
Extend `scripts/mcp/test_mcp_query_rules_block.sh` to cover all test cases.

**Pros:**
- Follows existing pattern
- Easy to run manually
- Good for end-to-end testing

**Cons:**
- Shell scripting complexity
- Harder to maintain

### Option B: Create New TAP Test
Create `test/tap/tests/mcp_query_rules-t.cpp` following the pattern of `mcp_module-t.cpp`.

**Pros:**
- Consistent with existing test framework
- Better integration with CI
- Cleaner C++ code
- Better error reporting

**Cons:**
- Requires rebuild
- Less accessible for manual testing

### Option C: Hybrid Approach (Recommended)
1. **TAP Test** (`mcp_query_rules-t.cpp`): Core functionality tests
   - LOAD/SAVE commands
   - Table operations
   - Statistics tracking
   - Basic rule evaluation

2. **Shell Script** (`test_mcp_query_rules_all.sh`): End-to-end integration tests
   - Complex rule chaining
   - Multiple action types
   - Real MCP server interaction

---

## Test File Structure

### TAP Test Structure
```cpp
// test/tap/tests/mcp_query_rules-t.cpp

int main() {
    // Part 1: Rule CRUD operations
    test_rule_create();
    test_rule_read();
    test_rule_update();
    test_rule_delete();

    // Part 2: LOAD/SAVE commands
    test_load_save_commands();

    // Part 3: Runtime table
    test_runtime_table();

    // Part 4: Statistics table
    test_stats_table();

    // Part 5: Query digest
    test_query_digest();

    // Part 6: Rule evaluation
    test_block_action();
    test_rewrite_action();
    test_timeout_action();
    test_okmsg_action();

    // Part 7: Rule chaining
    test_flag_chaining();

    return exit_status();
}
```

### Shell Test Structure
```bash
# scripts/mcp/test_mcp_query_rules_all.sh

test_block_action() { ... }
test_rewrite_action() { ... }
test_timeout_action() { ... }
test_okmsg_action() { ... }
test_flag_chaining() { ... }
```

---

## SQL Rule Templates

### Block Rule Template
```sql
INSERT INTO mcp_query_rules (
    rule_id, active, username, schemaname, tool_name,
    match_pattern, negate_match_pattern, re_modifiers,
    flagIN, flagOUT, error_msg, apply, comment
) VALUES (
    100, 1, NULL, NULL, NULL,
    'DROP TABLE', 0, 'CASELESS',
    0, NULL,
    'Blocked by rule: DROP TABLE not allowed',
    1, 'Block DROP TABLE'
);
```

### Rewrite Rule Template
```sql
INSERT INTO mcp_query_rules (
    rule_id, active, username, schemaname, tool_name,
    match_pattern, replace_pattern, re_modifiers,
    flagIN, flagOUT, apply, comment
) VALUES (
    200, 1, NULL, NULL, 'run_sql_readonly',
    'SELECT \* FROM (.*)', 'SELECT count(*) FROM \1',
    'EXTENDED', 0, NULL,
    1, 'Rewrite SELECT * to SELECT count(*)'
);
```

### Timeout Rule Template
```sql
INSERT INTO mcp_query_rules (
    rule_id, active, username, schemaname, tool_name,
    match_pattern, timeout_ms, re_modifiers,
    flagIN, flagOUT, apply, comment
) VALUES (
    300, 1, NULL, NULL, NULL,
    'SELECT.*FROM.*large_table', 5000,
    'CASELESS', 0, NULL,
    1, 'Timeout queries on large_table'
);
```

### OK Message Rule Template
```sql
INSERT INTO mcp_query_rules (
    rule_id, active, username, schemaname, tool_name,
    match_pattern, OK_msg, re_modifiers,
    flagIN, flagOUT, apply, comment
) VALUES (
    400, 1, NULL, NULL, NULL,
    'PING', 'PONG', 'CASELESS',
    0, NULL, 1, 'Return PONG for PING'
);
```

---

## Recommended Next Actions

1. **Start with Phase 1-5**: Create TAP test for table operations and statistics
   - These don't require MCP server interaction
   - Can be tested through admin interface only

2. **Create test SQL files**: Organize rule templates in `scripts/mcp/rules/`
   - `block_rule.sql` (already exists)
   - `rewrite_rule.sql`
   - `timeout_rule.sql`
   - `okmsg_rule.sql`
   - `chaining_rule.sql`

3. **Extend shell test**: Modify `test_mcp_query_rules_block.sh` to `test_mcp_query_rules_all.sh`
   - Add rewrite, timeout, OK_msg tests
   - Add flag chaining tests

4. **Create TAP test**: New file `test/tap/tests/mcp_query_rules-t.cpp`
   - Core functionality tests
   - Statistics tracking tests

5. **Integration tests**: End-to-end tests with actual MCP server
   - Test through JSON-RPC interface
   - Verify response contents

---

## Test Dependencies

- **ProxySQL**: Must be running with MCP module enabled
- **MySQL client**: For admin interface commands
- **curl**: For MCP JSON-RPC requests
- **jq**: For JSON parsing in shell tests
- **TAP library**: For C++ tests

## Test Execution Order

1. Start ProxySQL with MCP enabled
2. Run TAP tests (fast, no external dependencies)
3. Run shell tests (require MCP server)
4. Verify all tests pass
5. Clean up test rules
