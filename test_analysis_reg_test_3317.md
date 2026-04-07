# Test Failure Analysis: reg_test_3317-lock_hostgroup_special_queries-t

## Test Overview

**Test Name:** `reg_test_3317-lock_hostgroup_special_queries-t`
**Purpose:** Verifies that after locking on a hostgroup, ProxySQL forwards simple special queries (SET NAMES, SET autocommit, etc.) properly to the backend connection.

## Current Configuration (From Running Infrastructure)

### mysql_servers
```
hostgroup_id  hostname                    port  status
0             mariadb1.infra-mariadb10    3306  ONLINE
1             mariadb1.infra-mariadb10    3306  ONLINE
1             mariadb2.infra-mariadb10    3306  ONLINE
1             mariadb3.infra-mariadb10    3306  ONLINE
1700          mariadb1.infra-mariadb10    3306  ONLINE
1701          mariadb1.infra-mariadb10    3306  ONLINE
1701          mariadb2.infra-mariadb10    3306  ONLINE
1701          mariadb3.infra-mariadb10    3306  ONLINE
```

**Key Finding:** Hostgroup 1300 (referenced in test error) DOES NOT EXIST in mysql_servers!

### mysql_users (testuser)
```
username    default_hostgroup  transaction_persistent
testuser    1700               1
```

**Key Finding:** User 'testuser' has default_hostgroup = 1700, NOT 1300

### mysql_query_rules
```
(empty table - no query rules configured)
```

**Key Finding:** No query rules exist to route queries to any specific hostgroup

### Global Variables (lock_hostgroup related)
```
variable_name                        variable_value
mysql-set_query_lock_on_hostgroup    1
pgsql-set_query_lock_on_hostgroup    1
```

**Key Finding:** lock_hostgroup feature IS enabled

## Test Flow (Detailed)

The test performs 4 check iterations, each with 2 sub-tests (total 8 tests planned):

```
For each check (SET NAMES, SET autocommit, SET SESSION character_set_server, SET SESSION character_set_results):
  1. Create new connection to ProxySQL (port 6033, user 'testuser')
  2. Execute: SET inexisting_variable = ''
     - Expected: Query fails, ProxySQL locks connection to hostgroup
  3. Test #N: Verify invalid query failed (ok assertion)
  4. Execute the actual SET query being tested (e.g., SET NAMES latin7)
  5. Test #N+1: Verify SET query succeeded by checking session variables
  6. Close connection
```

## The Failure

**Observed Behavior:**
- Tests 1-4 pass (invalid query fails, connection locks to hostgroup)
- Tests 5-8 never execute because SET queries fail with:
  ```
  ProxySQL Error: connection is locked to hostgroup 1300 but trying to reach hostgroup 0
  ```

## Root Cause Analysis

The test is failing because of a **HOSTGROUP MISMATCH**. The test thinks it's locking to hostgroup 1300, but:

1. **Hostgroup 1300 does not exist** in mysql_servers table
2. **User 'testuser' has default_hostgroup = 1700**, not 1300
3. **No query rules** exist to route SET queries to any specific hostgroup

### What Actually Happens:

1. Test connects as 'testuser' → ProxySQL assigns default_hostgroup = 1700
2. `SET inexisting_variable = ''` is issued
3. Query fails (as expected), but the error mentions hostgroup 1300 in the error message
4. Connection is locked to hostgroup 1700 (the actual default for testuser)
5. `SET NAMES latin7` is issued
6. Without query rules, SET statements need routing logic
7. ProxySQL tries to route to hostgroup 0 (fallback/default behavior)
8. Error: `connection is locked to hostgroup 1300 but trying to reach hostgroup 0`

### The Error Message Mystery

The error message mentions hostgroup 1300, but:
- mysql_servers doesn't have hostgroup 1300
- testuser's default_hostgroup is 1700

This suggests one of:
1. The error message is misleading/stale
2. There was hostgroup 1300 in old CI configuration
3. ProxySQL has internal default/fallback to 1300 in some code path

## Why This Worked Before (Old CI System)

The old CI system likely had:
1. **Hostgroup 1300 configured** in mysql_servers pointing to MySQL backends
2. **testuser with default_hostgroup = 1300** OR query rules routing SET to 1300
3. **Query rules** matching SET statements and routing appropriately

## Why It Fails Now (New CI System)

The new isolated CI system:
1. Uses hostgroups 1700/1701 (not 1300)
2. User 'testuser' has default_hostgroup = 1700
3. No query rules for SET statement routing
4. The test expects hostgroup 1300 which doesn't exist

## The Real Issue

The test is **hardcoded** to expect hostgroup 1300 behavior, but the infrastructure uses hostgroup 1700. The test needs to either:

1. **Use the configured hostgroup (1700)** instead of assuming 1300
2. **Configure hostgroup 1300** in the test setup
3. **Have query rules** that properly route SET statements

## Debugging Commands Used

```bash
# Check mysql_servers
mysql -uradmin -pradmin -h127.0.0.1 -P6032 -e "SELECT hostgroup_id, hostname, port, status FROM mysql_servers ORDER BY hostgroup_id, hostname"

# Check mysql_users
mysql -uradmin -pradmin -h127.0.0.1 -P6032 -e "SELECT username, default_hostgroup, transaction_persistent FROM mysql_users ORDER BY username"

# Check mysql_query_rules
mysql -uradmin -pradmin -h127.0.0.1 -P6032 -e "SELECT rule_id, active, match_pattern, destination_hostgroup, apply FROM mysql_query_rules ORDER BY rule_id"

# Check global variables
mysql -uradmin -pradmin -h127.0.0.1 -P6032 -e "SELECT variable_name, variable_value FROM global_variables WHERE variable_name LIKE '%lock%' ORDER BY variable_name"
```

## Recommended Fix Options

### Option 1: Modify Test to Use Hostgroup 1700
Update the test to use hostgroup 1700 (which is the actual default_hostgroup for testuser):
- Change test expectations from hostgroup 1300 to 1700
- OR query for the actual default_hostgroup at runtime

### Option 2: Configure Hostgroup 1300 in CI
Add hostgroup 1300 to the ProxySQL configuration in the CI setup:
- Add servers to hostgroup 1300
- Ensure testuser has default_hostgroup = 1300

### Option 3: Add Query Rules for SET Statements
Configure query rules that route SET statements properly:
```sql
INSERT INTO mysql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply)
VALUES (1, 1, '^SET ', 1700, 1);
LOAD MYSQL QUERY RULES TO RUNTIME;
```

### Option 4: Self-Contained Test (Recommended)
Modify the test to:
1. Connect to Admin interface
2. Detect the current configuration (which hostgroup exists)
3. Configure query rules dynamically for the test
4. Run the test with proper routing
5. Clean up (optional)

## Summary

The test fails because it's hardcoded for hostgroup 1300, but the CI infrastructure uses hostgroup 1700. The error message mentioning hostgroup 1300 is misleading - the actual configuration has testuser pointing to hostgroup 1700. The test needs to be updated to work with the actual infrastructure configuration, OR the infrastructure needs to provide hostgroup 1300 as expected by the test.
