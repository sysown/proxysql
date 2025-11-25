# ProxySQL Hostgroup Backend Credentials Test

This test environment validates the new **hostgroup-based backend credentials** feature in ProxySQL, which allows different backend credentials per hostgroup while using a single frontend credential.

## Quick Start

Run the complete test suite with one command:

```bash
cd test/backend-credentials
./run-tests.sh
```

This will:
1. Build ProxySQL from source with the new feature
2. Start 10 database containers (5 MySQL + 5 PostgreSQL)
3. Configure separate frontend/backend credentials
4. Run 14 automated validation tests (8 MySQL + 6 PostgreSQL)
5. Display results and clean up

**Expected result:** All 14 tests pass ✅

For manual testing or detailed exploration, continue reading below.

## Feature Overview

**Before this feature:**
- ProxySQL used the same credentials for both frontend (app → ProxySQL) and backend (ProxySQL → MySQL) connections

**After this feature:**
- Frontend users connect to ProxySQL with their own credentials
- ProxySQL uses **different credentials per hostgroup** when connecting to backend MySQL servers
- Mapping: Each hostgroup can have exactly one backend user with specific credentials

## Test Environment Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          Application                             │
│                                                                  │
│  app_user / app_password_123  |  standard_user / standard_pass  │
└──────────────────┬────────────────────────────┬─────────────────┘
                   │                            │
                   │ Port 6033                  │ Port 6033
                   ▼                            ▼
┌────────────────────────────────────────────────────────────────┐
│                         ProxySQL                                │
│                                                                 │
│  Frontend User:  app_user (default_hostgroup = 10)            │
│                  standard_user (default_hostgroup = 30)        │
│                                                                 │
│  Backend User HG10: reader_user / reader_pass_456             │
│  Backend User HG20: writer_user / writer_pass_789             │
│  Backend User HG30: standard_user (same as frontend)          │
└───────────┬─────────────────┬─────────────────┬───────────────┘
            │                 │                 │
    ┌───────┘                 │                 └────────┐
    │                         │                          │
    │ HG10 (Reads)            │ HG20 (Writes)       HG30 (Standard)
    │ reader_user             │ writer_user         standard_user
    │                         │                          │
┌───▼───┐ ┌────────┐     ┌───▼────┐ ┌────────┐    ┌───▼────┐
│MySQL  │ │ MySQL  │     │ MySQL  │ │ MySQL  │    │ MySQL  │
│HG10-1 │ │ HG10-2 │     │ HG20-1 │ │ HG20-2 │    │ HG30-1 │
└───────┘ └────────┘     └────────┘ └────────┘    └────────┘
```

## Components

### 1. **ProxySQL** (built from source)
- Port 6033: MySQL interface (frontend)
- Port 6543: PostgreSQL interface (frontend)
- Port 6032: Admin interface
- Configuration: `proxysql.cnf` + SQL-based user setup

### 2. **MySQL Servers** (5 containers)
- **Hostgroup 10** (Read): `mysql-hg10-1`, `mysql-hg10-2`
  - Backend credentials: `reader_user / reader_pass_456`
  - Permissions: SELECT only

- **Hostgroup 20** (Write): `mysql-hg20-1`, `mysql-hg20-2`
  - Backend credentials: `writer_user / writer_pass_789`
  - Permissions: ALL on testdb

- **Hostgroup 30** (Standard mode): `mysql-hg30-1`
  - Backend credentials: `standard_user / standard_pass_999` (same as frontend)
  - Tests backward compatibility with classic ProxySQL behavior

### 3. **PostgreSQL Servers** (5 containers)
- **Hostgroup 10** (Read): `pgsql-hg10-1`, `pgsql-hg10-2`
  - Backend credentials: `pgsql_reader / pgsql_reader_pass`
  - Permissions: SELECT only

- **Hostgroup 20** (Write): `pgsql-hg20-1`, `pgsql-hg20-2`
  - Backend credentials: `pgsql_writer / pgsql_writer_pass`
  - Permissions: ALL on testdb

- **Hostgroup 30** (Standard mode): `pgsql-hg30-1`
  - Backend credentials: `pgsql_standard / pgsql_standard_pass` (same as frontend)
  - Tests backward compatibility with classic ProxySQL behavior

### 4. **Test Runner**
- Executes 14 automated validation tests (8 MySQL + 6 PostgreSQL)
- Connects as frontend users `app_user`, `standard_user`, `pgsql_app`, `pgsql_standard`
- Verifies queries are routed correctly with proper backend credentials
- Tests both new feature and standard ProxySQL mode for both MySQL and PostgreSQL

## Configuration Details

Users are configured via SQL (not via `proxysql.cnf` as `backend`/`frontend` flags are not supported in config files):

### Frontend User (configured via SQL)
```sql
INSERT INTO mysql_users (username, password, default_hostgroup, default_schema, frontend, backend, comment)
VALUES ('app_user', 'app_password_123', 10, 'testdb', 1, 0, 'Frontend user');
```

- `frontend = 1` - This user accepts frontend connections
- `backend = 0` - This user is NOT used for backend connections
- `default_hostgroup = 10` - Maps to hostgroup 10

### Backend User for Hostgroup 10
```sql
INSERT INTO mysql_users (username, password, default_hostgroup, frontend, backend, comment)
VALUES ('reader_user', 'reader_pass_456', 10, 0, 1, 'Backend credentials for hostgroup 10');
```

- `frontend = 0` - This user does NOT accept frontend connections
- `backend = 1` - This user is ONLY for backend connections
- `default_hostgroup = 10` - ProxySQL uses this user when connecting to HG10

### Backend User for Hostgroup 20
```sql
INSERT INTO mysql_users (username, password, default_hostgroup, frontend, backend, comment)
VALUES ('writer_user', 'writer_pass_789', 20, 0, 1, 'Backend credentials for hostgroup 20');
```

### Standard Mode User (Hostgroup 30)
```sql
INSERT INTO mysql_users (username, password, default_hostgroup, default_schema, frontend, backend, comment)
VALUES ('standard_user', 'standard_pass_999', 30, 'testdb', 1, 1, 'Standard mode - same credentials for frontend and backend');
```

- `frontend = 1, backend = 1` - Used for both frontend and backend (classic ProxySQL behavior)
- Tests backward compatibility

### Query Routing Rules (for app_user)
- `SELECT` queries → Hostgroup 10 (uses `reader_user`)
- `SELECT ... FOR UPDATE` → Hostgroup 20 (uses `writer_user`)
- `INSERT/UPDATE/DELETE` queries → Hostgroup 20 (uses `writer_user`)

### Standard Mode (for standard_user)
- All queries → Hostgroup 30 (uses `standard_user` for both frontend and backend)
- Tests backward compatibility with classic ProxySQL behavior

## Running the Tests

### Prerequisites
- Docker and Docker Compose installed
- Sufficient resources (10 database containers + ProxySQL: 5 MySQL + 5 PostgreSQL)

### Automated Test Suite (Recommended)

Run the complete test suite:

```bash
cd test/backend-credentials
./run-tests.sh
```

This script will:
1. Build ProxySQL from source with the new feature
2. Start 10 database containers (5 MySQL + 5 PostgreSQL)
3. Configure ProxySQL with separate frontend/backend credentials
4. Run 14 automated validation tests (8 MySQL + 6 PostgreSQL)
5. Display test results
6. Clean up resources

### Manual Testing

If you want to explore manually without cleanup:

```bash
cd test/backend-credentials
docker compose up --build
```

This will start all services and run the test suite, but leave containers running for manual exploration.

### Expected Output

```
==========================================
ProxySQL Hostgroup Backend Credentials Test
==========================================

⏳ Waiting for ProxySQL to be ready...

📊 Verifying ProxySQL is configured...
----------------------------------------
Attempting connection as frontend user (app_user)...
✅ Frontend user can connect (backend: mysql-hg10-1)
Attempting connection as standard user (standard_user)...
✅ Standard user can connect (backend: mysql-hg30-1, classic ProxySQL mode)

==========================================
MYSQL TESTS
==========================================

Running MySQL Functional Tests (8 tests)
----------------------------------------

🧪 Testing: Frontend connection as app_user (verify HG10 backend)... PASSED
🧪 Testing: Read query to hostgroup 10... PASSED
🧪 Testing: SELECT data from read servers... PASSED
🧪 Testing: INSERT into write servers (using @@hostname)... PASSED
🧪 Testing: Verify write landed on HG20 server... PASSED
🧪 Testing: SELECT FOR UPDATE routed to HG20... PASSED
🧪 Testing: Standard user connection (verify HG30 backend)... PASSED
🧪 Testing: Standard user query to HG30... PASSED

==========================================
POSTGRESQL TESTS
==========================================

Running PostgreSQL Functional Tests (6 tests)
----------------------------------------

🧪 Testing: PG Frontend connection as pgsql_app... PASSED
🧪 Testing: PG Read query to hostgroup 10... PASSED
🧪 Testing: PG INSERT into write servers... PASSED
🧪 Testing: PG Verify write landed on HG20 server... PASSED
🧪 Testing: PG Standard user connection (verify HG30 backend)... PASSED
🧪 Testing: PG Standard user query to HG30... PASSED

==========================================
Backend Credential Verification
==========================================

🔍 Checking which users are connecting to backend MySQL servers...

Hostgroup 10 (Read) - Expected backend user: reader_user
  Checking mysql-hg10-1... Backend user connections detected
  Checking mysql-hg10-2... Backend user connections detected

Hostgroup 20 (Write) - Expected backend user: writer_user
  Checking mysql-hg20-1... Backend user connections detected
  Checking mysql-hg20-2... Backend user connections detected

==========================================
OVERALL TEST SUMMARY
==========================================

✅ All 14 tests passed! (8 MySQL + 6 PostgreSQL)

The hostgroup-based backend credentials feature is working correctly:
  • Frontend user 'app_user' connects to ProxySQL
  • ProxySQL uses 'reader_user' credentials for hostgroup 10 (reads)
  • ProxySQL uses 'writer_user' credentials for hostgroup 20 (writes)
  • Write queries are correctly routed to HG20 servers
  • Standard mode (frontend=backend=1) still works correctly
```

### Manual Testing

If you want to keep the environment running for manual exploration:

```bash
docker compose up
```

Then in another terminal:

**Connect to ProxySQL Admin interface:**
```bash
docker exec -it proxysql-test mysql -h 127.0.0.1 -P 6032 -uadmin -padmin
```

**Connect as frontend users:**
```bash
# New feature mode (separate credentials)
docker exec -it proxysql-test mysql -h 127.0.0.1 -P 6033 -uapp_user -papp_password_123 -D testdb

# Standard mode (same credentials)
docker exec -it proxysql-test mysql -h 127.0.0.1 -P 6033 -ustandard_user -pstandard_pass_999 -D testdb
```

**Query backend servers directly:**
```bash
# Hostgroup 10 server (read) - with reader_user
docker exec -it mysql-hg10-1 mysql -ureader_user -preader_pass_456 -D testdb -e "SELECT * FROM test_reads;"

# Hostgroup 20 server (write) - with writer_user
docker exec -it mysql-hg20-1 mysql -uwriter_user -pwriter_pass_789 -D testdb -e "SELECT * FROM test_writes;"

# Hostgroup 30 server (standard) - with standard_user
docker exec -it mysql-hg30-1 mysql -ustandard_user -pstandard_pass_999 -D testdb -e "SELECT * FROM hg30_data;"
```

**Test query routing:**
```bash
# From app_user - these will use DIFFERENT backend credentials
docker exec -it proxysql-test mysql -h 127.0.0.1 -P 6033 -uapp_user -papp_password_123 -D testdb -e "SELECT @@hostname;"  # Returns mysql-hg10-* (read)
docker exec -it proxysql-test mysql -h 127.0.0.1 -P 6033 -uapp_user -papp_password_123 -D testdb -e "SELECT @@hostname FROM test_writes LIMIT 1 FOR UPDATE;"  # Returns mysql-hg20-* (write)
```

## Validating the Feature

### Automated Test Suite (14 Tests)

The test suite validates both MySQL and PostgreSQL implementations:

**MySQL Tests (8 tests):**
1. **Test 1**: Frontend connection uses correct backend (HG10) - verifies using `@@hostname`
2. **Test 2**: Read queries return data from HG10 servers
3. **Test 3**: SELECT statements execute on read servers
4. **Test 4**: INSERT queries use `@@hostname` and write to backend
5. **Test 5**: Writes land on HG20 servers (not HG10)
6. **Test 6**: SELECT FOR UPDATE is routed to HG20 (write hostgroup)
7. **Test 7**: Standard mode connection works (frontend=backend=1)
8. **Test 8**: Standard mode queries execute correctly

**PostgreSQL Tests (6 tests):**
9. **Test 9**: PG Frontend connection with separate credentials
10. **Test 10**: PG Read queries use pgsql_reader backend credentials
11. **Test 11**: PG Write queries use pgsql_writer backend credentials
12. **Test 12**: PG Writes land on correct HG20 servers
13. **Test 13**: PG Standard mode (frontend=backend=1)
14. **Test 14**: Backend credential verification for all PG hostgroups

### How to Confirm It's Working

1. **Frontend credentials are different from backend**:
   - App connects with: `app_user / app_password_123`
   - ProxySQL connects to HG10 with: `reader_user / reader_pass_456`
   - ProxySQL connects to HG20 with: `writer_user / writer_pass_789`

2. **Query routing works correctly**:
   - SELECT queries go to HG10 with `reader_user` credentials
   - SELECT FOR UPDATE goes to HG20 with `writer_user` credentials
   - Write queries (INSERT/UPDATE/DELETE) go to HG20 with `writer_user` credentials

3. **Backend servers only have specific users**:
   - HG10 servers: Only `reader_user` has access (SELECT only)
   - HG20 servers: Only `writer_user` has access (ALL privileges)
   - HG30 servers: `standard_user` for both frontend and backend (classic mode)
   - App credentials (`app_user`) don't exist on HG10/HG20 backend servers

4. **Constraint enforcement**:
   - Only ONE backend user allowed per hostgroup
   - Attempting to add a second backend user for the same hostgroup fails

5. **Backward compatibility**:
   - Standard ProxySQL mode (frontend=backend=1) still works
   - Existing applications don't need changes

### Test the Constraint

Try adding a second backend user for hostgroup 10 (should fail):

```bash
docker exec -it proxysql-test mysql -h 127.0.0.1 -P 6032 -uadmin -padmin -e \
  "INSERT INTO mysql_users (username, password, frontend, backend, default_hostgroup) \
   VALUES ('another_reader', 'pass', 0, 1, 10);"
```

Expected error:
```
ERROR 1064 (42000): Only one backend user allowed per hostgroup
```

## Cleanup

Stop and remove all containers:
```bash
docker compose down -v
```

## Troubleshooting

### Check ProxySQL logs
```bash
docker logs proxysql-test
```

### Check MySQL server logs
```bash
docker logs mysql-hg10-1
docker logs mysql-hg20-1
```

### Verify ProxySQL stats
```sql
-- Connection pool stats
SELECT * FROM stats_mysql_connection_pool;

-- Query stats
SELECT * FROM stats_mysql_query_rules;

-- User stats
SELECT * FROM stats_mysql_users;
```

## Implementation Files

The hostgroup-based backend credentials feature is implemented in:

- `include/MySQL_Authentication.hpp` - Added `lookup_backend_for_hostgroup()`
- `lib/MySQL_Authentication.cpp` - Implementation
- `lib/MySQL_Session.cpp` - Uses hostgroup lookup when connecting to backend
- `lib/Admin_Bootstrap.cpp` - SQLite triggers to enforce one backend user per hostgroup

Similar implementations for PostgreSQL:
- `include/PgSQL_Authentication.h`
- `lib/PgSQL_Authentication.cpp`
- `lib/PgSQL_Session.cpp`


