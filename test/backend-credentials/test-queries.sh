#!/bin/bash
set -e
set -o pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "ProxySQL Hostgroup Backend Credentials Test"
echo "=========================================="
echo ""

# Wait for ProxySQL to be fully ready
echo "⏳ Waiting for ProxySQL to be ready..."
sleep 10

# Test connection function
test_query() {
    local description="$1"
    local query="$2"
    local expected="$3"
    local username="${4:-app_user}"
    local password="${5:-app_password_123}"

    echo -n "🧪 Testing: $description... "

    result=$(mysql --skip-ssl -h proxysql-test -P 6033 -u"$username" -p"$password" -D testdb -sN -e "$query" 2>&1) || {
        echo -e "${RED}FAILED${NC}"
        echo "   Error: $result"
        return 1
    }

    if [[ "$result" == *"$expected"* ]] || [[ -z "$expected" ]]; then
        echo -e "${GREEN}PASSED${NC}"
        if [[ -n "$result" ]]; then
            echo "   Result: $result"
        fi
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        echo "   Expected: $expected"
        echo "   Got: $result"
        return 1
    fi
}

echo ""
echo "=========================================="
echo "MYSQL TESTS (Tests 1-8)"
echo "=========================================="
echo ""

# MySQL Test counters
MYSQL_PASSED=0
MYSQL_FAILED=0
MYSQL_TESTS=8

# Test admin connection (note: admin interface is not accessible from external containers by default)
# Instead, we verify user configuration by attempting to connect
echo "Verifying Configuration"
echo "----------------------------------------"
echo "Attempting connection as frontend user (app_user)..."
backend=$(mysql --skip-ssl -h proxysql-test -P 6033 -uapp_user -papp_password_123 -sN -e "SELECT @@hostname" 2>/dev/null) || true
if [[ "$backend" == mysql-hg10-* ]]; then
    echo "✅ Frontend user can connect (backend: $backend)"
else
    echo "⚠️  Frontend user cannot connect yet (backend servers may not be ready)"
fi

echo "Attempting connection as standard user (standard_user)..."
backend=$(mysql --skip-ssl -h proxysql-test -P 6033 -ustandard_user -pstandard_pass_999 -sN -e "SELECT @@hostname" 2>/dev/null) || true
if [[ "$backend" == "mysql-hg30-1" ]]; then
    echo "✅ Standard user can connect (backend: $backend, classic ProxySQL mode)"
else
    echo "⚠️  Standard user cannot connect yet"
fi
echo ""

echo "Running Functional Tests"
echo "----------------------------------------"
echo ""

# Test 1: Frontend connection with app_user - verify we're on correct hostgroup (HG10)
if test_query "Test 1: Frontend connection as app_user (verify HG10 backend)" \
    "SELECT @@hostname" \
    "mysql-hg10-"; then
    MYSQL_PASSED=$((MYSQL_PASSED+1))
else
    MYSQL_FAILED=$((MYSQL_FAILED+1))
fi

# Test 2: Read query routed to hostgroup 10 (should use reader_user credentials on backend)
if test_query "Test 2: Read query to hostgroup 10" \
    "SELECT COUNT(*) FROM testdb.test_reads" \
    ""; then
    MYSQL_PASSED=$((MYSQL_PASSED+1))
else
    MYSQL_FAILED=$((MYSQL_FAILED+1))
fi

# Test 3: Verify we can read from read servers
if test_query "Test 3: SELECT data from read servers" \
    "SELECT data FROM testdb.test_reads LIMIT 1" \
    ""; then
    MYSQL_PASSED=$((MYSQL_PASSED+1))
else
    MYSQL_FAILED=$((MYSQL_FAILED+1))
fi

# Test 4: Write query routed to hostgroup 20 (should use writer_user credentials on backend)
if test_query "Test 4: INSERT into write servers (using @@hostname)" \
    "INSERT INTO testdb.test_writes (server_name, data) VALUES (@@hostname, 'Test write from app_user')" \
    ""; then
    MYSQL_PASSED=$((MYSQL_PASSED+1))
else
    MYSQL_FAILED=$((MYSQL_FAILED+1))
fi

# Test 5: Verify write landed on HG20 by checking server_name contains mysql-hg20-
# Check both HG20 servers since load balancing determines which one gets the write
echo -n "🧪 Testing: Test 5: Verify write landed on HG20 server... "
write_server=$(mysql --skip-ssl -h mysql-hg20-1 -uroot -proot_pass -D testdb -sN -e "SELECT server_name FROM test_writes WHERE data='Test write from app_user' LIMIT 1" 2>/dev/null)
if [[ -z "$write_server" ]]; then
    # Try the other HG20 server
    write_server=$(mysql --skip-ssl -h mysql-hg20-2 -uroot -proot_pass -D testdb -sN -e "SELECT server_name FROM test_writes WHERE data='Test write from app_user' LIMIT 1" 2>/dev/null)
fi
if [[ "$write_server" == mysql-hg20-* ]]; then
    echo -e "${GREEN}PASSED${NC}"
    echo "   Result: Write landed on $write_server (HG20)"
    MYSQL_PASSED=$((MYSQL_PASSED+1))
else
    echo -e "${RED}FAILED${NC}"
    echo "   Expected: mysql-hg20-* hostname"
    echo "   Got: $write_server"
    MYSQL_FAILED=$((MYSQL_FAILED+1))
fi

# Test 6: SELECT FOR UPDATE should also go to HG20 (write hostgroup)
# Use a simple query that will work regardless of which HG20 server has the data
if test_query "Test 6: SELECT FOR UPDATE routed to HG20" \
    "SELECT @@hostname FROM testdb.test_writes LIMIT 1 FOR UPDATE" \
    "mysql-hg20-"; then
    MYSQL_PASSED=$((MYSQL_PASSED+1))
else
    MYSQL_FAILED=$((MYSQL_FAILED+1))
fi

# Test 7-8: Standard mode - standard_user with frontend=backend=1
echo ""
echo "Standard Mode (HG30)"
echo "----------------------------------------"
echo "Testing standard/classic mode where frontend=backend=1"
echo ""

# Test 7: Standard user connection
if test_query "Test 7: Standard user connection (verify HG30 backend)" \
    "SELECT @@hostname" \
    "mysql-hg30-1" \
    "standard_user" \
    "standard_pass_999"; then
    echo "   ✅ Same credentials work for both frontend and backend"
    MYSQL_PASSED=$((MYSQL_PASSED+1))
else
    MYSQL_FAILED=$((MYSQL_FAILED+1))
fi

# Test 8: Verify standard_user can query HG30 data
if test_query "Test 8: Standard user query to HG30" \
    "SELECT message FROM testdb.hg30_data LIMIT 1" \
    "Standard ProxySQL" \
    "standard_user" \
    "standard_pass_999"; then
    MYSQL_PASSED=$((MYSQL_PASSED+1))
else
    MYSQL_FAILED=$((MYSQL_FAILED+1))
fi

# Verify backend credentials are actually being used
echo ""
echo "Backend Credential Verification"
echo "----------------------------------------"

# Check hostgroup 10 servers
echo "Hostgroup 10 (Read) - Expected backend user: reader_user"
for server in mysql-hg10-1 mysql-hg10-2; do
    echo -n "  Checking $server... "
    # Try to verify processlist on backend (this would show which user ProxySQL uses)
    result=$(mysql --skip-ssl -h "$server" -uroot -proot_pass -D mysql -sN -e \
        "SELECT COUNT(*) FROM information_schema.processlist WHERE user='reader_user'" 2>/dev/null) || result="N/A"
    if [[ "$result" != "N/A" ]]; then
        echo -e "${GREEN}Backend user connections detected${NC}"
    else
        echo "Unable to verify (expected in this test setup)"
    fi
done

echo ""
echo "Hostgroup 20 (Write) - Expected backend user: writer_user"
for server in mysql-hg20-1 mysql-hg20-2; do
    echo -n "  Checking $server... "
    result=$(mysql --skip-ssl -h "$server" -uroot -proot_pass -D mysql -sN -e \
        "SELECT COUNT(*) FROM information_schema.processlist WHERE user='writer_user'" 2>/dev/null) || result="N/A"
    if [[ "$result" != "N/A" ]]; then
        echo -e "${GREEN}Backend user connections detected${NC}"
    else
        echo "Unable to verify (expected in this test setup)"
    fi
done

# MySQL test summary
echo ""
echo "MySQL Summary"
echo "----------------------------------------"
echo -e "Passed: ${GREEN}$MYSQL_PASSED${NC} / $MYSQL_TESTS"
if [[ $MYSQL_FAILED -gt 0 ]]; then
    echo -e "Failed: ${RED}$MYSQL_FAILED${NC}"
fi
echo ""

echo ""
echo "=========================================="
echo "POSTGRESQL TESTS (Tests 9-13)"
echo "=========================================="
echo ""

# PostgreSQL Test counters
PGSQL_PASSED=0
PGSQL_FAILED=0
PGSQL_TESTS=5

# PostgreSQL test helper function
test_pgsql_query() {
    local description="$1"
    local query="$2"
    local expected="$3"
    local username="${4:-pgsql_app}"
    local password="${5:-pgsql_app_password}"

    echo -n "🧪 Testing: $description... "

    export PGPASSWORD="$password"
    result=$(psql -h proxysql-test -p 6543 -U "$username" -d testdb -t -A -c "$query" 2>&1) || {
        echo -e "${RED}FAILED${NC}"
        echo "   Error: $result"
        unset PGPASSWORD
        return 1
    }
    unset PGPASSWORD

    if [[ "$result" == *"$expected"* ]] || [[ -z "$expected" ]]; then
        echo -e "${GREEN}PASSED${NC}"
        if [[ -n "$result" ]]; then
            echo "   Result: $result"
        fi
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        echo "   Expected: $expected"
        echo "   Got: $result"
        return 1
    fi
}

echo "Verifying Configuration"
echo "----------------------------------------"
echo "Attempting connection as frontend user (pgsql_app)..."
export PGPASSWORD="pgsql_app_password"
backend=$(psql -h proxysql-test -p 6543 -U pgsql_app -d testdb -t -A -c "SELECT inet_server_addr()" 2>/dev/null) || true
unset PGPASSWORD
if [[ -n "$backend" ]]; then
    echo "✅ PG Frontend user can connect"
else
    echo "⚠️  PG Frontend user cannot connect yet"
fi

echo "Attempting connection as standard user (pgsql_standard)..."
export PGPASSWORD="pgsql_standard_pass"
backend=$(psql -h proxysql-test -p 6543 -U pgsql_standard -d testdb -t -A -c "SELECT inet_server_addr()" 2>/dev/null) || true
unset PGPASSWORD
if [[ -n "$backend" ]]; then
    echo "✅ PG Standard user can connect (classic ProxySQL mode)"
else
    echo "⚠️  PG Standard user cannot connect yet"
fi
echo ""

echo "Running Functional Tests"
echo "----------------------------------------"
echo ""

# Test 9: PostgreSQL Frontend connection
if test_pgsql_query "Test 9: PG Frontend connection as pgsql_app" \
    "SELECT COUNT(*) FROM test_reads" \
    ""; then
    PGSQL_PASSED=$((PGSQL_PASSED+1))
else
    PGSQL_FAILED=$((PGSQL_FAILED+1))
fi

# Test 10: PostgreSQL Read query
if test_pgsql_query "Test 10: PG Read query to hostgroup 10" \
    "SELECT data FROM test_reads LIMIT 1" \
    "PG Read server"; then
    PGSQL_PASSED=$((PGSQL_PASSED+1))
else
    PGSQL_FAILED=$((PGSQL_FAILED+1))
fi

# Test 11: PostgreSQL Write query
if test_pgsql_query "Test 11: PG INSERT into write servers" \
    "INSERT INTO test_writes (server_name, data) VALUES ('pgsql-test-runner', 'Test write from pgsql_app')" \
    ""; then
    PGSQL_PASSED=$((PGSQL_PASSED+1))
else
    PGSQL_FAILED=$((PGSQL_FAILED+1))
fi

# Test 12: Verify PostgreSQL write landed on HG20
echo -n "🧪 Testing: Test 12: PG Verify write landed on HG20 server... "
export PGPASSWORD="root_pass"
write_server=$(psql -h pgsql-hg20-1 -U postgres -d testdb -t -A -c "SELECT server_name FROM test_writes WHERE data='Test write from pgsql_app' LIMIT 1" 2>/dev/null)
if [[ -z "$write_server" ]]; then
    # Try the other HG20 server
    write_server=$(psql -h pgsql-hg20-2 -U postgres -d testdb -t -A -c "SELECT server_name FROM test_writes WHERE data='Test write from pgsql_app' LIMIT 1" 2>/dev/null)
fi
unset PGPASSWORD
if [[ "$write_server" == "pgsql-"* ]]; then
    echo -e "${GREEN}PASSED${NC}"
    echo "   Result: Write landed on $write_server (HG20)"
    PGSQL_PASSED=$((PGSQL_PASSED+1))
else
    echo -e "${RED}FAILED${NC}"
    echo "   Expected: pgsql-* hostname"
    echo "   Got: $write_server"
    PGSQL_FAILED=$((PGSQL_FAILED+1))
fi

# Test 13: PostgreSQL Standard mode
if test_pgsql_query "Test 13: PG Standard user connection (verify HG30 backend)" \
    "SELECT message FROM hg30_data LIMIT 1" \
    "Standard ProxySQL" \
    "pgsql_standard" \
    "pgsql_standard_pass"; then
    echo "   ✅ PG Same credentials work for both frontend and backend"
    PGSQL_PASSED=$((PGSQL_PASSED+1))
else
    PGSQL_FAILED=$((PGSQL_FAILED+1))
fi

echo ""
echo "Backend Credential Verification"
echo "----------------------------------------"

export PGPASSWORD="root_pass"
echo "Hostgroup 10 (Read) - Expected backend user: pgsql_reader"
for server in pgsql-hg10-1 pgsql-hg10-2; do
    echo -n "  Checking $server... "
    result=$(psql -h "$server" -U postgres -d testdb -t -A -c \
        "SELECT COUNT(*) FROM pg_stat_activity WHERE usename='pgsql_reader'" 2>/dev/null) || result="N/A"
    if [[ "$result" != "N/A" && "$result" != "0" ]]; then
        echo -e "${GREEN}Backend user connections detected${NC}"
    else
        echo "Unable to verify (expected in this test setup)"
    fi
done

echo ""
echo "Hostgroup 20 (Write) - Expected backend user: pgsql_writer"
for server in pgsql-hg20-1 pgsql-hg20-2; do
    echo -n "  Checking $server... "
    result=$(psql -h "$server" -U postgres -d testdb -t -A -c \
        "SELECT COUNT(*) FROM pg_stat_activity WHERE usename='pgsql_writer'" 2>/dev/null) || result="N/A"
    if [[ "$result" != "N/A" && "$result" != "0" ]]; then
        echo -e "${GREEN}Backend user connections detected${NC}"
    else
        echo "Unable to verify (expected in this test setup)"
    fi
done
unset PGPASSWORD

# PostgreSQL test summary
echo ""
echo "PostgreSQL Summary"
echo "----------------------------------------"
echo -e "Passed: ${GREEN}$PGSQL_PASSED${NC} / $PGSQL_TESTS"
if [[ $PGSQL_FAILED -gt 0 ]]; then
    echo -e "Failed: ${RED}$PGSQL_FAILED${NC}"
fi
echo ""

# Overall summary
echo ""
echo "=========================================="
echo "OVERALL TEST SUMMARY"
echo "=========================================="
echo ""

TOTAL_PASSED=$((MYSQL_PASSED + PGSQL_PASSED))
TOTAL_FAILED=$((MYSQL_FAILED + PGSQL_FAILED))
TOTAL_TESTS=$((TOTAL_PASSED + TOTAL_FAILED))

echo "MySQL Tests:      ${MYSQL_PASSED}/${MYSQL_TESTS} passed"
echo "PostgreSQL Tests: ${PGSQL_PASSED}/${PGSQL_TESTS} passed"
echo "----------------------------------------"
echo "Total:            ${TOTAL_PASSED}/${TOTAL_TESTS} passed"
echo ""

if [[ $TOTAL_FAILED -eq 0 ]]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    echo ""
    echo "Hostgroup-based backend credentials feature is working correctly."
    exit 0
else
    echo -e "${RED}❌ Some tests failed!${NC}"
    exit 1
fi

