#!/bin/bash
#
# Run auth plugin TAP tests locally
#
# Usage:
#   ./run_auth_plugin_test.sh              # Run from inside dev container
#   docker compose exec dev ./test/tap/tests/run_auth_plugin_test.sh  # Run from host
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXYSQL_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration (can be overridden via environment)
: "${TAP_MYSQLHOST:=mariadb}"
: "${TAP_MYSQLPORT:=3306}"
: "${TAP_MYSQLPASSWORD:=root}"
: "${TAP_MYSQLUSERNAME:=root}"
: "${TAP_HOST:=127.0.0.1}"
: "${TAP_PORT:=6033}"
: "${TAP_ADMINHOST:=127.0.0.1}"
: "${TAP_ADMINPORT:=6032}"
: "${TAP_ADMINUSERNAME:=admin}"
: "${TAP_ADMINPASSWORD:=admin}"

export TAP_MYSQLHOST TAP_MYSQLPORT TAP_MYSQLPASSWORD TAP_MYSQLUSERNAME
export TAP_HOST TAP_PORT TAP_ADMINHOST TAP_ADMINPORT TAP_ADMINUSERNAME TAP_ADMINPASSWORD

cleanup() {
    log_info "Cleaning up..."
    # Graceful shutdown via admin interface
    if mysql -h"$TAP_ADMINHOST" -P"$TAP_ADMINPORT" -u"$TAP_ADMINUSERNAME" -p"$TAP_ADMINPASSWORD" \
        -N -e "PROXYSQL SHUTDOWN" 2>/dev/null; then
        sleep 2
    fi
    # Force kill if still running
    pkill -9 proxysql 2>/dev/null || true
}

trap cleanup EXIT

# Step 1: Build ProxySQL if needed
if [[ ! -f "$PROXYSQL_ROOT/src/proxysql" ]]; then
    log_info "Building ProxySQL..."
    make -C "$PROXYSQL_ROOT" -j"$(nproc)"
else
    log_info "ProxySQL binary found, skipping build"
fi

# Step 2: Build auth plugin
log_info "Building static auth plugin..."
make -C "$PROXYSQL_ROOT/plugins/MySQL_AuthPlugin/static" clean all

# Step 3: Compile test
log_info "Compiling auth plugin test..."
cd "$SCRIPT_DIR"

# Compile TAP helper if needed
if [[ ! -f tap.o ]]; then
    g++ -c ../tap/tap.cpp -I"$PROXYSQL_ROOT/include" -o tap.o
fi

g++ -o test_mysql_authplugin-t test_mysql_authplugin-t.cpp tap.o \
    -I../tap \
    -I"$PROXYSQL_ROOT/deps/mariadb-client-library/mariadb_client/include" \
    -L"$PROXYSQL_ROOT/deps/mariadb-client-library/mariadb_client/libmariadb" \
    -std=c++17 -O2 \
    -lmariadb -lpthread -lm -lz -lssl -lcrypto

# Step 4: Start ProxySQL
log_info "Starting ProxySQL with auth plugin..."
pkill -9 proxysql 2>/dev/null || true
rm -rf /tmp/proxysql
mkdir -p /tmp/proxysql

cd "$PROXYSQL_ROOT"
./src/proxysql -f -c test_auth_plugin.cfg > /tmp/proxysql/proxysql.log 2>&1 &
PROXYSQL_PID=$!

# Wait for ProxySQL to start
sleep 3

if ! ps -p $PROXYSQL_PID > /dev/null 2>&1; then
    log_error "ProxySQL failed to start. Log:"
    cat /tmp/proxysql/proxysql.log
    exit 1
fi

log_info "ProxySQL started (PID: $PROXYSQL_PID)"

# Check if auth plugin loaded
if ! mysql -h"$TAP_ADMINHOST" -P"$TAP_ADMINPORT" -u"$TAP_ADMINUSERNAME" -p"$TAP_ADMINPASSWORD" \
    -N -e "SELECT 1" 2>/dev/null | grep -q 1; then
    log_error "Cannot connect to ProxySQL admin interface"
    exit 1
fi

# Step 5: Run test
log_info "Running auth plugin test..."
echo ""
cd "$SCRIPT_DIR"
./test_mysql_authplugin-t
TEST_RC=$?

echo ""
if [[ $TEST_RC -eq 0 ]]; then
    log_info "All tests passed!"
else
    log_error "Some tests failed (exit code: $TEST_RC)"
fi

exit $TEST_RC
