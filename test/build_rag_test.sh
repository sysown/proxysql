#!/bin/bash
#
# build_rag_test.sh - Simple build script for RAG test
#

set -e

# Check if we're in the right directory
if [ ! -f "test_rag_schema.cpp" ]; then
    echo "ERROR: test_rag_schema.cpp not found in current directory"
    exit 1
fi

# Try to find ProxySQL source directory
PROXYSQL_SRC=$(pwd)
if [ ! -f "${PROXYSQL_SRC}/include/proxysql.h" ]; then
    # Try to find it in parent directories
    PROXYSQL_SRC=$(while [ ! -f ./include/proxysql.h ]; do cd .. 2>/dev/null || exit 1; if [ "$(pwd)" = "/" ]; then exit 1; fi; done; pwd)
fi

if [ ! -f "${PROXYSQL_SRC}/include/proxysql.h" ]; then
    echo "ERROR: Could not find ProxySQL source directory"
    exit 1
fi

echo "Found ProxySQL source at: ${PROXYSQL_SRC}"

# Set up include paths
IDIRS="-I${PROXYSQL_SRC}/include \
       -I${PROXYSQL_SRC}/deps/jemalloc/jemalloc/include/jemalloc \
       -I${PROXYSQL_SRC}/deps/mariadb-client-library/mariadb_client/include \
       -I${PROXYSQL_SRC}/deps/libconfig/libconfig/lib \
       -I${PROXYSQL_SRC}/deps/re2/re2 \
       -I${PROXYSQL_SRC}/deps/sqlite3/sqlite3 \
       -I${PROXYSQL_SRC}/deps/pcre/pcre \
       -I${PROXYSQL_SRC}/deps/clickhouse-cpp/clickhouse-cpp \
       -I${PROXYSQL_SRC}/deps/clickhouse-cpp/clickhouse-cpp/contrib/absl \
       -I${PROXYSQL_SRC}/deps/libmicrohttpd/libmicrohttpd \
       -I${PROXYSQL_SRC}/deps/libmicrohttpd/libmicrohttpd/src/include \
       -I${PROXYSQL_SRC}/deps/libhttpserver/libhttpserver/src \
       -I${PROXYSQL_SRC}/deps/libinjection/libinjection/src \
       -I${PROXYSQL_SRC}/deps/curl/curl/include \
       -I${PROXYSQL_SRC}/deps/libev/libev \
       -I${PROXYSQL_SRC}/deps/json"

# Compile the test
echo "Compiling test_rag_schema..."
g++ -std=c++11 -ggdb ${IDIRS} test_rag_schema.cpp -o test_rag_schema -pthread -ldl

echo "SUCCESS: test_rag_schema compiled successfully"
echo "Run with: ./test_rag_schema"