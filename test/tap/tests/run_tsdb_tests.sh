#!/usr/bin/env bash
# Quick script to run TSDB tests
# Usage: ./run_tsdb_tests.sh [clean]

set -e

cd "$(dirname "$0")"

if [ "$1" == "clean" ]; then
    echo "Cleaning previous builds..."
    make clean 2>/dev/null || true
fi

echo "Building TSDB tests..."
make test_tsdb 2>/dev/null || make

echo ""
echo "Running TSDB shell tests..."
./test_tsdb.sh

echo ""
echo "Running TSDB unit tests..."
./test_tsdb || prove test_tsdb-t.cpp

echo ""
echo "TSDB tests complete!"
