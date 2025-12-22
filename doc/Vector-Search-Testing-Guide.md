# ProxySQL SQLite3 Server Vector Search Testing Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Testing Tools](#testing-tools)
4. [Step-by-Step Testing Procedures](#step-by-step-testing-procedures)
5. [Advanced Testing Scenarios](#advanced-testing-scenarios)
6. [Troubleshooting](#troubleshooting)
7. [Expected Results](#expected-results)
8. [Additional Resources](#additional-resources)

## Overview

This guide provides comprehensive step-by-step instructions for testing the vector search capabilities in ProxySQL's SQLite3 server. The testing covers connectivity verification, vector table creation, data insertion, similarity searches, and practical use cases.

**Target Audience**: ProxySQL developers, database administrators, and users who want to verify vector search functionality.

**Prerequisites**:
- ProxySQL built with sqlite-vec support and running with `--sqlite3-server`
- MySQL client tools installed
- Basic knowledge of SQL and vector concepts

---

## Prerequisites

### System Requirements
- ProxySQL version with sqlite-vec integration (v3.1-vec1 or later)
- MySQL client (mysql command line tool)
- Standard Linux/Unix environment

### ProxySQL Configuration
Ensure ProxySQL is running with SQLite3 server enabled:

```bash
# Check if ProxySQL is running
ps aux | grep proxysql

# Check if SQLite3 server is listening on port 6030
netstat -tlnp | grep 6030

# Check logs for any startup errors
tail -f /var/log/proxysql.log
```

---

## Environment Setup

### 1. Test Environment Preparation

```bash
# Create a dedicated testing directory
mkdir -p ~/proxysql-vector-test
cd ~/proxysql-vector-test

# Create a test script file
cat > test_vector_search.sh << 'EOF'
#!/bin/bash

# Test script for ProxySQL vector search functionality
# This script performs comprehensive testing of sqlite-vec integration

set -e

echo "=== ProxySQL Vector Search Testing Script ==="
echo "Starting at: $(date)"
echo ""

# Configuration
PROXYSQL_HOST="127.0.0.1"
PROXYSQL_PORT="6030"
MYSQL_USER="root"
MYSQL_PASS="root"

# Test results tracking
PASSED=0
FAILED=0

# Function to execute MySQL query and handle results
execute_test() {
    local test_name="$1"
    local sql_query="$2"
    local expected="$3"

    echo "Testing: $test_name"
    echo "Query: $sql_query"

    # Execute query and capture results
    result=$(mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" -s -N -e "$sql_query" 2>&1)
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo "✅ SUCCESS: $test_name"
        echo "Result: $result"
        ((PASSED++))
    else
        echo "❌ FAILED: $test_name"
        echo "Error: $result"
        ((FAILED++))
    fi

    echo "----------------------------------------"
    echo ""
}

# Main testing logic starts here
EOF

# Make script executable
chmod +x test_vector_search.sh
```

### 2. Python Testing Tools

Create a Python script for more complex vector operations:

```python
# Create vector_generator.py
cat > vector_generator.py << 'EOF'
#!/usr/bin/env python3
"""
Vector Generator for ProxySQL Vector Search Testing
Generates test vectors of various dimensions and formats
"""

import json
import random
import math
import sys

class VectorGenerator:
    """Generate test vectors for vector search testing"""

    def __init__(self, dimension=128):
        self.dimension = dimension

    def generate_unit_vector(self, position=None):
        """Generate a unit vector with 1.0 at specified position"""
        if position is None:
            position = random.randint(0, self.dimension - 1)

        vector = [0.0] * self.dimension
        vector[position] = 1.0
        return vector

    def generate_random_vector(self, sparsity=0.1):
        """Generate a random vector with specified sparsity"""
        vector = [0.0] * self.dimension
        num_non_zero = int(self.dimension * sparsity)

        for _ in range(num_non_zero):
            idx = random.randint(0, self_dimension - 1)
            value = random.uniform(0.1, 1.0)
            vector[idx] = value

        return vector

    def generate_similar_vector(self, original_vector, similarity=0.9):
        """Generate a vector similar to the original"""
        new_vector = original_vector.copy()

        # Add small random perturbations
        for i in range(self.dimension):
            if random.random() < 0.3:  # 30% of dimensions get modified
                perturbation = random.uniform(-0.1, 0.1)
                new_vector[i] = max(0.0, new_vector[i] + perturbation)

        # Normalize to maintain approximate magnitude
        magnitude = math.sqrt(sum(x*x for x in new_vector))
        if magnitude > 0:
            new_vector = [x/magnitude for x in new_vector]

        return new_vector

    def vector_to_json(self, vector):
        """Convert vector to JSON string format for SQL"""
        return json.dumps(vector)

    def generate_test_set(self, count=10):
        """Generate a diverse set of test vectors"""
        vectors = []

        # Add unit vectors
        for i in range(min(3, self.dimension)):
            vectors.append({
                'id': i + 1,
                'type': 'unit',
                'vector': self.generate_unit_vector(i),
                'description': f'Unit vector with 1.0 at position {i}'
            })

        # Add random vectors
        for i in range(count - 3):
            vectors.append({
                'id': i + 4,
                'type': 'random',
                'vector': self.generate_random_vector(),
                'description': f'Random vector #{i+1}'
            })

        return vectors

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 vector_generator.py <dimension> [count]")
        sys.exit(1)

    dimension = int(sys.argv[1])
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    generator = VectorGenerator(dimension)
    test_vectors = generator.generate_test_set(count)

    print(f"Generated {len(test_vectors)} test vectors of {dimension} dimensions:")
    print("-" * 60)

    for vec in test_vectors:
        print(f"ID: {vec['id']}")
        print(f"Type: {vec['type']}")
        print(f"Description: {vec['description']}")
        print(f"Vector: {generator.vector_to_json(vec['vector'])[:100]}...")
        print()

if __name__ == "__main__":
    main()
EOF

# Make Python script executable
chmod +x vector_generator.py
```

---

## Testing Tools

### 1. MySQL Command Line Client

The primary tool for testing is the standard MySQL client:

```bash
# Basic connection test
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "SELECT 1 as connectivity_test;"
```

### 2. Comprehensive Test Script

Create an enhanced test script with more comprehensive checks:

```bash
# Enhanced test script
cat > comprehensive_test.sh << 'EOF'
#!/bin/bash

# Comprehensive ProxySQL Vector Search Testing Script
# Tests all aspects of sqlite-vec integration

PROXYSQL_HOST="127.0.0.1"
PROXYSQL_PORT="6030"
MYSQL_USER="root"
MYSQL_PASS="root"

LOG_FILE="vector_test_$(date +%Y%m%d_%H%M%S).log"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Test result tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test case
run_test() {
    local test_name="$1"
    local sql="$2"
    local expected_pattern="$3"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log "TEST: $test_name"
    log "QUERY: $sql"

    # Execute the query
    result=$(mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" -s -N -e "$sql" 2>&1)
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        # Check if result matches expected pattern
        if echo "$result" | grep -q "$expected_pattern"; then
            log "✅ PASSED: $test_name"
            log "RESULT: $result"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            log "❌ FAILED: $test_name - Pattern not matched"
            log "EXPECTED: $expected_pattern"
            log "RESULT: $result"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    else
        log "❌ FAILED: $test_name - Query execution error"
        log "ERROR: $result"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi

    log "---"
}

# Start comprehensive testing
log "Starting comprehensive ProxySQL vector search testing..."
log "Log file: $LOG_FILE"

# Test 1: Basic connectivity
run_test "Basic Connectivity" "SELECT 1 as test;" "1"

# Test 2: Database listing
run_test "Database Listing" "SHOW DATABASES;" "main"

# Test 3: Current database
run_test "Current Database" "SELECT database();" "main"

# More tests will be added...
EOF

chmod +x comprehensive_test.sh
```

---

## Step-by-Step Testing Procedures

### Phase 1: Connectivity Testing

```bash
#!/bin/bash
# Phase 1: Test connectivity to ProxySQL SQLite3 server

echo "=== Phase 1: Connectivity Testing ==="

# Test 1.1: Basic connection
echo "Test 1.1: Basic connection test"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "SELECT 'Connected successfully' as status;" || {
    echo "❌ Connection failed. Please ensure ProxySQL is running with --sqlite3-server"
    exit 1
}

# Test 1.2: Verify database access
echo "Test 1.2: Database access verification"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "SHOW DATABASES;"

# Test 1.3: Current database verification
echo "Test 1.3: Current database check"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "SELECT database() as current_db;"

echo "✅ Phase 1 completed: Connectivity established"
```

### Phase 2: Vector Table Creation

```bash
#!/bin/bash
# Phase 2: Test vector table creation

echo "=== Phase 2: Vector Table Creation ==="

# Test 2.1: Create embeddings table
echo "Test 2.1: Creating embeddings vector table"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
CREATE VIRTUAL TABLE IF NOT EXISTS embeddings USING vec0(
    vector float[128]
);
" || {
    echo "❌ Failed to create embeddings table"
    exit 1
}

# Test 2.2: Verify table creation
echo "Test 2.2: Verifying vector table creation"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
SELECT name
FROM sqlite_master
WHERE type='table' AND name LIKE '%embedding%'
ORDER BY name;
"

# Test 2.3: Create additional test tables
echo "Test 2.3: Creating additional vector tables"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
CREATE VIRTUAL TABLE IF NOT EXISTS documents USING vec0(
    embedding float[128]
);

CREATE VIRTUAL TABLE IF NOT EXISTS test_vectors USING vec0(
    features float[256]
);
"

echo "✅ Phase 2 completed: Vector tables created successfully"
```

### Phase 3: Data Insertion

```bash
#!/bin/bash
# Phase 3: Test vector data insertion

echo "=== Phase 3: Data Insertion ==="

# Test 3.1: Insert simple unit vectors
echo "Test 3.1: Inserting unit vectors"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
INSERT INTO embeddings(rowid, vector) VALUES
  (1, '[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]'),
  (2, '[0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]'),
  (3, '[0.9, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]');
"

# Test 3.2: Verify inserted data
echo "Test 3.2: Verifying inserted vectors"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "SELECT rowid, 'vector inserted' as status FROM embeddings;"

# Test 3.3: Insert document embeddings
echo "Test 3.3: Inserting document embeddings"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
INSERT INTO documents(rowid, embedding) VALUES
  (1, '[0.2, 0.8, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]'),
  (2, '[0.1, 0.1, 0.7, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]'),
  (3, '[0.6, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]');
"

echo "✅ Phase 3 completed: Data insertion successful"
```

### Phase 4: Vector Similarity Search

```bash
#!/bin/bash
# Phase 4: Test vector similarity search

echo "=== Phase 4: Vector Similarity Search ==="

# Test 4.1: Exact match search
echo "Test 4.1: Exact match search"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
SELECT '=== Exact Match Test ===' as header;
SELECT rowid, distance
FROM embeddings
WHERE vector MATCH json('[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]')
ORDER BY distance ASC;
"

# Test 4.2: Similar vector search
echo "Test 4.2: Similar vector search"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
SELECT '=== Similar Vector Test ===' as header;
SELECT rowid, distance
FROM embeddings
WHERE vector MATCH json('[0.9, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]')
ORDER BY distance ASC;
"

# Test 4.3: Document similarity search
echo "Test 4.3: Document similarity search"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
SELECT '=== Document Similarity Test ===' as header;
SELECT rowid, distance
FROM documents
WHERE embedding MATCH json('[0.5, 0.5, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]')
ORDER BY distance ASC LIMIT 3;
"

echo "✅ Phase 4 completed: Vector similarity search working"
```

### Phase 5: Practical Use Cases

```bash
#!/bin/bash
# Phase 5: Test practical use cases

echo "=== Phase 5: Practical Use Cases ==="

# Test 5.1: Create a product recommendation system
echo "Test 5.1: Creating product recommendation system"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
-- Create product embeddings table
CREATE VIRTUAL TABLE IF NOT EXISTS products USING vec0(
    product_embedding float[128]
);

-- Insert product embeddings (simplified)
INSERT INTO products(rowid, product_embedding) VALUES
  (1, '[0.8, 0.1, 0.05, 0.05, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]'),  -- Electronics
  (2, '[0.1, 0.8, 0.05, 0.05, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]');  -- Clothing
"

# Test 5.2: Find similar products
echo "Test 5.2: Finding similar products"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
SELECT '=== Product Recommendations ===' as header;
SELECT rowid as product_id, distance
FROM products
WHERE product_embedding MATCH json('[0.75, 0.15, 0.05, 0.05, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]')
ORDER BY distance ASC LIMIT 3;
"

# Test 5.3: Create user session tracking
echo "Test 5.3: Creating user session tracking"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
-- Create user sessions table
CREATE VIRTUAL TABLE IF NOT EXISTS user_sessions USING vec0(
    session_vector float[128]
);

-- Insert user session vectors
INSERT INTO user_sessions(rowid, session_vector) VALUES
  (1, '[0.6, 0.3, 0.05, 0.05, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]'),
  (2, '[0.1, 0.7, 0.1, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]');
"

# Test 5.4: Find similar user sessions
echo "Test 5.4: Finding similar user sessions"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
SELECT '=== User Session Analysis ===' as header;
SELECT rowid as session_id, distance
FROM user_sessions
WHERE session_vector MATCH json('[0.55, 0.35, 0.05, 0.05, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]')
ORDER BY distance ASC LIMIT 3;
"

echo "✅ Phase 5 completed: Practical use cases demonstrated"
```

---

## Advanced Testing Scenarios

### Performance Testing

```bash
#!/bin/bash
# Performance testing for vector operations

echo "=== Performance Testing ==="

# Test 1: Bulk insertion performance
echo "Test 1: Bulk insertion performance"
time mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
BEGIN;
$(for i in {4..100}; do
  echo "INSERT INTO embeddings(rowid, vector) VALUES
    ($i, '[$(for j in {1..127}; do echo -n "0.0"; [ $j -lt 127 ] && echo -n ", "; done)]');"
done)
COMMIT;
"

# Test 2: Search performance
echo "Test 2: Search performance"
time mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
SELECT rowid, distance
FROM embeddings
WHERE vector MATCH json('[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]')
ORDER BY distance ASC LIMIT 10;
"

echo "✅ Performance testing completed"
```

### Error Handling Tests

```bash
#!/bin/bash
# Test error handling scenarios

echo "=== Error Handling Tests ==="

# Test 1: Invalid dimension
echo "Test 1: Invalid dimension test"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
INSERT INTO embeddings(rowid, vector) VALUES
  (999, '[1.0, 0.0]');" 2>&1 || echo "✅ Expected error caught"

# Test 2: Invalid JSON
echo "Test 2: Invalid JSON test"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
INSERT INTO embeddings(rowid, vector) VALUES
  (1000, 'invalid json');" 2>&1 || echo "✅ Expected error caught"

# Test 3: Non-existent table
echo "Test 3: Non-existent table test"
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "
SELECT * FROM non_existent_table;" 2>&1 || echo "✅ Expected error caught"

echo "✅ Error handling tests completed"
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Connection Issues

**Problem**: `ERROR 2003 (HY000): Can't connect to MySQL server on '127.0.0.1:6030'`

```bash
# Solution: Check if ProxySQL is running with --sqlite3-server
ps aux | grep proxysql
# Check if port 6030 is listening
netstat -tlnp | grep 6030
# Check logs
tail -f /var/log/proxysql.log
```

#### 2. Permission Issues

**Problem**: `ERROR 1045 (28000): Access denied for user 'root'@'localhost'`

```bash
# Solution: Check user credentials in ProxySQL
mysql -h 127.0.0.1 -P 6032 -u admin -padmin -e "
SELECT username, password, active FROM mysql_users
WHERE username = 'root';
"
```

#### 3. Vector Dimension Errors

**Problem**: `ERROR 1045 (28000): Dimension mismatch for inserted vector`

**Solution**: Ensure all vectors match the table dimension (e.g., 128 dimensions).

#### 4. Extension Not Available

**Problem**: Vector commands not working

```bash
# Solution: Verify sqlite-vec is compiled and linked
nm src/proxysql | grep sqlite3_vec_init
# Should show: T sqlite3_vec_init
```

### Debug Commands

```bash
# Debug connection issues
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "SELECT version() as sqlite_version;"

# Check available tables
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "SELECT name FROM sqlite_master WHERE type='table';"

# Check vector table structure
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "SELECT name FROM sqlite_master WHERE name LIKE '%vector%';"

# Test basic SQLite functionality
mysql -h 127.0.0.1 -P 6030 -u root -proot -e "SELECT 1+1 as math_test;"
```

---

## Expected Results

### Phase 1: Connectivity
- ✅ Successful connection to port 6030
- ✅ `SHOW DATABASES` returns `main`
- ✅ `SELECT database()` returns `main`

### Phase 2: Vector Table Creation
- ✅ `CREATE VIRTUAL TABLE USING vec0` succeeds
- ✅ Tables appear in `sqlite_master`
- ✅ Internal vec0 tables created (e.g., `*_vector_chunks00`)

### Phase 3: Data Insertion
- ✅ Vector insertion without dimension errors
- ✅ All vectors properly stored with correct dimensions
- ✅ Row count matches inserted records

### Phase 4: Vector Similarity Search
- ✅ Exact match returns distance 0.0
- ✅ Similar vectors return small distances (0.0 < distance < 0.5)
- ✅ Different vectors return larger distances (> 1.0)
- ✅ Results properly ordered by distance

### Phase 5: Practical Use Cases
- ✅ Product recommendation system works
- ✅ User session analysis functions
- ✅ Document similarity search operational

### Advanced Testing
- ✅ Performance tests show reasonable execution times
- ✅ Error handling works as expected
- ✅ Bulk operations perform correctly

---

## Additional Resources

### Documentation
- [ProxySQL Official Documentation](https://proxysql.com/documentation/)
- [sqlite-vec GitHub Repository](https://github.com/asg017/sqlite-vec)
- [SQLite Virtual Table Documentation](https://www.sqlite.org/vtab.html)

### Tools and Utilities
- MySQL Client: Standard command-line tool
- Python Vector Generator: `vector_generator.py` (included)
- Test Scripts: `test_vector_search.sh`, `comprehensive_test.sh`

### Community Support
- ProxySQL Mailing List
- GitHub Issues for ProxySQL
- SQLite mailing list for extension-specific questions

### Example Applications
- Product recommendation engines
- Document similarity systems
- User behavior analysis
- Anomaly detection
- Content-based filtering

---

## Conclusion

This comprehensive testing guide provides everything needed to verify and reproduce vector search functionality in ProxySQL's SQLite3 server. The step-by-step approach ensures thorough testing of all components, from basic connectivity to advanced use cases.

**Remember**: The key to successful vector search testing is ensuring:
1. ProxySQL is built with sqlite-vec support
2. Running with `--sqlite3-server` option
3. Using correct MySQL credentials
4. Following proper vector dimension requirements
5. Testing both functionality and performance

Happy testing! 🚀