# Vector Search Testing Guide

This directory contains test scripts for verifying ProxySQL's vector search capabilities using the sqlite-vec extension.

## Overview

The testing framework is organized into four main test scripts, each covering a specific aspect of vector search functionality:

1. **Connectivity Testing** - Verify basic connectivity to ProxySQL SQLite3 server
2. **Vector Table Creation** - Test creation and verification of vector tables
3. **Data Insertion** - Test insertion of vector data into tables
4. **Similarity Search** - Test vector similarity search functionality

## Prerequisites

Before running the tests, ensure you have:

1. **ProxySQL running** with SQLite3 backend enabled
2. **mysql client** installed and accessible
3. **Test database** configured with appropriate credentials
4. **sqlite-vec extension** loaded in ProxySQL

## Test Configuration

All scripts use the following configuration (modify in each script as needed):

```bash
PROXYSQL_HOST="127.0.0.1"
PROXYSQL_PORT="6030"
MYSQL_USER="root"
MYSQL_PASS="root"
```

## Running the Tests

Each test script is self-contained and executable. Run them in sequence:

### 1. Connectivity Test
```bash
./test_connectivity.sh
```
Tests basic connectivity to ProxySQL and database operations.

### 2. Vector Table Creation Test
```bash
./test_vector_tables.sh
```
Tests creation of virtual tables using sqlite-vec extension.

### 3. Data Insertion Test
```bash
./test_data_insertion.sh
```
Tests insertion of 128-dimensional vectors into vector tables.

### 4. Similarity Search Test
```bash
./test_similarity_search.sh
```
Tests vector similarity search with various query patterns.

## Test Descriptions

### test_connectivity.sh
- **Purpose**: Verify basic connectivity to ProxySQL SQLite3 server
- **Tests**: Basic SELECT, database listing, current database
- **Expected Result**: All connectivity tests pass

### test_vector_tables.sh
- **Purpose**: Test creation and verification of vector tables
- **Tests**: CREATE VIRTUAL TABLE statements, table verification
- **Vector Dimensions**: 128 and 256 dimensions
- **Expected Result**: All vector tables created successfully

### test_data_insertion.sh
- **Purpose**: Test insertion of vector data
- **Tests**: Insert unit vectors, document embeddings, verify counts
- **Vector Dimensions**: 128 dimensions
- **Expected Result**: All data inserted correctly

### test_similarity_search.sh
- **Purpose**: Test vector similarity search functionality
- **Tests**: Exact match, similar vector, document similarity, result ordering
- **Query Pattern**: `WHERE vector MATCH json(...)`
- **Expected Result**: Correct distance calculations and result ordering

## Test Results

Each script provides:
- Real-time feedback during execution
- Success/failure status for each test
- Detailed error messages when tests fail
- Summary of passed/failed tests

Exit codes:
- `0`: All tests passed
- `1`: One or more tests failed

## Troubleshooting

### Common Issues

1. **Connection Errors**
   - Verify ProxySQL is running
   - Check host/port configuration
   - Verify credentials

2. **Table Creation Errors**
   - Ensure sqlite-vec extension is loaded
   - Check database permissions
   - Verify table doesn't already exist

3. **Insertion Errors**
   - Check vector format (JSON array)
   - Verify dimension consistency
   - Check data types

4. **Search Errors**
   - Verify JSON format in MATCH queries
   - Check vector dimensions match table schema
   - Ensure proper table and column names

### Debug Mode

For detailed debugging, modify the scripts to:
1. Add `set -x` at the beginning for verbose output
2. Remove `-s -N` flags from mysql commands for full result sets
3. Add intermediate validation queries

## Integration with CI/CD

These scripts can be integrated into CI/CD pipelines:

```bash
#!/bin/bash
# Example CI script
set -e

echo "Running vector search tests..."

./test_connectivity.sh
./test_vector_tables.sh
./test_data_insertion.sh
./test_similarity_search.sh

echo "All tests completed successfully!"
```

## Customization

### Adding New Tests

1. Create new test script following existing pattern
2. Use `execute_test()` function for consistent testing
3. Include proper error handling and result validation
4. Update README with new test description

### Modifying Test Data

Edit the vector arrays in:
- `test_data_insertion.sh` for insertion tests
- `test_similarity_search.sh` for search queries

### Configuration Changes

Update variables at the top of each script:
- Connection parameters
- Test data vectors
- Expected patterns

## Support

For issues related to:
- **ProxySQL configuration**: Check ProxySQL documentation
- **sqlite-vec extension**: Refer to sqlite-vec documentation
- **Test framework**: Review script source code and error messages

---

*This testing framework is designed to be comprehensive yet modular. Feel free to extend and modify based on your specific testing requirements.*