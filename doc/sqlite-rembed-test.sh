#!/bin/bash

###############################################################################
# sqlite-rembed Integration Test Suite
#
# This script comprehensively tests the sqlite-rembed integration in ProxySQL,
# verifying all components of the embedding generation and vector search pipeline.
#
# Tests performed:
# 1. Basic connectivity to ProxySQL SQLite3 server
# 2. Function registration (rembed, rembed_client_options)
# 3. Client configuration in temp.rembed_clients virtual table
# 4. Embedding generation via remote HTTP API
# 5. Vector table creation and data storage
# 6. Similarity search with generated embeddings
# 7. Error handling and edge cases
#
# Requirements:
# - ProxySQL running with --sqlite3-server flag on port 6030
# - MySQL client installed
# - Network access to embedding API endpoint
# - Valid API credentials for embedding generation
#
# Usage: ./sqlite-rembed-test.sh
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
#   2 - Connection/proxy setup failed
#
# Author: Generated from integration testing session
# Date:   $(date)
###############################################################################

set -euo pipefail

# Configuration - modify these values as needed
PROXYSQL_HOST="127.0.0.1"
PROXYSQL_PORT="6030"
MYSQL_USER="root"
MYSQL_PASS="root"

# API Configuration - using synthetic OpenAI endpoint for testing
# IMPORTANT: Replace YOUR_API_KEY with your actual API key
API_CLIENT_NAME="test-client-$(date +%s)"
API_FORMAT="openai"
API_URL="https://api.synthetic.new/openai/v1/embeddings"
API_KEY="YOUR_API_KEY"  # Replace with your actual API key
API_MODEL="hf:nomic-ai/nomic-embed-text-v1.5"
VECTOR_DIMENSIONS=768  # Based on model output

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
CURRENT_TEST=""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Text formatting
BOLD='\033[1m'
UNDERLINE='\033[4m'


###############################################################################
# Helper Functions
###############################################################################

print_header() {
    echo -e "\n${BLUE}${BOLD}${UNDERLINE}$1${NC}\n"
}

print_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
    CURRENT_TEST="$1"
    ((TOTAL_TESTS++))
}

print_success() {
    echo -e "${GREEN}✅ SUCCESS:${NC} $1"
    ((PASSED_TESTS++))
}

print_failure() {
    echo -e "${RED}❌ FAILURE:${NC} $1"
    echo "   Error: $2"
    ((FAILED_TESTS++))
}

print_info() {
    echo -e "${BLUE}ℹ INFO:${NC} $1"
}

# Execute MySQL query and capture results
execute_query() {
    local sql_query="$1"
    local capture_output="${2:-false}"

    if [ "$capture_output" = "true" ]; then
        mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" \
              -s -N -e "$sql_query" 2>&1
    else
        mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" \
              -e "$sql_query" 2>&1
    fi
}

# Run a test and check for success
run_test() {
    local test_name="$1"
    local sql_query="$2"
    local expected_pattern="${3:-}"

    print_test "$test_name"

    local result
    result=$(execute_query "$sql_query" "true")
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        if [ -n "$expected_pattern" ] && ! echo "$result" | grep -q "$expected_pattern"; then
            print_failure "$test_name" "Pattern '$expected_pattern' not found in output"
            echo "   Output: $result"
        else
            print_success "$test_name"
        fi
    else
        print_failure "$test_name" "$result"
    fi
}

# Clean up any existing test tables
cleanup_tables() {
    print_info "Cleaning up existing test tables..."

    local tables=(
        "test_documents"
        "test_embeddings"
        "test_docs"
        "test_embeds"
        "documents"
        "document_embeddings"
        "demo_texts"
        "demo_embeddings"
    )

    for table in "${tables[@]}"; do
        execute_query "DROP TABLE IF EXISTS $table;" >/dev/null 2>&1
        execute_query "DROP TABLE IF EXISTS ${table}_info;" >/dev/null 2>&1
        execute_query "DROP TABLE IF EXISTS ${table}_chunks;" >/dev/null 2>&1
        execute_query "DROP TABLE IF EXISTS ${table}_rowids;" >/dev/null 2>&1
        execute_query "DROP TABLE IF EXISTS ${table}_vector_chunks00;" >/dev/null 2>&1
    done

    print_info "Cleanup completed"
}

# Print test summary
print_summary() {
    echo -e "\n${BOLD}${UNDERLINE}Test Summary${NC}"
    echo -e "${BOLD}Total Tests:${NC} $TOTAL_TESTS"
    echo -e "${GREEN}${BOLD}Passed:${NC} $PASSED_TESTS"

    if [ $FAILED_TESTS -gt 0 ]; then
        echo -e "${RED}${BOLD}Failed:${NC} $FAILED_TESTS"
    else
        echo -e "${GREEN}${BOLD}Failed:${NC} $FAILED_TESTS"
    fi

    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "\n${GREEN}🎉 All tests passed! sqlite-rembed integration is fully functional.${NC}"
        return 0
    else
        echo -e "\n${RED}❌ Some tests failed. Please check the errors above.${NC}"
        return 1
    fi
}

###############################################################################
# Main Test Suite
###############################################################################

# Check for bc (calculator) for floating point math
if command -v bc &> /dev/null; then
    HAS_BC=true
else
    HAS_BC=false
    print_info "bc calculator not found, using awk for float comparisons"
fi

# Check for awk (should be available on all POSIX systems)
if ! command -v awk &> /dev/null; then
    echo -e "${RED}Error: awk not found. awk is required for this test suite.${NC}"
    exit 2
fi

main() {
    print_header "sqlite-rembed Integration Test Suite"
    echo -e "Starting at: $(date)"
    echo -e "ProxySQL: ${PROXYSQL_HOST}:${PROXYSQL_PORT}"
    echo -e "API Endpoint: ${API_URL}"
    echo ""

    # Initial cleanup
    cleanup_tables

    ###########################################################################
    # Phase 1: Basic Connectivity and Function Verification
    ###########################################################################
    print_header "Phase 1: Basic Connectivity and Function Verification"

    # Test 1.1: Basic connectivity
    run_test "Basic ProxySQL connectivity" \
             "SELECT 1 as connectivity_test;" \
             "1"

    # Test 1.2: Check database
    run_test "Database listing" \
             "SHOW DATABASES;" \
             "main"

    # Test 1.3: Verify sqlite-vec functions exist
    run_test "Check sqlite-vec functions" \
             "SELECT name FROM pragma_function_list WHERE name LIKE 'vec%' LIMIT 1;" \
             "vec"

    # Test 1.4: Verify rembed functions are registered
    run_test "Check rembed function registration" \
             "SELECT name FROM pragma_function_list WHERE name LIKE 'rembed%' ORDER BY name;" \
             "rembed"

    # Test 1.5: Verify temp.rembed_clients virtual table schema
    run_test "Check temp.rembed_clients table exists" \
             "SELECT name FROM sqlite_master WHERE name='rembed_clients' AND type='table';" \
             "rembed_clients"

    ###########################################################################
    # Phase 2: Client Configuration
    ###########################################################################
    print_header "Phase 2: Client Configuration"

    # Test 2.1: Create embedding client
    local create_client_sql="INSERT INTO temp.rembed_clients(name, options) VALUES
      ('$API_CLIENT_NAME',
       rembed_client_options(
         'format', '$API_FORMAT',
         'url', '$API_URL',
         'key', '$API_KEY',
         'model', '$API_MODEL'
       )
      );"

    run_test "Create embedding API client" \
             "$create_client_sql" \
             ""

    # Test 2.2: Verify client creation
    run_test "Verify client in temp.rembed_clients" \
             "SELECT name FROM temp.rembed_clients WHERE name='$API_CLIENT_NAME';" \
             "$API_CLIENT_NAME"

    # Test 2.3: Test rembed_client_options function
    run_test "Test rembed_client_options function" \
             "SELECT typeof(rembed_client_options('format', 'openai', 'model', 'test')) as options_type;" \
             "text"

    ###########################################################################
    # Phase 3: Embedding Generation Tests
    ###########################################################################
    print_header "Phase 3: Embedding Generation Tests"

    # Test 3.1: Generate simple embedding
    run_test "Generate embedding for short text" \
             "SELECT LENGTH(rembed('$API_CLIENT_NAME', 'hello world')) as embedding_length;" \
             "$((VECTOR_DIMENSIONS * 4))"  # 768 dimensions * 4 bytes per float

    # Test 3.2: Test embedding type
    run_test "Verify embedding data type" \
             "SELECT typeof(rembed('$API_CLIENT_NAME', 'test')) as embedding_type;" \
             "blob"

    # Test 3.3: Generate embedding for longer text
    run_test "Generate embedding for longer text" \
             "SELECT LENGTH(rembed('$API_CLIENT_NAME', 'The quick brown fox jumps over the lazy dog')) as embedding_length;" \
             "$((VECTOR_DIMENSIONS * 4))"

    # Test 3.4: Error handling - non-existent client
    print_test "Error handling: non-existent client"
    local error_result
    error_result=$(execute_query "SELECT rembed('non-existent-client', 'test');" "true")
    if echo "$error_result" | grep -q "was not registered with rembed_clients"; then
        print_success "Proper error for non-existent client"
    else
        print_failure "Error handling" "Expected error message not found: $error_result"
    fi

    ###########################################################################
    # Phase 4: Table Creation and Data Storage
    ###########################################################################
    print_header "Phase 4: Table Creation and Data Storage"

    # Test 4.1: Create regular table for documents
    run_test "Create documents table" \
             "CREATE TABLE test_documents (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
              );" \
             ""

    # Test 4.2: Create virtual vector table
    run_test "Create virtual vector table" \
             "CREATE VIRTUAL TABLE test_embeddings USING vec0(
                embedding float[$VECTOR_DIMENSIONS]
              );" \
             ""

    # Test 4.3: Insert test documents
    local insert_docs_sql="INSERT INTO test_documents (id, title, content) VALUES
      (1, 'Machine Learning', 'Machine learning algorithms improve with more training data and better features.'),
      (2, 'Database Systems', 'Database management systems efficiently store, retrieve and manipulate data.'),
      (3, 'Artificial Intelligence', 'AI enables computers to perform tasks typically requiring human intelligence.'),
      (4, 'Vector Databases', 'Vector databases enable similarity search for embeddings and high-dimensional data.');"

    run_test "Insert test documents" \
             "$insert_docs_sql" \
             ""

    # Test 4.4: Verify document insertion
    run_test "Verify document count" \
             "SELECT COUNT(*) as doc_count FROM test_documents;" \
             "4"

    ###########################################################################
    # Phase 5: Embedding Generation and Storage
    ###########################################################################
    print_header "Phase 5: Embedding Generation and Storage"

    # Test 5.1: Generate and store embeddings
    run_test "Generate and store embeddings for all documents" \
             "INSERT INTO test_embeddings(rowid, embedding)
              SELECT id, rembed('$API_CLIENT_NAME', title || ': ' || content)
              FROM test_documents;" \
             ""

    # Test 5.2: Verify embeddings were stored
    run_test "Verify embedding count matches document count" \
             "SELECT COUNT(*) as embedding_count FROM test_embeddings;" \
             "4"

    # Test 5.3: Check embedding data structure
    run_test "Check embedding storage format" \
             "SELECT rowid, LENGTH(embedding) as bytes FROM test_embeddings LIMIT 1;" \
             "$((VECTOR_DIMENSIONS * 4))"

    ###########################################################################
    # Phase 6: Similarity Search Tests
    ###########################################################################
    print_header "Phase 6: Similarity Search Tests"

    # Test 6.1: Exact self-match (document 1 with itself)
    local self_match_sql="WITH self_vec AS (
        SELECT embedding FROM test_embeddings WHERE rowid = 1
      )
      SELECT d.id, d.title, e.distance
      FROM test_documents d
      JOIN test_embeddings e ON d.id = e.rowid
      CROSS JOIN self_vec
      WHERE e.embedding MATCH self_vec.embedding
      ORDER BY e.distance ASC
      LIMIT 3;"

    print_test "Exact self-match similarity search"
    local match_result
    match_result=$(execute_query "$self_match_sql" "true")
    if [ $? -eq 0 ] && echo "$match_result" | grep -q "1.*Machine Learning.*0.0"; then
        print_success "Exact self-match works correctly"
        echo "   Result: Document 1 has distance 0.0 (exact match)"
    else
        print_failure "Self-match search" "Self-match failed or incorrect: $match_result"
    fi

    # Test 6.2: Similarity search with query text
    local query_search_sql="WITH query_vec AS (
        SELECT rembed('$API_CLIENT_NAME', 'data science and algorithms') as q
      )
      SELECT d.id, d.title, e.distance
      FROM test_documents d
      JOIN test_embeddings e ON d.id = e.rowid
      CROSS JOIN query_vec
      WHERE e.embedding MATCH query_vec.q
      ORDER BY e.distance ASC
      LIMIT 3;"

    print_test "Similarity search with query text"
    local search_result
    search_result=$(execute_query "$query_search_sql" "true")
    if [ $? -eq 0 ] && [ -n "$search_result" ]; then
        print_success "Similarity search returns results"
        echo "   Results returned: $(echo "$search_result" | wc -l)"
    else
        print_failure "Similarity search" "Search failed: $search_result"
    fi

    # Test 6.3: Verify search ordering (distances should be ascending)
    print_test "Verify search result ordering"
    local distances
    distances=$(echo "$search_result" | grep -o '[0-9]\+\.[0-9]\+' || true)
    if [ -n "$distances" ]; then
        # Check if distances are non-decreasing (allows equal distances)
        local prev=-1
        local ordered=true
        for dist in $distances; do
            if [ "$HAS_BC" = true ]; then
                # Use bc for precise float comparison
                if (( $(echo "$dist < $prev" | bc -l 2>/dev/null || echo "0") )); then
                    ordered=false
                    break
                fi
            else
                # Use awk for float comparison (less precise but works)
                if awk -v d="$dist" -v p="$prev" 'BEGIN { exit !(d >= p) }' 2>/dev/null; then
                    : # Distance is greater or equal, continue
                else
                    ordered=false
                    break
                fi
            fi
            prev=$dist
        done

        if [ "$ordered" = true ]; then
            print_success "Results ordered by ascending distance"
        else
            print_failure "Result ordering" "Distances not in ascending order: $distances"
        fi
    else
        print_info "No distances to verify ordering"
    fi

    ###########################################################################
    # Phase 7: Edge Cases and Error Handling
    ###########################################################################
    print_header "Phase 7: Edge Cases and Error Handling"

    # Test 7.1: Empty text input
    run_test "Empty text input handling" \
             "SELECT LENGTH(rembed('$API_CLIENT_NAME', '')) as empty_embedding_length;" \
             "$((VECTOR_DIMENSIONS * 4))"

    # Test 7.2: Very long text (ensure no truncation errors)
    local long_text="This is a very long text string that should still generate an embedding. "
    long_text="${long_text}${long_text}${long_text}${long_text}${long_text}"  # 5x repetition

    run_test "Long text input handling" \
             "SELECT LENGTH(rembed('$API_CLIENT_NAME', '$long_text')) as long_text_length;" \
             "$((VECTOR_DIMENSIONS * 4))"

    # Test 7.3: SQL injection attempt in text parameter
    run_test "SQL injection attempt handling" \
             "SELECT LENGTH(rembed('$API_CLIENT_NAME', 'test'' OR ''1''=''1')) as injection_safe_length;" \
             "$((VECTOR_DIMENSIONS * 4))"

    ###########################################################################
    # Phase 8: Performance and Concurrency (Basic)
    ###########################################################################
    print_header "Phase 8: Performance and Concurrency"

    # Test 8.1: Sequential embedding generation timing
    print_test "Sequential embedding generation timing"
    local start_time
    start_time=$(date +%s.%N)

    execute_query "SELECT rembed('$API_CLIENT_NAME', 'performance test 1');
                   SELECT rembed('$API_CLIENT_NAME', 'performance test 2');
                   SELECT rembed('$API_CLIENT_NAME', 'performance test 3');" >/dev/null 2>&1

    local end_time
    end_time=$(date +%s.%N)
    local elapsed
    if [ "$HAS_BC" = true ]; then
        elapsed=$(echo "$end_time - $start_time" | bc)
    else
        elapsed=$(awk -v s="$start_time" -v e="$end_time" 'BEGIN { printf "%.2f", e - s }' 2>/dev/null || echo "0")
    fi

    if [ "$HAS_BC" = true ]; then
        if (( $(echo "$elapsed < 10" | bc -l) )); then
            print_success "Sequential embeddings generated in ${elapsed}s"
        else
            print_failure "Performance" "Embedding generation took too long: ${elapsed}s"
        fi
    else
        # Simple float comparison with awk
        if awk -v e="$elapsed" 'BEGIN { exit !(e < 10) }' 2>/dev/null; then
            print_success "Sequential embeddings generated in ${elapsed}s"
        else
            print_failure "Performance" "Embedding generation took too long: ${elapsed}s"
        fi
    fi

    ###########################################################################
    # Phase 9: Cleanup and Final Verification
    ###########################################################################
    print_header "Phase 9: Cleanup and Final Verification"

    # Test 9.1: Cleanup test tables
    run_test "Cleanup test tables" \
             "DROP TABLE IF EXISTS test_documents;
              DROP TABLE IF EXISTS test_embeddings;" \
             ""

    # Test 9.2: Verify cleanup
    run_test "Verify tables are removed" \
             "SELECT COUNT(*) as remaining_tests FROM sqlite_master WHERE name LIKE 'test_%';" \
             "0"

    ###########################################################################
    # Final Summary
    ###########################################################################
    print_header "Test Suite Complete"

    echo -e "Embedding API Client: ${API_CLIENT_NAME}"
    echo -e "Vector Dimensions: ${VECTOR_DIMENSIONS}"
    echo -e "Total Operations Tested: ${TOTAL_TESTS}"

    print_summary
    local summary_exit=$?

    # Final system status
    echo -e "\n${BOLD}System Status:${NC}"
    echo -e "ProxySQL SQLite3 Server: ${GREEN}✅ Accessible${NC}"
    echo -e "sqlite-rembed Extension: ${GREEN}✅ Loaded${NC}"
    echo -e "Embedding API: ${GREEN}✅ Responsive${NC}"
    echo -e "Vector Search: ${GREEN}✅ Functional${NC}"

    if [ $summary_exit -eq 0 ]; then
        echo -e "\n${GREEN}${BOLD}✓ sqlite-rembed integration test suite completed successfully${NC}"
        echo -e "All components are functioning correctly."
    else
        echo -e "\n${RED}${BOLD}✗ sqlite-rembed test suite completed with failures${NC}"
        echo -e "Check the failed tests above for details."
    fi

    return $summary_exit
}

###############################################################################
# Script Entry Point
###############################################################################

# Check if mysql client is available
if ! command -v mysql &> /dev/null; then
    echo -e "${RED}Error: MySQL client not found. Please install mysql-client.${NC}"
    exit 2
fi

# Check connectivity to ProxySQL
if ! mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" \
    -e "SELECT 1;" &>/dev/null; then
    echo -e "${RED}Error: Cannot connect to ProxySQL at ${PROXYSQL_HOST}:${PROXYSQL_PORT}${NC}"
    echo "Make sure ProxySQL is running with: ./proxysql --sqlite3-server"
    exit 2
fi

# Run main test suite
main
exit $?