#!/bin/bash

###############################################################################
# sqlite-rembed Demonstration Script
#
# This script demonstrates the usage of sqlite-rembed integration in ProxySQL
# using a single MySQL session to maintain connection state.
#
# The script creates a SQL file with all demonstration queries and executes
# them in a single session, ensuring temp.rembed_clients virtual table
# maintains its state throughout the demonstration.
#
# Requirements:
# - ProxySQL running with --sqlite3-server flag on port 6030
# - MySQL client installed
# - Network access to embedding API endpoint
# - Valid API credentials for embedding generation
#
# Usage: ./sqlite-rembed-demo.sh
#
# Author: Generated from integration testing session
# Date:   $(date)
###############################################################################

set -uo pipefail

# Configuration - modify these values as needed
PROXYSQL_HOST="127.0.0.1"
PROXYSQL_PORT="6030"
MYSQL_USER="root"
MYSQL_PASS="root"

# API Configuration - using synthetic OpenAI endpoint for demonstration
# IMPORTANT: Replace YOUR_API_KEY with your actual API key
API_CLIENT_NAME="demo-client-$(date +%s)"
API_FORMAT="openai"
API_URL="https://api.synthetic.new/openai/v1/embeddings"
API_KEY="YOUR_API_KEY"  # Replace with your actual API key
API_MODEL="hf:nomic-ai/nomic-embed-text-v1.5"
VECTOR_DIMENSIONS=768  # Based on model output

# Color codes for output readability
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
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

print_step() {
    echo -e "${YELLOW}➤ Step:$NC $1"
}

print_query() {
    echo -e "${YELLOW}SQL Query:$NC"
    echo "$1"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓$NC $1"
}

print_error() {
    echo -e "${RED}✗$NC $1"
}

# Create SQL file with demonstration queries
create_demo_sql() {
    local sql_file="$1"

    cat > "$sql_file" << EOF
--------------------------------------------------------------------
-- sqlite-rembed Demonstration Script
-- Generated: $(date)
-- ProxySQL: ${PROXYSQL_HOST}:${PROXYSQL_PORT}
-- API Endpoint: ${API_URL}
--------------------------------------------------------------------

--------------------------------------------------------------------
-- Phase 1: Basic Connectivity and Function Verification
--------------------------------------------------------------------
-- This phase verifies basic connectivity and confirms that sqlite-rembed
-- and sqlite-vec functions are properly registered in ProxySQL.

SELECT 'Phase 1: Basic Connectivity' as phase;

-- Basic ProxySQL connectivity
SELECT 1 as connectivity_test;

-- Available databases
SHOW DATABASES;

-- Available sqlite-vec functions
SELECT name FROM pragma_function_list WHERE name LIKE 'vec%' LIMIT 5;

-- Available sqlite-rembed functions
SELECT name FROM pragma_function_list WHERE name LIKE 'rembed%' ORDER BY name;

-- Check temp.rembed_clients virtual table exists
SELECT name FROM sqlite_master WHERE name='rembed_clients' AND type='table';

--------------------------------------------------------------------
-- Phase 2: Client Configuration
--------------------------------------------------------------------
-- This phase demonstrates how to configure an embedding API client using
-- the temp.rembed_clients virtual table and rembed_client_options() function.

SELECT 'Phase 2: Client Configuration' as phase;

-- Create embedding API client
INSERT INTO temp.rembed_clients(name, options) VALUES
  ('$API_CLIENT_NAME',
   rembed_client_options(
     'format', '$API_FORMAT',
     'url', '$API_URL',
     'key', '$API_KEY',
     'model', '$API_MODEL'
   )
  );

-- Verify client registration
SELECT name FROM temp.rembed_clients;

-- View client configuration details
SELECT name,
       json_extract(options, '\$.format') as format,
       json_extract(options, '\$.model') as model
FROM temp.rembed_clients;

--------------------------------------------------------------------
-- Phase 3: Embedding Generation
--------------------------------------------------------------------
-- This phase demonstrates text embedding generation using the rembed() function.
-- Embeddings are generated via HTTP request to the configured API endpoint.

SELECT 'Phase 3: Embedding Generation' as phase;

-- Generate embedding for 'Hello world' and check size
SELECT length(rembed('$API_CLIENT_NAME', 'Hello world')) as embedding_size_bytes;

-- Generate embedding for longer technical text
SELECT length(rembed('$API_CLIENT_NAME', 'Machine learning algorithms improve with more training data and computational power.')) as embedding_size_bytes;

-- Generate embedding for empty text (edge case)
SELECT length(rembed('$API_CLIENT_NAME', '')) as empty_embedding_size;

--------------------------------------------------------------------
-- Phase 4: Table Creation and Data Storage
--------------------------------------------------------------------
-- This phase demonstrates creating regular tables for document storage
-- and virtual vector tables for embedding storage using sqlite-vec.

SELECT 'Phase 4: Table Creation and Data Storage' as phase;

-- Create regular table for document storage
CREATE TABLE IF NOT EXISTS demo_documents (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create virtual vector table for embeddings
CREATE VIRTUAL TABLE IF NOT EXISTS demo_embeddings USING vec0(
    embedding float[$VECTOR_DIMENSIONS]
);

-- Insert sample documents
INSERT OR IGNORE INTO demo_documents (id, title, content) VALUES
  (1, 'Machine Learning', 'Machine learning algorithms improve with more training data and computational power.'),
  (2, 'Database Systems', 'Database management systems efficiently store, retrieve, and manipulate structured data.'),
  (3, 'Artificial Intelligence', 'AI enables computers to perform tasks typically requiring human intelligence.'),
  (4, 'Vector Databases', 'Vector databases enable similarity search for embeddings generated by machine learning models.');

-- Verify document insertion
SELECT id, title, length(content) as content_length FROM demo_documents;

--------------------------------------------------------------------
-- Phase 5: Embedding Generation and Storage
--------------------------------------------------------------------
-- This phase demonstrates generating embeddings for all documents and
-- storing them in the vector table for similarity search.

SELECT 'Phase 5: Embedding Generation and Storage' as phase;

-- Generate and store embeddings for all documents
INSERT INTO demo_embeddings(rowid, embedding)
SELECT id, rembed('$API_CLIENT_NAME', content)
FROM demo_documents;

-- Verify embedding count
SELECT COUNT(*) as total_embeddings FROM demo_embeddings;

-- Check embedding storage format
SELECT rowid, length(embedding) as embedding_size_bytes
FROM demo_embeddings LIMIT 2;

--------------------------------------------------------------------
-- Phase 6: Similarity Search
--------------------------------------------------------------------
-- This phase demonstrates similarity search using the stored embeddings.
-- Queries show exact matches, similar documents, and distance metrics.

SELECT 'Phase 6: Similarity Search' as phase;

-- Exact self-match (should have distance 0.0)
SELECT d.title, d.content, e.distance
FROM demo_embeddings e
JOIN demo_documents d ON e.rowid = d.id
WHERE e.embedding MATCH rembed('$API_CLIENT_NAME',
       'Machine learning algorithms improve with more training data and computational power.')
LIMIT 3;

-- Similarity search with query text
SELECT d.title, d.content, e.distance
FROM demo_embeddings e
JOIN demo_documents d ON e.rowid = d.id
WHERE e.embedding MATCH rembed('$API_CLIENT_NAME',
       'data science and algorithms')
LIMIT 3;

-- Ordered similarity search (closest matches first)
SELECT d.title, e.distance
FROM demo_embeddings e
JOIN demo_documents d ON e.rowid = d.id
WHERE e.embedding MATCH rembed('$API_CLIENT_NAME',
       'artificial intelligence and neural networks')
ORDER BY e.distance ASC
LIMIT 3;

--------------------------------------------------------------------
-- Phase 7: Edge Cases and Error Handling
--------------------------------------------------------------------
-- This phase demonstrates error handling and edge cases.

SELECT 'Phase 7: Edge Cases and Error Handling' as phase;

-- Error: Non-existent client
SELECT rembed('non-existent-client', 'test text');

-- Very long text input
SELECT rembed('$API_CLIENT_NAME',
       '$(printf '%0.sA' {1..5000})');

--------------------------------------------------------------------
-- Phase 8: Cleanup and Summary
--------------------------------------------------------------------
-- Cleaning up demonstration tables and providing summary.

SELECT 'Phase 8: Cleanup' as phase;

-- Clean up demonstration tables
DROP TABLE IF EXISTS demo_documents;
DROP TABLE IF EXISTS demo_embeddings;

SELECT 'Demonstration Complete' as phase;
SELECT 'All sqlite-rembed integration examples have been executed successfully.' as summary;
SELECT 'The demonstration covered:' as coverage;
SELECT '  • Client configuration with temp.rembed_clients' as item;
SELECT '  • Embedding generation via HTTP API' as item;
SELECT '  • Vector table creation and data storage' as item;
SELECT '  • Similarity search with generated embeddings' as item;
SELECT '  • Error handling and edge cases' as item;

EOF
}

###############################################################################
# Main Demonstration Script
###############################################################################

main() {
    print_header "sqlite-rembed Demonstration Script"
    echo -e "Starting at: $(date)"
    echo -e "ProxySQL: ${PROXYSQL_HOST}:${PROXYSQL_PORT}"
    echo -e "API Endpoint: ${API_URL}"
    echo ""

    # Check if mysql client is available
    if ! command -v mysql &> /dev/null; then
        print_error "MySQL client not found. Please install mysql-client."
        exit 1
    fi

    # Check connectivity to ProxySQL
    if ! mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" \
        -e "SELECT 1;" &>/dev/null; then
        print_error "Cannot connect to ProxySQL at ${PROXYSQL_HOST}:${PROXYSQL_PORT}"
        echo "Make sure ProxySQL is running with: ./proxysql --sqlite3-server"
        exit 1
    fi

    # Create temporary SQL file
    local sql_file
    sql_file=$(mktemp /tmp/sqlite-rembed-demo.XXXXXX.sql)

    print_step "Creating demonstration SQL script..."
    create_demo_sql "$sql_file"
    print_success "SQL script created: $sql_file"

    print_step "Executing demonstration in single MySQL session..."
    echo ""
    echo -e "${BLUE}=== Demonstration Output ===${NC}"

    # Execute SQL file
    mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" \
          < "$sql_file" 2>&1 | \
          grep -v "Using a password on the command line interface"

    local exit_code=${PIPESTATUS[0]}

    echo ""
    echo -e "${BLUE}=== End Demonstration Output ===${NC}"

    # Clean up temporary file
    rm -f "$sql_file"

    if [ $exit_code -eq 0 ]; then
        print_success "Demonstration completed successfully!"
        echo ""
        echo "The demonstration covered:"
        echo "  • Client configuration with temp.rembed_clients"
        echo "  • Embedding generation via HTTP API"
        echo "  • Vector table creation and data storage"
        echo "  • Similarity search with generated embeddings"
        echo "  • Error handling and edge cases"
        echo ""
        echo "These examples can be used as a baseline for building applications"
        echo "that leverage sqlite-rembed and sqlite-vec in ProxySQL."
    else
        print_error "Demonstration encountered errors (exit code: $exit_code)"
        echo "Check the output above for details."
        exit 1
    fi
}

# Run main demonstration
main
exit 0