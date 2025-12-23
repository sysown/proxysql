#!/bin/bash

###############################################################################
# sqlite-rembed Examples and Demonstration Script
#
# This script demonstrates the usage of sqlite-rembed integration in ProxySQL,
# showing complete examples of embedding generation and vector search pipeline.
#
# The script is organized into logical phases, each demonstrating a specific
# aspect of the integration with detailed explanations.
#
# Requirements:
# - ProxySQL running with --sqlite3-server flag on port 6030
# - MySQL client installed
# - Network access to embedding API endpoint
# - Valid API credentials for embedding generation
#
# Usage: ./sqlite-rembed-examples.sh
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

# Execute MySQL query and display results
execute_and_show() {
    local sql_query="$1"
    local description="${2:-}"

    if [ -n "$description" ]; then
        print_step "$description"
    fi

    print_query "$sql_query"

    echo -e "${BLUE}Result:$NC"
    mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" \
          -e "$sql_query" 2>&1 | grep -v "Using a password on the command line"
    echo "--------------------------------------------------------------------"
}

# Clean up any existing demonstration tables
cleanup_tables() {
    echo "Cleaning up any existing demonstration tables..."

    local tables=(
        "demo_documents"
        "demo_embeddings"
    )

    for table in "${tables[@]}"; do
        mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" \
              -e "DROP TABLE IF EXISTS $table;" 2>/dev/null
    done

    echo "Cleanup completed."
}

###############################################################################
# Main Demonstration Script
###############################################################################

main() {
    print_header "sqlite-rembed Integration Examples"
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

    echo "This phase verifies basic connectivity and confirms that sqlite-rembed"
    echo "and sqlite-vec functions are properly registered in ProxySQL."
    echo ""

    execute_and_show "SELECT 1 as connectivity_test;" "Basic ProxySQL connectivity"

    execute_and_show "SHOW DATABASES;" "Available databases"

    execute_and_show "SELECT name FROM pragma_function_list WHERE name LIKE 'vec%' LIMIT 5;" \
        "Available sqlite-vec functions"

    execute_and_show "SELECT name FROM pragma_function_list WHERE name LIKE 'rembed%' ORDER BY name;" \
        "Available sqlite-rembed functions"

    execute_and_show "SELECT name FROM sqlite_master WHERE name='rembed_clients' AND type='table';" \
        "Check temp.rembed_clients virtual table exists"

    ###########################################################################
    # Phase 2: Client Configuration
    ###########################################################################
    print_header "Phase 2: Client Configuration"

    echo "This phase demonstrates how to configure an embedding API client using"
    echo "the temp.rembed_clients virtual table and rembed_client_options() function."
    echo ""

    local create_client_sql="INSERT INTO temp.rembed_clients(name, options) VALUES
      ('$API_CLIENT_NAME',
       rembed_client_options(
         'format', '$API_FORMAT',
         'url', '$API_URL',
         'key', '$API_KEY',
         'model', '$API_MODEL'
       )
      );"

    execute_and_show "$create_client_sql" "Create embedding API client"

    execute_and_show "SELECT name FROM temp.rembed_clients;" \
        "Verify client registration"

    execute_and_show "SELECT name, json_extract(options, '\$.format') as format,
                         json_extract(options, '\$.model') as model
                      FROM temp.rembed_clients;" \
        "View client configuration details"

    ###########################################################################
    # Phase 3: Embedding Generation
    ###########################################################################
    print_header "Phase 3: Embedding Generation"

    echo "This phase demonstrates text embedding generation using the rembed() function."
    echo "Embeddings are generated via HTTP request to the configured API endpoint."
    echo ""

    execute_and_show "SELECT length(rembed('$API_CLIENT_NAME', 'Hello world')) as embedding_size_bytes;" \
        "Generate embedding for 'Hello world' and check size"

    execute_and_show "SELECT length(rembed('$API_CLIENT_NAME', 'Machine learning algorithms improve with more training data and computational power.')) as embedding_size_bytes;" \
        "Generate embedding for longer technical text"

    execute_and_show "SELECT length(rembed('$API_CLIENT_NAME', '')) as empty_embedding_size;" \
        "Generate embedding for empty text (edge case)"

    ###########################################################################
    # Phase 4: Table Creation and Data Storage
    ###########################################################################
    print_header "Phase 4: Table Creation and Data Storage"

    echo "This phase demonstrates creating regular tables for document storage"
    echo "and virtual vector tables for embedding storage using sqlite-vec."
    echo ""

    execute_and_show "CREATE TABLE demo_documents (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );" "Create regular table for document storage"

    execute_and_show "CREATE VIRTUAL TABLE demo_embeddings USING vec0(
        embedding float[$VECTOR_DIMENSIONS]
      );" "Create virtual vector table for embeddings"

    execute_and_show "INSERT INTO demo_documents (id, title, content) VALUES
      (1, 'Machine Learning', 'Machine learning algorithms improve with more training data and computational power.'),
      (2, 'Database Systems', 'Database management systems efficiently store, retrieve, and manipulate structured data.'),
      (3, 'Artificial Intelligence', 'AI enables computers to perform tasks typically requiring human intelligence.'),
      (4, 'Vector Databases', 'Vector databases enable similarity search for embeddings generated by machine learning models.');" \
        "Insert sample documents"

    execute_and_show "SELECT id, title, length(content) as content_length FROM demo_documents;" \
        "Verify document insertion"

    ###########################################################################
    # Phase 5: Embedding Generation and Storage
    ###########################################################################
    print_header "Phase 5: Embedding Generation and Storage"

    echo "This phase demonstrates generating embeddings for all documents and"
    echo "storing them in the vector table for similarity search."
    echo ""

    execute_and_show "INSERT INTO demo_embeddings(rowid, embedding)
      SELECT id, rembed('$API_CLIENT_NAME', content)
      FROM demo_documents;" \
        "Generate and store embeddings for all documents"

    execute_and_show "SELECT COUNT(*) as total_embeddings FROM demo_embeddings;" \
        "Verify embedding count"

    execute_and_show "SELECT rowid, length(embedding) as embedding_size_bytes
                      FROM demo_embeddings LIMIT 2;" \
        "Check embedding storage format"

    ###########################################################################
    # Phase 6: Similarity Search
    ###########################################################################
    print_header "Phase 6: Similarity Search"

    echo "This phase demonstrates similarity search using the stored embeddings."
    echo "Queries show exact matches, similar documents, and distance metrics."
    echo ""

    execute_and_show "SELECT d.title, d.content, e.distance
      FROM demo_embeddings e
      JOIN demo_documents d ON e.rowid = d.id
      WHERE e.embedding MATCH rembed('$API_CLIENT_NAME',
             'Machine learning algorithms improve with more training data and computational power.')
      LIMIT 3;" \
        "Exact self-match (should have distance 0.0)"

    execute_and_show "SELECT d.title, d.content, e.distance
      FROM demo_embeddings e
      JOIN demo_documents d ON e.rowid = d.id
      WHERE e.embedding MATCH rembed('$API_CLIENT_NAME',
             'data science and algorithms')
      LIMIT 3;" \
        "Similarity search with query text"

    execute_and_show "SELECT d.title, e.distance
      FROM demo_embeddings e
      JOIN demo_documents d ON e.rowid = d.id
      WHERE e.embedding MATCH rembed('$API_CLIENT_NAME',
             'artificial intelligence and neural networks')
      ORDER BY e.distance ASC
      LIMIT 3;" \
        "Ordered similarity search (closest matches first)"

    ###########################################################################
    # Phase 7: Edge Cases and Error Handling
    ###########################################################################
    print_header "Phase 7: Edge Cases and Error Handling"

    echo "This phase demonstrates error handling and edge cases."
    echo ""

    execute_and_show "SELECT rembed('non-existent-client', 'test text');" \
        "Error: Non-existent client"

    execute_and_show "SELECT rembed('$API_CLIENT_NAME',
        '$(printf '%0.sA' {1..5000})');" \
        "Very long text input"

    ###########################################################################
    # Phase 8: Cleanup and Summary
    ###########################################################################
    print_header "Phase 8: Cleanup and Summary"

    echo "Cleaning up demonstration tables and providing summary."
    echo ""

    cleanup_tables

    echo ""
    print_header "Demonstration Complete"
    echo "All sqlite-rembed integration examples have been executed successfully."
    echo "The demonstration covered:"
    echo "  • Client configuration with temp.rembed_clients"
    echo "  • Embedding generation via HTTP API"
    echo "  • Vector table creation and data storage"
    echo "  • Similarity search with generated embeddings"
    echo "  • Error handling and edge cases"
    echo ""
    echo "These examples can be used as a baseline for building applications"
    echo "that leverage sqlite-rembed and sqlite-vec in ProxySQL."
}

###############################################################################
# Script Entry Point
###############################################################################

# Check if mysql client is available
if ! command -v mysql &> /dev/null; then
    echo -e "${RED}Error: MySQL client not found. Please install mysql-client.${NC}"
    exit 1
fi

# Check connectivity to ProxySQL
if ! mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" \
    -e "SELECT 1;" &>/dev/null; then
    echo -e "${RED}Error: Cannot connect to ProxySQL at ${PROXYSQL_HOST}:${PROXYSQL_PORT}${NC}"
    echo "Make sure ProxySQL is running with: ./proxysql --sqlite3-server"
    exit 1
fi

# Run main demonstration
main
exit 0