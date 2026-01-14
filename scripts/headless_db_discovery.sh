#!/usr/bin/env bash
#
# headless_db_discovery.sh
#
# Headless Database Discovery using Claude Code
#
# This script runs Claude Code in non-interactive mode to perform
# comprehensive database discovery. It works with any database
# type that is accessible via MCP (Model Context Protocol).
#
# Usage:
#   ./headless_db_discovery.sh [options]
#
# Options:
#   -d, --database DB_NAME     Database name to discover (default: discover from available)
#   -s, --schema SCHEMA        Schema name to analyze (default: all schemas)
#   -o, --output FILE          Output file for results (default: discovery_YYYYMMDD_HHMMSS.md)
#   -m, --mcp-config JSON      MCP server configuration (inline JSON)
#   -f, --mcp-file FILE        MCP server configuration file
#   -t, --timeout SECONDS      Timeout for discovery (default: 300)
#   -v, --verbose              Enable verbose output
#   -h, --help                 Show this help message
#
# Examples:
#   # Basic discovery (uses available MCP database connection)
#   ./headless_db_discovery.sh
#
#   # Discover specific database
#   ./headless_db_discovery.sh -d mydb
#
#   # With custom MCP server
#   ./headless_db_discovery.sh -m '{"mcpServers": {"mydb": {"command": "...", "args": [...]}}}'
#
#   # With output file
#   ./headless_db_discovery.sh -o my_discovery_report.md
#
# Environment Variables:
#   CLAUDE_PATH                Path to claude executable (default: ~/.local/bin/claude)
#   PROXYSQL_MCP_ENDPOINT      ProxySQL MCP endpoint URL
#   PROXYSQL_MCP_TOKEN         ProxySQL MCP auth token (optional)
#   PROXYSQL_MCP_INSECURE_SSL  Skip SSL verification (set to "1" to enable)
#

set -e

# Default values
DATABASE_NAME=""
SCHEMA_NAME=""
OUTPUT_FILE=""
MCP_CONFIG=""
MCP_FILE=""
TIMEOUT=300
VERBOSE=0
CLAUDE_CMD="${CLAUDE_PATH:-$HOME/.local/bin/claude}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_verbose() {
    if [ "$VERBOSE" -eq 1 ]; then
        echo -e "${BLUE}[VERBOSE]${NC} $1"
    fi
}

# Print usage
usage() {
    grep '^#' "$0" | grep -v '!/bin/' | sed 's/^# //' | sed 's/^#//'
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--database)
            DATABASE_NAME="$2"
            shift 2
            ;;
        -s|--schema)
            SCHEMA_NAME="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -m|--mcp-config)
            MCP_CONFIG="$2"
            shift 2
            ;;
        -f|--mcp-file)
            MCP_FILE="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate Claude Code is available
if [ ! -f "$CLAUDE_CMD" ]; then
    log_error "Claude Code not found at: $CLAUDE_CMD"
    log_error "Set CLAUDE_PATH environment variable or ensure claude is in ~/.local/bin/"
    exit 1
fi

# Set default output file if not specified
if [ -z "$OUTPUT_FILE" ]; then
    OUTPUT_FILE="discovery_$(date +%Y%m%d_%H%M%S).md"
fi

log_info "Starting Headless Database Discovery"
log_info "Output will be saved to: $OUTPUT_FILE"

# Build MCP configuration
MCP_ARGS=""
if [ -n "$MCP_CONFIG" ]; then
    MCP_ARGS="--mcp-config '$MCP_CONFIG'"
    log_verbose "Using inline MCP configuration"
elif [ -n "$MCP_FILE" ]; then
    if [ -f "$MCP_FILE" ]; then
        MCP_ARGS="--mcp-config $MCP_FILE"
        log_verbose "Using MCP configuration from: $MCP_FILE"
    else
        log_error "MCP configuration file not found: $MCP_FILE"
        exit 1
    fi
elif [ -n "$PROXYSQL_MCP_ENDPOINT" ]; then
    # Build inline MCP config for ProxySQL
    PROXYSQL_MCP_CONFIG="{\"mcpServers\": {\"proxysql\": {\"command\": \"python3\", \"args\": [\"$(dirname "$0")/../mcp/proxysql_mcp_stdio_bridge.py\"], \"env\": {\"PROXYSQL_MCP_ENDPOINT\": \"$PROXYSQL_MCP_ENDPOINT\""
    if [ -n "$PROXYSQL_MCP_TOKEN" ]; then
        PROXYSQL_MCP_CONFIG+=", \"PROXYSQL_MCP_TOKEN\": \"$PROXYSQL_MCP_TOKEN\""
    fi
    if [ "$PROXYSQL_MCP_INSECURE_SSL" = "1" ]; then
        PROXYSQL_MCP_CONFIG+=", \"PROXYSQL_MCP_INSECURE_SSL\": \"1\""
    fi
    PROXYSQL_MCP_CONFIG+="}}}}"
    MCP_ARGS="--mcp-config '$PROXYSQL_MCP_CONFIG'"
    log_verbose "Using ProxySQL MCP endpoint: $PROXYSQL_MCP_ENDPOINT"
else
    log_verbose "No explicit MCP configuration, using available MCP servers"
fi

# Build the discovery prompt
DATABASE_ARG=""
if [ -n "$DATABASE_NAME" ]; then
    DATABASE_ARG="database named '$DATABASE_NAME'"
else
    DATABASE_ARG="the first available database"
fi

SCHEMA_ARG=""
if [ -n "$SCHEMA_NAME" ]; then
    SCHEMA_ARG="the schema '$SCHEMA_NAME' within"
fi

DISCOVERY_PROMPT="You are a Database Discovery Agent. Your mission is to perform comprehensive analysis of $DATABASE_ARG.

${SCHEMA_ARG:+Focus on $SCHEMA_ARG}

Use the available MCP database tools to discover and document:

## 1. STRUCTURAL ANALYSIS
- List all tables in the database/schema
- For each table, describe:
  - Column names, data types, and nullability
  - Primary keys and unique constraints
  - Foreign key relationships
  - Indexes and their purposes
  - Any CHECK constraints or defaults

- Create an Entity Relationship Diagram (ERD) showing:
  - All tables and their relationships
  - Cardinality (1:1, 1:N, M:N)
  - Primary and foreign keys

## 2. DATA PROFILING
- For each table, analyze:
  - Row count
  - Data distributions for key columns
  - Null value percentages
  - Distinct value counts (cardinality)
  - Min/max/average values for numeric columns
  - Sample data (first few rows)

- Identify patterns and anomalies:
  - Duplicate records
  - Data quality issues
  - Unexpected distributions
  - Outliers

## 3. SEMANTIC ANALYSIS
- Infer the business domain:
  - What type of application/database is this?
  - What are the main business entities?
  - What are the business processes?

- Document business rules:
  - Entity lifecycles and state machines
  - Validation rules implied by constraints
  - Relationship patterns

- Classify tables:
  - Master/reference data (customers, products, etc.)
  - Transactional data (orders, transactions, etc.)
  - Junction/association tables
  - Configuration/metadata

## 4. PERFORMANCE & ACCESS PATTERNS
- Identify:
  - Missing indexes on foreign keys
  - Missing indexes on frequently filtered columns
  - Composite index opportunities
  - Potential N+1 query patterns

- Suggest optimizations:
  - Indexes that should be added
  - Query patterns that would benefit from optimization
  - Denormalization opportunities

## OUTPUT FORMAT

Provide your findings as a comprehensive Markdown report with:

1. **Executive Summary** - High-level overview
2. **Database Schema** - Complete table definitions
3. **Entity Relationship Diagram** - ASCII ERD
4. **Data Quality Assessment** - Score (1-100) with issues
5. **Business Domain Analysis** - Industry, use cases, entities
6. **Performance Recommendations** - Prioritized optimization list
7. **Anomalies & Issues** - All problems found with severity

Be thorough. Discover everything about this database structure and data.
Write the complete report to standard output."

# Log the command being executed (without showing the full prompt for clarity)
log_info "Running Claude Code in headless mode..."
log_verbose "Timeout: ${TIMEOUT}s"
if [ -n "$DATABASE_NAME" ]; then
    log_verbose "Target database: $DATABASE_NAME"
fi
if [ -n "$SCHEMA_NAME" ]; then
    log_verbose "Target schema: $SCHEMA_NAME"
fi

# Execute Claude Code in headless mode
# Using --print for non-interactive output
# Using --output-format text for readable markdown output
# Using --no-session-persistence to avoid saving the session

eval_command="$CLAUDE_CMD --print --no-session-persistence --timeout ${TIMEOUT} $MCP_ARGS"

log_verbose "Executing: $eval_command"

# Run the discovery and capture output
if eval "$eval_command" <<< "$DISCOVERY_PROMPT" > "$OUTPUT_FILE" 2>&1; then
    log_success "Discovery completed successfully!"
    log_info "Report saved to: $OUTPUT_FILE"

    # Print summary statistics
    if [ -f "$OUTPUT_FILE" ]; then
        lines=$(wc -l < "$OUTPUT_FILE")
        words=$(wc -w < "$OUTPUT_FILE")
        log_info "Report size: $lines lines, $words words"

        # Try to extract key info if report contains markdown headers
        if grep -q "^# " "$OUTPUT_FILE"; then
            log_info "Report sections:"
            grep "^# " "$OUTPUT_FILE" | head -10 | while read -r section; do
                echo "  - $section"
            done
        fi
    fi
else
    exit_code=$?
    log_error "Discovery failed with exit code: $exit_code"
    log_info "Check $OUTPUT_FILE for error details"

    # Show last few lines of output if it exists
    if [ -f "$OUTPUT_FILE" ]; then
        log_verbose "Last 20 lines of output:"
        tail -20 "$OUTPUT_FILE" | sed 's/^/  /'
    fi

    exit $exit_code
fi

log_success "Done!"
