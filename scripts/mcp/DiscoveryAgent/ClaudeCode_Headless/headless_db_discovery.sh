#!/usr/bin/env bash
#
# headless_db_discovery.sh
#
# Multi-Agent Database Discovery using Claude Code
#
# This script runs Claude Code in non-interactive mode to perform
# comprehensive database discovery using 4 collaborating agents:
# STRUCTURAL, STATISTICAL, SEMANTIC, and QUERY.
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
#   -t, --timeout SECONDS      Timeout for discovery in seconds (default: 3600 = 1 hour)
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
#

set -e

# Default values
DATABASE_NAME=""
SCHEMA_NAME=""
OUTPUT_FILE=""
MCP_CONFIG=""
MCP_FILE=""
TIMEOUT=3600  # 1 hour default (multi-agent discovery takes longer)
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

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROMPT_FILE="$SCRIPT_DIR/prompts/multi_agent_discovery_prompt.md"

# Validate prompt file exists
if [ ! -f "$PROMPT_FILE" ]; then
    log_error "Multi-agent discovery prompt not found at: $PROMPT_FILE"
    log_error "Ensure the prompts/ directory exists with multi_agent_discovery_prompt.md"
    exit 1
fi

log_info "Starting Multi-Agent Database Discovery"
log_info "Output will be saved to: $OUTPUT_FILE"
log_verbose "Using discovery prompt: $PROMPT_FILE"

# Read the base prompt
DISCOVERY_PROMPT="$(cat "$PROMPT_FILE")"

# Add database-specific context if provided
if [ -n "$DATABASE_NAME" ]; then
    DISCOVERY_PROMPT="$DISCOVERY_PROMPT

**Target Database:** $DATABASE_NAME"

    if [ -n "$SCHEMA_NAME" ]; then
        DISCOVERY_PROMPT="$DISCOVERY_PROMPT
**Target Schema:** $SCHEMA_NAME"
    fi

    log_verbose "Target database: $DATABASE_NAME"
    [ -n "$SCHEMA_NAME" ] && log_verbose "Target schema: $SCHEMA_NAME"
fi

# Build MCP args
MCP_ARGS=""
if [ -n "$MCP_CONFIG" ]; then
    MCP_ARGS="--mcp-config $MCP_CONFIG"
    log_verbose "Using inline MCP configuration"
elif [ -n "$MCP_FILE" ]; then
    if [ -f "$MCP_FILE" ]; then
        MCP_ARGS="--mcp-config $MCP_FILE"
        log_verbose "Using MCP configuration from: $MCP_FILE"
    else
        log_error "MCP configuration file not found: $MCP_FILE"
        exit 1
    fi
fi

# Log the command being executed
log_info "Running Claude Code in headless mode with 6-agent discovery..."
log_verbose "Timeout: ${TIMEOUT}s"

# Build Claude command
CLAUDE_ARGS=(
    --print
    --no-session-persistence
    --permission-mode bypassPermissions
)

# Add MCP configuration if available
if [ -n "$MCP_ARGS" ]; then
    CLAUDE_ARGS+=($MCP_ARGS)
fi

# Execute Claude Code in headless mode
log_verbose "Executing: $CLAUDE_CMD ${CLAUDE_ARGS[*]}"

# Run the discovery and capture output
if timeout "${TIMEOUT}s" $CLAUDE_CMD "${CLAUDE_ARGS[@]}" <<< "$DISCOVERY_PROMPT" > "$OUTPUT_FILE" 2>&1; then
    log_success "Discovery completed successfully!"
    log_info "Report saved to: $OUTPUT_FILE"

    # Print summary statistics
    if [ -f "$OUTPUT_FILE" ]; then
        lines=$(wc -l < "$OUTPUT_FILE")
        words=$(wc -w < "$OUTPUT_FILE")
        log_info "Report size: $lines lines, $words words"

        # Check if file is empty (no output)
        if [ "$lines" -eq 0 ]; then
            log_warn "Output file is empty - discovery may have failed silently"
            log_info "Try running with --verbose to see more details"
        fi

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

    # Exit code 124 means timeout command killed the process
    if [ "$exit_code" -eq 124 ]; then
        log_error "Discovery timed out after ${TIMEOUT} seconds"
        log_error "The multi-agent discovery process can take a long time for complex databases"
        log_info "Try increasing timeout with: --timeout $((TIMEOUT * 2))"
        log_info "Example: $0 --timeout $((TIMEOUT * 2))"
    else
        log_error "Discovery failed with exit code: $exit_code"
        log_info "Check $OUTPUT_FILE for error details"
    fi

    # Show last few lines of output if it exists
    if [ -f "$OUTPUT_FILE" ]; then
        file_size=$(wc -c < "$OUTPUT_FILE")
        if [ "$file_size" -gt 0 ]; then
            log_verbose "Last 30 lines of output:"
            tail -30 "$OUTPUT_FILE" | sed 's/^/  /'
        else
            log_warn "Output file is empty (0 bytes)"
            log_info "This usually means Claude Code failed to start or produced no output"
            log_info "Check that Claude Code is installed: $CLAUDE_CMD --version"
            log_info "Or try with --verbose for more debugging information"
        fi
    fi

    exit $exit_code
fi

log_success "Done!"
