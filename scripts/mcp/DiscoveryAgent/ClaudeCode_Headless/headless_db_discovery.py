#!/usr/bin/env python3
"""
Headless Database Discovery using Claude Code

This script runs Claude Code in non-interactive mode to perform
comprehensive database discovery. It works with any database
type that is accessible via MCP (Model Context Protocol).

Usage:
    python headless_db_discovery.py [options]

Examples:
    # Basic discovery (uses available MCP database connection)
    python headless_db_discovery.py

    # Discover specific database
    python headless_db_discovery.py --database mydb

    # With custom MCP server
    python headless_db_discovery.py --mcp-config '{"mcpServers": {...}}'

    # With output file
    python headless_db_discovery.py --output my_discovery_report.md
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color


def log_info(msg: str):
    """Log info message."""
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {msg}")


def log_success(msg: str):
    """Log success message."""
    print(f"{Colors.GREEN}[SUCCESS]{Colors.NC} {msg}")


def log_warn(msg: str):
    """Log warning message."""
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}")


def log_error(msg: str):
    """Log error message."""
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}", file=sys.stderr)


def log_verbose(msg: str, verbose: bool):
    """Log verbose message."""
    if verbose:
        print(f"{Colors.BLUE}[VERBOSE]{Colors.NC} {msg}")


def find_claude_executable() -> Optional[str]:
    """Find the Claude Code executable."""
    # Check CLAUDE_PATH environment variable
    claude_path = os.environ.get('CLAUDE_PATH')
    if claude_path and os.path.isfile(claude_path):
        return claude_path

    # Check default location
    default_path = Path.home() / '.local' / 'bin' / 'claude'
    if default_path.exists():
        return str(default_path)

    # Check PATH
    for path in os.environ.get('PATH', '').split(os.pathsep):
        claude = Path(path) / 'claude'
        if claude.exists() and claude.is_file():
            return str(claude)

    return None


def build_mcp_config(args) -> Optional[str]:
    """Build MCP configuration from command line arguments."""
    if args.mcp_config:
        return args.mcp_config

    if args.mcp_file:
        if os.path.isfile(args.mcp_file):
            with open(args.mcp_file, 'r') as f:
                return f.read()
        else:
            log_error(f"MCP configuration file not found: {args.mcp_file}")
            return None

    # Check for ProxySQL MCP environment variables
    proxysql_endpoint = os.environ.get('PROXYSQL_MCP_ENDPOINT')
    if proxysql_endpoint:
        script_dir = Path(__file__).parent.parent
        bridge_path = script_dir / 'scripts' / 'mcp' / 'proxysql_mcp_stdio_bridge.py'

        if not bridge_path.exists():
            bridge_path = Path(__file__).parent / 'mcp' / 'proxysql_mcp_stdio_bridge.py'

        mcp_config = {
            "mcpServers": {
                "proxysql": {
                    "command": "python3",
                    "args": [str(bridge_path)],
                    "env": {
                        "PROXYSQL_MCP_ENDPOINT": proxysql_endpoint
                    }
                }
            }
        }

        # Add optional parameters
        if os.environ.get('PROXYSQL_MCP_TOKEN'):
            mcp_config["mcpServers"]["proxysql"]["env"]["PROXYSQL_MCP_TOKEN"] = os.environ.get('PROXYSQL_MCP_TOKEN')

        if os.environ.get('PROXYSQL_MCP_INSECURE_SSL') == '1':
            mcp_config["mcpServers"]["proxysql"]["env"]["PROXYSQL_MCP_INSECURE_SSL"] = "1"

        return json.dumps(mcp_config)

    return None


def build_discovery_prompt(database: Optional[str], schema: Optional[str]) -> str:
    """Build the comprehensive database discovery prompt."""

    if database:
        database_target = f"database named '{database}'"
    else:
        database_target = "the first available database"

    schema_section = ""
    if schema:
        schema_section = f"""
Focus on the schema '{schema}' within the database.
"""

    prompt = f"""You are a Database Discovery Agent. Your mission is to perform comprehensive analysis of {database_target}.

{schema_section}
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
Write the complete report to standard output."""

    return prompt


def run_discovery(args):
    """Execute the database discovery process."""

    # Find Claude Code executable
    claude_cmd = find_claude_executable()
    if not claude_cmd:
        log_error("Claude Code executable not found")
        log_error("Set CLAUDE_PATH environment variable or ensure claude is in ~/.local/bin/")
        sys.exit(1)

    # Set default output file
    output_file = args.output or f"discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

    log_info("Starting Headless Database Discovery")
    log_info(f"Output will be saved to: {output_file}")
    log_verbose(f"Claude Code executable: {claude_cmd}", args.verbose)

    # Build MCP configuration
    mcp_config = build_mcp_config(args)
    if mcp_config:
        log_verbose("Using MCP configuration", args.verbose)

    # Build command arguments
    cmd_args = [
        claude_cmd,
        '--print',                    # Non-interactive mode
        '--no-session-persistence',   # Don't save session
        f'--timeout={args.timeout}',  # Set timeout
    ]

    # Add MCP configuration if available
    if mcp_config:
        cmd_args.extend(['--mcp-config', mcp_config])

    # Build discovery prompt
    prompt = build_discovery_prompt(args.database, args.schema)

    log_info("Running Claude Code in headless mode...")
    log_verbose(f"Timeout: {args.timeout}s", args.verbose)
    if args.database:
        log_verbose(f"Target database: {args.database}", args.verbose)
    if args.schema:
        log_verbose(f"Target schema: {args.schema}", args.verbose)

    # Execute Claude Code
    try:
        result = subprocess.run(
            cmd_args,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=args.timeout + 30,  # Add buffer for process overhead
        )

        # Write output to file
        with open(output_file, 'w') as f:
            f.write(result.stdout)

        if result.returncode == 0:
            log_success("Discovery completed successfully!")
            log_info(f"Report saved to: {output_file}")

            # Print summary statistics
            lines = result.stdout.count('\n')
            words = len(result.stdout.split())
            log_info(f"Report size: {lines} lines, {words} words")

            # Try to extract key sections
            lines_list = result.stdout.split('\n')
            sections = [line for line in lines_list if line.startswith('# ')]
            if sections:
                log_info("Report sections:")
                for section in sections[:10]:
                    print(f"  - {section}")
        else:
            log_error(f"Discovery failed with exit code: {result.returncode}")
            log_info(f"Check {output_file} for error details")

            if result.stderr:
                log_verbose(f"Stderr: {result.stderr}", args.verbose)

            sys.exit(result.returncode)

    except subprocess.TimeoutExpired:
        log_error("Discovery timed out")
        sys.exit(1)
    except Exception as e:
        log_error(f"Error running discovery: {e}")
        sys.exit(1)

    log_success("Done!")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Headless Database Discovery using Claude Code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic discovery (uses available MCP database connection)
  %(prog)s

  # Discover specific database
  %(prog)s --database mydb

  # With custom MCP server
  %(prog)s --mcp-config '{"mcpServers": {"mydb": {"command": "...", "args": [...]}}}'

  # With output file
  %(prog)s --output my_discovery_report.md

Environment Variables:
  CLAUDE_PATH                Path to claude executable
  PROXYSQL_MCP_ENDPOINT      ProxySQL MCP endpoint URL
  PROXYSQL_MCP_TOKEN         ProxySQL MCP auth token (optional)
  PROXYSQL_MCP_INSECURE_SSL  Skip SSL verification (set to "1" to enable)
        """
    )

    parser.add_argument(
        '-d', '--database',
        help='Database name to discover (default: discover from available)'
    )
    parser.add_argument(
        '-s', '--schema',
        help='Schema name to analyze (default: all schemas)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file for results (default: discovery_YYYYMMDD_HHMMSS.md)'
    )
    parser.add_argument(
        '-m', '--mcp-config',
        help='MCP server configuration (inline JSON)'
    )
    parser.add_argument(
        '-f', '--mcp-file',
        help='MCP server configuration file'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=300,
        help='Timeout for discovery in seconds (default: 300)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()
    run_discovery(args)


if __name__ == '__main__':
    main()
