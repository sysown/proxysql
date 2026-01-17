#!/usr/bin/env python3
"""
Headless Database Discovery using Claude Code (Multi-Agent)

This script runs Claude Code in non-interactive mode to perform
comprehensive database discovery using 4 collaborating agents:
STRUCTURAL, STATISTICAL, SEMANTIC, and QUERY.

Usage:
    python headless_db_discovery.py [options]

Examples:
    # Basic discovery
    python headless_db_discovery.py

    # Discover specific database
    python headless_db_discovery.py --database mydb

    # With output file
    python headless_db_discovery.py --output my_report.md
"""

import argparse
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


def get_discovery_prompt_path() -> str:
    """Get the path to the multi-agent discovery prompt."""
    script_dir = Path(__file__).resolve().parent
    prompt_path = script_dir / 'prompts' / 'multi_agent_discovery_prompt.md'
    if not prompt_path.exists():
        raise FileNotFoundError(
            f"Multi-agent discovery prompt not found at: {prompt_path}\n"
            "Ensure the prompts/ directory exists with multi_agent_discovery_prompt.md"
        )
    return str(prompt_path)


def build_discovery_prompt(database: Optional[str], schema: Optional[str]) -> str:
    """Build the multi-agent database discovery prompt."""

    # Read the base prompt from the file
    prompt_path = get_discovery_prompt_path()
    with open(prompt_path, 'r') as f:
        base_prompt = f.read()

    # Add database-specific context if provided
    if database:
        database_context = f"\n\n**Target Database:** {database}"
        if schema:
            database_context += f"\n**Target Schema:** {schema}"
        base_prompt += database_context

    return base_prompt


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

    log_info("Starting Multi-Agent Database Discovery")
    log_info(f"Output will be saved to: {output_file}")
    log_verbose(f"Claude Code executable: {claude_cmd}", args.verbose)
    log_verbose(f"Using discovery prompt: {get_discovery_prompt_path()}", args.verbose)

    # Build command arguments
    cmd_args = [
        claude_cmd,
        '--print',                          # Non-interactive mode
        '--no-session-persistence',         # Don't save session
        '--permission-mode', 'bypassPermissions',  # Bypass permission checks
    ]

    # Add MCP configuration if provided
    if args.mcp_config:
        cmd_args.extend(['--mcp-config', args.mcp_config])
        log_verbose(f"Using MCP config: {args.mcp_config}", args.verbose)
    elif args.mcp_file:
        cmd_args.extend(['--mcp-config', args.mcp_file])
        log_verbose(f"Using MCP config file: {args.mcp_file}", args.verbose)

    # Build discovery prompt
    try:
        prompt = build_discovery_prompt(args.database, args.schema)
    except FileNotFoundError as e:
        log_error(str(e))
        sys.exit(1)

    log_info("Running Claude Code in headless mode with 6-agent discovery...")
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

            # Check if output is empty
            if lines == 0 or not result.stdout.strip():
                log_warn("Output file is empty - discovery may have failed silently")
                log_info("Try running with --verbose to see more details")
                log_info("Check that Claude Code is working: claude --version")
            else:
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

            # Check if output file is empty
            if os.path.exists(output_file):
                file_size = os.path.getsize(output_file)
                if file_size == 0:
                    log_warn("Output file is empty (0 bytes)")
                    log_info("This usually means Claude Code failed to start or produced no output")
                    log_info("Check that Claude Code is installed and working:")
                    log_info(f"  {claude_cmd} --version")
                    log_info("Or try with --verbose for more debugging information")

            if result.stderr:
                log_verbose(f"Stderr: {result.stderr}", args.verbose)
            else:
                log_warn("No stderr output captured - check if Claude Code started correctly")

            sys.exit(result.returncode)

    except subprocess.TimeoutExpired:
        log_error(f"Discovery timed out after {args.timeout} seconds")
        log_error("The multi-agent discovery process can take a long time for complex databases")
        log_info(f"Try increasing timeout with: --timeout {args.timeout * 2}")
        log_info(f"Example: {sys.argv[0]} --timeout {args.timeout * 2}")
        sys.exit(1)
    except Exception as e:
        log_error(f"Error running discovery: {e}")
        sys.exit(1)

    log_success("Done!")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Multi-Agent Database Discovery using Claude Code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic discovery
  %(prog)s

  # Discover specific database
  %(prog)s --database mydb

  # With specific schema
  %(prog)s --database mydb --schema public

  # With output file
  %(prog)s --output my_discovery_report.md

  # With custom timeout for large databases
  %(prog)s --timeout 600

Environment Variables:
  CLAUDE_PATH    Path to claude executable

The discovery uses a 6-agent collaborative approach:
  - STRUCTURAL: Schemas, tables, relationships, indexes, constraints
  - STATISTICAL: Data distributions, quality, anomalies
  - SEMANTIC: Business domain, entities, rules, terminology
  - QUERY: Index efficiency, query patterns, optimization
  - SECURITY: Sensitive data, access patterns, vulnerabilities
  - META: Report quality analysis, prompt improvement suggestions

Agents collaborate through 5 rounds:
  1. Blind Exploration (5 analysis agents, independent discovery)
  2. Pattern Recognition (cross-agent collaboration)
  3. Hypothesis Testing (validation with evidence)
  4. Final Synthesis (comprehensive report)
  5. Meta Analysis (META agent analyzes report quality)

Findings are shared via MCP catalog and output as a structured markdown report.
The META agent also generates a separate meta-analysis document with prompt improvement suggestions.
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
        default=3600,
        help='Timeout for discovery in seconds (default: 3600 = 1 hour)'
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
