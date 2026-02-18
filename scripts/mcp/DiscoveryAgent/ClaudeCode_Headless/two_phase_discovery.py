#!/usr/bin/env python3
"""
Two-Phase Database Discovery

The Agent (via Claude Code) performs both phases:
1. Calls discovery.run_static to trigger ProxySQL's static harvest
2. Performs LLM semantic analysis using catalog data

This script is a wrapper that launches Claude Code with the prompts.
"""

import argparse
import sys
import json
import os
import subprocess

# Script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def load_prompt(filename):
    """Load prompt from file"""
    path = os.path.join(SCRIPT_DIR, "prompts", filename)
    with open(path, "r") as f:
        return f.read()


def main():
    parser = argparse.ArgumentParser(
        description="Two-Phase Database Discovery using Claude Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discovery all schemas
  %(prog)s --mcp-config mcp_config.json --target-id tap_mysql_default --schema test

  # Discovery specific schema
  %(prog)s --mcp-config mcp_config.json --target-id tap_mysql_default --schema sales

  # Discovery specific schema (REQUIRED)
  %(prog)s --mcp-config mcp_config.json --target-id tap_pgsql_default --schema public

  # With custom model
  %(prog)s --mcp-config mcp_config.json --target-id tap_mysql_default --schema sales --model claude-3-opus-20240229
        """
    )

    parser.add_argument(
        "--mcp-config",
        required=True,
        help="Path to MCP server configuration JSON"
    )
    parser.add_argument(
        "--schema",
        required=True,
        help="Schema/database to discover (REQUIRED)"
    )
    parser.add_argument(
        "--target-id",
        required=True,
        help="MCP target_id to use for static harvest and catalog/LLM tools (REQUIRED)"
    )
    parser.add_argument(
        "--model",
        default="claude-3.5-sonnet",
        help="Claude model to use (default: claude-3.5-sonnet)"
    )
    parser.add_argument(
        "--catalog-path",
        default="mcp_catalog.db",
        help="Path to SQLite catalog database (default: mcp_catalog.db)"
    )
    parser.add_argument(
        "--run-id",
        type=int,
        help="Run ID from Phase 1 static harvest (required if not using auto-fetch)"
    )
    parser.add_argument(
        "--output",
        help="Optional: Path to save discovery summary (DEPRECATED - all data in catalog)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without executing"
    )
    parser.add_argument(
        "--dangerously-skip-permissions",
        action="store_true",
        help="Bypass all permission checks (use only in trusted environments)"
    )
    parser.add_argument(
        "--mcp-only",
        action="store_true",
        default=True,
        help="Restrict to MCP tools only (disable Bash/Edit/Write - default: True)"
    )

    args = parser.parse_args()

    # Determine run_id
    run_id = None
    if args.run_id:
        run_id = args.run_id
    else:
        # Try to get the latest run_id from the static harvest output
        import subprocess
        import json as json_module
        try:
            # Run static harvest and parse the output to get run_id
            endpoint = os.getenv("PROXYSQL_MCP_ENDPOINT", "https://127.0.0.1:6071/mcp/query")
            harvest_query = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                        "name": "discovery.run_static",
                        "arguments": {
                            "target_id": args.target_id,
                            "schema_filter": args.schema
                        }
                }
            }
            result = subprocess.run(
                ["curl", "-k", "-s", "-X", "POST", endpoint,
                 "-H", "Content-Type: application/json",
                 "-d", json_module.dumps(harvest_query)],
                capture_output=True, text=True, timeout=30
            )
            response = json_module.loads(result.stdout)
            if response.get("result") and response["result"].get("content"):
                content = response["result"]["content"][0]["text"]
                harvest_data = json_module.loads(content)
                run_id = harvest_data.get("run_id")
            else:
                run_id = None
        except Exception as e:
            print(f"Warning: Could not fetch latest run_id: {e}", file=sys.stderr)
            print(f"Debug: {result.stdout[:500]}", file=sys.stderr)
            run_id = None

    if not run_id:
        print("Error: Could not determine run_id.", file=sys.stderr)
        print("Either:")
        print("  1. Run: ./static_harvest.sh --target-id <target_id> --schema <your_schema> first")
        print("  2. Or use: ./two_phase_discovery.py --run-id <run_id> --target-id <target_id> --schema <schema>")
        sys.exit(1)

    print(f"[*] Using run_id: {run_id} for target_id: {args.target_id}")

    # Load prompts
    try:
        system_prompt = load_prompt("two_phase_discovery_prompt.md")
        user_prompt = load_prompt("two_phase_user_prompt.md")
    except FileNotFoundError as e:
        print(f"Error: Could not load prompt files: {e}", file=sys.stderr)
        print(f"Make sure prompts are in: {os.path.join(SCRIPT_DIR, 'prompts')}", file=sys.stderr)
        sys.exit(1)

    # Replace placeholders in user prompt
    schema_filter = args.schema if args.schema else "all schemas"
    user_prompt = user_prompt.replace("<USE_THE_PROVIDED_RUN_ID>", str(run_id))
    user_prompt = user_prompt.replace("<TARGET_ID>", args.target_id)
    user_prompt = user_prompt.replace("<MODEL_NAME_HERE>", args.model)
    user_prompt = user_prompt.replace("<SCHEMA_FILTER>", schema_filter)

    # Dry run mode
    if args.dry_run:
        print("[DRY RUN] Two-Phase Database Discovery")
        print(f"  MCP Config: {args.mcp_config}")
        print(f"  Schema: {schema_filter}")
        print(f"  Target ID: {args.target_id}")
        print(f"  Model: {args.model}")
        print(f"  Catalog Path: {args.catalog_path}")
        print()
        print("System prompt:")
        print("  " + "\n  ".join(system_prompt.split("\n")[:10]))
        print("  ...")
        print()
        print("User prompt:")
        print("  " + "\n  ".join(user_prompt.split("\n")[:10]))
        print("  ...")
        return 0

    # Check if claude command is available
    try:
        result = subprocess.run(
            ["claude", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            raise FileNotFoundError
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("Error: 'claude' command not found. Please install Claude Code CLI.", file=sys.stderr)
        print("  Visit: https://claude.ai/download", file=sys.stderr)
        sys.exit(1)

    # Launch Claude Code with the prompts
    print("[*] Launching Claude Code for two-phase discovery...")
    print(f"    Schema: {schema_filter}")
    print(f"    Target ID: {args.target_id}")
    print(f"    Model: {args.model}")
    print(f"    Catalog: {args.catalog_path}")
    print(f"    MCP Config: {args.mcp_config}")
    print()

    # Create temporary files for prompts
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as system_file:
        system_file.write(system_prompt)
        system_path = system_file.name

    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as user_file:
        user_file.write(user_prompt)
        user_path = user_file.name

    try:
        # Build claude command
        # Pass prompt via stdin since it can be very long
        claude_cmd = [
            "claude",
            "--mcp-config", args.mcp_config,
            "--system-prompt", system_path,
            "--print",  # Non-interactive mode
        ]

        # Add permission mode - always use dangerously-skip-permissions for headless MCP operation
        # The permission-mode dontAsk doesn't work correctly with MCP tools
        claude_cmd.extend(["--dangerously-skip-permissions"])

        # Restrict to MCP tools only (disable Bash/Edit/Write) to enforce NO FILES rule
        if args.mcp_only:
            claude_cmd.extend(["--allowed-tools", ""])  # Empty string = disable all built-in tools

        # Execute claude with prompt via stdin
        with open(user_path, "r") as user_file:
            result = subprocess.run(claude_cmd, stdin=user_file)
        sys.exit(result.returncode)

    finally:
        # Clean up temporary files
        try:
            os.unlink(system_path)
        except:
            pass
        try:
            os.unlink(user_path)
        except:
            pass


if __name__ == "__main__":
    main()
