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
  %(prog)s --mcp-config mcp_config.json

  # Discovery specific schema
  %(prog)s --mcp-config mcp_config.json --schema sales

  # With custom model
  %(prog)s --mcp-config mcp_config.json --model claude-3-opus-20240229 --schema production
        """
    )

    parser.add_argument(
        "--mcp-config",
        required=True,
        help="Path to MCP server configuration JSON"
    )
    parser.add_argument(
        "--schema",
        help="Restrict discovery to one MySQL schema/database (optional)"
    )
    parser.add_argument(
        "--model",
        default="claude-3.5-sonnet",
        help="Claude model to use (default: claude-3.5-sonnet)"
    )
    parser.add_argument(
        "--catalog-path",
        default="/var/lib/proxysql/discovery_catalog.db",
        help="Path to SQLite catalog database (default: /var/lib/proxysql/discovery_catalog.db)"
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

    args = parser.parse_args()

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
    user_prompt = user_prompt.replace("<RUN_ID_HERE>", "{run_id from discovery.run_static}")
    user_prompt = user_prompt.replace("<MODEL_NAME_HERE>", args.model)
    user_prompt = user_prompt.replace("<SCHEMA_FILTER>", schema_filter)

    # Build discovery command for user
    discovery_args = []
    if args.schema:
        discovery_args.append(f"--schema-filter {args.schema}")
    discovery_args.append(f"--catalog-path {args.catalog_path}")

    user_prompt += f"""

## Your Discovery Command

When you begin, use these parameters:
```
discovery.run_static({", ".join(discovery_args)})
```

## Expected Coverage

- Summarize at least 50 high-value objects
- Create 3-10 domains with membership
- Create 10-30 metrics
- Create 15-50 question templates
"""

    # Dry run mode
    if args.dry_run:
        print("[DRY RUN] Two-Phase Database Discovery")
        print(f"  MCP Config: {args.mcp_config}")
        print(f"  Schema: {schema_filter}")
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
        claude_cmd = [
            "claude",
            "--prompt", user_path,
            "--system-prompt", system_path,
        ]

        # Add MCP server if specified
        if args.mcp_config:
            claude_cmd.extend(["--mcp", args.mcp_config])

        # Execute claude
        result = subprocess.run(claude_cmd)
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
