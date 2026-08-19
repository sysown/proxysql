#!/usr/bin/env python3
"""Launch the optional semantic phase after a deterministic MCP harvest."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


SYSTEM_PROMPT = """You are analyzing one database schema through ProxySQL MCP.
Use only the configured ProxySQL MCP tools. Read catalog objects for the supplied
target and run identifiers, then persist concise summaries through the LLM tools.
Do not use local files or shell commands for database discovery.
"""


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp-config", required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--model", default="claude-sonnet-4-5")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--dangerously-skip-permissions", action="store_true")
    return parser.parse_args()


def materialize_config(config_path):
    with config_path.open(encoding="utf-8") as stream:
        config = json.load(stream)
    servers = config.get("mcpServers", {})
    if "proxysql" not in servers:
        raise ValueError("MCP config must define mcpServers.proxysql")

    endpoint = os.environ.get("PROXYSQL_MCP_ENDPOINT")
    token = os.environ.get("TAP_MCP_AUTH_TOKEN") or os.environ.get(
        "PROXYSQL_MCP_TOKEN"
    )
    server = servers["proxysql"]
    if endpoint:
        server["url"] = endpoint
    if token:
        server.setdefault("headers", {})["Authorization"] = f"Bearer {token}"

    temporary = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", encoding="utf-8", delete=False
    )
    with temporary:
        json.dump(config, temporary)
    return Path(temporary.name)


def main():
    args = parse_args()
    config_path = Path(args.mcp_config)
    if not config_path.is_file():
        print(f"MCP config does not exist: {config_path}", file=sys.stderr)
        return 2
    try:
        with config_path.open(encoding="utf-8") as stream:
            config = json.load(stream)
        if "proxysql" not in config.get("mcpServers", {}):
            raise ValueError("missing mcpServers.proxysql")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Invalid MCP config: {error}", file=sys.stderr)
        return 2

    user_prompt = (
        f"Analyze schema {args.schema!r} for target {args.target_id!r} using "
        f"catalog run_id {args.run_id}. Persist the resulting semantic summary."
    )
    if args.dry_run:
        print("[DRY RUN] Two-Phase Database Discovery")
        print(f"  MCP Config: {config_path}")
        print(f"  Schema: {args.schema}")
        print(f"  Target ID: {args.target_id}")
        print(f"  Run ID: {args.run_id}")
        print(f"  Model: {args.model}")
        print(f"  Prompt: {user_prompt}")
        return 0

    claude = shutil.which("claude")
    if not claude:
        print("claude CLI is required when dry-run is disabled", file=sys.stderr)
        return 2

    rendered_config = materialize_config(config_path)
    try:
        command = [
            claude,
            "--mcp-config",
            str(rendered_config),
            "--model",
            args.model,
            "--system-prompt",
            SYSTEM_PROMPT,
            "--allowed-tools",
            "mcp__proxysql__*",
            "--print",
        ]
        if args.dangerously_skip_permissions:
            command.append("--dangerously-skip-permissions")
        result = subprocess.run(command, input=user_prompt, text=True, check=False)
        return result.returncode
    finally:
        rendered_config.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
