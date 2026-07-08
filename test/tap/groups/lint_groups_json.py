#!/usr/bin/env python3
"""
Lint groups.json for format compliance.

Enforces the conventions documented in test/tap/groups/README.md:
  - Valid JSON
  - One entry per line, compact arrays (no multi-line)
  - Format: '  "test-name-t" : [ "group1","group2" ],' (or no comma for last)
  - Keys sorted alphabetically
  - File starts with '{' and ends with '}'

Usage:
    python3 lint_groups_json.py [--fix] [path/to/groups.json]

    --fix   Auto-fix formatting issues (reformat in-place).

Exit codes:
    0 - Format is correct (or --fix applied successfully)
    1 - Format violations found (and no --fix, or --fix failed)
"""

import argparse
import json
import os
import re
import sys


def reformat_groups(groups_path):
    """Read groups.json and rewrite it in the canonical one-line-per-entry format."""
    with open(groups_path, "r") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        print(f"ERROR: Top-level value must be a JSON object", file=sys.stderr)
        return False

    sorted_keys = sorted(data.keys())
    lines = ["{"]
    for i, key in enumerate(sorted_keys):
        groups = data[key]
        # Sort groups for determinism, but keep special strings like @proxysql_min_version at end
        regular = sorted(g for g in groups if not g.startswith("@"))
        special = sorted(g for g in groups if g.startswith("@"))
        sorted_groups = regular + special
        groups_str = ",".join(f'"{g}"' for g in sorted_groups)
        comma = "," if i < len(sorted_keys) - 1 else ""
        lines.append(f'  "{key}" : [ {groups_str} ]{comma}')
    lines.append("}")
    lines.append("")  # trailing newline

    with open(groups_path, "w") as f:
        f.write("\n".join(lines))

    print(f"Fixed: {groups_path} ({len(sorted_keys)} entries, sorted, compact)")
    return True


def lint_groups(groups_path):
    """Lint groups.json and return (exit_code, error_count)."""
    if not os.path.isfile(groups_path):
        print(f"ERROR: {groups_path} not found", file=sys.stderr)
        return 1, 0

    with open(groups_path, "r") as f:
        raw = f.read()

    lines = raw.split("\n")
    errors = []

    # Check 1: valid JSON
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        errors.append(f"Invalid JSON: {e}")
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1, len(errors)

    if not isinstance(data, dict):
        errors.append("Top-level value must be a JSON object")
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1, len(errors)

    # Check 2: first and last lines
    if not lines or lines[0].strip() != "{":
        errors.append("Line 1: must be '{'")
    if lines[-1].strip() == "":
        if len(lines) < 2 or lines[-2].strip() != "}":
            errors.append(f"Last non-empty line: must be '}}'")
    elif lines[-1].strip() != "}":
        errors.append(f"Last line: must be '}}'")

    # Check 3: each entry is one line with correct format
    entry_pattern = re.compile(
        r'^  "([^"]+)" : \[ .+ \](,?)$'
    )
    keys_in_order = []
    entry_lines = lines[1:]
    for i, line in enumerate(entry_lines, start=2):
        stripped = line.strip()
        if stripped == "}" or stripped == "":
            continue
        m = entry_pattern.match(line)
        if not m:
            errors.append(
                f"Line {i}: does not match expected format "
                f"'  \"test-name\" : [ \"group1\",\"group2\" ],'  "
                f"Got: {line!r}"
            )
        else:
            keys_in_order.append(m.group(1))

    # Check 4: keys are sorted
    if keys_in_order != sorted(keys_in_order):
        for j in range(len(keys_in_order) - 1):
            if keys_in_order[j] > keys_in_order[j + 1]:
                errors.append(
                    f"Keys not sorted: '{keys_in_order[j + 1]}' "
                    f"should come before '{keys_in_order[j]}'"
                )
                break

    # Check 5: last entry has no trailing comma, others do
    entry_indices = []
    for i, line in enumerate(lines):
        if entry_pattern.match(line):
            entry_indices.append(i)
    if entry_indices:
        for idx in entry_indices[:-1]:
            if not lines[idx].rstrip().endswith(","):
                errors.append(f"Line {idx + 1}: non-last entry must end with comma")
        last_idx = entry_indices[-1]
        if lines[last_idx].rstrip().endswith(","):
            errors.append(f"Line {last_idx + 1}: last entry must not end with comma")

    if errors:
        print(f"groups.json format lint: {len(errors)} error(s) found:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        print(f"\n  Hint: run 'python3 {os.path.abspath(__file__)} --fix' to auto-fix", file=sys.stderr)
        return 1, len(errors)

    print(f"groups.json format lint: OK ({len(data)} entries, sorted, compact)")
    return 0, 0


def main():
    parser = argparse.ArgumentParser(description="Lint groups.json for format compliance.")
    parser.add_argument("path", nargs="?", default=None, help="Path to groups.json")
    parser.add_argument("--fix", action="store_true", help="Auto-fix formatting issues in-place")
    args = parser.parse_args()

    groups_path = args.path or os.path.join(os.path.dirname(__file__), "groups.json")

    if args.fix:
        ok = reformat_groups(groups_path)
        if not ok:
            return 1
        # Re-lint after fixing to confirm
        return lint_groups(groups_path)[0]

    return lint_groups(groups_path)[0]


if __name__ == "__main__":
    sys.exit(main())
