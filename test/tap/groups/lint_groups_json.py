#!/usr/bin/env python3
"""
Lint groups.json for format compliance.

Enforces the conventions documented in test/tap/groups/README.md:
  - Valid JSON
  - One entry per line, compact arrays (no multi-line)
  - Format: '  "test-name-t" : [ "group1","group2" ],' (or no comma for last)
  - Keys sorted alphabetically
  - File starts with '{' and ends with '}'

Exit codes:
    0 - Format is correct
    1 - Format violations found
"""

import json
import os
import re
import sys


def main():
    groups_path = os.path.join(os.path.dirname(__file__), "groups.json")
    if len(sys.argv) > 1:
        groups_path = sys.argv[1]

    if not os.path.isfile(groups_path):
        print(f"ERROR: {groups_path} not found", file=sys.stderr)
        return 1

    with open(groups_path, "r") as f:
        raw = f.read()

    lines = raw.split("\n")
    errors = []

    # Check 1: valid JSON
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        errors.append(f"Invalid JSON: {e}")
        # Can't do further checks
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if not isinstance(data, dict):
        errors.append("Top-level value must be a JSON object")
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # Check 2: first and last lines
    if not lines or lines[0].strip() != "{":
        errors.append("Line 1: must be '{'")
    if lines[-1].strip() == "":
        # Allow trailing newline — check second-to-last
        if len(lines) < 2 or lines[-2].strip() != "}":
            errors.append(f"Last non-empty line: must be '}}'")
    elif lines[-1].strip() != "}":
        errors.append(f"Last line: must be '}}'")

    # Check 3: each entry is one line with correct format
    entry_pattern = re.compile(
        r'^  "([^"]+)" : \[ .+ \](,?)$'
    )
    keys_in_order = []
    entry_lines = lines[1:]  # skip opening brace
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
        # Find first out-of-order key
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
        return 1

    print(f"groups.json format lint: OK ({len(data)} entries, sorted, compact)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
