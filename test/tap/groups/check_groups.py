#!/usr/bin/env python3
"""
Check consistency between groups.json and compiled TAP test binaries.

Two checks:
1. All tests listed in groups.json are compiled/ready to run.
   If not: WARNING (exit 0).
2. All compiled test binaries are listed in groups.json.
   If not: ERROR (exit 1).

Usage:
    python3 check_groups.py [--tap-root /path/to/test/tap]

Exit codes:
    0 - All compiled tests are in groups.json (warnings are OK)
    1 - Compiled tests found that are missing from groups.json
"""

import argparse
import json
import os
import stat
import sys


def find_compiled_tests(tap_root):
    """Find all compiled test binaries (*-t) under the TAP test directories."""
    test_dirs = [
        os.path.join(tap_root, "tests"),
        os.path.join(tap_root, "tests", "unit"),
        os.path.join(tap_root, "tests_with_deps", "deprecate_eof_support"),
    ]

    compiled = set()
    for d in test_dirs:
        if not os.path.isdir(d):
            continue
        for entry in os.listdir(d):
            path = os.path.join(d, entry)
            # Must be a file ending in -t, executable, and an ELF binary (not .cpp, .py, etc.)
            if (
                entry.endswith("-t")
                and os.path.isfile(path)
                and not entry.endswith(".cpp")
                and os.access(path, os.X_OK)
                and _is_elf(path)
            ):
                compiled.add(entry)

    return compiled


def _is_elf(path):
    """Check if a file is an ELF binary by reading the magic bytes."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            return magic == b"\x7fELF"
    except (OSError, IOError):
        return False


def load_groups(groups_path):
    """Load test names from groups.json."""
    with open(groups_path, "r") as f:
        data = json.load(f)
    return set(data.keys())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tap-root",
        default=os.path.join(os.path.dirname(__file__), ".."),
        help="Path to test/tap/ directory (default: auto-detect from script location)",
    )
    args = parser.parse_args()

    tap_root = os.path.realpath(args.tap_root)
    groups_path = os.path.join(tap_root, "groups", "groups.json")

    if not os.path.isfile(groups_path):
        print(f"ERROR: groups.json not found at {groups_path}", file=sys.stderr)
        return 1

    groups_tests = load_groups(groups_path)
    compiled_tests = find_compiled_tests(tap_root)

    exit_code = 0

    # --- Check 1: tests in groups.json but not compiled (WARNING) ---
    in_groups_not_compiled = sorted(groups_tests - compiled_tests)
    if in_groups_not_compiled:
        print(f"WARNING: {len(in_groups_not_compiled)} test(s) in groups.json are not compiled:")
        for t in in_groups_not_compiled:
            print(f"  - {t}")
        print()

    # --- Check 2: compiled tests not in groups.json (ERROR) ---
    compiled_not_in_groups = sorted(compiled_tests - groups_tests)
    if compiled_not_in_groups:
        print(f"ERROR: {len(compiled_not_in_groups)} compiled test(s) missing from groups.json:")
        for t in compiled_not_in_groups:
            print(f"  - {t}")
        exit_code = 1
    else:
        print(
            f"OK: All {len(compiled_tests)} compiled test binaries are registered "
            f"in groups.json ({len(groups_tests)} total entries)."
        )

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
