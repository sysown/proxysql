#!/usr/bin/env python3
"""
Check consistency between groups.json and executable TAP tests on disk.

Two checks:
1. All tests listed in groups.json exist as executable files on disk.
   If not: NOTE (exit 0). Tests may not be built yet or may be feature-gated.
2. All executable test files on disk are listed in groups.json.
   If not: ERROR (exit 1).

Usage:
    python3 check_groups.py [--tap-root /path/to/test/tap]

Exit codes:
    0 - All executable tests are in groups.json (notes are OK)
    1 - Executable tests found that are missing from groups.json
"""

import argparse
import json
import os
import stat
import sys


def find_executable_tests(tap_root):
    """Find all executable test files (*-t) under the TAP test directories.

    This includes ELF binaries, scripts (PHP, Python, shell), symlinks, etc.
    Anything that is executable and ends with -t is considered a runnable test.
    """
    scan_roots = [
        os.path.join(tap_root, "tests"),
        os.path.join(tap_root, "tests_with_deps"),
    ]

    executable = set()
    for scan_root in scan_roots:
        if not os.path.isdir(scan_root):
            continue
        for dirpath, _, filenames in os.walk(scan_root):
            for entry in filenames:
                path = os.path.join(dirpath, entry)
                # Must be a file ending in -t, executable (any type: ELF, script, symlink)
                if (
                    entry.endswith("-t")
                    and os.path.isfile(path)
                    and not entry.endswith(".cpp")
                    and os.access(path, os.X_OK)
                ):
                    executable.add(entry)

    return executable


def load_groups(groups_path):
    """Load test names from groups.json.

    Entries whose keys start with '@' are metadata tags (e.g. @proxysql_min_version)
    and are not test names, so they are excluded.
    """
    with open(groups_path, "r") as f:
        data = json.load(f)
    return {k for k in data.keys() if not k.startswith("@")}


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
    executable_tests = find_executable_tests(tap_root)

    exit_code = 0

    # --- Check 1: tests in groups.json but not found on disk (WARNING) ---
    in_groups_not_found = sorted(groups_tests - executable_tests)
    if in_groups_not_found:
        print(f"NOTE: {len(in_groups_not_found)} test(s) in groups.json are not yet available on disk "
              f"(not built, or feature-gated):")
        for t in in_groups_not_found:
            print(f"  - {t}")
        print()

    # --- Check 2: executable tests not in groups.json (ERROR) ---
    on_disk_not_in_groups = sorted(executable_tests - groups_tests)
    if on_disk_not_in_groups:
        print(f"ERROR: {len(on_disk_not_in_groups)} executable test(s) missing from groups.json:")
        for t in on_disk_not_in_groups:
            print(f"  - {t}")
        exit_code = 1
    else:
        print(
            f"OK: All {len(executable_tests)} executable tests are registered "
            f"in groups.json ({len(groups_tests)} total entries)."
        )

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
