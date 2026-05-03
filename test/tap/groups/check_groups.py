#!/usr/bin/env python3
"""
Check consistency between groups.json and TAP tests on disk.

Default (executable) mode — requires a prior build:
1. All tests listed in groups.json exist as executable files on disk.
   If not: ERROR (exit 1).
2. All executable test files on disk are listed in groups.json.
   If not: ERROR (exit 1).

Source mode (--source) — no build required, intended for PR lint CI:
1. All TAP source files (*-t.{cpp,sh,py,php} and executable *-t scripts)
   are listed in groups.json. If not: ERROR (exit 1).
2. Entries in groups.json with no matching source: NOTE (exit 0). Several
   binaries are produced from differently-named sources via explicit
   Makefile targets (e.g. mysql_reconnect_libmariadb-t from
   mysql_reconnect.cpp), so this direction is informational only.

Usage:
    python3 check_groups.py [--tap-root /path/to/test/tap] [--source]

Exit codes:
    0 - All checks passed (notes are OK)
    1 - Consistency error found
"""

import argparse
import json
import os
import stat
import sys

SCRIPT_EXTS = (".cpp", ".sh", ".py", ".php")


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


def find_source_tests(tap_root):
    """Find all TAP test source files under the TAP test directories.

    Recognized forms:
      - foo-t.cpp / foo-t.sh / foo-t.py / foo-t.php  -> expected binary 'foo-t'
      - executable file named 'foo-t' with no extension -> 'foo-t'

    Unlike find_executable_tests(), this does not require a build: it scans
    the source tree, so it works on a fresh checkout in a lint CI job.
    """
    scan_roots = [
        os.path.join(tap_root, "tests"),
        os.path.join(tap_root, "tests_with_deps"),
    ]

    sources = set()
    for scan_root in scan_roots:
        if not os.path.isdir(scan_root):
            continue
        for dirpath, _, filenames in os.walk(scan_root):
            for entry in filenames:
                if entry.endswith("-t"):
                    sources.add(entry)
                    continue
                for ext in SCRIPT_EXTS:
                    if entry.endswith("-t" + ext):
                        sources.add(entry[: -len(ext)])
                        break
    return sources


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
    parser.add_argument(
        "--source",
        action="store_true",
        help="Check groups.json against TAP source files instead of built "
             "executables. Use this in lint CI where no build has run.",
    )
    args = parser.parse_args()

    tap_root = os.path.realpath(args.tap_root)
    groups_path = os.path.join(tap_root, "groups", "groups.json")

    if not os.path.isfile(groups_path):
        print(f"ERROR: groups.json not found at {groups_path}", file=sys.stderr)
        return 1

    groups_tests = load_groups(groups_path)

    if args.source:
        found_tests = find_source_tests(tap_root)
        kind = "source"
        missing_on_disk_is_error = False
    else:
        found_tests = find_executable_tests(tap_root)
        kind = "executable"
        missing_on_disk_is_error = True

    exit_code = 0

    # --- Check 1: entries in groups.json with no matching file on disk ---
    in_groups_not_found = sorted(groups_tests - found_tests)
    if in_groups_not_found:
        label = "ERROR" if missing_on_disk_is_error else "NOTE"
        print(
            f"{label}: {len(in_groups_not_found)} test(s) in groups.json have no "
            f"matching {kind} file on disk:"
        )
        for t in in_groups_not_found:
            print(f"  - {t}")
        print()
        if missing_on_disk_is_error:
            exit_code = 1

    # --- Check 2: files on disk not in groups.json (always ERROR) ---
    on_disk_not_in_groups = sorted(found_tests - groups_tests)
    if on_disk_not_in_groups:
        print(f"ERROR: {len(on_disk_not_in_groups)} {kind} test(s) missing from groups.json:")
        for t in on_disk_not_in_groups:
            print(f"  - {t}")
        exit_code = 1
    else:
        print(
            f"OK: All {len(found_tests)} {kind} tests are registered "
            f"in groups.json ({len(groups_tests)} total entries)."
        )

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
