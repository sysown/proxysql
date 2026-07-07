#!/usr/bin/env python3
"""
Lint TAP-group *coverage* wiring (infra + GitHub Actions workflow).

This complements lint_groups_json.py (which only checks JSON *format*).
It answers two questions for every group referenced in groups.json:

  A. Does the group's infras.lst reference an infra that does not exist?
     (a "phantom" group that cannot start any backend, e.g. the old
     mysql91-gr / mysql92-gr stubs)

  B. Does a group that DOES have a real dbdeployer infra lack a GitHub
     Actions caller workflow (.github/workflows/CI-<group>.yml), i.e. it
     can run locally via run-tests-isolated.bash but never runs in CI?

Group -> infra resolution mirrors ensure-infras.bash:
  BASE_GROUP = <group> with a trailing -g<N>/_g<N> stripped; infra names
  are read from test/tap/groups/<group>/infras.lst, falling back to
  test/tap/groups/<BASE_GROUP>/infras.lst. Comment (#...) and blank lines
  are ignored; tokens containing '$' are env placeholders and are skipped
  (cannot be resolved statically).

Severity: WARN-ONLY by default -- this never reds CI on its own. Known,
tracked coverage gaps live in ALLOWLIST_NO_WORKFLOW so only *newly*
introduced infra-backed groups without a workflow are called out as NEW.
Pass --strict to turn phantom-infra and NEW missing-workflow findings into
a non-zero exit (for a future opt-in enforcement step).

Usage:
    python3 lint_group_coverage.py [--strict] [path/to/groups.json]
"""

import argparse
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", ".."))

# Families (BASE_GROUP) that have a real dbdeployer infra but intentionally
# have no GitHub Actions workflow yet. These are known/tracked gaps: the
# linter stays quiet about them so it can loudly flag anything NEW. Trim
# this list as workflows are added (e.g. mysql90-gr/mysql93-gr/mysql95-gr
# were removed from here once their CI-*.yml callers landed).
ALLOWLIST_NO_WORKFLOW = {
    "ai",
    "legacy-binlog",
    "mysql84-binlog",
    "mysql90",
    "mysql90-binlog",
    "mysql93",
    "mysql95",
    "mysql95-binlog",
    "mysqlx-soak",
    "pgsql17-repl",
}


def base_group(group):
    return re.sub(r"[-_]g\d+$", "", group)


def read_infra_names(group):
    """Return the list of concrete infra names for a group, or None if the
    group declares no infras.lst (legitimate for admin-only groups)."""
    base = base_group(group)
    for cand in (
        os.path.join(REPO_ROOT, "test", "tap", "groups", group, "infras.lst"),
        os.path.join(REPO_ROOT, "test", "tap", "groups", base, "infras.lst"),
    ):
        if os.path.isfile(cand):
            names = []
            with open(cand) as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if not line or "$" in line:  # blank/comment or env placeholder
                        continue
                    names.append(line)
            return names
    return None


def workflow_exists(group):
    return os.path.isfile(
        os.path.join(REPO_ROOT, ".github", "workflows", f"CI-{group}.yml")
    )


def lint_coverage(groups_path, strict=False):
    with open(groups_path) as f:
        data = json.load(f)

    groups = set()
    for v in data.values():
        for g in v:
            if not g.startswith("@"):
                groups.add(g)

    phantom = []          # (group, missing_infra)
    missing_wf_new = []   # infra-backed, no workflow, NOT allowlisted
    missing_wf_known = [] # infra-backed, no workflow, allowlisted

    for group in sorted(groups):
        infra_names = read_infra_names(group)
        concrete = infra_names or []
        missing = [
            n for n in concrete
            if not os.path.isdir(os.path.join(REPO_ROOT, "test", "infra", n))
        ]
        for n in missing:
            phantom.append((group, n))

        has_real_infra = bool(concrete) and not missing
        if has_real_infra and not workflow_exists(group):
            if base_group(group) in ALLOWLIST_NO_WORKFLOW:
                missing_wf_known.append(group)
            else:
                missing_wf_new.append(group)

    for group, infra in phantom:
        print(f"WARN [phantom-infra]  group '{group}': infras.lst references "
              f"missing infra 'test/infra/{infra}'", file=sys.stderr)
    for group in missing_wf_new:
        print(f"WARN [missing-workflow:NEW]  group '{group}' has a dbdeployer "
              f"infra but no .github/workflows/CI-{group}.yml -- it will never "
              f"run in GitHub Actions. Add the caller (+ ci-{group}.yml@GH-Actions) "
              f"or, if intentional, add '{base_group(group)}' to ALLOWLIST_NO_WORKFLOW.",
              file=sys.stderr)
    for group in missing_wf_known:
        print(f"note [missing-workflow:known]  group '{group}' has infra but no "
              f"workflow (allowlisted family '{base_group(group)}')")

    print(
        f"\ngroup coverage lint: {len(groups)} groups | "
        f"phantom-infra={len(phantom)} | "
        f"missing-workflow NEW={len(missing_wf_new)} known={len(missing_wf_known)}"
    )

    fail = strict and (phantom or missing_wf_new)
    if fail:
        print("group coverage lint: FAIL (--strict)", file=sys.stderr)
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description="Lint TAP-group infra/workflow coverage.")
    parser.add_argument("path", nargs="?", default=None, help="Path to groups.json")
    parser.add_argument("--strict", action="store_true",
                        help="Exit non-zero on phantom-infra or NEW missing-workflow findings")
    args = parser.parse_args()
    groups_path = args.path or os.path.join(SCRIPT_DIR, "groups.json")
    return lint_coverage(groups_path, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
