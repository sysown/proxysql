#!/usr/bin/env python3
"""
Lint TAP-group *coverage* wiring (infra + GitHub Actions workflow).

This complements lint_groups_json.py (which only checks JSON *format*).
It answers two questions for every group referenced in groups.json:

  A. Does the group's infras.lst reference an infra that does not exist?
     (a "phantom" group that cannot start any backend, e.g. the old
     mysql91 / mysql92 stubs, gr and non-gr)

  B. Can any GitHub Actions workflow actually select the group, i.e. does
     it run in CI at all -- or only locally via run-tests-isolated.bash?

     A group counts as wired if a CI-<group>.yml caller exists, OR its name
     appears in any workflow on this branch or on origin/GH-Actions (where
     the reusable half of every pair lives), OR it belongs to a dynamically
     discovered family. Groups with no infras.lst are checked too: needing no
     backend does not mean needing no workflow. Checking only for a
     CI-<group>.yml filename on this branch is what let no-infra-g1 sit
     unwired since it was created.

Group -> infra resolution mirrors ensure-infras.bash:
  BASE_GROUP = <group> with a trailing -g<N>/_g<N> stripped; infra names
  are read from test/tap/groups/<group>/infras.lst, falling back to
  test/tap/groups/<BASE_GROUP>/infras.lst. Comment (#...) and blank lines
  are ignored; tokens containing '$' are env placeholders and are skipped
  (cannot be resolved statically).

Severity: WARN-ONLY by default -- this never reds CI on its own. Known,
tracked coverage gaps live in ALLOWLIST_NO_WORKFLOW so only *newly*
introduced groups without a workflow are called out as NEW.
Pass --strict to turn phantom-infra and NEW missing-workflow findings into
a non-zero exit (for a future opt-in enforcement step).

Usage:
    python3 lint_group_coverage.py [--strict] [path/to/groups.json]
"""

import argparse
import json
import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", ".."))

# Families (BASE_GROUP) that have a real dbdeployer infra but intentionally
# have no GitHub Actions workflow yet. These are known/tracked gaps: the
# linter stays quiet about them so it can loudly flag anything NEW. Trim
# this list as workflows are added (e.g. mysql90-gr/mysql93-gr/mysql95-gr
# were removed from here once their CI-*.yml callers landed).
ALLOWLIST_NO_WORKFLOW = {
    "legacy-binlog",
    "mysql84-binlog",
    "mysql90",
    "mysql90-binlog",
    "mysql93",
    "mysql95",
    "mysql95-binlog",
    "mysqlx-soak",
    "pgsql17-repl",
    # --- pre-existing debt surfaced when the check was widened -------------
    # These were invisible while the linter only inspected infra-backed groups
    # and only looked for a CI-<group>.yml filename. They are unwired on both
    # branches, i.e. tests registered in them do not run in CI. Allowlisted so
    # the linter reports only genuinely NEW gaps; trim as workflows land.
    "mysql-auto_increment_delay_multiplex=0",
    "mysql-multiplexing=false",
    "mysql-query_digests=0",
    "mysql-query_digests_keep_comment=1",
    "mysql91-gr",
    "mysql92-gr",
    "mysqlx-e2e",
    "pgsql-repl",
    "todo",
    # NOTE: 'no-infra' is deliberately NOT allowlisted. It is a real, currently
    # unwired group (5 tests, incl. reg_test_5363_admin_monitor_caching_sha2-t)
    # and finding it is what prompted widening this check. Add CI-no-infra-g1.yml
    # (+ ci-no-infra-g1.yml@GH-Actions) rather than silencing it here.
}


def base_group(group):
    return re.sub(r"[-_]g\d+$", "", group)


def read_infra_names(group):
    """Return the list of concrete infra names for a group, or None if the
    group declares no infras.lst (legitimate for admin-only groups)."""
    base = base_group(group)
    candidates = [
        os.path.join(REPO_ROOT, "test", "tap", "groups", group, "infras.lst"),
        os.path.join(REPO_ROOT, "test", "tap", "groups", base, "infras.lst"),
    ]
    for cand in dict.fromkeys(candidates):  # dedupe when group == base
        if not os.path.isfile(cand):
            continue
        names = []
        with open(cand, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                # ensure-infras reads line-by-line; splitting on whitespace
                # is a harmless superset for the one-name-per-line files we
                # have. Skip env placeholders (${INFRA}/${INFRA_TYPE}) -- they
                # cannot be resolved statically.
                for token in line.split():
                    if "$" not in token:
                        names.append(token)
        return names
    return None


# Group families whose CI wiring is generated at run time rather than written
# out as a CI-<group>.yml, so a static name lookup cannot see them.
#   cluster_sim_*  -> CI-cluster-simulator.yml builds its matrix from
#                     `test/infra/control/cluster-simulator-ci.bash discover`,
#                     which selects every groups.json entry starting with this
#                     prefix. Adding such a group wires it up automatically.
DYNAMIC_DISCOVERY_PREFIXES = ("cluster_sim_",)


def _local_workflow_blob():
    """Filenames + contents of .github/workflows on the current branch."""
    parts = []
    wf_dir = os.path.join(REPO_ROOT, ".github", "workflows")
    for root, _dirs, files in os.walk(wf_dir):
        for name in files:
            parts.append(name)
            try:
                with open(os.path.join(root, name), encoding="utf-8", errors="replace") as f:
                    parts.append(f.read())
            except OSError:
                pass
    return "\n".join(parts)


def _gh_actions_workflow_blob():
    """Filenames + contents of .github/workflows on origin/GH-Actions.

    Returns None when the ref is unavailable (shallow clone, no remote, no git).
    The caller must then skip the workflow check rather than report false gaps:
    the reusable half of every workflow pair lives on that branch, so without it
    we cannot tell a genuinely unwired group from one wired only over there.
    """
    try:
        listing = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", "origin/GH-Actions", ".github/workflows"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, check=False,
        )
        if listing.returncode != 0:
            return None
        files = listing.stdout.split()
        if not files:
            return None
        parts = ["\n".join(files)]
        for path in files:
            blob = subprocess.run(
                ["git", "show", f"origin/GH-Actions:{path}"],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, check=False,
            )
            if blob.returncode == 0:
                parts.append(blob.stdout)
        return "\n".join(parts)
    except (OSError, subprocess.SubprocessError):
        return None


def workflow_covers(group, local_blob, gh_blob):
    """True when this group can actually be selected by some CI workflow.

    A group is wired up if ANY of these hold:
      1. a caller file is named after it (.github/workflows/CI-<group>.yml)
      2. its name appears anywhere in a workflow on this branch -- covers
         groups selected by an env/matrix entry rather than a dedicated file,
         e.g. 'TAP_GROUP: mysqlx-tsan-g1' inside a larger workflow
      3. its name appears in a workflow on origin/GH-Actions (the reusable half)
      4. it belongs to a family discovered dynamically (see
         DYNAMIC_DISCOVERY_PREFIXES)

    Checking only (1) is what let no-infra-g1 go unnoticed in both directions:
    it has no dedicated caller, and matching names in file *contents* is needed
    to avoid flagging the matrix-driven groups that are genuinely wired.
    """
    if group.startswith(DYNAMIC_DISCOVERY_PREFIXES):
        return True
    for ext in ("yml", "yaml"):
        if os.path.isfile(os.path.join(REPO_ROOT, ".github", "workflows", f"CI-{group}.{ext}")):
            return True
    if group in local_blob:
        return True
    if gh_blob is not None and group in gh_blob:
        return True
    return False


def classify_group(group, local_blob, gh_blob, check_workflows=True):
    """Return (missing_infras, workflow_state) for one group.

    missing_infras: list of infra names referenced but absent on disk.
    workflow_state: None when a workflow covers the group, the group is a
                    phantom, or workflow checking is disabled;
                    "new" / "known" when nothing in CI can select the group.

    NOTE: an absent or empty infras.lst does NOT exempt a group. Such a group
    still needs a workflow to ever run in CI -- it simply needs no backend.
    Exempting them is exactly why no-infra-g1 was never reported despite having
    no CI wiring on either branch since it was created.
    """
    concrete = read_infra_names(group) or []
    missing = [
        n for n in concrete
        if not os.path.isdir(os.path.join(REPO_ROOT, "test", "infra", n))
    ]
    workflow_state = None
    # A phantom group cannot start its backend, so demanding a workflow for it
    # would just be noise on top of the phantom finding.
    if check_workflows and not missing and not workflow_covers(group, local_blob, gh_blob):
        workflow_state = "known" if base_group(group) in ALLOWLIST_NO_WORKFLOW else "new"
    return missing, workflow_state


def collect_groups(data):
    groups = set()
    for group_list in data.values():
        for g in group_list:
            if not g.startswith("@"):
                groups.add(g)
    return groups


def resolve_groups_path(groups_path):
    """Resolve to a real path inside the repo. Guards against a path
    argument escaping the repository tree (pythonsecurity:S8707)."""
    resolved = os.path.realpath(groups_path)
    if os.path.commonpath([resolved, REPO_ROOT]) != REPO_ROOT:
        raise ValueError(f"refusing to read groups.json outside repo: {resolved}")
    return resolved


def lint_coverage(groups_path, strict=False):
    groups_path = resolve_groups_path(groups_path)
    with open(groups_path, encoding="utf-8") as f:
        data = json.load(f)

    local_blob = _local_workflow_blob()
    gh_blob = _gh_actions_workflow_blob()
    check_workflows = gh_blob is not None
    if not check_workflows:
        print("NOTE  origin/GH-Actions is not available (shallow clone or missing "
              "remote); skipping the missing-workflow check. The reusable half of "
              "every workflow pair lives on that branch, so without it any finding "
              "would be a guess. Run `git fetch origin GH-Actions` to enable it.",
              file=sys.stderr)

    phantom = []          # (group, missing_infra)
    missing_wf_new = []
    missing_wf_known = []
    for group in sorted(collect_groups(data)):
        missing, wf_state = classify_group(group, local_blob, gh_blob, check_workflows)
        phantom.extend((group, infra) for infra in missing)
        if wf_state == "new":
            missing_wf_new.append(group)
        elif wf_state == "known":
            missing_wf_known.append(group)

    for group, infra in phantom:
        print(f"WARN [phantom-infra]  group '{group}': infras.lst references "
              f"missing infra 'test/infra/{infra}'", file=sys.stderr)
    for group in missing_wf_new:
        print(f"WARN [missing-workflow:NEW]  group '{group}' is not selectable by "
              f"any workflow on this branch or on origin/GH-Actions -- tests "
              f"registered in it never run in CI. Add the caller "
              f".github/workflows/CI-{group}.yml (+ ci-{group}.yml@GH-Actions), or "
              f"if intentional add '{base_group(group)}' to ALLOWLIST_NO_WORKFLOW.",
              file=sys.stderr)
    for group in missing_wf_known:
        print(f"note [missing-workflow:known]  group '{group}' has no workflow "
              f"(allowlisted family '{base_group(group)}')")

    print(
        f"\ngroup coverage lint: {len(collect_groups(data))} groups | "
        f"phantom-infra={len(phantom)} | "
        f"missing-workflow NEW={len(missing_wf_new)} known={len(missing_wf_known)}"
    )

    if strict and (phantom or missing_wf_new):
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
