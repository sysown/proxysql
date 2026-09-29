#!/usr/bin/env python3
"""Lint test/tap/groups/tier-sweep.lst against groups.json and the CI wiring.

CI-tier-sweep (the merge-only v3.0/v3.1 sweep) reads its work list from
tier-sweep.lst. That file is the one piece of the sweep which is *data* rather
than logic, so it is the one piece that can silently rot. Two ways it rots:

  A. A name is listed that is not in groups.json (renamed/removed group). The
     sweep would then try to run a group that does not exist.

  B. A group is wired into regular CI and runnable on a downgrade tier, but is
     NOT listed. This is the dangerous direction: the sweep quietly stops
     covering a group, and because it is advisory nobody notices.

This check fails on A and on B, and warns (never fails) on groups that are
listed but no longer runnable on any sweep tier, since that is usually a
harmless tag change rather than a wiring mistake.

The "wired" definition must stay identical to the one in
test/tap/groups/lint_group_coverage.py: a CI-<group>.yml caller on this branch,
or the group name appearing in any workflow on this branch or on
origin/GH-Actions (where the reusable half of every caller/reusable pair
lives). Divergence between the two scripts would make the list and the lint
disagree, so if you change one, change both.

Usage:
  check_tier_sweep_groups.py [rev]        # default: HEAD (groups.json) and HEAD+origin/GH-Actions
"""
from __future__ import annotations

import collections
import json
import pathlib
import re
import subprocess
import sys

# NOTE: deliberately no `packaging` here. The lint job's environment is not
# guaranteed to have it, and every other script in this directory parses
# versions without it. A dotted triple compared numerically is sufficient here
# (3.10 > 3.9, which a string compare gets wrong).
#
# The "wired" definition must stay identical to the one in
# test/tap/groups/lint_group_coverage.py: a CI-<group>.yml caller on this
# branch, the group name appearing in any workflow on this branch or on
# origin/GH-Actions (where the reusable half of every caller/reusable pair
# lives), or membership of a dynamically discovered family. Divergence between
# the two scripts would make the list and the lint disagree, so if you change
# one, change both.

REPO = pathlib.Path(__file__).resolve().parents[3]
GROUPS_JSON = REPO / "test/tap/groups/groups.json"
SWEEP_LIST = REPO / "test/tap/groups/tier-sweep.lst"
ACTIONS_REF = "origin/GH-Actions"

# Must mirror DYNAMIC_DISCOVERY_PREFIXES in lint_group_coverage.py. These
# families have no CI-<group>.yml caller; a workflow discovers them at run time
# (CI-cluster-simulator.yml runs `cluster-simulator-ci.bash discover`, which
# selects every cluster_sim_* group from groups.json). Omitting this is how six
# cluster_sim_* groups stayed out of the sweep while the checker still
# reported OK.
DYNAMIC_DISCOVERY_PREFIXES = ("cluster_sim_",)

# Groups that regular CI runs, but the SWEEP's stock build cannot run.
#
# "Wired into regular CI" is necessary but not sufficient. A group can be
# exercised in CI only because that workflow produced a build and a runtime
# the sweep does not. cluster_sim_* is exactly that case:
# CI-cluster-simulator.yml runs `make build_cluster_simulator` and then
# `cluster-simulator-ci.bash stage`, and the group env files point at
# test/deps/cluster_simulator/cluster_simulator and its tests tree. The sweep
# builds a stock `make ubuntu24-tap` handoff, which does not build that dep,
# and run-tests-isolated.bash has no simulator handling whatsoever. So these
# groups would be selected, find a missing runtime, and fail -- every sweep
# run, forever, for a reason that has nothing to do with the tier.
#
# Listing them is therefore a deliberate exclusion, not an oversight. Removing
# it means teaching the sweep to build and stage the simulator, which is a
# separate piece of work.
BUILD_UNSUPPORTED_PREFIXES = ("cluster_sim_",)

# The two tiers the sweep builds, as upper bounds. Matched to the Makefile's
# GIT_VERSION bump for each feature tier (Makefile:82-92): a v3.1 build reports
# 3.1.x and a v3.0 build reports 3.0.x, so anything up to the next minor counts.
TIER_CEILINGS = {"v30": "3.0.99", "v31": "3.1.99"}

def workflow_blob(ref: str) -> str:
    """Filenames + contents of .github/workflows at `ref`, as one string.

    Substring matching against this blob is what lint_group_coverage.py does
    (it tests `group in blob`). Matching on a `-g<N>` token regex instead --
    which is what this file did originally -- silently misses any group whose
    name has no `-g<N>` suffix. There is exactly one today, `pgsql-repl`, and it
    was consequently excluded from the sweep while this checker reported OK.
    So: mirror the reference implementation rather than approximating it.
    """
    parts: list[str] = []
    for path in git(
        "ls-tree", "-r", "--name-only", ref, ".github/workflows/", check=True
    ).split():
        parts.append(path)
        try:
            parts.append(git("show", f"{ref}:{path}", check=True))
        except SystemExit:
            raise
    return "\n".join(parts)


def parse_version(value: str) -> tuple[int, ...]:
    """'3.1.11' -> (3, 1, 11). Numeric, so 3.10 sorts above 3.9."""
    parts: list[int] = []
    for chunk in value.strip().split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def git(*args: str, check: bool = False) -> str:
    """Run git and return stdout.

    `check=False` is for genuinely optional probes (is origin/GH-Actions
    fetched?). `check=True` is for anything whose failure would silently change
    the verdict: git() returning "" on a real error used to empty `wired`, and
    check (B) then passed without flagging anything -- a green lint that had
    checked nothing.
    """
    proc = subprocess.run(
        ("git", *args), cwd=REPO, capture_output=True, text=True
    )
    if check and proc.returncode != 0:
        print(
            f"ERROR: `git {' '.join(args)}` failed (exit {proc.returncode}): "
            f"{proc.stderr.strip()}",
            file=sys.stderr,
        )
        sys.exit(1)
    return proc.stdout if proc.returncode == 0 else ""


def wired_group_names(refs: list[str], all_groups: set[str]) -> set[str]:
    """Groups selectable by some workflow, per lint_group_coverage.py's rule.

    Three conditions, in the reference implementation's spirit:
      (a) a CI-<group>.yml caller exists;
      (b) the group name appears anywhere in a workflow's filename or content
          (substring, not a token regex -- see workflow_blob);
      (c) the group belongs to a dynamically discovered family.
    """
    found: set[str] = set()
    for ref in refs:
        blob = workflow_blob(ref)
        for group in all_groups:
            if group in blob:
                found.add(group)
        for path in git(
            "ls-tree", "-r", "--name-only", ref, ".github/workflows/", check=True
        ).split():
            m = re.match(r"\.github/workflows/[Cc]I-(.+)\.ya?ml$", path)
            if m:
                found.add(m.group(1))
    return found


def load_min_versions() -> dict[str, tuple[int, ...]]:
    """test name -> highest @proxysql_min_version it requires."""
    with GROUPS_JSON.open(encoding="utf-8") as stream:
        groups = json.load(stream)

    required: dict[str, tuple[int, ...]] = {}
    for name, entries in groups.items():
        need = (0, 0, 0)
        for entry in entries:
            if isinstance(entry, str) and entry.startswith("@proxysql_min_version:"):
                need = parse_version(entry.split(":", 1)[1])
                break
        required[name] = need
    return required


def load_members(required: dict[str, tuple[int, ...]]) -> dict[str, list[str]]:
    with GROUPS_JSON.open(encoding="utf-8") as stream:
        groups = json.load(stream)
    members: dict[str, list[str]] = collections.defaultdict(list)
    for name, entries in groups.items():
        for entry in entries:
            if not str(entry).startswith("@"):
                members[entry].append(name)
    return members


def survivors(group: str, members: dict[str, list[str]],
              required: dict[str, tuple[int, ...]], ceiling: str) -> int:
    limit = parse_version(ceiling)
    return sum(1 for t in members.get(group, []) if required[t] <= limit)


def read_sweep_list() -> list[str]:
    names: list[str] = []
    for line in SWEEP_LIST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        names.append(line)
    return names


def main() -> int:
    problems: list[str] = []
    warnings: list[str] = []

    if not GROUPS_JSON.exists():
        print(f"ERROR: {GROUPS_JSON} not found", file=sys.stderr)
        return 1
    if not SWEEP_LIST.exists():
        print(f"ERROR: {SWEEP_LIST} not found", file=sys.stderr)
        return 1

    required = load_min_versions()
    members = load_members(required)
    listed = read_sweep_list()

    refs = ["HEAD"]
    if git("rev-parse", "--verify", "--quiet", ACTIONS_REF).strip():
        refs.append(ACTIONS_REF)
    else:
        warnings.append(
            f"{ACTIONS_REF} is not fetched; only this branch's workflows were "
            "examined, so some groups may look unwired that are not"
        )
    wired = wired_group_names(refs, set(members))
    # Families selected at run time by a workflow's own discovery step have no
    # CI-<group>.yml caller and never appear in a workflow's text, so they are
    # wired by definition (mirrors lint_group_coverage.py).
    dynamic = {
        g for g in members
        if g.startswith(DYNAMIC_DISCOVERY_PREFIXES)
    }
    wired |= dynamic

    # (A) listed but not a real group -> the sweep would fail on it
    for name in listed:
        if name not in members:
            problems.append(
                f"{name}: listed in tier-sweep.lst but absent from groups.json"
            )

    duplicates = [n for n, c in collections.Counter(listed).items() if c > 1]
    for name in duplicates:
        problems.append(f"{name}: listed more than once in tier-sweep.lst")

    def sweep_can_build(group: str) -> bool:
        """False for families needing a build the sweep does not produce."""
        return not group.startswith(BUILD_UNSUPPORTED_PREFIXES)

    runnable_any = [
        g for g in members
        if sweep_can_build(g)
        and any(survivors(g, members, required, c) for c in TIER_CEILINGS.values())
    ]

    # (B) wired + runnable on some tier but not listed -> silently dropped coverage
    for group in sorted(set(runnable_any) & wired):
        if group not in listed:
            problems.append(
                f"{group}: wired into regular CI and runnable on at least one "
                "sweep tier, but missing from tier-sweep.lst"
            )

    # a listed group the sweep cannot build -> would fail every run
    for name in listed:
        if name in members and not sweep_can_build(name):
            problems.append(
                f"{name}: listed, but the sweep's stock build cannot run it "
                "(needs a dedicated build/runtime); remove it or teach the "
                "sweep to build that first"
            )

    # listed but now dead on every tier -> harmless tag change, just note it
    for name in listed:
        if name in members and not any(
            survivors(name, members, required, c) for c in TIER_CEILINGS.values()
        ):
            warnings.append(
                f"{name}: listed, but every test is gated out on v3.0 AND v3.1; "
                "it will always skip"
            )

    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)

    total = sum(
        survivors(g, members, required, TIER_CEILINGS["v30"]) for g in listed
    )
    print(
        f"tier-sweep.lst: {len(listed)} groups "
        f"({total} test-runs on v3.0, refs={refs})"
    )
    if problems:
        print(
            f"FAIL: tier sweep group list is out of sync with groups.json/CI "
            f"({len(problems)} problem(s))",
            file=sys.stderr,
        )
        return 1
    print("tier-sweep.lst OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
