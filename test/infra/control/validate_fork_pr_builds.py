#!/usr/bin/env python3
"""Validate the fork-PR build isolation contract.

The reusable half of every workflow pair lives on the GH-Actions branch, so
the contract spans three documents:

  <base-ref>:.github/workflows/CI-builds.yml        trusted caller
  <base-ref>:.github/workflows/CI-builds-fork.yml  fork caller
  <actions-ref>:.github/workflows/ci-builds.yml    reusable callee

A fork pull request runs untrusted code, so the fork caller must hold no
write-capable token, must not receive secrets, must only be reachable for
fork heads, and must pin the callee to an immutable commit. The callee in
turn must default to trusted, must force untrusted runs onto GitHub-hosted
runners, and must gate every privileged step behind ``inputs.trusted``.

This used to be an embedded Ruby heredoc. It is Python because the repo
already depends on PyYAML (scripts/lint/, test/scripts/lib/utils.py) and
because run-ci-lint.bash already drives its other structural checks with
python3. The Ruby needed an interpreter that is not installed on a default
dev box, and nothing in CI ever ran it.

Usage: validate_fork_pr_builds.py <base-ref> <gh-actions-ref>
"""
import re
import subprocess
import sys

import yaml

# The callee cannot run fork code on a self-hosted runner, so an untrusted
# call must not resolve to one. Mirrors the expression in ci-builds.yml.
RUNS_ON_UNTRUSTED = re.compile(
    r"\A\$\{\{\s*inputs\.trusted\s*&&\s*\("
    r".*\)\s*\|\|\s*'ubuntu-24\.04'\s*\}\}\Z",
    re.DOTALL,
)
TRUSTED_PREFIX = re.compile(r"\A\$\{\{\s*inputs\.trusted\s*&&")

# Snapshot of the build matrix as of the callee SHA pinned by
# CI-builds-fork.yml. Refresh this together with that pin. It was four
# entries until 64b1465a9 / 308c14d67 (2026-09-06) retired the duplicate
# legs. Note this couples a v3.0 lint to GH-Actions content: changing the
# matrix there is a deliberate change that has to be mirrored here.
EXPECTED_MATRIX = [("ubuntu24", "-tap-genai-gcov")]

PRIVILEGED_USES = ("LouisBrunner/checks-action", "actions/cache/", "actions/upload-artifact")
PRIVILEGED_NAME = re.compile(
    r"Pack (bin|test) cache|Pack src \+ matrix for handoff|Upload handoff|Archive artifacts"
)


def top_level_disjunction(condition):
    """True if ``condition`` has a ``||`` outside parentheses.

    A privileged step is safe when its gate cannot be satisfied without
    inputs.trusted. The dangerous shape is a TOP-LEVEL ``||``, as in
    ``inputs.trusted && a || b`` or ``(inputs.trusted && a) || b``, where
    the right operand can hold alone and bypass the guard. A ``||`` nested
    inside parentheses is already covered by the leading
    ``inputs.trusted &&`` prefix -- e.g. the ``Archive artifacts`` gate
    ``inputs.trusted && failure() && !cancelled() && (a || b)`` -- so only
    a ``||`` at paren depth 0 counts against the step.
    """
    depth = 0
    index = 0
    while index < len(condition):
        char = condition[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|":
            if condition[index + 1:index + 2] == "|" and depth == 0:
                return True
            index += 1
        index += 1
    return False


def on_key(document):
    """Return a workflow's trigger mapping.

    YAML 1.1 reads a bare ``on:`` key as the boolean True, which is what
    PyYAML does, so accept either spelling.
    """
    if "on" in document:
        return document["on"]
    return document[True]


def contains_unsafe_checkout(value):
    if isinstance(value, dict):
        return any(
            (str(key) == "allow-unsafe-pr-checkout" and child is True)
            or contains_unsafe_checkout(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(contains_unsafe_checkout(child) for child in value)
    return False


def validate(base, fork, reusable):
    """Return a list of contract violations; empty means the contract holds."""
    problems = []

    def require(condition, message):
        if not condition:
            problems.append(message)

    def fetch(mapping, key, message):
        if key not in mapping:
            problems.append(message)
            return None
        return mapping[key]

    # --- trusted caller -------------------------------------------------
    base_run = fetch(base.get("jobs", {}), "run", "trusted CI-builds has no run job")
    if base_run is not None:
        require(
            "head_repository.full_name == github.repository" in str(base_run.get("if", "")),
            "trusted CI-builds lacks same-repository guard",
        )
        require(base_run.get("permissions") == "write-all", "trusted CI-builds permission changed")
        require(base_run.get("secrets") == "inherit", "trusted CI-builds secret handoff changed")

    # --- fork caller ----------------------------------------------------
    require("pull_request" in (on_key(fork) or {}), "fork workflow is not pull_request-triggered")
    require(
        fork.get("permissions") == {"contents": "read"},
        "fork workflow permissions are not exactly contents: read",
    )
    fork_jobs = fork.get("jobs", {})
    fork_run = fetch(fork_jobs, "run", "fork workflow has no run job")
    if fork_run is not None:
        require(
            "head.repo.fork" in str(fork_run.get("if", "")),
            "fork workflow is not restricted to fork heads",
        )
        require(
            re.fullmatch(
                r"sysown/proxysql/\.github/workflows/ci-builds\.yml@[0-9a-f]{40}",
                str(fork_run.get("uses", "")),
            )
            is not None,
            "fork workflow does not pin the reusable workflow to a full commit SHA",
        )
        require(
            fork_run.get("with", {}).get("trusted") is False,
            "fork workflow does not select untrusted mode",
        )
    for name, job in fork_jobs.items():
        require("secrets" not in job, f"fork job {name!r} inherits or passes secrets")
        require("permissions" not in job, f"fork job {name!r} overrides read-only workflow permissions")

    # --- reusable callee ------------------------------------------------
    inputs = on_key(reusable).get("workflow_call", {}).get("inputs", {})
    trusted_input = inputs.get("trusted", {})
    require(trusted_input.get("default") is True, "reusable workflow lacks trusted=true default")

    builds = reusable.get("jobs", {}).get("builds")
    if builds is None:
        problems.append("reusable workflow has no builds job")
        return problems

    # The same callee serves both callers, and a called workflow may only
    # narrow the caller's token, never widen it. CI-builds-fork.yml grants
    # exactly `contents: read`, so ANY callee job asking for more makes
    # GitHub reject the whole call before a job starts -- which presents as
    # a bare `startup_failure` with zero jobs and no useful log. The
    # resolve-tap-mode job requesting `pull-requests: read` did exactly that
    # to every fork PR. Trusted runs get their scopes from the caller's
    # write-all and need no job-level block at all.
    for name, job in reusable.get("jobs", {}).items():
        requested = job.get("permissions")
        if not requested:
            continue
        for scope, level in requested.items():
            if scope != "contents" or level not in ("read", "none"):
                problems.append(
                    f"callee job {name!r} requests {scope}: {level}, which the fork "
                    f"caller does not grant; this fails the whole call at startup"
                )

    require(
        RUNS_ON_UNTRUSTED.match(str(builds.get("runs-on", ""))) is not None,
        "untrusted mode does not force ubuntu-24.04",
    )

    try:
        actual_matrix = sorted(
            (entry["dist"], entry["type"])
            for entry in builds["strategy"]["matrix"]["include"]
        )
    except (KeyError, TypeError) as error:
        problems.append(f"cannot read build matrix: {error}")
        actual_matrix = None
    if actual_matrix is not None:
        require(
            actual_matrix == EXPECTED_MATRIX,
            f"unexpected build matrix: {actual_matrix!r} (expected {sorted(EXPECTED_MATRIX)!r})",
        )

    privileged = []
    for job in reusable.get("jobs", {}).values():
        for step in job.get("steps") or []:
            uses = str(step.get("uses", ""))
            name = str(step.get("name", ""))
            if any(token in uses for token in PRIVILEGED_USES) or PRIVILEGED_NAME.search(name):
                privileged.append(step)

    require(bool(privileged), "no privileged steps discovered")
    for step in privileged:
        label = step.get("name") or step.get("uses")
        condition = step.get("if") or ""
        require(
            TRUSTED_PREFIX.match(condition) is not None and not top_level_disjunction(condition),
            f"privileged step is not trusted-gated: {label}",
        )

    # --- both callers and the callee ------------------------------------
    for label, document in (("CI-builds", base), ("CI-builds-fork", fork), ("ci-builds", reusable)):
        require(not contains_unsafe_checkout(document), f"unsafe fork checkout enabled in {label}")

    return problems


def load_workflow(spec):
    result = subprocess.run(
        ["git", "show", spec], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise SystemExit(f"cannot read {spec}: {result.stderr.strip()}")
    return yaml.safe_load(result.stdout)


def main(argv):
    if len(argv) != 3:
        print(f"usage: {argv[0]} <base-ref> <gh-actions-ref>", file=sys.stderr)
        return 2
    base_ref, actions_ref = argv[1], argv[2]
    base = load_workflow(f"{base_ref}:.github/workflows/CI-builds.yml")
    fork = load_workflow(f"{base_ref}:.github/workflows/CI-builds-fork.yml")
    reusable = load_workflow(f"{actions_ref}:.github/workflows/ci-builds.yml")

    problems = validate(base, fork, reusable)
    if problems:
        print(f"FAIL: fork PR build isolation contract violated ({len(problems)}):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"Fork PR build isolation contract OK (base={base_ref}, callee={actions_ref})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
