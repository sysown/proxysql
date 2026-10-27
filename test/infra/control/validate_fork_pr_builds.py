#!/usr/bin/env python3
"""Validate the fork-PR build isolation contract.

The reusable half of every workflow pair lives on the GH-Actions branch, so
the contract spans three documents:

  <base-ref>:.github/workflows/CI-builds.yml        trusted caller
  <base-ref>:.github/workflows/CI-builds-fork.yml  fork caller
  <actions-ref>:.github/workflows/<pinned-name>    reusable callee

A fork pull request runs untrusted code, so the fork caller must hold no
write-capable token, must not receive secrets, must only be reachable for
fork heads, and must pin the callee to an immutable commit. The callee in
turn must force untrusted runs onto GitHub-hosted runners and disable every
privileged step. The legacy shared callee defaults to trusted and gates on
``inputs.trusted``; the dedicated untrusted snapshot forces literal false.

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
CALLEE_REFERENCE = re.compile(
    r"sysown/proxysql/\.github/workflows/(?P<filename>ci-builds(?:-untrusted)?\.yml)@(?P<sha>[0-9a-f]{40})"
)
RUNS_ON_FORCED_FALSE = re.compile(RUNS_ON_UNTRUSTED.pattern.replace(r'inputs\.trusted', 'false'), re.DOTALL)
DISABLED_PREFIX = re.compile(r"\A\$\{\{\s*false\s*(?:&&|\}\}\Z)")
TRUSTED_PREFIX = re.compile(r"\A\$\{\{\s*inputs\.trusted\s*&&")

# Snapshot of the build matrix as of the callee SHA pinned by
# CI-builds-fork.yml. Refresh this together with that pin. It was four
# entries until 64b1465a9 / 308c14d67 (2026-09-06) retired the duplicate
# legs, then a single 'ubuntu24'/'-tap-genai-gcov' entry until the feature-tier
# sweep (PR #6234, 2026-09-28) lifted the tier out of the `type` substring and
# into an explicit `tier`/`variant` matrix key -- so the `type` token is now
# just '-tap', and '-tap-genai-gcov' no longer appears. Note this couples a
# v3.0 lint to GH-Actions content: changing the matrix there is a deliberate
# change that has to be mirrored here. It is real friction -- the lint went red
# within an hour of #6234 landing -- but it is the coupling that would have
# caught -tap-mysqlx reaching fork builds unreviewed, so keep it.
EXPECTED_MATRIX = [("ubuntu24", "-tap")]

# The callee grew a `tier` input in #6234. An untrusted caller must not be able
# to select a tier: CI-builds-fork.yml pins the callee to a commit SHA and
# passes only `trusted: false`, so the input must resolve to its default. Pin
# the default to v40 (the historical behaviour) so that adding a downgrade tier
# to the caller/reusable cannot silently change what a fork PR builds.
EXPECTED_TIER_DEFAULT = "v40"
EXPECTED_TIER_VARIANTS = {"v30", "v31", "v40"}

# GitHub accepts a whole `permissions:` block only as a mapping of scopes or
# as one of these two strings. `permissions: {}` disables every scope and is
# a legal (narrowing) mapping, not a string.
VALID_WHOLE_BLOCK_STRINGS = ("read-all", "write-all")

from ci_tier_conditions import condition_allows

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


def widenings_beyond_fork_caller(permissions):
    """Return (scope, level) pairs that exceed the fork caller's grant.

    CI-builds-fork.yml grants exactly ``contents: read``, and a called
    workflow may only narrow the caller's token, never widen it. Anything
    beyond that is rejected by GitHub before a job is scheduled, so it has
    to be reported rather than raised on -- including the string form
    ``read-all`` / ``write-all``, which grants every scope.

    ``none`` is an explicit denial and therefore always a narrowing, so it
    is never a widening whatever the scope.

    A value that is not valid ``permissions`` syntax at all is reported by
    :func:`permission_declaration_fault`, not here.
    """
    if permissions is None:
        return []
    if isinstance(permissions, str):
        # `read-all` / `write-all` are the valid shorthand forms. Both grant
        # more than contents:read.
        return [] if permissions not in VALID_WHOLE_BLOCK_STRINGS else [
            (permissions, permissions)
        ]
    if not isinstance(permissions, dict):
        return []

    widenings = []
    for scope, level in permissions.items():
        if level == "none":
            continue
        if scope == "contents":
            if level != "read":
                widenings.append((scope, level))
        else:
            widenings.append((scope, level))
    return widenings


def permission_declaration_fault(label, permissions):
    """Return a problem string for a malformed ``permissions:`` value, else None.

    GitHub accepts exactly three shapes for a whole ``permissions`` block: a
    mapping of scopes, the string ``read-all``, or the string ``write-all``.
    ``permissions: {}`` is a legal mapping that disables every scope. ``none``
    is a *scope* value inside a mapping, not a whole-block value, and a scalar
    such as ``42`` is not syntax at all.

    Both of those can be rejected by GitHub before a job is scheduled, and the
    widening check cannot see them -- it returns nothing for a value it does
    not recognise -- so an unvalidated callee would pass the contract and
    then fail the whole untrusted call.
    """
    if permissions is None:
        return None
    if isinstance(permissions, dict):
        return None
    if isinstance(permissions, str) and permissions in VALID_WHOLE_BLOCK_STRINGS:
        return None
    return (
        f"callee {label} has an invalid permissions value {permissions!r}; expected a "
        f"mapping of scopes, {{}}, 'read-all' or 'write-all'"
    )


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
        condition = str(base_run.get("if", ""))
        caller_events = base.get("on", base.get(True, {})) or {}
        legacy_guard = "head_repository.full_name == github.repository" in condition
        native_guard = ("github.event.pull_request.head.repo.full_name == github.repository" in condition
                        and "!github.event.pull_request.head.repo.fork" in condition)
        require(
            (native_guard if 'pull_request' in caller_events else legacy_guard)
            and ('workflow_run' not in caller_events or legacy_guard),
            "trusted CI-builds lacks same-repository guard",
        )
        # Check actual foreign/fork event paths as well as guard presence.
        # A substring check alone accepts a guard followed by "|| true".
        scenarios = []
        if 'pull_request' in caller_events:
            for source, is_fork in [('outside/fork', True), ('outside/repo', False), ('sysown/proxysql', True)]:
                scenarios.append({
                    'github.event.pull_request': True,
                    'github.event.pull_request.head.repo.full_name': source,
                    'github.event.pull_request.head.repo.fork': is_fork,
                    'github.event.workflow_run': None,
                })
        if 'workflow_run' in caller_events or not caller_events:
            scenarios.append({
                'github.event.pull_request': None,
                'github.event.pull_request.head.repo.full_name': '',
                'github.event.pull_request.head.repo.fork': False,
                'github.event.workflow_run.head_repository.full_name': 'outside/fork',
            })
        for scenario in scenarios:
            try:
                allowed = condition_allows(condition, 'v31', 'normal', event_context={
                    'github.event.pull_request.labels.*.name': [], **scenario})
                require(not allowed, 'trusted CI-builds allows a foreign or fork source')
            except ValueError as error:
                problems.append('trusted CI-builds condition cannot be verified: ' + str(error))
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
    dedicated = False
    if fork_run is not None:
        reference = CALLEE_REFERENCE.fullmatch(str(fork_run.get("uses", "")))
        dedicated = reference is not None and reference["filename"] == "ci-builds-untrusted.yml"
        require(
            "head.repo.fork" in str(fork_run.get("if", "")),
            "fork workflow is not restricted to fork heads",
        )
        require(
            reference is not None,
            "fork workflow does not pin the reusable workflow to a full commit SHA",
        )
        require(
            fork_run.get("with", {}).get("trusted") is False,
            "fork workflow does not select untrusted mode",
        )
        if dedicated:
            require(fork_run.get('with', {}).get('control_ref') == reference['sha'],
                    'dedicated fork control_ref must match its immutable callee SHA')
    for name, job in fork_jobs.items():
        require("secrets" not in job, f"fork job {name!r} inherits or passes secrets")
        require("permissions" not in job, f"fork job {name!r} overrides read-only workflow permissions")

    # --- reusable callee ------------------------------------------------
    inputs = on_key(reusable).get("workflow_call", {}).get("inputs", {})
    trusted_input = inputs.get("trusted", {})
    if dedicated:
        require(trusted_input.get('default') is False, 'dedicated reusable workflow lacks trusted=false default')
        for name, job in reusable.get('jobs', {}).items():
            require('uses' not in job, f'dedicated untrusted job {name!r} delegates to another workflow')
    else:
        require(trusted_input.get("default") is True, "reusable workflow lacks trusted=true default")

    # The `tier` input selects the feature tier. A fork PR reaches the callee
    # only via CI-builds-fork.yml, which pins a commit SHA and passes just
    # `trusted: false`, so `tier` always resolves to its default. Pin it, so a
    # future downgrade tier cannot be smuggled onto the untrusted path.
    if 'plan' not in reusable.get('jobs', {}):
        tier_input = inputs.get("tier", {})
        require(
            tier_input.get("default") == EXPECTED_TIER_DEFAULT,
            f"reusable workflow tier input default is {tier_input.get('default')!r}, "
            f"expected {EXPECTED_TIER_DEFAULT!r}",
        )
    if 'plan' not in reusable.get('jobs', {}):
        # And the resolve-tier job must reject anything outside the known set,
        # rather than defaulting an unknown tier to a build.
        resolve_tier = reusable.get("jobs", {}).get("resolve-tier", {})
        resolve_run = next(
            (s.get("run", "") for s in resolve_tier.get("steps") or [] if s.get("id") == "t"),
            "",
        )
        for tier in sorted(EXPECTED_TIER_VARIANTS):
            require(
                f"{tier})" in resolve_run,
                f"resolve-tier does not handle the {tier} tier",
            )
        require(
            re.search(r"^\s*\*\)\s*$", resolve_run, re.M) is not None,
            "resolve-tier has no catch-all that fails on an unknown tier",
        )
        # A job may not widen the token beyond the least-privileged caller, which
        # grants exactly contents: read (see 5e8468db4).
        require(
            "permissions" not in resolve_tier,
            "resolve-tier declares permissions:, which breaks the contents:read-only fork caller",
        )
    else:
        planner = reusable['jobs']['plan']
        require('permissions' not in planner, 'planner widens fork token permissions')
        require(planner.get('runs-on') == 'ubuntu-24.04' or RUNS_ON_UNTRUSTED.match(str(planner.get('runs-on', ''))) is not None,
                'untrusted planner does not force ubuntu-24.04')
        selections = [step for step in planner.get('steps', []) if 'ci_tier_runtime.py plan' in str(step.get('run', ''))]
        require(len(selections) == 1 and selections[0].get('env', {}).get('TRUSTED') == ('${{ false }}' if dedicated else '${{ inputs.trusted }}'),
                'planner must preserve caller trust when resolving labels')

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
    #
    # Checked at the workflow level as well as per job: either is enough to
    # reintroduce the same rejection.
    for label, requested in [("workflow", reusable.get("permissions"))] + [
        (f"job {name!r}", job.get("permissions"))
        for name, job in reusable.get("jobs", {}).items()
    ]:
        fault = permission_declaration_fault(label, requested)
        if fault is not None:
            problems.append(fault)
            continue
        for scope, level in widenings_beyond_fork_caller(requested):
            problems.append(
                f"callee {label} requests {scope}: {level}, which the fork "
                f"caller does not grant; this fails the whole call at startup"
            )

    require(
        (builds.get('runs-on') == 'ubuntu-24.04' or
         RUNS_ON_FORCED_FALSE.match(str(builds.get('runs-on', ''))) is not None) if dedicated else
        RUNS_ON_UNTRUSTED.match(str(builds.get("runs-on", ""))) is not None,
        "untrusted mode does not force ubuntu-24.04",
    )

    if 'plan' in reusable.get('jobs', {}):
        needs=builds.get('needs') or []
        needs=[needs] if isinstance(needs,str) else needs
        require('plan' in needs, 'builds must depend on plan')
        require(builds.get('strategy', {}).get('matrix') == '${{ fromJson(needs.plan.outputs.matrix) }}',
                'build matrix must come from the trusted-aware configuration planner')
    else:
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
            if any(token in uses for token in PRIVILEGED_USES) or PRIVILEGED_NAME.search(name) or re.search(r'ci_tier_runtime.py (result|finalize|units)', str(step.get('run', ''))):
                privileged.append((step, job.get('if', '')))

    require(bool(privileged), "no privileged steps discovered")
    for step, job_condition in privileged:
        label = step.get("name") or step.get("uses")
        conditions = [str(step.get("if") or ""), str(job_condition or "")]
        require(
            any((DISABLED_PREFIX if dedicated else TRUSTED_PREFIX).match(condition) is not None
                and not top_level_disjunction(condition) for condition in conditions),
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
    reference = CALLEE_REFERENCE.fullmatch(str(fork.get('jobs', {}).get('run', {}).get('uses', '')))
    if reference is None:
        print('FAIL: fork workflow does not pin an allowed reusable workflow to a full commit SHA', file=sys.stderr)
        return 1
    reusable = load_workflow(f"{actions_ref}:.github/workflows/{reference['filename']}")

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
