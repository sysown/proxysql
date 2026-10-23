# CI rerun recovery implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans; execution method is already native. Steps use checkbox syntax for tracking.

**Goal:** Make automatic CI reruns recover safely and aggregate retained native results correctly.

**Architecture:** Retain immutable trigger/producer identities and all native validation. Add an absence-only automatic binding fallback and compare historical execution intervals for cloned native successes.

**Tech Stack:** Python standard library unittest, GitHub Actions YAML.

**Spec:** `docs/superpowers/specs/2026-10-23-ci-rerun-recovery-design.md`

## Global Constraints

- Work only on `fix/ci-rerun-recovery`, based on `GH-Actions`; never commit on `v3.0`.
- Do not alter artifact PR #6520 or manually change its check conclusions.
- Recover only the exact original accepted producer; existing invalid bindings and manual missing snapshots fail closed.
- Preserve native failure, cancellation and unfinished-job validation.
- Implement natively, then request one fresh whole-branch review. Do not merge the CI-control PR without authorization.

## Review Focus

- Missing and unreadable bindings must have distinct behavior.
- Repository, SHA and both trigger identity fields must remain immutable.
- Manual and foreign-repository snapshots must not be reconstructed from mutable inputs.
- Retained jobs with absent or ambiguous execution intervals must not qualify as old successes.
- Fresh native reruns must invalidate old custom successes even when their native job succeeds.

### Task 1: Recover automatic bindings

**Files:** Modify `.github/scripts/ci_tier_runtime.py`; test `.github/scripts/tests/test_ci_tier_runtime.py`.

**Interfaces:** `consumer()` consumes existing `context()`, `GitHubAPI.artifacts/json_artifact`, `verify_binding` and `load_bound`; its emitted matrices and binding schema remain unchanged.

- [ ] Add regressions for absent automatic binding recovery, existing binding precedence, invalid artifact/identity rejection, API errors, and manual/foreign rejection.
- [ ] Run the new tests; expect failure at missing binding lookup before recovery.
- [ ] Implement absence-only lookup of the original `ci-accepted-producer-a{trigger_attempt}` and verify its identity before loading the manifest.
- [ ] Run `python3 -m unittest discover -s .github/scripts/tests -q`; expect all tests pass.
- [ ] Commit the runtime fix and regressions.

### Task 2: Recognize retained native jobs

**Files:** Modify `.github/scripts/ci_tier_checks.py`; test `.github/scripts/tests/test_ci_tier_checks.py`.

**Interfaces:** `observations(plan, api, verify_native=True)` preserves its result shape and `reconcile()` contract; historical job requests use the result's recorded attempt.

- [ ] Add regressions for cloned successful execution intervals, fresh reruns, absent/ambiguous history, missing timestamps and native non-success/unfinished outcomes.
- [ ] Run the new tests; expect the retained-success case to remain pending incorrectly.
- [ ] Compare nonempty full-name/start/end fingerprints with successful historical jobs, caching historical lists per workflow attempt; keep native failure/unfinished handling first.
- [ ] Run the complete unittest suite; expect all tests pass.
- [ ] Commit the observation fix and regressions.

### Task 3: Bound CodeQL with sufficient completion time

**Files:** Modify `.github/workflows/ci-codeql.yml`.

**Interfaces:** Existing CodeQL matrix and result reporting are unchanged; the job timeout becomes 180 minutes.

- [ ] Set the finite 180-minute job budget with a brief reason referencing build/analysis completion overhead.
- [ ] Run the complete unittest suite, actionlint, Python compilation and `git diff --check`; expect success.
- [ ] Commit, obtain one fresh independent whole-branch review, and address important findings with RED→GREEN tests in one fix pass.
- [ ] Push the feature branch and create a PR targeting `GH-Actions`, with the reproducible failure cases and test evidence. Request activation approval only after the concrete PR is reviewable.
