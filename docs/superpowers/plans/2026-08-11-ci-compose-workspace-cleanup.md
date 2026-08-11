# Self-hosted CI Compose Workspace Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent stale Docker Compose build containers from contaminating persistent self-hosted CI workspaces, while preserving useful and stable failure diagnostics.

**Architecture:** `ci-builds.yml` already maps each Docker build project to its matrix distribution (`ubuntu24`, `ubuntu22`, or `debian12`). Add targeted Compose teardown before the pre-checkout ownership repair and before the final repair. Restrict failure artifacts to logs produced by a failed Build step, rather than the live checkout.

**Tech Stack:** GitHub Actions reusable workflow YAML, Docker Compose, Python 3 YAML parsing, live self-hosted CI verification.

## Global Constraints

- Base the branch on `origin/GH-Actions`; do not modify `v3.0` or PR #6038.
- Touch only `.github/workflows/ci-builds.yml` for the implementation.
- Do not change workflow permissions or use broad Docker pruning.
- Target Compose only with `${{ matrix.dist }}`, which matches the Makefile's `IMG_NAME`.
- Preserve the existing ownership checks and run the postflight cleanup on every job outcome.
- Use a descriptive commit message with a substantive body.

---

### Task 1: Make self-hosted Compose cleanup quiescent and failure artifacts stable

**Files:**
- Modify: `.github/workflows/ci-builds.yml:155-190,641-672`
- Test: local YAML parser and a real CI-builds run on the self-hosted pool

**Interfaces:**
- Consumes: `${{ matrix.dist }}`, `GITHUB_WORKSPACE`, existing `docker-compose.yml`, and the `build` step id.
- Produces: a workspace with no running Compose project for the active matrix distribution before ownership checks; a failure artifact limited to `ci_build_log` after a failed build.

- [ ] **Step 1: Establish the configuration-test boundary**

This workflow controls a self-hosted Docker daemon and persistent runner
workspace, neither of which is available in the local worktree. Do not add a
source-text assertion: it would only test YAML spelling, not container cleanup
or workspace ownership. Use the existing failed CI run as the red observation,
then validate YAML locally and run the corrected workflow on the real
self-hosted pool after the GH-Actions PR is merged.

- [ ] **Step 2: Add the preflight targeted cleanup**

Insert a self-hosted-only step before the current ownership guard. It must:

```yaml
    - name: Stop stale Docker Compose project (self-hosted)
      if: ${{ inputs.trusted && runner.environment == 'self-hosted' && steps.cache-check.outputs.cache-hit != 'true' }}
      run: |
        set -euo pipefail
        workspace="${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is not set}"
        compose_file="${workspace}/proxysql/docker-compose.yml"
        if [ -f "${compose_file}" ]; then
          docker-compose -f "${compose_file}" -p "${{ matrix.dist }}" down -v --remove-orphans
        fi
```

- [ ] **Step 3: Add postflight cleanup and narrow the failure artifact**

Insert the same targeted cleanup before the existing final ownership repair, with `always()` in its condition. Change the artifact condition and payload to:

```yaml
      if: ${{ inputs.trusted && steps.build.outcome == 'failure' && !cancelled() }}
      with:
        path: proxysql/ci_build_log/
        if-no-files-found: warn
```

- [ ] **Step 4: Validate the workflow locally and schedule live verification**

Run:

```bash
python3 - <<'PY'
import pathlib
import yaml

with pathlib.Path('.github/workflows/ci-builds.yml').open(encoding='utf-8') as workflow_file:
    yaml.safe_load(workflow_file)
print('YAML parsed: .github/workflows/ci-builds.yml')
PY
git diff --check
```

Expected: the workflow parses and the diff has no whitespace errors. After the
GH-Actions change merges, retrigger a CI-builds run for the same PR and verify
that the GenAI gcov matrix entry reaches checkout and Build without an
ownership-guard or artifact-zipping failure.

- [ ] **Step 5: Inspect the diff and commit**

Verify that only the planned workflow and planning documents are staged. Commit with a title such as `fix(ci): quiesce stale Compose build projects` and a two-paragraph body explaining the observed root-owned writer race, the matrix-scoped cleanup, and the narrowed artifact behavior.
