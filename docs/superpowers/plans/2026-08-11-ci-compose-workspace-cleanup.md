# Self-hosted CI Compose Workspace Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent stale Docker Compose build containers from contaminating persistent self-hosted CI workspaces, while preserving useful and stable failure diagnostics.

**Architecture:** `ci-builds.yml` maps Docker build projects to distribution names. Because each self-hosted VM receives the CI-builds matrix legs serially, teardown must cover the explicit project set `debian12`, `ubuntu22`, and `ubuntu24` before ownership repair and again before the final repair. The set is defined once as a job environment value. Each teardown attempts every project, including a label-based container fallback if the Compose file is absent. Restrict failure artifacts to logs produced by a failed Build or Check build step, rather than the live checkout.

**Tech Stack:** GitHub Actions reusable workflow YAML, Docker Compose, Python 3 YAML parsing, live self-hosted CI verification.

## Global Constraints

- Base the branch on `origin/GH-Actions`; do not modify `v3.0` or PR #6038.
- Touch only `.github/workflows/ci-builds.yml` for the implementation.
- Do not change workflow permissions or use broad Docker pruning.
- Target only the explicit CI-build project set `debian12`, `ubuntu22`, and `ubuntu24`, which matches the Makefile's `IMG_NAME` values.
- Preserve the existing ownership checks and run the postflight cleanup on every job outcome.
- Use a descriptive commit message with a substantive body.

---

### Task 1: Make self-hosted Compose cleanup quiescent and failure artifacts stable

**Files:**
- Modify: `.github/workflows/ci-builds.yml:155-190,641-672`
- Test: local YAML parser and a real CI-builds run on the self-hosted pool

**Interfaces:**
- Consumes: `CI_BUILD_COMPOSE_PROJECTS`, `GITHUB_WORKSPACE`, `docker-compose.yml` when present, Compose project labels, and the `build` / `check_build` step ids.
- Produces: a workspace with no running CI-build Compose project before ownership checks; a failure artifact limited to `ci_build_log` after a failed build.

- [ ] **Step 1: Establish the configuration-test boundary**

This workflow controls a self-hosted Docker daemon and persistent runner
workspace, neither of which is available in the local worktree. Do not add a
source-text assertion: it would only test YAML spelling, not container cleanup
or workspace ownership. Use the existing failed CI run as the red observation,
then validate YAML locally and run the corrected workflow on the real
self-hosted pool after the GH-Actions PR is merged.

- [ ] **Step 2: Add the preflight targeted cleanup**

Insert a self-hosted-only step before the current ownership guard. It must loop
over `CI_BUILD_COMPOSE_PROJECTS`, rather than only the active matrix project,
and retain a failure status until every project has been attempted. When the
Compose file is absent, it must force-remove only containers labelled with one
of those explicit project names:

```yaml
    - name: Stop stale Docker Compose project (self-hosted)
      if: ${{ inputs.trusted && runner.environment == 'self-hosted' && steps.cache-check.outputs.cache-hit != 'true' }}
      run: |
        set -euo pipefail
        workspace="${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is not set}"
        compose_file="${workspace}/proxysql/docker-compose.yml"
        cleanup_status=0
        for compose_project in ${CI_BUILD_COMPOSE_PROJECTS}; do
          if [ -f "${compose_file}" ]; then
            if ! docker-compose -f "${compose_file}" -p "${compose_project}" down -v --remove-orphans; then
              cleanup_status=1
            fi
          fi
          stale_containers="$(docker ps -aq --filter "label=com.docker.compose.project=${compose_project}")" || {
            cleanup_status=1
            stale_containers=""
          }
          if [ -n "${stale_containers}" ]; then
            while IFS= read -r container_id; do
              [ -n "${container_id}" ] || continue
              if ! docker rm -f "${container_id}"; then
                cleanup_status=1
              fi
            done <<< "${stale_containers}"
          fi
        done
        exit "${cleanup_status}"
```

- [ ] **Step 3: Add postflight cleanup and narrow the failure artifact**

Insert the same targeted cleanup before the existing final ownership repair, with `always()` in its condition. Give Check build the `check_build` id. Change the artifact condition and payload to:

```yaml
      if: ${{ inputs.trusted && failure() && !cancelled() && (steps.build.outcome == 'failure' || steps.check_build.outcome == 'failure') }}
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
