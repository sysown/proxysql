# PR-label-selected CI product tiers implementation plan

Execution status: Tasks 1–4 and 6 are implemented; Task 5 is implemented with
an unresolved strict lifecycle guarantee; Task 7 has local validation and one
independent review, with live GitHub validation outstanding. The original
checklist below remains the acceptance specification; the validation report and
ledger record executed checks and deviations rather than checking unproven items.


> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Select additional CI product tiers through PR labels, report each configuration on the PR, and remove the post-merge tier sweep without affecting PR #5882 during development.

**Architecture:** Retain the existing trigger/build/test cascade and dedicated test workflows. Resolve labels once, build the selected tiers in one producer run, and pass an immutable execution manifest to consumers. Share configuration, artifact, and reporting helpers across consumers.

**Tech Stack:** GitHub Actions reusable workflows, Python 3 standard library, Bash, `gh`, existing YAML tooling and TAP harness. No service or persistent database.

**Spec:** `docs/superpowers/specs/2026-09-29-pr-label-selected-ci-tiers-design.md` in the callers worktree.

## Global constraints

- Do not add `labeled` or `unlabeled` triggers. Label edits neither start nor cancel CI.
- Default tiers: `[v40]`; `ci:v3.0` adds `v30`; `ci:v3.1` adds `v31`, in that order.
- `ci:asan` independently selects ASAN for every selected standard TAP tier.
- Use no tier flag for v3.0, `PROXYSQL31=1` for v3.1, and `PROXYSQL40=1` for v4.0.
- Downstream jobs must never query labels again.
- Pushes and direct manual dispatches retain v4.0/normal defaults.
- Fork builds retain their existing isolation and permissions.
- Do not modify PR #5882, its branch, its labels, or its workflows/runs.
- Do not push changes directly to `v3.0` or `GH-Actions`; do not merge either branch.
- Remove the current post-merge `CI-tier-sweep`, including its reusable workflow. Do not replace it with a scheduled sweep in this change.
- Do not change repository branch-protection settings here.
- Tests use fixtures and local validation first. Live Actions behavior remains a separate validation boundary.

## Review focus

1. Two executions of the same SHA with different labels or ASAN modes must never exchange artifacts (Tasks 1–3).
2. Nested reusable workflows, manual-only callers, and directly embedded artifact names must not escape conversion or inflate expected checks (Tasks 1, 4).
3. Mixed groups and the disabled automatic unit-test caller must not lose lower-tier coverage when the sweep is removed (Tasks 4, 6).
4. Concurrent completion, partial reruns, cancellation before setup, and missing reporting must never produce an early successful aggregate (Task 5).
5. An old caller or running sweep during staged rollout must not resolve a deleted reusable or lose runtime data (Tasks 3, 6, 7).

## Worktrees and file responsibilities

Run all commands in the appropriate existing worktree; do not create new ones.

- **E:** `/data/rene/proxysql/.worktrees/ci-pr-tiers-engine`, branch `feature/ci-pr-tiers-engine`, based on `b83e4a156`.
- **C:** `/data/rene/proxysql/.worktrees/ci-pr-tiers-callers`, branch `feature/ci-pr-tiers-callers`, based on `696781be8`.

New files in E:

| File | Responsibility |
| --- | --- |
| `.github/ci-tier-consumers.json` | Explicit caller/job/group capabilities, specialty exclusions, and manual-only status |
| `.github/scripts/ci_tier_plan.py` | Resolve labels/context; validate and generate configuration and manifests |
| `.github/scripts/ci_tier_artifacts.py` | Locate the exact producer/attempt and restore matching artifacts |
| `.github/scripts/ci_tier_checks.py` | Create/update execution-scoped checks and reconcile the aggregate |
| `.github/workflows/ci-tier-context.yml` | Shared, short consumer setup: resolve manifest, matrix, and control revision |
| `.github/workflows/ci-tier-summary.yml` | Short serialized aggregate reconciliation job, called by finalizers |
| `.github/scripts/tests/test_ci_tier_{plan,artifacts,checks,workflows}.py` | Behavioral fixtures and workflow contract tests |

New files in C:

| File | Responsibility |
| --- | --- |
| `test/infra/control/check_ci_tier_fanout.py` | Cross-branch route/coverage contract replacing the sweep-list validator |
| `test/infra/control/test_check_ci_tier_fanout.py` | Mutation fixtures proving missing routes and privilege changes fail |

The consumer inventory in Task 1 is the exact edit list for E's reusable consumers and C's caller titles. Keep source, TAP fixtures, and live documentation changes on C; only CI workflows/scripts/catalogue belong on E.

## Interfaces shared by the tasks

Use Python dictionaries serialized as JSON at the process boundary. Validate required keys and enum values; reject unsupported schema versions.

- `resolve_selection(context: dict, trusted: bool, fetch_pr: Callable[[int], dict]) -> dict` returns `tiers: list[str]`, `mode: normal|asan`, and nullable `pr_number`. Context supplies the original event, repository, tested SHA, trigger ID, and attempt. The adapter distinguishes a non-PR event from a PR event with missing association.
- `make_plan(context: dict, selection: dict, catalogue: dict) -> dict` returns schema `1`, `execution_id`, source repository/SHA, trigger ID/attempt, producer ID/attempt, control SHA, selection, build legs, and candidate checks.
- `execution_id` is `t<TRIGGER_ID>-a<TRIGGER_ATTEMPT>-b<BUILD_ID>-a<BUILD_ATTEMPT>`. Direct producer dispatch uses its own run identity as the origin. No branch name or arbitrary user text is used as an artifact key.
- Each build leg has `tier`, `mode`, `coverage: bool`, `variant`, and `artifact_name`. Use `ci-handoff-<execution_id>-<tier>-<mode>-full`; configuration records preserve v4.0 coverage independently of ASAN.
- Publish `ci-plan-<execution_id>` before builds. After builds, publish immutable `ci-manifest-<execution_id>` containing actual binary versions, artifact IDs, applicable check records, and check IDs. Consumers use this final manifest. An initial candidate with zero runnable tests becomes an explicitly not-applicable record, not a passing test.
- Each check record has `key`, caller workflow, job/group, tier/mode, required/applicable flags, display name, and check ID. `key` is stable within the execution; external IDs include `execution_id` and `key`.
- `consumer_matrix(manifest: dict, consumer_key: str) -> list[dict]` returns applicable configurations for one consumer. No selected configuration is an explicit no-work result, handled before matrix expansion.
- `resolve_producer(context: dict, api: GitHubAPI) -> dict` validates origin and obtains the exact producer identity. `load_manifest(producer: dict, api: GitHubAPI) -> dict` reads only that producer's artifacts. `restore_handoff(manifest: dict, leg: dict, destination: Path, api: GitHubAPI) -> None` validates names/metadata and binary tier before running tests.
- `aggregate_state(manifest: dict, observations: list[dict]) -> dict` returns check status/conclusion and summary counts. `publish_result(...)` updates the execution's existing check; `reconcile(...)` fetches current observations and updates its aggregate while serialized by execution ID.
- CLI subcommands wrap these functions; do not duplicate selection or artifact lookup inside YAML shell blocks. Pass JSON through files/env or structured subprocess arguments, never interpolate PR content into shell source.

### Task 1: Catalogue consumers and implement configuration resolution

**Files:** E's `ci-tier-consumers.json`, `ci_tier_plan.py`, `test_ci_tier_plan.py`; existing `resolve-tap-build-mode.bash` and its tests.

**Consumes:** Original event/trigger context, current labels, caller/reusable wiring from C and E.
**Produces:** Selection and plan interfaces above; exact inventory of workflows to convert, including nested reusables and manual-only consumers.

- [ ] Write selection tests for all eight label combinations, exact matching, duplicates/order, unrelated labels, push/manual defaults, untrusted callers, label-query errors, malformed context, zero PR association, and ambiguous association. Assert a trusted PR label lookup happens once; untrusted/non-PR cases make no label call.
- [ ] Run `python3 -m unittest discover -s .github/scripts/tests -p test_ci_tier_plan.py` in E; verify failure is due to missing implementation.
- [ ] Implement `resolve_selection` and `make_plan`. Preserve the existing ASAN script as a compatibility adapter until every caller uses the combined selection. Do not weaken its error behavior.
- [ ] Inventory reachable central-handoff consumers from actual caller YAML, following nested `uses:` links and distinguishing enabled `workflow_run` listeners from comments/manual dispatch. Record each runtime group and capability in the catalogue. Include `ci-basictests.yml`, `ci-unit-group.yml`, third-party workflows, and both jobs in `ci-mysqlx.yml`; wrappers using `ci-ai-gcov.yml` do not imply plugin dependence.
- [ ] Add catalogue tests: unknown central-handoff consumers fail; nested wrappers resolve; a manual-only caller does not create expected automatic checks; two jobs in one workflow remain distinct. Treat compiler/version constraints as capabilities, not name-based guesses.
- [ ] Re-run selection and existing ASAN resolver tests; require all pass. Commit tests and implementation separately, following repository convention.

### Task 2: Bind artifacts and reruns to one execution

**Files:** E's `ci_tier_artifacts.py`, `test_ci_tier_artifacts.py`; plan schema tests from Task 1.

**Consumes:** The versioned plan and GitHub run/artifact metadata.
**Produces:** Exact producer discovery, manifest validation, and artifact restoration interfaces above.

- [ ] Write fixtures with two producer runs for the same SHA but different labels/modes, two attempts of one build run, expired/missing artifacts, delayed artifact indexes, malformed manifests, wrong repositories, wrong SHA, and wrong compiled product versions. Assert no fallback to a repository-wide newest-SHA match.
- [ ] Test reruns explicitly: a new producer attempt gets a new execution ID; rerunning a test workflow keeps its original producer binding. Store a small immutable binding artifact on the first consumer attempt so later attempts do not rediscover a newer producer.
- [ ] Run `python3 -m unittest discover -s .github/scripts/tests -p test_ci_tier_artifacts.py`; verify the tests fail before implementation.
- [ ] Implement the artifact functions using run-scoped artifact APIs, bounded retries, pagination, and metadata validation. Check archive paths before extraction. An absent binding on a later consumer attempt is a visible failure, not permission to choose a newer producer.
- [ ] Implement producer discovery through execution-scoped build-registration check metadata on the source SHA. The registration records the trigger ID/attempt and producer ID/attempt and links to the real build run. This works with old caller titles; it does not depend on parsing a SHA from `displayTitle`.
- [ ] Test a consumer label mutation, a stale build-registration check, ambiguous registrations, a first attempt cancelled before binding, and a 404/permission failure separately. Manual consumer dispatch must provide a producer run/attempt via optional inputs or fail with a concrete instruction; it must not guess an artifact by SHA.
- [ ] Re-run the artifact tests and selection tests. Commit tests and implementation separately.

### Task 3: Build selected configurations and retain lower-tier units

**Files:** E's `ci-builds.yml`, `ci-trigger.yml`, `ci-unit-group.yml`, `test_ci_tier_workflows.py`, both plugin-handoff regression scripts; C's `CI-builds.yml` title.

**Consumes:** Tasks 1–2's plan, producer registration, and handoff contracts.
**Produces:** One registered producer run, tier/mode build matrix, final manifest, and correctly correlated trigger completion.

- [ ] Add workflow fixtures asserting one shared selection job, no `labeled`/`unlabeled` events, one build leg per selected tier, `fail-fast: false`, explicit flags, and tier-aware plugin/coverage gates. Add fork fixtures asserting no label API, artifact publication, privileged checks, or self-hosted routing.
- [ ] Run the workflow tests and confirm they fail against the old single-tier build wiring.
- [ ] Replace the separate mode/tier setup jobs with combined setup for the standard pipeline, retaining a compatible explicit-tier path while the old sweep exists. Publish the initial plan/registration before expensive work. Route eligible trusted setup directly using the existing pool policy and keep the reusable permissions compatible with fork callers.
- [ ] Drive `builds` from the plan matrix. Stage the control helpers from an explicit `control_ref` (production default, candidate ref for isolated validation); record the resolved commit and use that commit for all subsequent script checkouts. Put tier/mode/coverage metadata in each artifact and retain the lower-tier pruning behavior.
- [ ] Update plugin-handoff tests to assert the eligibility truth table (trusted v4.0 only) and preserve their actual staging/restoration failure tests. Do not merely substitute an expected string.
- [ ] Preserve the sweep's lower-tier `unit-tests-g1` execution with jobs inside the existing `CI-builds` workflow, after each lower-tier artifact is ready. Reuse `ci-unit-group.yml` with explicit producer configuration. Filter by the built binary's actual version before checking executable paths. These unit jobs do not require a new caller trigger; existing specialty ASAN/TSAN workflows remain unchanged.
- [ ] Finalize applicability from built versions and source group metadata, publish the final manifest, and have `CI-trigger` wait for its exact registered producer's conclusion. Preserve bounded API-error handling. A failed required build/unit job fails the trigger and prevents downstream fanout.
- [ ] Test two same-SHA triggers completing out of order, a failed lower-tier build, a unit binary missing after filtering, and a cancelled producer. Ensure no healthy matrix leg is cancelled by another leg's failure and no queued required work becomes a false success.
- [ ] Run plan/artifact/workflow tests plus both plugin-handoff scripts and `test-prune-tier-handoff.bash`. Commit tests and implementation separately; keep sweep compatibility until Task 6's removal commit.

### Task 4: Convert every central-handoff consumer

**Files:** E's `ci-tier-context.yml` and catalogue-listed consumer reusables/wrappers; C's matching caller titles and optional manual-producer inputs; `test_ci_tier_workflows.py`.

**Consumes:** Final manifest, exact producer binding, and `consumer_matrix`.
**Produces:** Correct per-tier fanout, names, runtime identifiers, and artifact restoration for every inventoried consumer.

- [ ] Add failing behavioral fixtures for a TAP group (`ci-mysql84-gr-g2.yml`), shared group runner (`ci-ai-gcov.yml`), unit consumer, third-party consumer, and plugin-only MySQLX jobs. Assert correct names, artifact producer, coverage gates, no extra label queries, and explicit no-applicable-tests behavior.
- [ ] Run `python3 -m unittest discover -s .github/scripts/tests -p test_ci_tier_workflows.py` and confirm failures identify missing consumer contracts.
- [ ] Implement shared consumer setup once per workflow, not once per tier. Feed matrix/configuration outputs into test jobs and merge setup with existing runner selection where practical; retain the approved trust/runner policy. Optional manual dispatch inputs name a producer run and attempt without adding any event type.
- [ ] Convert all catalogue consumers, following nested wrappers. Replace embedded SHA-only handoff lookup blocks with Task 2's helper. Add tier/mode to job/check names and tier/execution/job identity to artifact names and infrastructure identifiers, retaining existing backend setup/cleanup behavior.
- [ ] Gate plugin restoration and gcov collection on actual capabilities/instrumentation. Use version-filtered group selection for mixed groups. For `ci-unit-group.yml`, apply the same minimum-version semantics before asserting that selected binaries exist.
- [ ] Update outer run titles to include trigger run/attempt alongside branch and SHA, without guessing later label resolution. Do not change any existing event filters or enable the manual-only `CI-unittests` trigger.
- [ ] Test catalogue completeness with an unconverted hardcoded artifact consumer, mixed AI-named groups containing lower-tier tests, multiple jobs sharing one artifact, zero selected tests, and conflicting log/container identities. Require the validator to reject every deliberate mutation.
- [ ] Run the full helper/workflow suite and record coverage by consumer family. Commit tests and consumer conversions separately.

### Task 5: Publish queued checks and reconcile final results

**Files:** E's `ci_tier_checks.py`, `ci-tier-summary.yml`, `test_ci_tier_checks.py`, producer/consumer finalizers in the catalogue-listed workflows.

**Consumes:** Plan/manifest expected checks, execution identity, GitHub check/job observations.
**Produces:** Queued and terminal per-configuration checks and `CI / selected tiers` on the tested PR SHA.

- [ ] Write tests for queued -> running -> success/failure, failed builds blocking fanout, not-applicable groups, cancelled/missing jobs, publication errors, duplicate check names, concurrent completion, stale attempts, and out-of-order updates. Assert aggregate success requires all required applicable records to succeed.
- [ ] Run `python3 -m unittest discover -s .github/scripts/tests -p test_ci_tier_checks.py`; verify failure before implementation.
- [ ] Implement check creation before build/test execution and update the same check IDs throughout. Key records by execution and logical job, not display name. Use direct Actions URLs. A reporting error must fail its reporting step and remain visible.
- [ ] Implement short finalizer calls to `ci-tier-summary.yml` with `always()` and execution-scoped concurrency, `cancel-in-progress: false`. Re-fetch observations inside the serialized job. Running tests update their own checks before requesting reconciliation; they must never directly publish aggregate success from a stale snapshot.
- [ ] Account for GitHub replacing an older pending concurrency job: each reconciliation must recompute every required result, so a later request subsumes skipped pending requests. Do not count reconciliation-job cancellation as a test outcome. Missing/cancelled test jobs still block success.
- [ ] On a consumer rerun, invalidate that consumer's prior terminal result before execution and use native run/attempt observations to reject stale reports. A producer rerun has a separate manifest/aggregate. Include a fixture where a delayed old attempt reports success after a newer failure.
- [ ] On producer failure, conclude candidate downstream checks as blocked/skipped with the failed build link and fail the aggregate. A cancellation preventing all finalizers from running may leave an execution pending; missing terminal evidence must never be converted into success. Document this API/event limitation in validation results.
- [ ] Run reporting tests with interleaved mocked API calls and workflow fixtures asserting required finalizers and permissions. Commit tests and implementation separately.

### Task 6: Replace the sweep coverage guard and remove the sweep

**Files:** C's `check_ci_tier_fanout.py`, `test_check_ci_tier_fanout.py`, `run-ci-lint.bash`, `doc/GH-Actions/README.md`; both sweep workflows, C's `tier-sweep.lst`/old validator, E's `.github/shards.json`.

**Consumes:** Catalogue, actual caller/reusable wiring, source groups and minimum versions, original 54-group sweep coverage.
**Produces:** Equivalent applicable lower-tier routing, no active sweep wiring, and updated documentation.

- [ ] Write cross-branch validator fixtures for an omitted lower-tier group, a manual-only caller falsely treated as automatic, an unknown group, version comparison `3.10 > 3.9`, duplicated routes, a missing nested reusable, and an unexplained specialty exclusion. Preserve the original sweep list as test migration evidence, not a runtime work list.
- [ ] Run `python3 -m unittest discover -s test/infra/control -p test_check_ci_tier_fanout.py` in C; verify failure before implementation.
- [ ] Implement `check_ci_tier_fanout.py --callers-ref REF --engine-ref REF`; it reads both revisions explicitly, validates the catalogue/routes against source groups, and checks all prior applicable sweep groups. The new build-contained lower-tier unit jobs satisfy `unit-tests-g1`. Inspect, rather than blindly waive, plugin-related exclusions.
- [ ] Wire this validator into `run-ci-lint.bash` with an explicit candidate engine-ref override for local paired validation; preserve the production default. Apply the same candidate-ref override to the existing fork contract validation so local tests do not accidentally validate the production engine.
- [ ] Commit deletion of the caller separately from deletion of the runtime list/helpers. Remove the reusable and unused shards file in a separate E cleanup commit; remove the obsolete list/validator only after replacement coverage passes. Verify no live references remain, excluding historical docs and migration fixtures.
- [ ] Update the CI architecture documentation with labels, defaults, ASAN composition, exact producer binding, manual producer inputs, per-tier check naming, cancelled-run limits, and removal of the post-merge sweep. Explain that outer run titles identify the execution while jobs/checks identify the tier.
- [ ] Run the new validator against both candidate branches and its mutation tests. Commit tests, runtime removal, and documentation in reviewable groups.

### Task 7: Validate the paired changes and prepare reviewable delivery

**Files:** Both candidate worktrees; verification record appended to this plan.

**Consumes:** Completed Tasks 1–6 and their recorded baseline failures.
**Produces:** Tested local branches, concrete rollout order, review results, and clearly stated live-validation limits.

- [ ] Run all `.github/scripts/tests` Python suites/scripts in E, existing ASAN/pruning tests, and Bash syntax checks for modified scripts. Require both formerly failing plugin-handoff tests to pass.
- [ ] Run workflow YAML/action validation on each candidate tree, then cross-branch reference/input/permission validation. Check both production wiring and the exact candidate-ref probe wiring, including nested control-script checkouts. Do not assert that YAML parsing alone validates reusable-workflow contracts.
- [ ] Run C's `test/infra/control/run-ci-lint.bash` with the candidate engine override, the new coverage validator, and the fork contract validator against the paired refs. Compare trigger maps with the base commits: only the sweep is removed; optional dispatch inputs may be added; other event definitions remain identical.
- [ ] Verify all eight selection combinations end-to-end through fixture planning, producer manifest generation, consumer matrices, artifact restoration, and reporting. Include exact group-count evidence before/after sweep removal and mark not-applicable groups explicitly.
- [ ] Perform a whole-change independent review, with emphasis on producer identity, failed/cancelled jobs, trust boundaries, nested consumers, and rollout compatibility. Resolve findings and rerun affected checks.
- [ ] Record rollout stages for eventual human-controlled integration: first remove the sweep caller while retaining runtime data; allow active sweeps to finish; integrate engine support and consumer changes while retaining compatibility needed by old callers; integrate caller titles/manual inputs/new lint; finally delete unused sweep reusable/runtime data. Split review commits/PRs as required by this order rather than merging both branch tips blindly.
- [ ] Verify PR #5882's worktree/branch were not modified and no production refs, labels, workflow runs, or branch protections were changed. Report unrelated upstream movement as such, rather than restoring old refs.
- [ ] Record local test results and outstanding live validation. Do not launch a full extra CI fanout or merge shared refs as part of preparation. Any live probe must use candidate refs throughout and a separate test execution.

## Plan self-review and execution handoff

- Requirements are covered by Tasks 1–6; validation and isolation are covered by Task 7.
- Each Review Focus condition has an explicit test in its owning task.
- Task interfaces use the same plan/manifest schema, execution identity, and function names throughout.
- The baseline caller lint, ASAN selector, and pruning tests passed. The two plugin condition tests must be repaired and re-run under Task 3; they are not waived.
- Recommended execution method: **Native** (one implementer in this session, then an independent whole-change review). The tasks share manifest and reporting interfaces, so sequential implementation reduces coordination overhead and conflicting workflow edits.
- Status: implementation and independent review completed locally; corrections verified.
  The strict aggregate rerun guarantee remains an explicit limitation, not an accepted
  relaxation of the design. See `2026-09-29-pr-label-selected-ci-tiers-validation.md`.
