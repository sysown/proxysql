# CI tier execution parity implementation plan

> For agentic workers: use superpowers:executing-plans to implement these tasks inline.

**Goal:** Every selected product tier uses the existing v4.0 test workflows, runtime containers, harnesses, sanitizer settings, and coverage collection.

**Architecture:** Keep the single producer label snapshot and exact artifact/attempt binding. Replace the producer-only lower-tier unit runner with the existing ASAN/coverage and TSAN consumers, expanded over the same selected-tier matrix. Compilation feature flags and version-based test filtering are the only behavioral tier differences; check names and artifact identities identify the tier.

**Tech Stack:** GitHub Actions, Python, Bash, Docker Compose.

**Spec:** User instruction of 2026-09-30: v3.0/v3.1/v4.0 differ only in compilation; tests may be filtered, but must use the same harness.

## Global constraints

- Preserve ci:v3.0, ci:v3.1, and ci:asan label selection; label changes do not trigger workflows.
- No edits or pushes to PR 5882; use separate engine and caller branches/PRs.
- Keep third-party suites manual and preserve existing v4.0 execution semantics.
- Fail for missing required executables, malformed selection, missing version, and failed tests; unsupported feature tests may be filtered.
- Every tier uses coverage instrumentation and identical sanitizer settings within each test workflow.

## Review focus

- Producer failure and reruns must not leave sanitizer checks falsely green or permanently queued.
- A consumer must use the accepted producer selection, never re-read current PR labels.
- Version filtering must exclude unavailable feature tests without hiding missing supported tests.
- Source rebuild consumers must check out the exact tested SHA and control SHA.
- Artifacts/checks must remain distinct when multiple tiers run concurrently.

### Task 1: Share instrumentation and remove the special unit path

Files: engine .github/scripts/ci_tier_plan.py, ci_tier_runtime.py, ci-tier-consumers.json, workflows/ci-builds.yml, scripts/tests/test_ci_tier_*.py.

- [x] Add failing contract tests for equal coverage flags and no producer test runner.
- [x] Set instrumentation uniformly and remove runtime.units and its virtual catalogue check.
- [x] Apply the same version-based pruning in each build.
- [x] Run engine contract tests.

### Task 2: Generalize the existing sanitizer workflows

Files: engine workflows/ci-unit-tests-{asan-coverage,tsan}.yml; caller workflows/CI-unit-tests-{asan-coverage,tsan}.yml; product run-unit-tests-asan-coverage.bash and selector tests.

- [x] Add tests requiring both canonical sanitizer workflows for every selected tier.
- [x] Move the current workflow bodies into reusable consumers using the accepted matrix; change only compilation flags, identity/reporting, and shared test filtering.
- [x] Preserve canonical Docker execution commands and sanitizer options.
- [x] Apply existing version pruning before both canonical sanitizer commands; preserve the product scripts unchanged.
- [x] Replace product workflows with thin callers; keep existing triggers.
- [x] Update route validation to cover real sanitizer consumers instead of the removed producer runner.

### Task 3: Audit all execution paths and verify the paired change

- [x] Inspect tier-conditioned consumer steps; use feature applicability filtering rather than tier-specific harnesses.
- [x] Verify unchanged integration/third-party execution commands and coverage behavior across tiers.
- [x] Run Python contracts, paired fanout validation, actionlint, shell checks, and representative real Docker/harness checks.
- [x] Request one independent review of the complete paired diff; fix substantive findings.
- [ ] Commit and create paired PRs documenting merge order and validation limits.

## Execution notes

- The canonical ASAN runner enumerates compiled unit executables. Apply the existing version-based pruning helper before both sanitizer runs, identically for all tiers; this preserves both test commands byte-for-byte and avoids changing the product harness. Selector/pruning tests cover filtering.
- Manual third-party rows also accept every selected tier. MySQLX applicability uses its version-gated test group instead of a hardcoded tier restriction.

## Expanded audit and validation

- CI-maketest and CodeQL now use the producer-bound tier matrix. macOS unit smoke, cluster simulation, and PostgreSQL compatibility retain their independent triggers and use a shared run-level selection snapshot with immutable rerun binding.
- Cluster simulation retains its fixed GCOV build mode, with tier-specific cache keys and compiled-version verification. Fixed ASAN and TSAN configurations remain fixed for every selected tier.
- Group-less consumers declare their execution step so route validation detects a disabled or missing test/analysis step independently of TAP group coverage.
- Review fixes: attempt-specific standalone artifacts; selectable control_ref; tier-keyed cluster caches and compiled-version checks.
- Engine contract tests: 59 passing. Caller route tests: 16 passing. Workflow lint, pruning regression checks, and the complete paired CI lint suite pass.
- Real Docker smoke: two unchanged repository unit tests (149 TAP assertions) built with ASAN/GCOV and run via the exact canonical workflow command for each tier; all passed and produced LCOV. TSAN subset checks also passed for all three tiers with the same ASLR preparation used by CI; a required missing executable correctly failed the workflow. Full product builds and hosted macOS execution remain CI validation.
