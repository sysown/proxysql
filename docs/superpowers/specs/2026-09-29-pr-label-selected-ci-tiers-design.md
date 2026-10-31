# PR-label-selected CI product tiers

Status: approved design; isolated implementation prepared. See the validation report
for the unresolved strict rerun-reporting guarantee and live-validation boundary.

## Intent and agreed behavior

Test additional ProxySQL product configurations before merging, with identifiable
results on the originating PR. Follow the existing `ci:asan` model: labels change
the configuration of an ordinary CI execution, not its triggering events.

| Labels at configuration resolution | Product tiers |
| --- | --- |
| Neither tier label | v4.0 |
| `ci:v3.0` | v4.0, v3.0 |
| `ci:v3.1` | v4.0, v3.1 |
| Both tier labels | v4.0, v3.0, v3.1 |

`ci:asan` independently selects ASAN for every selected standard TAP tier.
It replaces the normal build for that tier; it does not double the matrix.
Tier labels must match exactly. Each configuration tests the same source SHA,
using no tier flag for v3.0, `PROXYSQL31=1` for v3.1, and `PROXYSQL40=1`
for v4.0. These are product configurations, not source branches to check out.

Do not add `labeled` or `unlabeled` triggers. Label edits neither start nor
cancel CI. Resolve the labels once during central build setup, as ASAN does
today; a label change before that resolution affects that execution, whereas a
change after it affects the next ordinary execution. Downstream jobs must never
query labels again. A consumer-only rerun uses its original build configuration.

Remove the current post-merge `CI-tier-sweep`, including its reusable workflow.
Do not replace it with a scheduled sweep in this change. The user's request to
remove it supersedes the earlier suggestion of retaining a scheduled backstop.

## Isolation and delivery

Work is isolated in two local branches and worktrees:

| Base | Working branch | Worktree |
| --- | --- | --- |
| `origin/v3.0` at `696781be8` | `feature/ci-pr-tiers-callers` | `.worktrees/ci-pr-tiers-callers` |
| `origin/GH-Actions` at `b83e4a156` | `feature/ci-pr-tiers-engine` | `.worktrees/ci-pr-tiers-engine` |

Do not modify PR #5882, its branch, its labels, or its workflows/runs. Its remote
head at isolation verification is `3f0def2d6e408561de3efb18b7fc5adf428ff65f`.
Its existing local worktree remains on `f677fb909b9b70b9f248a61eb9299db99315a435`.

Do not push changes directly to `v3.0` or `GH-Actions`. Updating the shared
`GH-Actions` ref would affect other PRs even without touching their branches.
Prepare coordinated review branches. Any eventual live validation must use
explicit candidate refs in a separate probe, including nested control-script
checkouts; existing default-branch `workflow_run` callers otherwise resolve the
production implementations. Do not run a full extra fanout merely to validate
YAML or selection logic while the CI queue is congested.

The caller deletion must precede deletion of the reusable sweep in production,
and any already-running sweep must be allowed to finish before its runtime
helpers are removed. Preparation here does not authorize merging either branch.

## Existing machinery and chosen approach

Keep the two-branch caller/reusable split and the existing
`CI-trigger` -> `CI-builds` -> test-workflow cascade. Extend the central build
matrix and the standard artifact consumers rather than copying the whole
workflow catalogue per tier or retaining a separate sweep pipeline.

The current `ci-builds.yml` already accepts a tier, validates its flags, and
stages plugins only on v4.0. Preserve that support and the tested version-aware
pruning helper. The changes are in configuration selection, artifact identity,
fanout, and reporting.

Rejected alternatives:

- Adding PR triggers to the sweep keeps a separate shard-only reporting path
  and duplicates orchestration rather than making the ordinary tests tier-aware.
- Copying every workflow for each tier creates three independently maintained
  implementations and makes fixes easy to apply inconsistently.
- Re-querying labels in each consumer can select tiers that were never built,
  especially during long queues or partial reruns.

## Configuration and handoff contract

Extend the ASAN resolver into one central configuration resolver. For a trusted
PR-backed execution, fetch its labels once and emit the ordered tier list and
TAP mode. Pushes and direct manual dispatches retain v4.0/normal defaults.
Fork builds retain their existing isolation and permissions; a tier label does
not grant access to secrets, writable checks, or self-hosted infrastructure.
If a PR-backed execution cannot resolve its associated PR or fetch its labels,
fail visibly rather than silently reducing coverage. Do not pick an arbitrary
PR when association is ambiguous.

Persist a versioned JSON execution manifest before expensive builds. It contains:

- Source repository and tested SHA, associated PR when present.
- Originating trigger run ID and attempt.
- Build run ID and attempt, plus the selected control implementation revision.
- Selected tiers, TAP mode, and actual coverage instrumentation for each tier.
- The expected applicable workflow/group and tier combinations.
- Artifact identities and PR check identities for this execution.

One `CI-builds` run contains all selected build legs with `fail-fast: false`.
Do not create several indistinguishable `CI-builds` runs for one trigger.
Correlate it to the trigger run ID/attempt, rather than the current search for
any build whose display title contains the SHA. A new run for the same SHA must
not accidentally reuse a different ASAN mode or tier selection.

Consumers resolve the producer manifest and download artifacts from that exact
build run/attempt. Artifact names distinguish tier and mode; diagnostics include
the producer identity. Do not fall back to the newest repository-wide artifact
matching only a SHA. A missing or mismatched manifest/artifact is an error.
Validate the restored binary's product version and handoff metadata before tests.

Keep coverage instrumentation separate from product selection: preserve current
v4.0 coverage behavior and v3.0/v3.1 debug builds. ASAN composes with those settings.
Gate coverage collection/uploads using the actual instrumentation metadata.
Do not request gcov files from an uninstrumented lower-tier build.

## Test fanout and applicability

Each ordinary consumer of the central handoff expands across the selected tiers
that it supports. Its job names, artifacts, runtime infrastructure identifiers,
logs, and coverage flags distinguish the configuration. Preserve dedicated
per-group workflow reporting, including `CI-mysql84-gr-g2`.

Inventory every central-handoff consumer, including `ci-unit-group.yml` and
third-party integration workflows; do not rely only on matches for the literal
`HANDOFF_VARIANT` key. Some consumers embed the artifact name directly.
Independently built specialty pipelines (for example unit ASAN/TSAN and cluster
simulator builds) retain their existing scope and triggering behavior.

Use the existing minimum-version selection rules for TAP tests. Mixed groups
must retain their lower-tier tests; do not infer an entire group's eligibility
from words such as `ai` or `genai` in its name. A workflow requiring an unavailable
plugin is v4.0-only unless it has an explicitly supported lower-tier path.
Groups with no applicable tests must be reported as not applicable, never as
having passed tests that were not run.

Replace the sweep-only coverage validator with a tier-fanout coverage contract.
Before removing `tier-sweep.lst`, verify that every currently covered applicable
group has a route through the new fanout, or record a concrete, reviewed reason
why its prior sweep route was invalid. Preserve unit coverage. This prevents
deleting the sweep from silently deleting useful lower-tier coverage.

Keep the current build-success gate: if a required build fails, the trigger
fails and test fanout does not run. Complete the corresponding queued test
checks as blocked/skipped with the build failure linked, and fail the execution
summary. A failed requested tier cannot result in an overall successful run.

## Reporting and runner use

Use explicit GitHub job names and custom PR check names, for example:

```text
CI-mysql84-gr-g2 / tests (v3.0, mysql84, debug)
CI-mysql84-gr-g2 / tests (v3.1, mysql84, asan)
CI-mysql84-gr-g2 / tests (v4.0, mysql84, coverage)
CI-mysql84-gr-g2 / tests (v4.0, mysql84, asan+gcov)
```

Create queued checks on the real PR SHA once the central execution plan is
known, before individual test runners start. Consumers update those same checks
instead of creating duplicate names. Include run identity in check metadata and
direct links to the actual Actions execution. Check publication failures must
be visible; do not silently treat them as successful reporting.

Provide a `CI / selected tiers` summary whose success requires all applicable
requested checks to succeed. Updates must be scoped to the execution manifest
and tolerate concurrent completions, retries, and out-of-order updates. Missing,
failed, cancelled, or unexpectedly skipped required work cannot produce success.
Reuse completion/finalization steps rather than introduce a runner that waits
for the entire fanout. Do not change repository branch-protection settings here.

The outer Actions run title is evaluated before runner-side label resolution.
Under the unchanged trigger model it cannot interpolate a later job output.
Keep source branch/SHA and trigger identity in that title, and put exact selected
tiers in the job names, PR checks, and execution summary. A workflow spanning
multiple tiers must not have a title falsely identifying it as a single tier.
This refines the earlier proposal to put dynamically resolved tiers in every
run title without changing the user-visible check naming requirement.

Avoid adding a separate hosted-runner prerequisite per tier. Reuse existing
setup jobs where possible, and route trusted eligible planning work directly to
the configured self-hosted pool. Preserve the trust boundary and existing test
runner policy; a broad runner-scheduler redesign is outside this change.

## Removal and documentation

Remove:

- `v3.0:.github/workflows/CI-tier-sweep.yml`.
- `GH-Actions:.github/workflows/ci-tier-sweep.yml`.
- Sweep-only `.github/shards.json`, after verifying no remaining consumers.
- `test/tap/groups/tier-sweep.lst` and its obsolete validator once the replacement
  fanout coverage contract verifies equivalent applicable coverage.
- The sweep-only entry in `test/infra/control/run-ci-lint.bash`, replacing it with
  the new contract check.

Update `doc/GH-Actions/README.md` and relevant live workflow comments to describe
label selection, immutable execution selection, names, artifact identities, and
manual versus PR defaults. Historical specs need not be rewritten. Retain and
test `prune-tier-handoff.bash`, which remains useful for lower-tier artifacts.

## Validation and acceptance

1. Test all eight combinations of the two tier labels and `ci:asan`; assert
   exact build legs, modes, and applicable test fanout. Test near-match labels,
   unrelated labels, push/manual defaults, and untrusted callers.
2. Test failed label reads, malformed context, missing/ambiguous PR association,
   and malformed manifests. None may silently select less coverage.
3. Test label mutation between producer and consumer, repeated executions for
   the same SHA, build and consumer attempts, and wrong-tier artifacts. Consumers
   must remain bound to their producer configuration.
4. Exercise representative TAP, unit-group, third-party, and plugin-only workflow
   planning and handoff restoration using fixtures. Verify coverage gating,
   version filtering, retained applicable groups, and no artifact-name collisions.
5. Test queued/running/terminal PR checks, failed builds, cancelled jobs, missing
   results, and out-of-order completion. The aggregate must never pass early.
6. Run YAML/action validation, shell checks, configuration/handoff tests, caller
   lint, and the cross-branch fork-isolation contract against the candidate refs.
   Compare existing trigger definitions and verify absence of label triggers.
7. Verify both sweep workflow files and all live sweep-only wiring are removed.
   Confirm production refs and PR #5882 remain unchanged by this work.
8. Record live GitHub execution as a separate validation boundary: local fixtures
   cannot prove Actions scheduling, permissions propagation, or PR UI behavior.
   Any live probe must be explicitly isolated from production reusable refs.

## Baseline evidence

On the isolated starting revisions, `run-ci-lint.bash` passes, as do
`test-resolve-tap-build-mode.bash` and `test-prune-tier-handoff.bash`.
The lint log is `/tmp/ci-pr-tiers-baseline-lint.log`.

Two handoff regression scripts fail before changes:
`test-genai-plugin-handoff.py:42` expects `contains(matrix.type,'-genai')`, and
`test-mysqlx-runtime-handoff.py:77` expects `contains(matrix.type,'-mysqlx')`.
Commit `f772900f8` replaced these workflow conditions with the explicit
`needs.resolve-tier.outputs.is_v40 == 'true'` gate. Update the tests to exercise
plugin staging eligibility across tiers and retain their runtime staging checks,
rather than merely changing the expected substring. These failures are not
evidence of a plugin staging runtime failure, but they prevent claiming a clean
handoff-test baseline.

## References

- Existing ASAN contract:
  `docs/superpowers/specs/2026-08-15-pr-label-controlled-tap-asan-design.md`.
- Current CI architecture: `doc/GH-Actions/README.md` (some historical sections
  still describe the retired cache-based handoff; actual workflows take precedence).
- GitHub's run-title expression limits:
  <https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#run-name>.
- GitHub job naming and dependency behavior:
  <https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-jobs>.
