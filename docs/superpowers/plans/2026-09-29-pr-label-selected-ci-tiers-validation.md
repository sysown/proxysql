# Selected-tier CI implementation validation

Updated after automated review on 2026-09-29. This is a review candidate, not a production
rollout or a claim that live GitHub execution has passed.

## Branches and isolation

- Engine: `feature/ci-pr-tiers-engine`, based on `b83e4a156`, candidate
  `d7418b7cd`; worktree `../ci-pr-tiers-engine`.
- Callers: `feature/ci-pr-tiers-callers`, based on `696781be8`; this worktree.
- PR #5882's local worktree remains clean at `f677fb909b9b70b9f248a61eb9299db99315a435`.
- Read-only GitHub verification still shows PR #5882 at
  `3f0def2d6e408561de3efb18b7fc5adf428ff65f` on
  `feature/pgsql-native-backend-protocol`.
- Review branches are published as PRs #6263 and #6264. No merge, workflow
  dispatch, label change, branch-protection change, or production-ref update
  was performed. Both worktrees are retained.

## Implemented behavior

Default v4.0, with additive `ci:v3.0` and `ci:v3.1`; `ci:asan` independently
selects the mode for every selected tier. Labels and variable matrices are
snapshotted during producer setup. The 73 changed caller workflows retain their
original trigger maps; label events were not added.

Queued checks, explicit tier/mode names, execution-scoped handoffs, actual version
filtering, coverage gates, and a selected-tier summary are wired through 84
catalogue entries and 67 consumer bodies. Lower-tier units run inside the producer.
The sweep caller, reusable, shards, runtime group list and old validator are
removed. All 54 former sweep groups have validated routes for **both** lower tiers.

The trigger saves the exact producer it accepted before completing. Consumers
resolve that immutable acceptance and preserve their binding on reruns. Full
producer reruns create another plan; partial retries retain the successful plan
and skip already-published artifact names. Cross-repository source access uses
the existing optional artifact-read token; caller reporting uses the caller's
repository, SHA and token. Manual subsets use distinct summary and check names.

## Local evidence

- 43 helper/workflow Python tests pass, covering selection, immutable identity,
  safe archive extraction, real tar/zstd/ZIP restoration and binary execution,
  version filtering, partial reruns, delayed consumers, manual/cross-repository
  ownership, legacy multi-instance callers, and the reproduced summary race.
- Both plugin handoff regression scripts pass, as do the existing ASAN resolver
  and tier-pruning shell suites.
- Full `test/infra/control/run-ci-lint.bash` passes using the automatically
  selected companion SHA. The missing-engine-ref path also passes, skipping
  paired structural checks while still running every validator test suite. Its advisory group-coverage output retains the baseline warning
  `missing-workflow NEW=1 known=36`; this is not a warning-free claim.
- Fork-isolation mutation tests: 22 passed. Tier-route mutation tests: 11 passed,
  including removal of either lower tier, disabled routes, selected-matrix wiring,
  both modes, and producer unit coverage. Engine-ref selection tests: 2 passed.
- Engine actionlint passes for the full workflow directory. Caller actionlint
  passes for all 74 modified workflows (embedded shellcheck disabled in both).
  Full embedded shellcheck retains legacy diagnostics; the modified lint scripts
  pass standalone shellcheck. Whole-tree caller actionlint still has
  pre-existing deprecated `macos-13` labels in unrelated workflows.
- Trigger-map comparison, Python compilation, `git diff --check`, Bash syntax
  and shellcheck of the modified lint entry point pass.

Actual catalogue plus repository matrix-variable snapshot, using representative
3.0.12/3.1.12/4.0.12 versions and source group metadata:

| Tier labels | Mode | Applicable / candidate checks |
| --- | --- | --- |
| None | normal | 209 / 209 |
| None | ASAN | 209 / 209 |
| v3.1 | normal | 415 / 415 |
| v3.1 | ASAN | 415 / 415 |
| v3.0 | normal | 414 / 415 |
| v3.0 | ASAN | 414 / 415 |
| Both | normal | 620 / 621 |
| Both | ASAN | 620 / 621 |

`ai-g2` is explicitly not applicable to v3.0. For every combination, complete
success observations pass and removing one required observation prevents success.
These are fixture results, not real product builds or Actions runs.

## Independent review disposition

One independent whole-change review examined the initial implementation; the
implementer then corrected findings and ran targeted regressions. No second
independent review of the corrections is claimed.

| Finding | Disposition |
| --- | --- |
| Internal `../../lib` symlinks rejected | Fixed; real archive regression plus escape rejection |
| Actual two-component minimum-version tags rejected | Fixed and tested |
| Partial consumer reruns remain pending | Fixed using native job presence in the current attempt |
| Producer reruns rebind delayed consumers | Fixed with trigger acceptance artifact and immutable consumer bindings |
| Partial producer uploads collide | Retain plan and skip published handoffs/metadata/manifests; logs include attempt |
| Cross-repository access and reporting broken | Separate source-read credentials and caller reporting ownership |
| Manual subset duplicates central aggregate | Distinct reporting namespace, aggregate and individual check names |
| Old multi-instance caller incompatibility | Resolve original instance from snapshotted cells and stable input-specific binding names |
| Build registration remains pending | Registration is a completed registration-only check; builds have separate checks |
| MySQLX nested checkout escapes candidate ref | Uses resolved control SHA |
| Migration validator accepts incomplete lower-tier routes | Requires both tiers and actual group invocation |
| Concurrent summary publication/rerun lifecycle | Mitigated, but strict guarantee remains unresolved; see below |

## Automated review corrections

- Lower-tier test steps no longer depend on the coverage-only flag. Runner-pool
  pickers use hosted runners so they can assess a saturated self-hosted pool.
- Coverage uploads identify the tested SHA, and parser-algorithm coverage names
  match the infrastructure identity.
- Artifact downloads allow 900 seconds and retry bounded transient read failures.
  Ambiguous write failures are never replayed; explicit rate-limit rejections
  may retry. Error output does not disclose subprocess stderr or payloads.
- Manual consumers require both producer run and attempt; titles identify that
  producer. Reporting permissions are explicit throughout summary calls.
- Fanout validation checks enabled automatic routes, actual group invocation,
  selected-tier matrices and required dependencies for both lower tiers/modes.
  Unsupported conditions fail closed. Fork checks accept either job or step
  trust guards and require the producer to depend on its plan.
- `.github/ci-tier-engine-ref` pins the reviewed companion commit for lint while
  production lacks the catalogue. Candidate data is fetched, not executed.
  Once production contains the catalogue, lint automatically selects production.
  Missing-ref handling covers both paired checks while all validator tests run.
- Operator documentation restores the clean-build warning and staged rollout
  requirements and clarifies that `control_ref` selects scripts only.

Follow-up Cubic review on the published revision:

- Negation before a comparison is rejected with a diagnostic rather than
  translated with Python's different precedence. Independent negation terms,
  such as `!cancelled() && matrix.tier != 'v40'`, remain supported.
- Coverage requires an enabled matrix source: the consumer call, shared workflow
  output, context job output and runtime step must be wired together. The
  producer's plan output is checked too. Mutation tests cover disabled sources,
  broken output mappings, missing steps and the wrong runtime command or file.
  This is a structural contract; engine tests validate runtime-emitted cells.
- A fetched legacy engine without a companion pin fails with a clear diagnostic.
  Manual-run documentation directs searches to producer run/attempt, since the
  title SHA is the dispatch ref's SHA.
- Both comments about empty automatic producer inputs describe the intended
  paired contract: the engine inputs are optional strings defaulting to empty,
  and `consumer()` loads the trigger's accepted-producer artifact when no manual
  run ID is supplied. They do not require caller changes; live candidate
  validation and staged rollout remain necessary.
- The full paired lint suite and standalone shellcheck pass after these changes.

These corrections do not close the reporting/live-validation limits below.

## Remaining reporting and live-validation boundary

The strict guarantee that an aggregate can never show an earlier success after
any rerun starts is **not fulfilled**. The reproduced interleaving now revalidates
terminal publication and corrects the stale result; native job outcomes are
checked at the success boundary. However, GitHub Checks updates are not atomic
with workflow rerun events. There can be transient stale presentation, and a
rerun cancelled before every reporting/finalization opportunity can leave its
preceding result visible. Missing initial results still cannot produce success.

Native Actions checks remain necessary; the custom aggregate must not become a
standalone merge gate. Closing the strict guarantee needs an event-aware lifecycle
reporter or a revised aggregate contract. That would require a separate design
decision because this change deliberately preserves triggering events and avoids
an always-waiting fanout observer. This report records the gap; it does not treat
it as user approval to relax the design.

Live scheduling, permissions propagation, PR UI behavior, real multi-GB payload
resource use, and API quotas at the full matrix scale remain unverified. A host
loader failure during binary-version verification falls back to the existing
Ubuntu 24 packaging image, but real lower-tier builds have not been run here.
No claim of improved CI latency is made.

## Eventual integration order

Do not merge both branch tips blindly or update shared `GH-Actions` to test them.
These changes are prepared for coordinated review only.

1. Use explicit candidate reusable refs **and** candidate `control_ref` throughout
   an isolated probe; a script checkout override alone does not change a reusable
   workflow definition. Resolve the reporting contract and live validation first.
2. Remove the sweep caller using its separate deletion commit; retain sweep runtime
   files while active sweeps finish.
3. Arrange a controlled switch after **all old central-build/trigger/consumer
   cascades**, including any PR #5882 cascade, have drained. Old triggers have no
   accepted-producer artifact and must not feed newly converted consumers. The
   compatibility for old caller inputs does not make in-flight old artifacts
   compatible with the new manifest schema.
4. Integrate engine support/consumers while retaining the sweep reusable/runtime
   helpers as needed; the engine's separate deletion commit makes this staging
   possible. Then integrate caller input/title/lint changes.
5. Remove remaining sweep runtime data once no old execution needs it. Production
   integration and any pause of ordinary starts are operator-controlled actions,
   not actions performed by this task.
