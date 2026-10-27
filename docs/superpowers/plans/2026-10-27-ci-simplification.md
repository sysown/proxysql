# CI simplification implementation plan

**Goal:** Remove avoidable work and failure points identified in the approved CI audit, preserving test coverage, artifact identity, reruns and safe extraction.

**Architecture:** Make each change independently reviewable. Shared execution code belongs on GH-Actions; workflow callers and their validators belong on v3.0. Use native workflow completion to fan out the current cascade. Retain the legacy trigger adapter while other maintained branches still call it.

**Constraints:** Preserve commit history and the configured maintainer identity. Do not run benchmarks or modify PostgreSQL forwarding. Keep checksums, source/tier binding, fork isolation, failed-job reruns, diagnostic logs and existing test applicability.

## Tasks

- [ ] Build status: add a regression executing the actual build pipeline with a failing producer and successful container log; enable pipefail and delete log-text success inference. Files: ci-builds.yml; test_ci_tier_workflows.py.
- [ ] Coordination: move plan, finalization and consumer-context metadata jobs to hosted runners. Files: ci-builds.yml; ci-tier-context.yml. Verify existing workflow contracts and YAML.
- [ ] Retention: retain the handoff for the same period as its manifests/bindings. File: ci-builds.yml. Verify artifact declarations.
- [ ] Lint: run on PR changes, manual dispatch and maintained-branch pushes; remove the feature-branch push label lookup and obsolete lookup tests. Files: CI-lint-groups-json.yml; test_ci_skip_label.py. Keep PR skip-label behavior.
- [ ] Runner selection: replace copied selectors with one shared selector while preserving hosted distributions and explicit failure policies. Use the existing real-gh/local-API behavioral tests, including pagination and API errors. Files: shared picker workflow/script; existing consumer workflows; test_ci_runner_selection.py; workflow contracts.
- [ ] Native cascade: trigger the current source CI-builds workflow directly from source events; trigger consumers on its completion. Publish the accepted producer from build finalization, bind consumers to the completed run and preserve retained successful artifacts on partial reruns. Keep legacy trigger handling for v2.7/v4.0 callers. Files: ci-builds.yml; ci_tier_runtime.py; CI-builds.yml; CI-trigger.yml; source consumer wrappers and fanout/cancellation validators. Test source events, source SHA, acceptance after success only, failed producers, missing/foreign acceptance, and failed-job reruns.
- [ ] Documentation and integration: describe the resulting event flow and the retained legacy boundary. Run complete shared Python tests, source workflow validators and repository lint. Open paired PRs with the required merge order; do not merge global CI changes without owner review.

## Audit correction: archive restoration

The first decompression pass checks the complete archive before any files are extracted. Existing tests require both unsafe members and corrupt trailing zstd data to leave the checkout untouched. A single streaming extraction would violate that guarantee. Preserving it would require staging and safe publication, increasing code and filesystem complexity. Retain the current two-pass implementation; it has a demonstrated correctness purpose rather than being redundant validation.
