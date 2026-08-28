# PR-label-controlled TAP ASAN build

## Goal

Make the existing TAP integration build and fan-out run under AddressSanitizer
only when the pull request has the `ci:asan` label.  A labeled run replaces the
normal TAP integration build for that commit; it does not add a second fan-out.

## Scope

This design changes only the central CI build-and-handoff path on the
`GH-Actions` branch.  The existing `CI-unit-tests-asan-coverage` workflow is
unchanged.  MySQLX and other specialty build variants are out of scope for this
change.

## Trigger policy

- Keep the existing `pull_request`, `push`, `workflow_run`, and
  `workflow_dispatch` triggers unchanged.  Do not add `labeled` or `unlabeled`
  triggers.
- A label change takes effect only on the next ordinary CI run.  Pushing an
  empty commit is the explicit way to start that run.
- `workflow_dispatch` and non-PR builds always use the normal TAP mode.

## Mode resolution

At the start of the reusable `ci-builds.yml` workflow on `GH-Actions`, resolve
the pull request associated with the triggering workflow run and query its
current labels through the GitHub API.

- If the PR has `ci:asan`, select `asan` mode.
- If it does not, select `normal` mode.
- If the run is not PR-backed, select `normal` mode.
- If a PR-backed run cannot determine its labels, fail the build.  Falling back
  silently to a normal build would make a requested sanitizer run look green.

The resolved mode is logged prominently and made available to the build step.

## Build and handoff

The existing TAP build matrix keeps its current artifact and build-handoff
names.  In `asan` mode, the standard TAP build receives `WITHASAN=1` and
`TEST_WITHASAN=1`; in normal mode it receives neither setting.

The build produces one flavor only.  Reusing the existing handoff names means
the current downstream TAP workflows restore exactly the artifact built for
their commit, without per-group workflow changes or a doubled artifact budget.

## Fan-out behavior

The fan-out remains unchanged.  Downstream workflows continue to download the
same `src` and `test` handoffs they use today.  A `ci:asan`-labeled PR therefore
runs the same integration TAP checks, but against ASAN-instrumented binaries.

Runtime support needed for sanitized containers (ASAN runtime, options, and
ASLR handling) is deliberately a follow-up shared-infrastructure task; it is
not solved by the build-mode selector itself.

## Verification

1. On an unlabeled PR, confirm `ci-builds` reports `normal` and publishes the
   existing normal handoff names; normal fan-out remains green.
2. Add `ci:asan`, push an empty commit, and confirm `ci-builds` reports `asan`,
   uses the sanitizer flags, and publishes the same handoff names.
3. Confirm ordinary TAP fan-out restores those handoffs without workflow-file
   changes.
4. Simulate or force a label-query failure for a PR-backed run and confirm the
   build fails rather than selecting normal mode.
5. Confirm a manual dispatch remains normal and
   `CI-unit-tests-asan-coverage` retains its current trigger behavior.
