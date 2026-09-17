# Pre-push CI lint gate design

## Context

PR #6151 reached GitHub with an avoidable `groups.json` ordering failure. The
repository currently defines its lint contract only as individual commands in
`.github/workflows/CI-lint-groups-json.yml`; there is no active Git hook and no
single local command that executes the whole job. This lets local verification
omit a check that CI runs.

## Goal

Make the complete CI lint command set executable through one repository-owned
entry point and block ordinary pushes when any of those commands fails.

## Design

Add `test/infra/control/run-ci-lint.bash` as the canonical lint runner. It will
run, in the same order, every validation command currently listed in the CI
lint job, use fail-fast shell settings, print the check being executed, and
return non-zero as soon as a check fails.

Change `.github/workflows/CI-lint-groups-json.yml` to retain its checkout and
`GH-Actions` fetch setup, then invoke the canonical runner. CI and the local
hook will therefore execute the same maintained command list instead of two
copies that can drift.

Add an executable `.githooks/pre-push` that resolves the current worktree root
and invokes the canonical runner there. Configure this repository with:

```bash
git config core.hooksPath .githooks
```

Git does not activate versioned hooks automatically, so `.githooks/README.md`
will document that one-time command for other clones. The current repository
will be configured as part of this change. The standard `git push --no-verify`
escape hatch remains available for an intentional bypass.

## Failure behavior

The hook will not modify files or auto-fix lint. It will report the failing
command and stop the push. Developers must fix the violation, rerun the lint
runner, and push again. Missing runner files or inability to determine the
worktree are also hard failures, because silently skipping the gate would
restore the current problem.

## Testing

Add a shell contract test before the hook implementation. It will verify that:

- the tracked pre-push hook exists and is executable;
- the hook delegates to the canonical runner from the current worktree;
- the GitHub Actions workflow delegates to that same runner;
- a failing lint command makes the hook return non-zero;
- a successful lint command lets the hook return zero.

The current unsorted `groups.json` entry is the real failure reproduction. After
the contract test is observed failing, fix the ordering and implement the
shared runner and hook. Final verification will execute the contract test, the
canonical full lint runner, the hook itself, and `git diff --check` before the
branch is pushed.

## Scope

This change only centralizes and enforces the existing CI lint job. It does not
add unrelated formatters, auto-fix files, run builds or TAP integration suites,
or change the meaning of any existing lint check.
