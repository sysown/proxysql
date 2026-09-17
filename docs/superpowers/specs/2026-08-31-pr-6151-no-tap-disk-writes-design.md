# PR 6151 TAP Disk-Safety and Conflict-Resolution Design

## Goal

Remove every disk-configuration mutation introduced by PR 6151 and bring the
feature branch up to date with `v3.0` without losing either the feature changes
or newer base-branch work.

## TAP Disk-Safety Contract

The `mysql-server_version_by_interface-t.cpp` TAP test must not execute
`SAVE MYSQL VARIABLES TO DISK`, `LOAD MYSQL VARIABLES FROM DISK`, or any
equivalent command that writes, restores, or directly manipulates ProxySQL's
disk configuration.

The test will continue to cover behavior that belongs to TAP-owned runtime
state:

- configuration-file startup in its self-launched ProxySQL process;
- Admin-variable updates followed by `LOAD MYSQL VARIABLES TO RUNTIME`;
- listener-specific handshake and internal-response behavior;
- scalar fallback behavior; and
- cluster synchronization through the existing cluster test.

Disk round-trip assertions will be removed rather than replaced with a private
SQLite database, a temporary disk database, or direct table writes. Persistence
is owned by ProxySQL's established variable machinery and is outside this
feature test's scope.

## Documentation

The feature design and implementation plan must not claim that this TAP saves
or restores disk configuration. They will state explicitly that disk
persistence is not exercised by this feature's TAP coverage.

## Conflict Resolution

The current `origin/v3.0` branch will be merged into the feature branch. A merge
commit is preferred over rebasing because it resolves the PR conflict without
rewriting the published branch history.

For each conflict, the resolution will preserve the latest `v3.0` behavior and
reapply only PR 6151's intended additions:

- retain the centralized lint runner integration in the lint workflow;
- retain the per-interface version selection in `MySQL_Session.cpp` alongside
  current base-branch session changes;
- retain the new TAP group entry while preserving current sorted base entries;
- retain the new unit targets while preserving current base targets.

No unrelated base-branch changes will be altered.

## Verification

Completion requires all of the following:

- a case-insensitive scan of PR-added TAP code finds no executable
  `SAVE ... TO DISK` or `LOAD ... FROM DISK` command;
- the focused per-interface unit, protocol, and self-launched TAP tests pass;
- the repository CI lint runner passes, including the real pre-push hook;
- `git diff --check` reports no whitespace errors;
- Git reports no unmerged paths;
- a merge-tree or GitHub PR check reports no remaining conflict with `v3.0`;
  and
- the branch is pushed without rewriting its existing published history.
