# PgSQL Poisoned-Query ASAN UAF Implementation Plan

**Goal:** Keep the incoming simple-query packet alive until request logging and
parser cleanup finish, then verify the complete ASAN TAP fan-out on PR #6083.

**Design:** `CurrentQuery` borrows its SQL pointer from the packet handled by
`handler_poisoned_simple_query()`. Preserve the existing ownership model and
move `RequestEnd()` before `l_free()` in both exits; do not add a copy or change
mirror-session behavior.

## Implementation

1. Use the existing failing ASAN run of
   `pgsql-retry_guard_in_txn_on_broken_backend-t` as the regression's red state.
2. Reorder finalization and packet release in both malformed and normal exits.
3. Run formatting/diff checks and focused source checks, then commit and push
   `ci/verify-asan-label` so the label-selected ASAN workflow reruns.
4. Inspect all prior failed PR #6083 jobs, group failures by sanitizer signature,
   and compare them against the fresh run before making any additional fix.
