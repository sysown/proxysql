# Task 8 Report: IAM-aware backend pool identity and reset safety

## Result

Authentication mode is now part of MySQL backend pool identity. Local and
global checkout receive the session's resolved backend policy, preserve the
existing session-variable scoring within the compatible mode, and lazily
destroy same-username entries left behind by a runtime PASSWORD/AWS_IAM policy
change. Different backend users in the same server/hostgroup do not cause
cross-user pool churn when their authentication modes differ.

Established IAM connections remain reusable for the exact same username and
mode, including beyond the token's 15-minute generation lifetime. An IAM
connection that would need identity/session reset is destroyed instead. IAM is
also excluded defensively from `CHANGING_USER_SERVER`,
`RESETTING_CONNECTION`, the asynchronous reset queue, and detached-session
reset handling, while the existing password `COM_CHANGE_USER` behavior remains
unchanged. A PASSWORD connection whose reloaded backend policy is malformed is
failed closed before verification, `CHANGING_USER_SERVER`, detached reset, or
reset-worker processing can send its retained credential.

Authorized unknown-user pass-through remains an ordinary PASSWORD connection
even though it intentionally has no backend authentication row. Successful
pass-through authorization is recorded on the established connection, so a
synthetic detached reset session and the reset worker can distinguish that
specific `backend_user_not_found` case from an untrusted missing row. The
authorization cannot override malformed policy data or enable reset for IAM.

Implementation commits:

- `cc31f5870ad02526713246af9f052deb685c6c92`
  (`feat(mysql): isolate IAM connections in backend pools`)
- `be43d385a671a9714d47bcbfb29bec84d091573a`
  (`fix(mysql): harden IAM pool policy boundaries`)
- `4e4ff6f01459183654a240a8b39abb43499ef17e`
  (`fix(mysql): preserve rowless passthrough reset reuse`)

## TDD evidence

### RED

The new pool test and its Makefile target were written before the production
changes, then built with:

```bash
make -C test/tap/tests/unit -j \
  connection_pool_unit-t aws_iam_pool_unit-t
./test/tap/tests/unit/aws_iam_pool_unit-t
```

After correcting a test-only fixture requirement (`mysql_init()` does not
populate `MYSQL::charset` in this minimal harness), the clean pre-production
run had nine intended failures:

- both same-username cross-mode identity checks
- PASSWORD-to-IAM and IAM-to-PASSWORD global policy changes
- local-cache policy mismatch draining
- IAM exclusion from `destroy_MyConn_from_pool()` reset queueing
- IAM exclusion inside the reset queue consumer itself
- IAM replacement in `CHANGING_USER_SERVER`
- IAM destruction in `RESETTING_CONNECTION`

The fixture crash was diagnosed under GDB and fixed only in test setup before
confirming the behavioral RED. Later, three lifecycle checks were changed from
freed-pointer address comparisons to pool membership/connection-state checks
because allocator address reuse made pointer inequality an invalid assertion.

### GREEN

The final focused source snapshot was rebuilt and passed:

```bash
make -C lib -j
make -C test/tap/tests/unit -j \
  aws_iam_pool_unit-t connection_pool_unit-t
./test/tap/tests/unit/aws_iam_pool_unit-t
./test/tap/tests/unit/connection_pool_unit-t
```

- `aws_iam_pool_unit-t`: 30/30
- `connection_pool_unit-t`: 24/24
- 20 consecutive repetitions of each focused binary also passed

The focused coverage includes the username/mode matrix, IAM reuse after 16
minutes, both runtime policy-change directions, local and global lazy drain,
the actual reset worker, destroy/reset/change-user state handling, and a
positive regression proving that ordinary password connections still retain
their reset queue and quality-1 `COM_CHANGE_USER` reuse behavior.

### Controller review iteration 1

The review regressions were added before the corresponding production fixes.
The first clean run had 26 assertions and nine intended failures:

- all four global mixed-user/mixed-mode preservation and exact-reuse checks
- both local mixed-user preservation checks
- attached PASSWORD reload-to-INVALID failed to terminate
- direct `CHANGING_USER_SERVER` with INVALID policy called the wrapped
  `mysql_change_user_start()`
- `RESETTING_CONNECTION` with INVALID policy called the wrapped reset path

An additional reset-worker INVALID-policy assertion was then added and failed
alone as assertion 27 before the worker guard was implemented. The final
focused suite passes 27/27. Its mixed-user cases exercise both directions
(PASSWORD checkout preserving unrelated IAM, and IAM checkout preserving
unrelated PASSWORD) in both global and thread-local pools. Its INVALID cases
exercise an attached processing session, direct change-user state, detached
reset state, and the actual asynchronous reset consumer.

Two test-harness corrections were required while establishing RED: the minimal
session fixture needed frontend protocol initialization before the generic
error packet could be generated, and the wrapped asynchronous change-user call
needed to return `MYSQL_WAIT_READ` so a forbidden invocation was observed
without completing and looping. Neither correction changed production code.

### Final review: rowless pass-through reset preservation

The final review regressions were written before the production change. The
first focused run reached assertion 22 and failed because the detached reset
destroyed the authorized rowless pass-through connection. Fixture cleanup then
encountered the already-destroyed pointer, so ownership cleanup was corrected
in test code before continuing. Tightening the test to the intended connection
API then produced a compile RED because `MySQL_Connection` had no
`set_rowless_passthrough_authorized()` member.

The GREEN implementation records successful rowless pass-through authorization
on the connection and permits reset only when all three facts still hold:

- the established connection is PASSWORD mode
- the live policy failure is exactly `backend_user_not_found`
- the connection carries the successful pass-through authorization marker

The focused suite now passes 30/30. New assertions cover the detached
`RESETTING_CONNECTION` path, the actual asynchronous reset worker, and a
negative unmarked missing-row case. Existing malformed-policy and IAM worker
tests explicitly attempt to set the marker and still prove that neither can
reach `COM_CHANGE_USER`.

## Sanitizers

The focused pool binaries were rebuilt against an ASan-enabled library:

```bash
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -C lib -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 \
  make -C test/tap/tests/unit -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 \
  make -C test/tap/tests/unit -j \
  "$PWD/lib/libproxysql.a"
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 \
  make -C test/tap/tests/unit -j \
  aws_iam_pool_unit-t connection_pool_unit-t
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
  ./test/tap/tests/unit/aws_iam_pool_unit-t
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
  ./test/tap/tests/unit/connection_pool_unit-t
```

Result: 30/30 and 24/24 with no AddressSanitizer or LeakSanitizer diagnostic.
The first combined clean-library/unit invocation exposed the unit Makefile's
feature auto-detection ordering: it evaluated the absent archive before its
recursive build and therefore omitted ClickHouse test globals. No test ran in
that invocation. Building the archive target first with the same environment,
then rebuilding the focused targets, resolved the harness ordering issue.
The normal library and unit binaries were rebuilt afterward; `nm` and `ldd`
checks found no ASan/TSan symbols or runtime dependencies in the final focused
artifact.

## Regression validation

After restoring normal non-sanitized artifacts, all nine relevant unit suites
were built together with parallel make and passed:

- `aws_iam_policy_unit-t`: 31/31
- `aws_iam_connection_config_unit-t`: 34/34
- `aws_iam_token_manager_unit-t`: 39/39
- `aws_iam_completion_queue_unit-t`: 9/9
- `aws_iam_session_state_unit-t`: 22/22
- `aws_iam_connection_secret_unit-t`: 47/47
- `mariadb_tls_server_name_unit-t`: 8/8
- `connection_pool_unit-t`: 24/24
- `aws_iam_pool_unit-t`: 30/30

Total: 244/244 TAP assertions.

The existing daemon-backed regressions were rebuilt for the `PROXYSQL40=1`
DEBUG target and passed in fresh registered isolated MySQL 8.4 environments:

- `test_passthrough_auth_pool_reuse-t`: 19/19
- `reg_test_3504-change_user-t`: 96/96

The first normal-binary setup attempt stopped before tests because the
registered MySQL 8.4 group config sets the DEBUG-only `admin-debug` variable.
The DEBUG target was then built with the same `PROXYSQL40=1` invocation
environment. After the root clean, the first test discovery found no TAP
binaries, and the first change-user execution found its libmysql/libmariadb
helper binaries absent. The two test binaries and both helpers were rebuilt
with `PROXYSQL40=1 make -C test/tap/tests -j ...`; both complete suites then
passed. These were harness prerequisites, not product failures. The isolated
containers and network were removed after validation.

After daemon validation, final normal artifacts were restored with exactly the
requested top-level environment (ClickHouse remained enabled by default):

```bash
PROXYSQL40=1 make -j clean
PROXYSQL40=1 make -j
```

That build completed successfully. The unit archive and all nine suites were
then rebuilt through the unit harness using `PROXYSQL40=1` only and produced
the 244/244 result above.

`git diff --check` was clean before the implementation commit.

## Security checks

- Pool compatibility requires exact username and recorded auth mode.
- PASSWORD/AWS_IAM mismatches for the requested backend username are removed
  only on checkout; unrelated usernames remain pooled, and user reload does
  not synchronously scan all live connections.
- IAM checkout deletes any candidate that would require `COM_CHANGE_USER`.
- IAM destruction cannot enqueue reset work, and the reset worker independently
  discards an IAM entry if one is ever queued.
- Both session change-user/reset states replace or destroy IAM connections
  before `async_change_user()`.
- INVALID reloaded policy destroys an attached PASSWORD connection and clears
  pending state before change-user; detached reset and reset-worker paths also
  discard it without invoking `async_change_user()`.
- A connection-level marker preserves reset/salvage only for an already
  authorized rowless pass-through PASSWORD identity. The marker is cleared for
  non-PASSWORD modes, cannot relax malformed policies, and an unmarked missing
  row is discarded.
- `change_user_start()` asserts that neither IAM mode nor an IAM handshake
  secret can reach the MariaDB change-user call.
- Existing exact-identity IAM sessions may multiplex on the authenticated
  connection; token age does not invalidate an already established session.

## Concerns

None. Live AWS/RDS authentication remains outside this pool-focused task, but
the deterministic pool, sanitizer, and existing daemon-backed regressions all
pass.
