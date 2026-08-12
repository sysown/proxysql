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

Implementation commits:

- `cc31f5870ad02526713246af9f052deb685c6c92`
  (`feat(mysql): isolate IAM connections in backend pools`)
- `be43d385a671a9714d47bcbfb29bec84d091573a`
  (`fix(mysql): harden IAM pool policy boundaries`)

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

- `aws_iam_pool_unit-t`: 27/27
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

## Sanitizers

The focused pool binaries were rebuilt against an ASan-enabled library:

```bash
make -C lib -j clean
NOJEMALLOC=1 WITHASAN=1 PROXYSQLCLICKHOUSE=1 \
  make -C lib -j libproxysql.a
make -C test/tap/tests/unit -j clean
NOJEMALLOC=1 WITHASAN=1 make -C test/tap/tests/unit -j \
  aws_iam_pool_unit-t connection_pool_unit-t
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
  ./test/tap/tests/unit/aws_iam_pool_unit-t
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
  ./test/tap/tests/unit/connection_pool_unit-t
```

Result: 27/27 and 24/24 with no AddressSanitizer or LeakSanitizer diagnostic.
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
- `aws_iam_pool_unit-t`: 27/27

Total: 241/241 TAP assertions.

The existing daemon-backed regressions were rebuilt for the PROXYSQL31 DEBUG
tier and passed in registered isolated MySQL 8.4 environments:

- `test_passthrough_auth_pool_reuse-t`: 19/19
- `reg_test_3504-change_user-t`: 96/96

The first pass-through attempt on the stable tier correctly exposed an
environment mismatch: that tier forces pass-through authentication off. The
DEBUG tier was then selected. The first change-user attempt exposed missing
libmysql/libmariadb helper binaries; both helpers were built with
`make -C test/tap/tests -j` and the complete suite then passed. These were
harness prerequisites, not product failures. The isolated containers and
network were stopped after validation.

During the final review rebuild, one unit link invocation omitted the required
`PROXYSQLCLICKHOUSE=1` harness flag and therefore mixed ClickHouse-enabled
library objects with test globals that did not define `GloClickHouse*`. No test
executed in that invocation. Rebuilding the same targets with the required
flag linked cleanly and produced the 241/241 result above.

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
- `change_user_start()` asserts that neither IAM mode nor an IAM handshake
  secret can reach the MariaDB change-user call.
- Existing exact-identity IAM sessions may multiplex on the authenticated
  connection; token age does not invalidate an already established session.

## Concerns

None. Live AWS/RDS authentication remains outside this pool-focused task, but
the deterministic pool, sanitizer, and existing daemon-backed regressions all
pass.
