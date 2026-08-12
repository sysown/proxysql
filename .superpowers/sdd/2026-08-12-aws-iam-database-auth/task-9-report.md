# Task 9 Report: IAM 1045 Retry and Detached Kill Helpers

## Result

Task 9 is complete in implementation commit
`6e7f279cae0ef1bcee8679718091e7eaafee5572`
(`feat(mysql): bound IAM auth retries and kill helpers`).

The MySQL session now gives an IAM backend authentication failure exactly one
fresh-token retry, and only when the first terminal connector result is MySQL
1045 with a recorded nonzero token generation and exact validated IAM key.
The retry conditionally invalidates only that exact key/generation, destroys
the failed connection, and disables the ordinary multi-server retry budget.
A repeated 1045 is terminal; IAM transport/TLS and other protocol errors do
not invalidate or retry. Password-mode behavior remains on the pre-existing
path.

Detached IAM kill helpers now carry authentication metadata rather than a
password/token. Inside the already-detached helper they validate the same IAM
connection key, request a current token through the blocking token-source path
with a bounded deadline, enforce TLS and endpoint hostname verification, issue
the requested `KILL`, and cleanse both the secure token and Connector/C
`MYSQL::passwd` copy. The original backend connection and its handshake secret
are never read, cleared, or modified by the helper.

## RED

The relevant Task 8 baseline was clean before adding the Task 9 tests:

- `aws_iam_session_state_unit-t`: 22/22
- `aws_iam_connection_secret_unit-t`: 47/47

The production code was then left unchanged while both new tests were added.
The genuine RED results were:

- `aws_iam_failure_unit-t`: exit 1, with 8/10 assertions failing. The two
  passing controls were the existing transport/no-invalidation disposition
  and ordinary password retry. Exact key/generation invalidation, one fresh
  acquisition, retry ceiling, stale-generation preservation, generic client
  error, and redacted repeated-1045 diagnostic were absent.
- `aws_iam_kill_helper_unit-t`: compile failure because production `KillArgs`
  had only the existing 9/10-argument password constructors and no IAM
  metadata/deadline constructor. Thus no IAM helper behavior could compile,
  much less pass.

This captured the missing public/state behavior before any implementation
change. The client ERR assertion uses a narrow link wrapper around the public
protocol emission method to observe error code, SQLSTATE, and message without
growing a synthetic event-loop/socket harness.

## GREEN implementation

### Bounded IAM 1045 handling

- The session preserves the validated `AwsIamTokenKey`, completion generation,
  and a per-acquisition fresh-token retry flag until terminal connect handling.
- The first qualifying IAM 1045 calls conditional
  `invalidate(key, generation)`, destroys the failed connection, zeros the
  normal retry budget, and re-enters the normal IAM acquisition path.
- The retry token replaces the preserved identity/generation; a second 1045
  receives no third acquisition.
- IAM TLS/transport/non-1045 errors are terminal without invalidation.
- Every terminal IAM connector failure sends fixed error 9002 / `HY000` /
  `Unable to connect to backend`; backend `mysql_error()` text never enters
  the client packet.
- The repeated fresh-token 1045 diagnostic contains redacted metadata and a
  SigV4 clock-skew hint. Tests prove that backend text, token material, access
  keys, and session tokens are absent.
- Success, timeout, cancellation, and terminal cleanup reset the acquisition
  metadata. Ordinary password connections retain their existing retry and
  error behavior.

### Detached IAM kill helpers

- `KillArgs` carries authentication mode, configured endpoint, region,
  database user, and helper deadline. Its password field is always null for
  IAM mode.
- The helper resolves SSL policy using the configured endpoint/database user,
  runs the shared IAM connection validator, and calls `request_blocking()`
  only inside the detached helper.
- IAM connector options enforce SSL, certificate verification, cleartext
  plugin use, disabled reconnect, and TLS server name equal to the configured
  endpoint while the transport may use a resolved IP.
- Query-kill construction passes IAM metadata without borrowing the original
  connection token. Both query and connection kill commands use the same
  helper implementation.
- The secure result and Connector/C password copy are explicitly cleansed on
  success and all exits. Password-mode helper construction and connection
  behavior are unchanged.

The focused GREEN result was:

- `aws_iam_failure_unit-t`: 10/10
- `aws_iam_kill_helper_unit-t`: 12/12

## Verification

All direct normal build invocations supplied only `PROXYSQL40=1`; ClickHouse
remained enabled by the repository defaults. Every make invocation used `-j`.
No `cleanall` was used.

### Focused repetition

The normal library and both focused binaries were rebuilt, then each focused
test was executed 20 times:

```bash
PROXYSQL40=1 make -C lib -j
PROXYSQL40=1 make -C test/tap/tests/unit -j \
  aws_iam_failure_unit-t aws_iam_kill_helper_unit-t
```

Result: 40/40 process executions passed.

### Address/Leak Sanitizer

The focused binaries were rebuilt against an ASan-enabled, no-jemalloc
library using only genuinely required cleans:

```bash
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -C lib -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 \
  make -C test/tap/tests/unit -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -C lib -j
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 \
  make -C test/tap/tests/unit -j \
  aws_iam_failure_unit-t aws_iam_kill_helper_unit-t
```

The first sanitizer execution found an 18-byte test-fixture leak from an
unnecessary manual duplicate of the synthetic CA path. The helper thread
already refreshes its own thread-local CA value, so that redundant fixture
allocation was removed. After rebuilding, both focused binaries passed five
ASan/LSan executions each with
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and no diagnostic: 10/10
sanitized process executions passed.

### Prior and focused unit suites

After restoring normal artifacts, the nine prior suites and both Task 9
suites passed together:

- `aws_iam_policy_unit-t`: 31/31
- `aws_iam_connection_config_unit-t`: 34/34
- `aws_iam_token_manager_unit-t`: 39/39
- `aws_iam_completion_queue_unit-t`: 9/9
- `aws_iam_session_state_unit-t`: 22/22
- `aws_iam_connection_secret_unit-t`: 47/47
- `mariadb_tls_server_name_unit-t`: 8/8
- `connection_pool_unit-t`: 24/24
- `aws_iam_pool_unit-t`: 30/30
- `aws_iam_failure_unit-t`: 10/10
- `aws_iam_kill_helper_unit-t`: 12/12

Total: 266/266 TAP assertions.

The final focused artifacts contain no ASan/TSan symbols and have no
ASan/TSan runtime dependency according to `nm` and `ldd`.

### Daemon-backed TAP checks

A `PROXYSQL40=1` DEBUG daemon and the two existing TAP tests plus their
change-user helpers were rebuilt. Both checks passed in one fresh registered,
isolated MySQL 8.4 environment:

- `test_passthrough_auth_pool_reuse-t`: 19/19
- `reg_test_3504-change_user-t`: 96/96

The isolated environment was removed after verification.

### Final normal build

The final normal daemon was restored successfully with:

```bash
PROXYSQL40=1 make -j clean
PROXYSQL40=1 make -j
```

The first unit relink after that full build encountered the already-documented
unit Makefile feature auto-detection ordering mismatch: optional artifacts
were detected after the archive had been evaluated, yielding missing template
symbols. No test ran in that invocation. The archive was rebuilt through the
unit harness's exact normal configuration with parallel make, after which the
final 266/266 suite passed:

```bash
PROXYSQL40=1 make -C lib -j clean
PROXYSQL40=1 make -C test/tap/tests/unit -j "$PWD/lib/libproxysql.a"
```

`git diff --check` was clean immediately before the implementation commit.

## Security review

- Retry is gated on IAM mode, errno 1045, no prior fresh retry, a live token
  source, a nonzero generation, and a complete exact key.
- Conditional invalidation cannot evict a newer cached generation.
- Ordinary password auth never enters the IAM invalidation/retry path.
- IAM non-1045/protocol/TLS errors are never masked by retry.
- Client failures are fixed and generic; logs contain only approved metadata
  and never backend error text or credential/token material.
- Detached helpers never receive the original IAM password/token, never wait
  on a MySQL worker, and never clear or mutate the original connection.
- Helper token copies are cleansed before connector close and on every exit.

## Concerns

None blocking. As expected for the deterministic Task 9 scope, live AWS
credential-provider and RDS authentication are not exercised here; provider,
connector, sanitizer, and daemon regression coverage is deterministic and
complete for the implemented branches.

## Controller review iteration 1

The five controller findings were corrected in implementation commit
`c2ebe87a3` (`fix(mysql): harden IAM retry and detached helpers`).

### RED evidence

The review regressions were added before their production corrections. The
focused RED results were:

- `aws_iam_pool_unit-t`: 30/31. The real
  `destroy_MyConn_from_pool()` call site dispatched no detached IAM
  connection-kill helper.
- `aws_iam_failure_unit-t`: the existing 10 assertions passed and all three
  new assertions failed. A fresh retry could reuse a compatible idle pooled
  IAM connection, its latch remained set after the idle/pool success path,
  and a key with port zero still invalidated/retried.
- `aws_iam_kill_helper_unit-t`: the three new helper-deadline assertions
  failed because the remaining deadline was not applied to Connector/C's TCP
  connect timeout. The lifetime regression was first captured as an exact
  compile/link RED because no safe source lease/publish/shutdown interface
  existed.

### Corrections and GREEN evidence

- The production pool-destroy path now creates and dispatches a metadata-only
  IAM `KillArgs` for non-idle connection destruction. IAM remains excluded
  from reset/change-user. Its call-site test observes the actual detached
  dispatch and proves the source connection and token remain unchanged.
- The one permitted fresh-token retry now bypasses both local and global pool
  checkout, forcing one new token and handshake. Successful acquisition,
  including the `ASYNC_IDLE`/pooled branch, clears the retry latch so a later
  independent 1045 can follow the bounded policy.
- Retry/invalidation now requires a complete key including a nonzero port.
- Detached helpers hold a move-only token-source lease across token request,
  connect, statistics, and cleanup. Shutdown rejects new leases and drains
  active helpers before destroying the source. A deterministic concurrent
  helper-vs-shutdown test proves the drain and post-shutdown rejection.
- The remaining helper deadline is translated into
  `MYSQL_OPT_CONNECT_TIMEOUT` before `mysql_real_connect`; an already-expired
  post-token deadline skips connect. TLS endpoint identity and transport
  address remain separately validated.

The updated focused suites passed 59/59 assertions:

- `aws_iam_pool_unit-t`: 31/31
- `aws_iam_failure_unit-t`: 13/13
- `aws_iam_kill_helper_unit-t`: 15/15

Each focused suite then passed 20 normal repetitions: 60/60 process runs.
The three suites passed five ASan/LSan repetitions each (15/15 process runs)
with no sanitizer diagnostic. The concurrent kill-helper suite also passed
under TSan (15/15 TAP assertions) with no diagnostic.

All eleven normal suites passed after the corrections:

- `aws_iam_policy_unit-t`: 31/31
- `aws_iam_connection_config_unit-t`: 34/34
- `aws_iam_token_manager_unit-t`: 39/39
- `aws_iam_completion_queue_unit-t`: 9/9
- `aws_iam_session_state_unit-t`: 22/22
- `aws_iam_connection_secret_unit-t`: 47/47
- `mariadb_tls_server_name_unit-t`: 8/8
- `connection_pool_unit-t`: 24/24
- `aws_iam_pool_unit-t`: 31/31
- `aws_iam_failure_unit-t`: 13/13
- `aws_iam_kill_helper_unit-t`: 15/15

Total: 273/273 TAP assertions. This full matrix was run once during the main
GREEN verification and again after the exact final daemon build and unit
archive restoration; both runs passed 273/273.

The daemon-backed regressions passed in a fresh isolated MySQL 8.4.8
environment:

- `test_passthrough_auth_pool_reuse-t`: 19/19
- `reg_test_3504-change_user-t`: 96/96

The first pass-through attempt used the DEBUG daemon's default one-second
backend timeout and hit a timing-only timeout. Raising that isolated daemon's
backend timeout to ten seconds produced a clean 19/19 rerun; the change-user
suite then passed 96/96. The isolated daemon, container, network, data, and
configuration were removed, and no shared environment was modified.

The required final normal root build completed successfully with exactly:

```bash
PROXYSQL40=1 make -j clean
PROXYSQL40=1 make -j
```

As in the original verification, attempting to relink the unit matrix
directly after the root build encountered the known archive/feature evaluation
mismatch (`Base_Session<...>::create_backend` was undefined) before any test
ran. Rebuilding the archive through the unit harness's normal configuration
resolved that harness-only mismatch, and the fresh 273/273 matrix above then
passed. The focused binaries and final daemon were checked with `ldd` and had
no ASan or TSan runtime dependency. `git diff --check` was clean before the
implementation commit.

All direct normal build commands used only `PROXYSQL40=1`; ClickHouse remained
enabled through repository defaults. Every make invocation used `-j`, cleanup
was limited to genuinely required configuration transitions, and `cleanall`
was never used.

### Review-iteration concerns

None blocking. Live AWS credential-provider and RDS authentication remain
outside this deterministic test environment; the retry gates, pool bypass,
production helper dispatch, helper/source shutdown coordination, connect
deadline, sanitizer coverage, and daemon regressions are covered locally.
