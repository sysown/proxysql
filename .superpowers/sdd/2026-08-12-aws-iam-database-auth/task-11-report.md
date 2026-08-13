# Task 11 report: controlled AWS IAM TLS/protocol regression coverage

## Outcome

Task 11 adds an always-runnable, SDK-independent controlled MySQL server and a
component-level TAP test that drives the production `MySQL_Connection` and
bundled Connector/C code through the real TCP, TLS, protocol-10, and
`mysql_clear_password` exchange. It verifies:

- an exact backend username and 2 KiB-plus recognizable token cross only the
  TLS-protected clear-password exchange;
- the transport peer is loopback while SNI and certificate verification use
  the configured RDS hostname;
- wrong-hostname, untrusted-CA, early transport-close, and delayed-handshake
  cancellation paths transmit no token;
- success, failure, and cancellation remove all transient ProxySQL and
  Connector/C token owners without replacing the stored ordinary password;
- an ordinary password connection in the same hostgroup never calls the IAM
  source and is refused when it attempts a non-TLS handshake;
- 1045 occurs after exactly one protected token transmission; and
- `use_ssl=0` and missing CA trust fail validation before token acquisition.

The controlled server accepts one loopback connection, implements only the
required handshake, applies bounded socket I/O and parent-side process
deadlines, and reports only username hex, token length/digest, TLS state, SNI,
and peer address. Test certificates and private keys are generated in a unique
temporary directory with the repository certificate helper, then removed.
Nothing is committed or persisted.

The existing cluster test now exercises exact IAM user-policy save/load and
the exact user-policy plus hostgroup-region round trip to a live replica. It
backs up and restores both main and disk `mysql_users`, including early-failure
cleanup.

Task 11 also fixes one genuine defect exposed by the new cancellation test:
`mysql_close_no_command()` did not close the async-context-owned PVIO or free a
pending `getaddrinfo()` result when a Connector/C connect coroutine was
cancelled before `mysql->net.pvio` was installed. The vendor patch now releases
those owners before destroying the coroutine context.

## Files changed

- `test/deps/aws_iam_mysql_server/Makefile`
- `test/deps/aws_iam_mysql_server/aws_iam_mysql_server.cpp`
- `test/tap/tests/test_aws_iam_backend_auth-t.cpp`
- `test/tap/tests/test_aws_iam_backend_auth-t.env`
- `test/tap/tests/Makefile`
- `test/tap/tests/unit/Makefile`
- `test/tap/tests/test_cluster_sync-t.cpp`
- `deps/mariadb-client-library/mariadb_lib.c.patch`

The unit Makefile rule is required because this test links the production
component archive rather than starting a daemon. The Connector/C patch is the
only completed behavior changed by Task 11, and it is the direct fix for the
leak demonstrated by the new cancellation case.

## TDD and debugging evidence

Before the controlled server existed, the focused test was built and run:

```bash
PROXYSQL40=1 make -C test/tap/tests -j test_aws_iam_backend_auth-t
./test/tap/tests/test_aws_iam_backend_auth-t
```

The genuine focused RED was:

```text
1..1
not ok 1 - controlled AWS IAM MySQL server is available
```

After the minimum server and fixture were added, the initial protocol work
found fixture defects in the frontend session stream, worker clock refresh,
and cancellation synchronization. The cancellation case was made
deterministic with a dedicated stage pipe emitted after accept but before the
delayed greeting. `strace` confirmed Connector/C had consumed the socket before
the earlier shared-stream notification, which explained the timing race.

The first leak check then produced a second meaningful RED. All sixteen TAP
assertions passed, but Valgrind exited 97 with approximately 16.5 KiB of direct
and indirect allocations rooted in `ma_pvio_init()` and `getaddrinfo()` on the
suspended connect. Inspection showed `mysql_close_no_command()` destroyed the
coroutine stack through `mysql_close_options()` but did not release
`async_context->pvio` or `pending_gai_res` when `mysql->net.pvio` was still
null. The narrow vendor-patch fix made the same Valgrind command exit zero.

The final focused build and normal run were:

```bash
PROXYSQL40=1 make -C test/tap/tests -j \
  test_aws_iam_backend_auth-t test_cluster_sync-t
timeout 45s ./test/tap/tests/test_aws_iam_backend_auth-t
```

Result: 16/16 assertions passed. The test prints an explicit diagnostic that
this is SDK-independent protocol coverage and does not claim SDK-on
provider/signing verification.

## Verification

The final leak/security run was:

```bash
timeout 120s valgrind --quiet --leak-check=full \
  --show-leak-kinds=definite,indirect \
  --errors-for-leak-kinds=definite,indirect --error-exitcode=97 \
  ./test/tap/tests/test_aws_iam_backend_auth-t
```

Result: 16/16 assertions, exit 0, with no definite or indirect leak report.
The combined TAP/stderr scan found none of the recognizable AWS environment
credentials, `Action=connect`, `TOKEN_MUST_NOT`, `X-Amz-Signature`, or other
token markers.

The relevant existing regression suites passed:

- `aws_iam_connection_secret_unit-t`: 47/47
- `aws_iam_connection_config_unit-t`: 34/34
- `aws_iam_session_state_unit-t`: 23/23
- `aws_iam_pool_unit-t`: 31/31
- `aws_iam_failure_unit-t`: 13/13
- `aws_iam_kill_helper_unit-t`: 15/15
- `aws_iam_token_manager_unit-t`: 39/39
- `test_aws_iam_metrics-t`: 9/9

Total: 211/211 assertions.

The existing pass-through and change-user regressions compiled together:

```bash
PROXYSQL40=1 make -C test/tap/tests -j \
  test_passthrough_auth_e2e-t test_passthrough_auth_pool_reuse-t \
  reg_test_3504-change_user-t
```

Their runtime environment requires the standard external MySQL 8/ProxySQL TAP
infra and was not present in this worktree, so runtime success is not claimed.

The prepared Connector/C patch was checked in both directions. A reverse dry
run from the prepared dependency tree succeeded for all eight hunks:

```bash
cd deps/mariadb-client-library/mariadb_client
patch --dry-run -R -p0 < ../mariadb_lib.c.patch
```

Independent review additionally applied the patch to a fresh MariaDB
Connector/C 3.3.8 source extraction and confirmed clean application and the
cleanup ordering.

A disposable local primary was created from the repository cluster fixture so
`test_cluster_sync-t` could spawn its own replica. The two Task 11 assertions
passed live:

```text
ok 6 - IAM user policy survives save/load exactly
ok 7 - cluster sync carries exact IAM user policy and hostgroup region
```

The broader 401-case test continued through assertion 13, then aborted in its
pre-existing `proxysql_servers` empty-table recovery sequence: the primary
resynced rows before the replica executed `INSERT ... SELECT` from its backup,
causing the existing unique `(hostname,port)` constraint to fire. This occurred
after and outside the new IAM block. Full cluster-suite GREEN is therefore not
claimed. The disposable primary, replica, configuration, database, logs, and
generated keys were stopped and moved to trash.

ASan and TSan rebuilds were not performed. They require a complete clean and
feature rebuild; no object corruption existed and the controller specifically
limited `make clean` to that case. Valgrind covered the security-sensitive
normal binary and found the real cancellation leak described above.

The final normal repository build was:

```bash
PROXYSQL40=1 make -j
```

It exited 0. Every Make invocation used `PROXYSQL40=1` and `-j`; ClickHouse was
left at the repository default. No `make clean` or `make cleanall` was used.
`git diff --check` passed, and a staged-content scan found no committed private
key.

## Independent review

The first review found three Important gaps and two Minor issues. The
controlled server could hang on a regression, its result did not assert the
username, and its companion lookup used Linux `/proc`. These were fixed with
bounded I/O and TERM/KILL/reap, exact username verification, and a build-time
absolute companion path. The review also correctly distinguished this
component test from the planned SDK-on daemon test and identified that a
literal cluster token-marker absence assertion was vacuous. The test and env
now explicitly state the SDK-independent scope, and the cluster assertions
were narrowed to only what they really prove.

The independent rereview returned `CLEAN/READY` for the explicitly
SDK-independent scope with no Critical or Important findings. It reconfirmed
the Connector/C cleanup and the final bounded teardown, protocol, identity,
and cluster-policy assertions.

## Limitations

There is no real AWS SDK for C++ installation on this host. Per the project
constraint, none was downloaded or vendored. Therefore this task does **not**
claim SDK-on daemon verification of default environment credentials, local
SigV4 signing, slow `credential_process` responsiveness, frontend disconnect,
or provider shutdown. Those session, pool, retry, change-user, and kill-helper
behaviors remain covered by the deterministic Task 3/7/8/9 unit suites listed
above, not by this 16-case protocol test.

For the same reason, the live cluster test proves only exact persisted policy
and region synchronization. It does not prove exclusion of a generated runtime
token from cluster serialization, because no SDK-on generated token existed in
that daemon. No token-exclusion claim is inferred from an arbitrary absent
marker.

The controlled test is component-level production-path coverage, not a full
ProxySQL daemon session. A real SDK-on host remains required to implement and
run the planned daemon/provider E2E variant using the reserved harmless values
in `test_aws_iam_backend_auth-t.env`.

## Commit

Implementation and tests: `3cf3face69b9de33c1f818a12c519d44a951f549`
(`test(mysql): cover IAM backend authentication protocol`).

This report is committed separately so it can record the implementation hash.
