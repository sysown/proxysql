# Task 13 report: complete verification matrix

## Outcome

The SDK-free implementation, deterministic fake-provider coverage, sanitizer
matrix, and isolated daemon regressions pass. Independent review found one
feature-off operator-diagnostic defect. A focused assertion reproduced the
blank failure category, and the narrow production fix now reports the required
`support_not_compiled` reason before token acquisition. All directly affected
and full regression matrices pass after that fix.

The host has no AWS SDK for C++ installation, no AWS credentials, and no real
RDS test contract. The AWS-enabled build/linkage matrix and real-RDS
authentication suite are therefore **not run and not passed**. The exact
missing-SDK failure was verified instead. No SDK was downloaded or vendored,
and no real credentials were used.

All authored Make invocations used `PROXYSQL40=1` and parallel `-j`. ClickHouse
was left at its repository default. `make clean` was used only for the initial
fresh build, required unit/archive ABI alignment after the header change, and
normal/ASan/TSan build-mode transitions. No `cleanall` invocation was used.

## Baseline

- Isolated worktree:
  `.worktrees/aws-iam-database-auth`
- Branch: `feature/aws-iam-database-auth`
- Initial HEAD: `92d843398719286e09ad40e1e560efa02e534b29`
- Merge base with `v3.0`: `cde544ce7ec88b5045c392fe1379f1cb4bd80672`
- Initial status: clean
- Pre-report range: 71 files, 12,075 insertions, 91 deletions

The full Task 13 brief, approved design and implementation plan, Task 1-12
reports, repository test-infrastructure guide, and verification/review skills
were read before execution.

## SDK-free normal build and unit matrix

The fresh transition and complete normal build passed:

```bash
PROXYSQL40=1 make -j clean
PROXYSQL40=1 make -j
```

The build produced the daemon plus the mysqlx and genai plugins. Compiler
warnings were pre-existing and outside the AWS IAM changes.

The build-gate behavioral suite passed:

```bash
bash test/infra/control/check-aws-iam-build-gate.bash
```

It covered the fake SDK root, hostile paths, no-op/freshness behavior, and
concurrent discovery. The gate rebuilds `libproxysql.a` with a configuration
different from the unit harness. The documented feature-mode alignment was
therefore performed, rather than treating missing optional template symbols
as a product defect:

```bash
PROXYSQL40=1 make -C lib -j clean
PROXYSQL40=1 make -C test/tap/tests/unit -j "$PWD/lib/libproxysql.a"
PROXYSQL40=1 make -C test/tap/tests/unit -j
```

Every default executable in `test/tap/tests/unit` was then run under a
180-second per-process timeout. All **108/108 default unit binaries passed**.
The explicit controlled backend-auth target then passed separately, preserving
the prior **109/109 binary verification scope**. The AWS IAM and directly
affected core results included:

- policy: 31/31
- connection configuration: 34/34
- token manager: 39/39
- completion queue: 9/9
- session state: 24/24
- connection secret: 47/47
- IAM pool: 31/31
- failure/retry: 13/13
- kill helper: 15/15
- TLS server name: 8/8
- general connection pool: 24/24
- controlled backend-auth component: 16/16
- AWS IAM metrics: 9/9

The focused daemon/regression binaries were also compiled. One later aggregate
rebuild after restoring the full root feature set reproduced the documented
unit-archive mismatch for `test_aws_iam_backend_auth-t` (`create_backend`
template symbol absent); all daemon-backed binaries in that command had built,
and the controlled test had already built and passed in the aligned normal
matrix above. This was a build-harness feature alignment issue, not a product
failure and required no code change.

## Focused deterministic protocol and metrics coverage

The SDK-independent controlled TLS/MySQL protocol and metrics tests passed:

```bash
timeout 120s ./test/tap/tests/test_aws_iam_backend_auth-t
timeout 120s ./test/tap/tests/test_aws_iam_metrics-t
```

- backend-auth protocol: 16/16
- AWS IAM metrics: 9/9

The protocol test covered protected token delivery after TLS, exact endpoint
identity/SNI, wrong host, untrusted CA, early transport close, cancellation,
generic 1045 handling, ordinary password coexistence, `use_ssl`, and missing
CA policy. It is explicitly component-level and SDK-independent; it does not
claim full daemon/provider or RDS coverage.

## Feature-off identity and exact missing-SDK behavior

The normal binary was required to be SDK-free. Fresh checks found no AWS SDK,
sanitizer runtime, or AWS C++ symbol in the normal daemon/archive:

```bash
bash test/infra/control/check-aws-iam-linkage.bash src/proxysql
ldd src/proxysql | rg 'aws-cpp-sdk|asan|tsan'
nm -C src/proxysql | rg 'Aws::'
nm -C lib/libproxysql.a | rg 'Aws::'
```

The release checker returned its expected status 1 and exact diagnostic:

```text
AWS IAM linkage check failed: binary is not an AWS IAM-enabled build (feature is disabled)
```

The dependency/symbol searches were empty. The linkage checker behavioral
suite also passed **25/25** cases on Linux, Darwin, static, package ownership,
legal material, stale metadata, Homebrew, RPM, and APK branches:

```bash
bash test/infra/control/check-aws-iam-linkage-test.bash
```

An empty temporary SDK prefix failed early as required:

```bash
fake_root=$(mktemp -d)
PROXYSQL40=1 PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$fake_root" \
  make -C lib -j
```

The command failed and stderr contained exactly:

```text
AWS SDK for C++ 1.9 or newer with core and rds is required
```

`ldconfig` and filesystem searches under `/usr`, `/usr/local`, and `/opt`
found no AWS `core`/`rds` SDK libraries or `AWSSDKConfig.cmake`. The variables
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`,
`RDS_ENDPOINT`, `RDS_PORT`, `RDS_DB_USER`, and `RDS_CA_FILE` were all unset;
only their set/unset state was inspected, never a value.

Consequently the system-SDK feature build, positive AWS linkage audit, and
system-package legal-material qualification were **not run and not passed**.
The Task 12 openSUSE packaging limitation remains: its selected SDK RPM does
not own the upstream LICENSE and NOTICE material required by the strict release
checker.

## ASan and TSan

The full ASan debug dependency, daemon, and plugin build passed:

```bash
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -j build_deps_debug
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -j build_src_debug
```

After the documented unit-harness archive alignment, these nine binaries
passed with `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and no report:

- token manager: 39/39
- connection secret: 47/47
- completion queue: 9/9
- session state: 24/24
- pool isolation: 31/31
- failure/retry: 13/13
- kill helper: 15/15
- controlled backend auth: 16/16
- AWS IAM metrics: 9/9

Reading `vm.mmap_rnd_bits` was denied by the environment, but the ASan
executables themselves completed successfully.

The full TSan debug dependency, daemon, and plugin build also passed:

```bash
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -j build_deps_debug
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -j build_src_debug
```

After the same feature-aligned archive rebuild, five focused concurrency
binaries passed with `TSAN_OPTIONS=halt_on_error=1` and no report:

- token manager: 39/39
- completion queue: 9/9
- session state: 24/24
- kill helper: 15/15
- AWS IAM metrics: 9/9

No sanitizer-driven implementation fix was needed.

## Isolated daemon regressions

All daemon tests used unique disposable Docker networks/containers and derived
test-only passwords. No shared daemon, shared backend, or real credential was
used. The main namespace was `aws-iam-task13-1786585782`, containing one
ProxySQL daemon and the repository MySQL 8.4 dbdeployer fixture.

The stock isolated-infrastructure post hook stopped on the unrelated,
unsupported `SET admin-debug` statement. The remainder of its generated
configuration was applied only inside the disposable daemon. The standard
Python runner then stopped before running a TAP binary on its unrelated `LOAD
DEBUG FROM DISK` reconfiguration command. Focused binaries were therefore run
inside a disposable `proxysql-ci-base` test runner attached only to the unique
network. Neither harness limitation changed tracked files or product behavior.

The focused results were:

- pass-through authentication E2E: 22/22
- pass-through pooled-connection reuse attack regression: 19/19
- pass-through metrics: 9/9
- COM_CHANGE_USER regression: 96/96
- general Prometheus metrics regression: 44/44

The first COM_CHANGE_USER attempt produced 96 invalid cases because the clean
had removed its two helper executables and the parent binary target does not
declare them as prerequisites. After explicitly rebuilding the helper targets
with `PROXYSQL40=1` and `-j`, the unchanged 96-case suite passed. This was test
setup, not a product failure.

A second unique namespace, `aws-iam-task13-cluster-1786586048`, ran the cluster
fixture. The Task 11 assertions passed live:

```text
ok 6 - IAM user policy survives save/load exactly
ok 7 - cluster sync carries exact IAM user policy and hostgroup region
```

The broader legacy 401-plan suite is **not claimed passed**. It executed 18
successful TAP assertions and then aborted its general `mysql_servers_v2`
module phase because the minimal isolated primary had no `mysql_servers` row
for that legacy updater. This was after the two AWS IAM assertions; no `not ok`
was emitted and the spawned replica exited cleanly. The result is recorded as
an isolated fixture/suite precondition, not AWS IAM product coverage.

Both namespaces, all associated containers, and both networks were removed
after execution.

## Real AWS integration

The opt-in real AWS/RDS command was intentionally not run:

```bash
PROXYSQLAWSIAM=1 RUN_AWS_IAM_INTEGRATION=1 \
  ./test/tap/tests/test_aws_iam_backend_auth-t
```

This host lacks all prerequisites: a system AWS SDK, authorized credentials,
RDS endpoint/user/region, readable real RDS CA, and the external integration
contract. Therefore successful RDS authentication, AWS denial, wrong
user/region, live credential rotation, real token refresh, and real RDS CA
behavior remain **not run and not passed**.

## Syntax, patch, scope, and security review

The following gates passed:

- `bash -n` for all changed shell scripts
- ShellCheck for all changed shell scripts
- PyYAML load of `.github/workflows/CI-aws-iam.yml`
- `git diff --check` for the working tree
- `git diff --check v3.0...HEAD` excluding the nested Connector/C patch
- no TODO/TBD or fake-secret marker in production/docs
- no changed `.pem`, `.key`, `.p12`, `.pfx`, or `.crt` file
- no AWS access-key-shaped literal, private-key header, or plaintext secret
  assignment in production/docs/workflow
- no AWS C++ symbol or DSO in the feature-off daemon/archive

The raw whole-range command `git diff --check v3.0...HEAD` reports 13 trailing
spaces in the newly added `tls_server_name.patch`. These are the required
single-space context-line markers of the *inner unified diff*, not whitespace
in generated source. Removing them would risk making the patch malformed. To
verify this exception rather than mask it, a disposable copy of the prepared
Connector/C tree was taken through the actual ordered patch series:

1. reverse `sslkeylogfile.patch`;
2. reverse `tls_server_name.patch`;
3. apply `tls_server_name.patch`;
4. apply `sslkeylogfile.patch`.

All four operations succeeded. The range excluding this nested patch passed
`git diff --check`, and the working tree had no whitespace error.

The complete pre-report scope remained the 71 planned implementation,
dependency patch, documentation, CI, and Task 3-12 report files. The final
combined range has 72 files: the four diagnostic-fix paths were already in the
planned range, and the only additional path is this Task 13 report. No
credential or fake-secret material was discovered.

## Final normal build

After the sanitizer transitions and isolated regressions, normal artifacts
were restored with a necessary clean transition and build:

```bash
PROXYSQL40=1 make -j clean
PROXYSQL40=1 make -j
```

The required final command was then run again from the stable normal tree:

```bash
PROXYSQL40=1 make -j
```

It exited 0. Final artifact checks found no AWS SDK, ASan, or TSan dependency
and no `Aws::` symbol. Artifact hashes at this gate were:

```text
a8a7af5d861cfa74cb155f4b543bb713aebf8d7a07c724f63e079ac95421e797  src/proxysql
dae85636087bb3b0bbd0604a9bf486bc8f6003a2b95216829973aea91e55c314  lib/libproxysql.a
```

## Issues and fixes

A real product defect was reproduced during independent review: an SDK-off IAM
connection failed closed but logged `category=''`, because the non-null stub was
mistaken for compiled support and its status-only failure object overrode the
fallback reason. The focused session assertion failed RED at 23/24. The narrow
fix adds a token-source support capability (true by default for real/fake
providers, false for the SDK-off stub), uses it in normal-session and kill-helper
validation, populates the stub's redacted category, and ignores empty provider
categories when choosing the operator fallback. The assertion and affected
session/kill/config suites passed GREEN at 24/24, 15/15, and 34/34; full unit,
ASan, TSan, and final normal matrices also passed.

Other observed failures were classified with direct evidence as build/test
harness or missing external infrastructure limitations:

- unit archive optional-feature mismatch: resolved by documented aligned
  archive rebuild;
- isolated post hook/Python runner debug commands unsupported by this build:
  bypassed only within disposable infrastructure;
- COM_CHANGE_USER helper binaries absent after clean: explicitly rebuilt;
- broad cluster fixture lacked a legacy module row after AWS IAM assertions:
  full suite not claimed;
- real system SDK/RDS contract unavailable: positive integrations not run.

## Residual limitations

- The Task 3 signer interface cannot forcibly cancel a credential provider
  implementation that never returns; bounded delivery/lifetime behavior is
  verified, but provider-internal cancellation remains outside the interface.
- The controlled protocol test is component-level and SDK-independent, not a
  full SDK-provider daemon session.
- The real AWS-enabled build, strict linked-package legal qualification, and
  real RDS authentication suite require external infrastructure not present on
  this host.
- The openSUSE SDK package legal-material blocker from Task 12 remains open.
- The SDK-off regression exercises the actual capability-based session
  rejection. The stub's async/blocking category population and the generic
  empty-category fallback are additional defensive branches without separate
  direct assertions; independent review classified this as non-blocking Minor.

## Independent review

The final staged diff and verification evidence received an independent fresh
review after the fix and ledger update. The reviewer confirmed both prior
Important findings resolved, found no Critical or Important issue, recorded
the defensive-branch coverage note above as Minor, and returned **READY** for
Task 13 handoff. The review independently confirmed the five-file staged
scope, 72-file combined range, 13 expected inner-patch warnings, final hashes,
and absence of AWS/ASan/TSan linkage or `Aws::` symbols.

## Chronological verification command ledger

This ledger records every command whose result contributes to the Task 13
acceptance claims, including expected nonzero results and the independent-review
RED/GREEN cycle. Read-only exploratory `sed`, `rg`, and `git` orientation
commands are not acceptance evidence and are not repeated here.

### Baseline, normal build, gate, and units

```bash
git status --short
git branch --show-current
git rev-parse HEAD
git log --oneline --decorate -20
git merge-base v3.0 HEAD
git diff --stat v3.0...HEAD
```

Result: exit 0; clean branch `feature/aws-iam-database-auth`, initial HEAD and
merge base recorded in the Baseline section, 71-file pre-report range.

```bash
PROXYSQL40=1 make -j clean
PROXYSQL40=1 make -j
```

Result: both exit 0; normal daemon and both default plugins built.

```bash
bash test/infra/control/check-aws-iam-build-gate.bash
if test/infra/control/check-aws-iam-linkage.bash src/proxysql; then
  echo 'unexpected linkage success'; exit 1
else
  rc=$?; test "$rc" -eq 1
fi
if ldd src/proxysql | rg -q 'aws-cpp-sdk'; then exit 1; fi
if nm -C src/proxysql | rg -q 'Aws::'; then exit 1; fi
if nm -C lib/libproxysql.a | rg -q 'Aws::'; then exit 1; fi
ldd src/proxysql | rg 'asan|tsan|aws-cpp-sdk' || true
```

Result: exit 0; build-gate cases passed, feature-off checker returned expected
1, and all AWS/sanitizer dependency and symbol searches were empty.

```bash
PROXYSQL40=1 make -C lib -j clean
PROXYSQL40=1 make -C test/tap/tests/unit -j "$PWD/lib/libproxysql.a"
PROXYSQL40=1 make -C test/tap/tests/unit -j
```

Result: exit 0; unit-mode archive and default unit targets built.

The initial complete-unit runner, from `test/tap/tests/unit`, was:

```bash
tmpdir=$(mktemp -d)
count=0
for test_bin in *-t; do
  if test -x "$test_bin"; then
    count=$((count + 1))
    if timeout 180s "./$test_bin" >"$tmpdir/output" 2>&1; then
      tap_plan=$(rg '^1\.\.[0-9]+' "$tmpdir/output" | tail -n 1 || true)
      echo "PASS $test_bin ${tap_plan:-no-plan}"
    else
      test_rc=$?
      echo "FAIL $test_bin rc=$test_rc output=$tmpdir/output"
      sed -n '1,240p' "$tmpdir/output"
      exit "$test_rc"
    fi
  fi
done
echo "UNIT_BINARIES_PASSED=$count scratch=$tmpdir"
```

Result: exit 0, `UNIT_BINARIES_PASSED=109` in the pre-review tree.

```bash
PROXYSQL40=1 make -C test/tap/tests -j \
  test_aws_iam_backend_auth-t test_aws_iam_metrics-t \
  test_passthrough_auth_e2e-t test_passthrough_auth_pool_reuse-t \
  reg_test_3504-change_user-t test_cluster_sync-t \
  test_passthrough_auth_metrics-t test_prometheus_metrics-t
timeout 120s ./test/tap/tests/test_aws_iam_backend_auth-t
timeout 120s ./test/tap/tests/test_aws_iam_metrics-t
```

Result: build exit 0; controlled protocol 16/16 and metrics 9/9.

### Missing SDK, host identity, and environment boundary

```bash
fake_root=$(mktemp -d)
if PROXYSQL40=1 PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$fake_root" \
    make -C lib -j 2>"$fake_root/error"; then
  echo "unexpected missing-SDK success"
  exit 1
fi
rg -F 'AWS SDK for C++ 1.9 or newer with core and rds is required' \
  "$fake_root/error"
echo "MISSING_SDK_DIAGNOSTIC_PASS scratch=$fake_root"
if ldconfig -p 2>/dev/null | rg -q 'aws-cpp-sdk-(core|rds)'; then
  echo 'SYSTEM_AWS_SDK_LIBRARIES_PRESENT'
else
  echo 'SYSTEM_AWS_SDK_LIBRARIES_ABSENT'
fi
sdk_config=$(find /usr /usr/local /opt -type f \
  \( -name 'AWSSDKConfig.cmake' -o -name 'aws-cpp-sdk-core-config.cmake' \) \
  -print -quit 2>/dev/null)
if test -n "$sdk_config"; then
  echo "SYSTEM_AWS_SDK_CONFIG_PRESENT=$sdk_config"
else
  echo 'SYSTEM_AWS_SDK_CONFIG_ABSENT'
fi
for var_name in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN \
  AWS_REGION RDS_ENDPOINT RDS_PORT RDS_DB_USER RDS_CA_FILE; do
  if test -n "${!var_name+x}"; then
    echo "$var_name=SET"
  else
    echo "$var_name=UNSET"
  fi
done
```

Result: overall exit 0; the nested feature build failed as expected with the
exact diagnostic; system SDK libraries/config were absent and every named
credential/RDS variable was unset.

### Initial sanitizer matrix

```bash
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -j build_deps_debug
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -j build_src_debug
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -C lib -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 \
  make -C test/tap/tests/unit -j "$PWD/lib/libproxysql.a"
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -C test/tap/tests/unit -j \
  aws_iam_token_manager_unit-t aws_iam_connection_secret_unit-t \
  aws_iam_completion_queue_unit-t aws_iam_session_state_unit-t \
  aws_iam_pool_unit-t aws_iam_failure_unit-t aws_iam_kill_helper_unit-t \
  test_aws_iam_backend_auth-t test_aws_iam_metrics-t
```

Result: every build exited 0.

```bash
sysctl -n vm.mmap_rnd_bits
scratch=$(mktemp -d)
for test_bin in aws_iam_token_manager_unit-t aws_iam_connection_secret_unit-t \
  aws_iam_completion_queue_unit-t aws_iam_session_state_unit-t \
  aws_iam_pool_unit-t aws_iam_failure_unit-t aws_iam_kill_helper_unit-t \
  test_aws_iam_backend_auth-t test_aws_iam_metrics-t; do
  if ! ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 timeout 180s \
      "./test/tap/tests/unit/$test_bin" >"$scratch/$test_bin.out" 2>&1; then
    status=$?
    echo "ASAN_FAIL $test_bin rc=$status"
    sed -n '1,240p' "$scratch/$test_bin.out"
    exit 1
  fi
  plan=$(sed -n 's/^1\.\.//p' "$scratch/$test_bin.out" | tail -1)
  echo "ASAN_PASS $test_bin plan=${plan:-unknown}"
done
echo "ASAN_SUITE_PASSED=9 scratch=$scratch"
```

Result: the environment denied the `sysctl` read, but the shell continued and
all nine binaries passed with no ASan report; overall exit 0.

```bash
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -j build_deps_debug
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -j build_src_debug
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -C lib -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 \
  make -C test/tap/tests/unit -j "$PWD/lib/libproxysql.a"
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -C test/tap/tests/unit -j \
  aws_iam_token_manager_unit-t aws_iam_completion_queue_unit-t \
  aws_iam_session_state_unit-t aws_iam_kill_helper_unit-t \
  test_aws_iam_metrics-t
scratch=$(mktemp -d)
for test_bin in aws_iam_token_manager_unit-t aws_iam_completion_queue_unit-t \
  aws_iam_session_state_unit-t aws_iam_kill_helper_unit-t \
  test_aws_iam_metrics-t; do
  TSAN_OPTIONS=halt_on_error=1 timeout 180s \
    "./test/tap/tests/unit/$test_bin" >"$scratch/$test_bin.out" 2>&1
  rc=$?
  if test "$rc" -ne 0; then
    echo "TSAN_FAIL $test_bin rc=$rc"
    sed -n '1,240p' "$scratch/$test_bin.out"
    exit 1
  fi
  plan=$(sed -n 's/^1\.\.//p' "$scratch/$test_bin.out" | tail -1)
  echo "TSAN_PASS $test_bin plan=${plan:-unknown}"
done
echo "TSAN_SUITE_PASSED=5 scratch=$scratch"
```

Result: every build and all five TSan processes exited 0 with no report.

### Disposable MySQL 8.4 daemon namespace

The normal-mode transition and daemon-focused compilation were:

```bash
PROXYSQL40=1 make -j clean
PROXYSQL40=1 make -j
PROXYSQL40=1 make -C test/tap/tests -j \
  test_passthrough_auth_e2e-t test_passthrough_auth_pool_reuse-t \
  reg_test_3504-change_user-t test_passthrough_auth_metrics-t \
  test_prometheus_metrics-t test_cluster_sync-t \
  test_aws_iam_backend_auth-t test_aws_iam_metrics-t
```

Result: the normal build exited 0. The aggregate focused build exited 2 only
for the documented feature-misaligned controlled target; every daemon-backed
target was present and executable.

Infrastructure start command:

```bash
export INFRA_ID="aws-iam-task13-$(date +%s)"
export TAP_GROUP=mysql84-g4
export SKIP_CLUSTER_START=1
printf 'INFRA_ID=%s TAP_GROUP=%s\n' "$INFRA_ID" "$TAP_GROUP"
printf '%s\n' "$INFRA_ID" > /tmp/aws-iam-task13-infra-id
./test/infra/control/ensure-infras.bash
```

Result: expected exit 1 after successfully starting namespace
`aws-iam-task13-1786585782`, ProxySQL, and MySQL 8.4 replication; the stock
post-hook stopped only at unsupported `SET admin-debug`.

The remaining generated configuration and group setup were applied only to
that disposable daemon:

```bash
infra_id=$(tr -d '\n' </tmp/aws-iam-task13-infra-id)
(
  cd test/infra/infra-dbdeployer-mysql84
  export INFRA_ID="$infra_id"
  export INFRA=${PWD##*/}
  export ROOT_PASSWORD=$(printf '%s' "$INFRA_ID" | sha256sum | head -c 10)
  set -a
  . ./.env
  set +a
  docker exec -i "proxysql.${INFRA_ID}" \
    mysql -uadmin -padmin -h127.0.0.1 -P6032 <<SQL
DELETE FROM mysql_users WHERE username='root';
DELETE FROM mysql_users WHERE username='testuser';
INSERT OR IGNORE INTO mysql_users
  (username,password,active,default_hostgroup,fast_forward,backend,frontend,comment)
VALUES ('root','${ROOT_PASSWORD}',1,${WHG},0,1,1,'dynamic-root-user');
INSERT OR IGNORE INTO mysql_users
  (username,password,active,default_hostgroup,fast_forward,backend,frontend,comment)
VALUES ('testuser','testuser',1,${WHG},0,1,1,'universal-testuser');
DELETE FROM mysql_users WHERE username='${INFRA}';
INSERT OR IGNORE INTO mysql_users
  (username,password,active,default_hostgroup,fast_forward,backend,frontend,comment)
VALUES ('${INFRA}','${INFRA}',1,${WHG},0,1,1,'${INFRA}');
UPDATE global_variables SET variable_value='monitor'
  WHERE variable_name='mysql-monitor_username';
UPDATE global_variables SET variable_value='monitor'
  WHERE variable_name='mysql-monitor_password';
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;
LOAD MYSQL VARIABLES TO RUNTIME;
INSERT INTO mysql_servers
  (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment)
SELECT 0,hostname,port,max_replication_lag,max_connections,'fallback-hg0'
FROM mysql_servers WHERE hostgroup_id=${WHG}
  AND NOT EXISTS (SELECT 1 FROM mysql_servers WHERE hostgroup_id=0);
INSERT INTO mysql_servers
  (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment)
SELECT 1,hostname,port,max_replication_lag,max_connections,'fallback-hg1'
FROM mysql_servers WHERE hostgroup_id=${RHG}
  AND NOT EXISTS (SELECT 1 FROM mysql_servers WHERE hostgroup_id=1);
INSERT INTO mysql_replication_hostgroups
  (writer_hostgroup,reader_hostgroup,comment)
SELECT 0,1,'fallback-repl-hg'
WHERE NOT EXISTS (SELECT 1 FROM mysql_replication_hostgroups
  WHERE writer_hostgroup=0 AND reader_hostgroup=1);
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;
SAVE MYSQL VARIABLES TO DISK;
SQL
)
echo 'SCOPED_INFRA_CONFIGURATION_OK'

infra_id=$(tr -d '\n' </tmp/aws-iam-task13-infra-id)
export WORKSPACE=$PWD
export INFRA_ID="$infra_id"
export TAP_GROUP=mysql84-g4
./test/tap/groups/mysql84/setup-infras.bash
docker exec "proxysql.${INFRA_ID}" mysql -uadmin -padmin \
  -h127.0.0.1 -P6032 -NBe \
  "SELECT COUNT(*) FROM runtime_mysql_servers
   WHERE hostgroup_id IN (0,1,2900,2901);
   SELECT COUNT(*) FROM runtime_mysql_users
   WHERE username IN ('root','testuser','infra-dbdeployer-mysql84');"
```

Result: both command groups exited 0; runtime rows were present.

The stock runner probe was:

```bash
export INFRA_ID=$(tr -d '\n' </tmp/aws-iam-task13-infra-id)
export TAP_GROUP=mysql84-g4
export SKIP_CLUSTER_START=1
export TEST_PY_TAP_INCL='test_passthrough_auth_(e2e|metrics|pool_reuse)-t'
./test/infra/control/run-tests-isolated.bash
```

Result: expected exit 1 before TAP execution at unsupported `LOAD DEBUG FROM
DISK`; this is the runner/debug-build precondition described above.

The three pass-through binaries were then executed by this exact disposable
runner command:

```bash
infra_id=$(tr -d '\n' </tmp/aws-iam-task13-infra-id)
root_password=$(printf '%s' "$infra_id" | sha256sum | head -c 10)
scratch=$(mktemp -d)
docker run --rm \
  --name "aws-iam-task13-direct.${infra_id}" \
  --network "${infra_id}_backend" \
  -v "$PWD:$PWD" -e WORKSPACE="$PWD" -e INFRA_ID="$infra_id" \
  -e ROOT_PASSWORD="$root_password" \
  -e DEFAULT_MYSQL_INFRA=infra-dbdeployer-mysql84 \
  -e INFRA_TYPE=infra-dbdeployer-mysql84 -e SKIP_CLUSTER_START=1 \
  proxysql-ci-base:latest /bin/bash -c '
    set -e
    . "$WORKSPACE/test/tap/groups/mysql84/env.sh"
    . "$WORKSPACE/test/infra/control/env-isolated.bash"
    export LD_LIBRARY_PATH="$WORKSPACE/test/tap/tap:$WORKSPACE/deps/re2/re2/obj:$WORKSPACE/deps/postgresql/postgresql/src/interfaces/libpq${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    cd "$WORKSPACE/test/tap/tests"
    for test_bin in test_passthrough_auth_e2e-t \
      test_passthrough_auth_pool_reuse-t test_passthrough_auth_metrics-t; do
      echo "DIRECT_DAEMON_START $test_bin"
      timeout 600s "./$test_bin"
      echo "DIRECT_DAEMON_PASS $test_bin"
    done
  ' >"$scratch/direct-daemon.out" 2>&1
rc=$?
cat "$scratch/direct-daemon.out"
echo "DIRECT_DAEMON_RC=$rc scratch=$scratch"
exit "$rc"
```

Result: exit 0; 22/22, 19/19, and 9/9.

The first change-user command used the same runner envelope with
`timeout 900s ./reg_test_3504-change_user-t`; it exited 1 with 96 invalid helper
results. The exact prerequisite repair and unchanged rerun were:

```bash
PROXYSQL40=1 make -C test/tap/tests -j \
  reg_test_3504-change_user_libmariadb_helper \
  reg_test_3504-change_user_libmysql_helper

infra_id=$(tr -d '\n' </tmp/aws-iam-task13-infra-id)
root_password=$(printf '%s' "$infra_id" | sha256sum | head -c 10)
scratch=$(mktemp -d)
docker run --rm --name "aws-iam-task13-change-user.${infra_id}" \
  --network "${infra_id}_backend" -v "$PWD:$PWD" \
  -e WORKSPACE="$PWD" -e INFRA_ID="$infra_id" \
  -e ROOT_PASSWORD="$root_password" \
  -e DEFAULT_MYSQL_INFRA=infra-dbdeployer-mysql84 \
  -e INFRA_TYPE=infra-dbdeployer-mysql84 -e SKIP_CLUSTER_START=1 \
  proxysql-ci-base:latest /bin/bash -c '
    set -e
    . "$WORKSPACE/test/tap/groups/mysql84/env.sh"
    . "$WORKSPACE/test/infra/control/env-isolated.bash"
    export LD_LIBRARY_PATH="$WORKSPACE/test/tap/tap:$WORKSPACE/deps/re2/re2/obj:$WORKSPACE/deps/postgresql/postgresql/src/interfaces/libpq${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    cd "$WORKSPACE/test/tap/tests"
    timeout 900s ./reg_test_3504-change_user-t
  ' >"$scratch/change-user.out" 2>&1
rc=$?
if test "$rc" -ne 0; then
  tail -120 "$scratch/change-user.out"; exit "$rc"
fi
plan=$(sed -n 's/^1\.\.//p' "$scratch/change-user.out" | tail -1)
ok_count=$(rg -c '^ok ' "$scratch/change-user.out")
not_ok_count=$(rg -c '^not ok ' "$scratch/change-user.out" || true)
echo "CHANGE_USER_PASS plan=$plan ok=$ok_count not_ok=${not_ok_count:-0}"
```

Result: helper build exit 0; unchanged suite exit 0, plan/ok 96, no `not ok`.

The Prometheus runner used the same envelope and environment, with:

```bash
timeout 600s ./test_prometheus_metrics-t
```

Result: exit 0, 44/44.

Teardown and isolation proof:

```bash
infra_id=$(tr -d '\n' </tmp/aws-iam-task13-infra-id)
docker rm -f "test-runner.${infra_id}" >/dev/null 2>&1 || true
INFRA_ID="$infra_id" ./test/infra/control/stop-proxysql-isolated.bash
if docker ps -a --format '{{.Names}}' | rg -q "$infra_id"; then
  docker ps -a --format '{{.Names}}\t{{.Status}}' | rg "$infra_id"; exit 1
fi
if docker network ls --format '{{.Name}}' |
    rg -q "^${infra_id}_backend$"; then
  echo "NETWORK_REMAINS ${infra_id}_backend"; exit 1
fi
echo "ISOLATED_INFRA_TORN_DOWN $infra_id"
```

Result: exit 0; no namespaced container or network remained.

### Disposable cluster namespace

```bash
export INFRA_ID="aws-iam-task13-cluster-$(date +%s)"
export SKIP_CLUSTER_START=1
printf '%s\n' "$INFRA_ID" > /tmp/aws-iam-task13-cluster-infra-id
./test/infra/control/start-proxysql-isolated.bash
```

Result: exit 0; namespace `aws-iam-task13-cluster-1786586048` started.

```bash
infra_id=$(tr -d '\n' </tmp/aws-iam-task13-cluster-infra-id)
root_password=$(printf '%s' "$infra_id" | sha256sum | head -c 10)
scratch=$(mktemp -d)
docker run --rm --name "cluster-runner.${infra_id}" \
  --hostname cluster-runner --network "${infra_id}_backend" \
  -v "$PWD:$PWD" -e WORKSPACE="$PWD" -e INFRA_ID="$infra_id" \
  -e ROOT_PASSWORD="$root_password" -e SKIP_CLUSTER_START=1 \
  proxysql-ci-base:latest /bin/bash -c '
    set -e
    . "$WORKSPACE/test/infra/control/env-isolated.bash"
    export LD_LIBRARY_PATH="$WORKSPACE/test/tap/tap:$WORKSPACE/deps/re2/re2/obj:$WORKSPACE/deps/postgresql/postgresql/src/interfaces/libpq${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    cd "$WORKSPACE/test/tap/tests"
    timeout 1800s ./test_cluster_sync-t
  ' >"$scratch/cluster.out" 2>&1
rc=$?
plan=$(sed -n 's/^1\.\.//p' "$scratch/cluster.out" | tail -1)
ok_count=$(rg -c '^ok ' "$scratch/cluster.out" || true)
not_ok_count=$(rg -c '^not ok ' "$scratch/cluster.out" || true)
echo "CLUSTER_RESULT rc=$rc plan=${plan:-unknown} ok=${ok_count:-0} not_ok=${not_ok_count:-0}"
rg -n "IAM user policy|cluster sync carries|not ok|Failed" \
  "$scratch/cluster.out" | tail -120
exit "$rc"
```

Result: exit 1 after 18 successful assertions because the minimal primary had
no legacy `mysql_servers` row; AWS IAM assertions 6 and 7 passed, and no
`not ok` appeared. Full 401-plan suite is not claimed.

```bash
infra_id=$(tr -d '\n' </tmp/aws-iam-task13-cluster-infra-id)
INFRA_ID="$infra_id" ./test/infra/control/stop-proxysql-isolated.bash
if docker ps -a --format '{{.Names}}' | rg -q "$infra_id"; then exit 1; fi
if docker network ls --format '{{.Name}}' |
    rg -q "^${infra_id}_backend$"; then exit 1; fi
echo "ISOLATED_CLUSTER_INFRA_TORN_DOWN $infra_id"
git diff --check
```

Result: exit 0; cluster namespace removed and working-tree whitespace clean.

### Syntax, linkage, security, and dependency-patch audit

```bash
bash test/infra/control/check-aws-iam-linkage-test.bash
for script in $(git diff --name-only v3.0...HEAD -- '*.bash' '*.sh'); do
  bash -n "$script"
done
shellcheck $(git diff --name-only v3.0...HEAD -- '*.bash' '*.sh')
python3 - <<'PY'
from pathlib import Path
import yaml
path = Path('.github/workflows/CI-aws-iam.yml')
yaml.safe_load(path.read_text())
print(f'YAML_OK {path}')
PY
```

Result: linkage behavior 25/25; every shell syntax/ShellCheck gate and workflow
YAML parse exited 0. An earlier YAML probe named the nonexistent lower-case
workflow and exited 1; correcting the inspected path, not product code, passed.

```bash
git diff --check
git diff --check v3.0...HEAD -- . \
  ':(exclude)deps/mariadb-client-library/tls_server_name.patch'
forbidden_pattern='TO''DO|TB''D|FAKE_AWS_SECRET|FAKE_SESSION_TOKEN'
if rg -n "$forbidden_pattern" include/Aws_Iam_* include/MySQL_Backend_Auth.h \
    lib/Aws_Iam_* lib/MySQL_Backend_Auth.cpp \
    doc/aws_iam_database_authentication.md; then exit 1; fi
if git diff --name-only v3.0...HEAD |
    rg -q '\.(pem|key|p12|pfx|crt)$'; then exit 1; fi
if git diff v3.0...HEAD -- include lib src doc .github |
    rg -n 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|aws_secret_access_key[[:space:]]*=[[:space:]]*[^$<{]'; then
  exit 1
fi
if git diff v3.0...HEAD -- include lib src doc .github |
    rg -n '^\+.*(password|token).*(proxy_error|fprintf|proxy_info|proxy_warning|proxy_debug)'; then
  exit 1
fi
git diff --shortstat v3.0...HEAD
```

Result: exit 0; the only raw whole-range exception is the 13 required inner
patch context markers; scans found no forbidden placeholder, credential/key
material, or new sensitive log expression.

```bash
scratch=$(mktemp -d)
cp -aL deps/mariadb-client-library/mariadb_client "$scratch/src"
(
  cd "$scratch/src"
  patch -R -p0 < "$OLDPWD/deps/mariadb-client-library/sslkeylogfile.patch"
  patch -R -p0 < "$OLDPWD/deps/mariadb-client-library/tls_server_name.patch"
  patch -p0 < "$OLDPWD/deps/mariadb-client-library/tls_server_name.patch"
  patch -p0 < "$OLDPWD/deps/mariadb-client-library/sslkeylogfile.patch"
)
echo "TLS_PATCH_SERIES_ROUNDTRIP_OK scratch=$scratch"
```

Result: exit 0; all four ordered reverse/apply operations succeeded.

### Independent-review defect reproduction and fix verification

The first focused compile command was:

```bash
PROXYSQL40=1 make -C test/tap/tests/unit -j \
  aws_iam_session_state_unit-t &&
./test/tap/tests/unit/aws_iam_session_state_unit-t
```

Result: exit 2 at link time with the known feature-mode `create_backend`
archive mismatch; the new assertion had not run.

The documented alignment and RED run were:

```bash
PROXYSQL40=1 make -C lib -j clean &&
PROXYSQL40=1 make -C test/tap/tests/unit -j "$PWD/lib/libproxysql.a" &&
PROXYSQL40=1 make -C test/tap/tests/unit -j \
  aws_iam_session_state_unit-t &&
./test/tap/tests/unit/aws_iam_session_state_unit-t
```

Result: exit 1; exactly one failure, `not ok 23`, because the SDK-off source
did not log `category='support_not_compiled'`.

After the narrow implementation fix, the directly affected GREEN command was:

```bash
PROXYSQL40=1 make -C lib -j clean &&
PROXYSQL40=1 make -C test/tap/tests/unit -j "$PWD/lib/libproxysql.a" &&
PROXYSQL40=1 make -C test/tap/tests/unit -j \
  aws_iam_session_state_unit-t aws_iam_kill_helper_unit-t \
  aws_iam_connection_config_unit-t &&
./test/tap/tests/unit/aws_iam_session_state_unit-t &&
./test/tap/tests/unit/aws_iam_kill_helper_unit-t &&
./test/tap/tests/unit/aws_iam_connection_config_unit-t
```

Result: exit 0; 24/24, 15/15, and 34/34.

The clean header-consistent full-unit rebuild and runner were:

```bash
PROXYSQL40=1 make -C test/tap/tests/unit -j clean &&
PROXYSQL40=1 make -C test/tap/tests/unit -j &&
set -o pipefail
passed=0; failed=0
for test_bin in test/tap/tests/unit/*-t; do
  if [ ! -x "$test_bin" ]; then continue; fi
  echo "RUN $test_bin"
  "$test_bin" 2>&1 | tail -n 3
  rc=${PIPESTATUS[0]}
  if [ "$rc" -eq 0 ]; then
    passed=$((passed + 1))
  else
    echo "FAIL rc=$rc $test_bin"; failed=$((failed + 1))
  fi
done
echo "UNIT_SUMMARY passed=$passed failed=$failed"
test "$failed" -eq 0
PROXYSQL40=1 make -C test/tap/tests/unit -j \
  test_aws_iam_backend_auth-t
./test/tap/tests/unit/test_aws_iam_backend_auth-t
```

Result: exit 0; default summary 108/0 and explicit controlled target 16/16.

The post-fix ASan build/alignment/run command used the same nine names listed
above and printed `ASAN_SUMMARY passed=9 failed=0`; every Make invocation was:

```bash
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -j build_deps_debug
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -j build_src_debug
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -C lib -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 \
  make -C test/tap/tests/unit -j "$PWD/lib/libproxysql.a"
PROXYSQL40=1 NOJEMALLOC=1 WITHASAN=1 make -C test/tap/tests/unit -j \
  aws_iam_token_manager_unit-t aws_iam_connection_secret_unit-t \
  aws_iam_completion_queue_unit-t aws_iam_session_state_unit-t \
  aws_iam_pool_unit-t aws_iam_failure_unit-t aws_iam_kill_helper_unit-t \
  test_aws_iam_backend_auth-t test_aws_iam_metrics-t
```

Result: all builds and nine `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`
processes exited 0; session was 24/24.

The post-fix TSan build/alignment/run command used the same five names listed
above and printed `TSAN_SUMMARY passed=5 failed=0`; every Make invocation was:

```bash
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -j build_deps_debug
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -j build_src_debug
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -C lib -j clean
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 \
  make -C test/tap/tests/unit -j "$PWD/lib/libproxysql.a"
PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -C test/tap/tests/unit -j \
  aws_iam_token_manager_unit-t aws_iam_completion_queue_unit-t \
  aws_iam_session_state_unit-t aws_iam_kill_helper_unit-t \
  test_aws_iam_metrics-t
```

Result: all builds and five `TSAN_OPTIONS=halt_on_error=1` processes exited 0;
session was 24/24.

### Final combined-diff audit

Unlike the earlier pre-review range scan, this audit included the unstaged
diagnostic fix, its test, and the staged Task 13 report:

```bash
git diff --check
git diff --cached --check
git diff --check v3.0 -- . \
  ':(exclude)deps/mariadb-client-library/tls_server_name.patch'
git diff --check v3.0 > /tmp/task13-raw-diff-check.out 2>&1 || raw_rc=$?
test "${raw_rc:-0}" -eq 2
raw_count=$(rg -c ': trailing whitespace\.$' \
  /tmp/task13-raw-diff-check.out)
test "$raw_count" -eq 13
forbidden_pattern='TO''DO|TB''D|FAKE_AWS_SECRET|FAKE_SESSION_TOKEN'
if rg -n "$forbidden_pattern" include/Aws_Iam_* \
    include/MySQL_Backend_Auth.h lib/Aws_Iam_* \
    lib/MySQL_Backend_Auth.cpp \
    doc/aws_iam_database_authentication.md; then exit 1; fi
if git diff --name-only v3.0 | \
    rg -q '\.(pem|key|p12|pfx|crt)$'; then exit 1; fi
if git diff v3.0 -- include lib src doc .github | \
    rg -n 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|aws_secret_access_key[[:space:]]*=[[:space:]]*[^$<{]'; then
  exit 1
fi
if git diff v3.0 -- include lib src doc .github | \
    rg -n '^\+.*(password|token).*(proxy_error|fprintf|proxy_info|proxy_warning|proxy_debug)'; then
  exit 1
fi
git diff --shortstat v3.0
git diff --name-only v3.0 | wc -l
```

Result: exit 0; working, staged, and combined whitespace checks passed when
the nested Connector/C patch was excluded; the raw check returned the expected
2 with exactly 13 inner-patch context warnings. Security scans were empty and
the combined scope contained 72 files.

### Final normal artifact and feature-off audit

```bash
PROXYSQL40=1 make -j clean
PROXYSQL40=1 make -j
```

Result: the required sanitizer-to-normal transition and complete normal build
exited 0.

After the combined-diff audit, the final standalone build and artifact audit
were:

```bash
PROXYSQL40=1 make -j
sha256sum src/proxysql lib/libproxysql.a
file src/proxysql
if ldd src/proxysql | rg -i 'aws|asan|tsan'; then exit 1; fi
if nm -C src/proxysql | rg 'Aws::'; then exit 1; fi
if nm -C lib/libproxysql.a | rg 'Aws::'; then exit 1; fi
if strings src/proxysql | rg -i 'libaws-cpp-sdk'; then exit 1; fi
git diff --check
git diff --cached --check
git diff --check v3.0 -- . \
  ':(exclude)deps/mariadb-client-library/tls_server_name.patch'
```

Result: the standalone build and every audit exited 0; hashes match the Final
normal build section, all forbidden dependency/symbol searches were empty,
and working, staged, and combined-diff whitespace checks passed.

## Commit

Tasks 1-12 implementation/report HEAD before this report:
`92d843398719286e09ad40e1e560efa02e534b29`.

The report commit is recorded after creation in the Task 13 handoff because a
commit cannot contain its own hash.
