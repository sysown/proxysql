# Vendored AWS SDK for C++ Static-Link Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver AWS IAM database authentication with a committed, pinned AWS SDK for C++ source bundle that is built offline and statically linked into `src/proxysql`, while fixing the outstanding review and CI defects before updating PR #6048.

**Architecture:** Keep the normal build completely SDK-free.  When `PROXYSQLAWSIAM=1`, a make dependency verifies and extracts one committed SDK 1.11.869 source bundle into an identity-specific build directory, performs an offline static CMake build of `core` and `rds` plus their required CRT archives, and writes an immutable make fragment containing exact include, archive, and system link flags.  A session holds a token-source lease rather than a raw global pointer for an entire asynchronous IAM wait, so global shutdown cannot destroy the source while that session can still use it.

**Tech Stack:** GNU Make, CMake 3.13+, AWS SDK for C++ 1.11.869, AWS CRT bundled sources, C++17, OpenSSL/curl/zlib system dependencies, TAP, ASan, TSan, Bash, GitHub Actions.

## Global Constraints

- Vendor exactly AWS SDK for C++ `1.11.869` as a Git-LFS-tracked source tarball under `deps/aws-sdk-cpp/`; it must include the recursively expanded AWS CRT source tree at the upstream-pinned revisions.
- `.gitattributes` tracks only `deps/aws-sdk-cpp/aws-sdk-cpp-1.11.869-with-crt.tar.xz` with the Git LFS filter.  CI and release checkouts hydrate it before any feature-on build; ProxySQL make rules only extract the local file.
- Do not download source, invoke `git`, use CMake FetchContent/ExternalProject, install an AWS SDK package, or discover `AWS_SDK_CPP_ROOT` during any ProxySQL build.
- `PROXYSQLAWSIAM=1` builds only static AWS SDK `core` and `rds` archives and the static CRT archives they require; no AWS SDK test, example, tool, or unrelated service is built.
- The feature-on daemon must define `Aws::RDS::RDSClient::GenerateConnectAuthToken` and must not have a dynamic dependency on `aws-cpp-sdk-*`, `aws-c-*`, `aws-crt-cpp`, `s2n`, or AWS-LC.  Dynamic OpenSSL, curl, zlib, and libc remain allowed.
- Default builds must not extract/compile AWS sources, link an AWS archive/DSO, initialize the AWS runtime, or create IAM provider workers.
- Every `make` invocation in implementation, tests, documentation, and CI must include `PROXYSQL40=1` and `-j`.  Do not set `PROXYSQLCLICKHOUSE` explicitly.  Use `PROXYSQL40=1 make -j clean` only for a demonstrated mode/sanitizer transition; never use `cleanall`.
- Preserve the existing `support_not_compiled` SDK-off behavior, redacted token diagnostics, ordinary password authentication, and no-token logging policy.
- Do not reply to or resolve the GitHub review threads unless the user explicitly requests that action.  Push only after all tasks, review gates, and final verification are complete.
- Do not claim real-RDS, credential-process, or SDK-on production endpoint verification unless a configured IAM-enabled RDS/Aurora environment is actually run.

---

## File and Responsibility Map

| Path | Responsibility |
| --- | --- |
| `include/MySQL_Session.h` | Own the `AwsIamTokenSourceLease` that keeps the provider alive during a session token wait. |
| `lib/MySQL_Session.cpp` | Acquire, use, cancel, clear, and release the session lease in every IAM waiting/terminal path. |
| `test/tap/tests/unit/aws_iam_session_state_unit-t.cpp` | Deterministic shutdown/re-publish lifetime regression for a waiting session. |
| `deps/aws-sdk-cpp/aws-sdk-cpp-1.11.869-with-crt.tar.xz` | Immutable recursively expanded SDK/CRT source payload, unpacked only below `build/` by Task 3. |
| `.gitattributes` | Git LFS tracking for the single large vendored source archive. |
| `deps/aws-sdk-cpp/aws-sdk-cpp-1.11.869-with-crt.sha256` | SHA-256 of the committed source tarball. |
| `deps/aws-sdk-cpp/aws-sdk-cpp-1.11.869-sources.json` | Top-level revision and every expanded submodule repository/revision. |
| `deps/aws-sdk-cpp/LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md` | Apache-2.0 and transitive attribution distributed with the source payload. |
| `deps/aws-sdk-cpp/verify-bundle.bash` | Strict, non-network checksum/layout/revision/attribution validator for the tarball. |
| `cmake/aws-sdk-cpp/BuildVendoredAwsSdk.cmake` | Offline extraction, CMake configuration/build, and immutable generated static-link fragment publication. |
| `common_mk/aws_sdk_cpp_flags.mk` | Feature-mode identity, serialized vendored build invocation, and inclusion of its immutable fragment. |
| `deps/Makefile`, `lib/Makefile`, `src/Makefile`, `Makefile` | Make dependency ordering so feature-on consumes generated static archives and feature-off remains untouched. |
| `test/infra/control/check-vendored-aws-sdk-build.bash` | Black-box manifest, hostile-path, stale identity, no-network, static-archive, and no-DSO build-gate tests. |
| `test/infra/control/check-aws-iam-linkage.bash` | Feature-on static-symbol/no-AWS-DSO audit rooted only in the generated vendor build tree. |
| `test/infra/control/check-aws-iam-linkage-test.bash` | Linkage-checker fixtures for static vendor archives, missing archive, injected service archive, and AWS DSO rejection. |
| `.github/workflows/CI-aws-iam.yml` | Full-history SDK-free, vendored static feature-on, missing-bundle, sanitizer, and protected real-AWS workflow jobs. |
| `test/tap/groups/groups.json` | Registers all IAM/TLS/metrics tests in the repository group runner. |
| `doc/aws_iam_database_authentication.md`, `README.md`, `docs/superpowers/specs/2026-08-13-vendored-aws-sdk-static-design.md` | Operator and maintainer documentation for the in-tree static vendor contract. |

### Task 1: Fix the reviewed asynchronous session lifetime defect

**Files:**
- Create: `.gitattributes`
- Modify: `include/MySQL_Session.h`
- Modify: `lib/MySQL_Session.cpp`
- Modify: `test/tap/tests/unit/aws_iam_session_state_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**
- Consumes: `AwsIamTokenSourceLease acquire_global_aws_iam_token_source()` and its move-only `get()`, `operator->()`, and destructor contract from `include/Aws_Iam_Sdk.h`.
- Produces: `MySQL_Session::aws_iam_token_source_lease` as the sole session-held provider reference while `status == WAITING_AWS_IAM_TOKEN`; a deterministic test-only fake source proves shutdown waits for that lease and the old session never uses a republished source.

- [ ] **Step 1: Add a deterministic failing lifetime test**

  In `aws_iam_session_state_unit-t.cpp`, add a blocking fake source that records `request_async`, blocks it on a condition variable, and records every cancellation/request source identity.  Start a session’s IAM wait, start `shutdown_global_aws_iam_token_source()` on another thread, and assert shutdown has not returned while the request is live.  Cancel the session, join shutdown, publish a different fake source, and assert the old session neither requests nor cancels the newly published source.

  ```cpp
  auto shutdown = std::async(std::launch::async, [] {
      shutdown_global_aws_iam_token_source();
  });
  ok(shutdown.wait_for(20ms) == std::future_status::timeout,
      "global shutdown waits for the session-owned IAM lease");
  session.cancel_aws_iam_wait("test_cancel");
  shutdown.get();
  ```

- [ ] **Step 2: Run the focused test to prove the raw-pointer bug**

  Run:

  ```bash
  PROXYSQL40=1 make -C test/tap/tests/unit -j aws_iam_session_state_unit-t
  TSAN_OPTIONS=halt_on_error=1 test/tap/tests/unit/aws_iam_session_state_unit-t
  ```

  Expected: the new assertion fails because `MySQL_Session` stores `GloAwsIamTokenSource` as a raw pointer and global shutdown has no session lease to wait for.

- [ ] **Step 3: Replace the raw session provider with an owned lease**

  In `MySQL_Session.h`, replace the raw member with a default-constructed move-only lease:

  ```cpp
  AwsIamTokenSourceLease aws_iam_token_source_lease {};
  ```

  In the `CONNECTING_SERVER` IAM branch, acquire a local lease before waiter registration, validate `lease && lease->supports_iam_database_authentication()`, and move it into the session only after the waiter is successfully registered.  Invoke `request_async`, `cancel`, and error handling through `aws_iam_token_source_lease.get()` only.  In every completion, cancel, timeout, backend-connect failure, destructor, and session reset path, cancel the request first where applicable, erase the waiter/metric state, then reset the lease:

  ```cpp
  if (aws_iam_token_source_lease) {
      aws_iam_token_source_lease->cancel(request_id);
  }
  aws_iam_token_source_lease = AwsIamTokenSourceLease{};
  ```

  Do not add a new raw global dereference to session logic.  `kill_query_thread()` continues using its existing scoped lease.

- [ ] **Step 4: Run focused normal, repeated, and TSan tests**

  Run:

  ```bash
  PROXYSQL40=1 make -C test/tap/tests/unit -j aws_iam_session_state_unit-t aws_iam_token_manager_unit-t aws_iam_completion_queue_unit-t
  test/tap/tests/unit/aws_iam_session_state_unit-t
  test/tap/tests/unit/aws_iam_session_state_unit-t
  TSAN_OPTIONS=halt_on_error=1 test/tap/tests/unit/aws_iam_session_state_unit-t
  ```

  Expected: all prior session assertions plus the new shutdown/re-publish assertion pass; no TSan race is reported.

- [ ] **Step 5: Audit the session paths and commit**

  Verify every reference to `aws_iam_token_source_lease` clears it on terminal state and no `aws_iam_token_source` raw member remains:

  ```bash
  rg -n 'aws_iam_token_source|GloAwsIamTokenSource' include/MySQL_Session.h lib/MySQL_Session.cpp
  git diff --check
  git add include/MySQL_Session.h lib/MySQL_Session.cpp test/tap/tests/unit/aws_iam_session_state_unit-t.cpp test/tap/tests/unit/Makefile
  git commit -m "fix(mysql): retain IAM provider during session wait"
  ```

### Task 2: Commit and validate the pinned, expanded AWS SDK source bundle

**Files:**
- Create: `deps/aws-sdk-cpp/aws-sdk-cpp-1.11.869-with-crt.tar.xz`
- Create: `deps/aws-sdk-cpp/aws-sdk-cpp-1.11.869-with-crt.sha256`
- Create: `deps/aws-sdk-cpp/aws-sdk-cpp-1.11.869-sources.json`
- Create: `deps/aws-sdk-cpp/LICENSE`
- Create: `deps/aws-sdk-cpp/NOTICE`
- Create: `deps/aws-sdk-cpp/THIRD_PARTY_NOTICES.md`
- Create: `deps/aws-sdk-cpp/verify-bundle.bash`
- Create: `test/infra/control/check-vendored-aws-sdk-build.bash`

**Interfaces:**
- Consumes: pinned AWS SDK C++ tag `1.11.869`, commit `c84017197daa00de9cc05b1166e9106e1079f7f3`, and its recursive gitlink revisions.
- Produces: a conventional complete source tarball with one top-level `aws-sdk-cpp-1.11.869/` directory, explicit nested `crt/aws-crt-cpp/` sources, a parseable JSON revision manifest, and `verify-bundle.bash ${BUNDLE_DIR}` returning zero only for an intact bundle.  It is not unpacked into `deps/`; Task 3 extracts it below `build/` during a feature-on compile.

- [ ] **Step 1: Write black-box bundle-validator fixtures before importing the real archive**

  Add to `check-vendored-aws-sdk-build.bash` a temporary synthetic bundle generator with a valid revision manifest and required nested paths.  Assert success for the fixture and failure with exact diagnostics for a bad tar SHA-256, absent `crt/aws-crt-cpp`, a changed manifest/revision digest, a missing `LICENSE`/`NOTICE`, and a path containing spaces and literal dollar signs.

  ```bash
  expect_failure 'AWS IAM vendor bundle checksum mismatch' \
    "$validator" "$bad_checksum_bundle"
  expect_failure 'AWS IAM vendor bundle is missing crt/aws-crt-cpp' \
    "$validator" "$missing_crt_bundle"
  ```

- [ ] **Step 2: Run the validator test to capture RED**

  Run:

  ```bash
  bash test/infra/control/check-vendored-aws-sdk-build.bash
  ```

  Expected: FAIL because `deps/aws-sdk-cpp/verify-bundle.bash` and the committed source bundle do not yet exist.

- [ ] **Step 3: Import the reproducible source-only bundle and validator**

  Create the tarball once from an upstream checkout of tag `1.11.869` with all
  recursive submodules initialized at their gitlink commits.  Keep the complete
  upstream source trees—including tests and feature-probe input—because CMake
  configuration can consume them even when test targets are disabled.  Remove
  only `.git` metadata, generated build directories, machine-local `.aws`
  configuration, and prebuilt object/library files before deterministic XZ
  archive creation.  Track the archive through a single `.gitattributes` LFS
  rule.  Preserve `crt/aws-crt-cpp`, `aws-c-*`,
  `aws-checksums`, `aws-lc`, and `s2n` intact.

  Make the JSON manifest record the SDK tag/commit plus `path`, `repository`,
  and `revision` for each expanded source tree.  The `crt/aws-crt-cpp` entry
  uses repository `https://github.com/awslabs/aws-crt-cpp.git` and revision
  `851d8d003c9d5150edab56807e2393013f3771de`.  The `.sha256` file and a
  matching literal expected digest in `verify-bundle.bash` bind the committed
  archive; updating this pinned release requires deliberately updating both.

  `verify-bundle.bash` must use fixed-key JSON parsing (Python standard
  library is permitted), `sha256sum`/`shasum -a 256`, `tar -tJf`, and `find`
  without sourcing, evaluating, or expanding manifest data.  It verifies the
  outer digest against both inputs, one safe top-level directory, exact
  revision map, required CRT paths, distinct license/notice files, and the
  absence of VCS/build/prebuilt/machine-local credential artifacts.  It never
  rejects legitimate upstream source/test filenames or prints environment
  variables, credentials, or token-like values.

- [ ] **Step 4: Run validator and archive-safety gates**

  Run:

  ```bash
  bash test/infra/control/check-vendored-aws-sdk-build.bash
  deps/aws-sdk-cpp/verify-bundle.bash deps/aws-sdk-cpp
  tar -tJf deps/aws-sdk-cpp/aws-sdk-cpp-1.11.869-with-crt.tar.xz | \
    rg '(^|/)(\.git|CMakeCache\.txt|CMakeFiles/|\.aws/(credentials|config)$|.*\.(a|o|so|dylib)$)' && exit 1 || true
  ```

  Expected: the fixture matrix and real bundle validator pass; the archive scan
  prints no repository metadata, CMake/build output, machine-local AWS
  configuration, or prebuilt objects/libraries.  Complete upstream source,
  probe, test, fixture, example, and documentation files are intentional.

- [ ] **Step 5: Audit legal material and commit the vendor payload separately**

  Confirm `THIRD_PARTY_NOTICES.md` maps every manifest tree to license/notice material and that the tarball digest matches its `.sha256` file.  Commit the binary archive and text metadata in their own traceable commit:

  ```bash
  git diff --check
  git add .gitattributes deps/aws-sdk-cpp test/infra/control/check-vendored-aws-sdk-build.bash
  git commit -m "deps: vendor AWS SDK C++ 1.11.869 sources"
  ```

### Task 3: Build and link the vendored SDK statically and offline

**Files:**
- Create: `cmake/aws-sdk-cpp/BuildVendoredAwsSdk.cmake`
- Modify: `common_mk/aws_sdk_cpp_flags.mk`
- Modify: `deps/Makefile`
- Modify: `lib/Makefile`
- Modify: `src/Makefile`
- Modify: `Makefile`
- Modify: `test/infra/control/check-vendored-aws-sdk-build.bash`
- Modify: `test/infra/control/check-aws-iam-linkage.bash`
- Modify: `test/infra/control/check-aws-iam-linkage-test.bash`
- Delete: `cmake/aws-sdk-cpp/CMakeLists.txt`
- Delete: `cmake/aws-sdk-cpp/DiscoverAwsSdk.cmake`

**Interfaces:**
- Consumes: `deps/aws-sdk-cpp/verify-bundle.bash`, the committed `1.11.869` archive/revision manifest, `PROXYSQLAWSIAM=1`, compiler identity, architecture, CMake version, and existing system OpenSSL/curl/zlib paths.
- Produces: `build/aws-sdk-cpp/${AWS_IAM_BUILD_ID}/aws-sdk-cpp.mk` with `AWS_IAM_CPPFLAGS`, `AWS_IAM_STATIC_ARCHIVES`, and `AWS_IAM_SYSTEM_LIBS`; all archive paths are beneath `build/aws-sdk-cpp/${AWS_IAM_BUILD_ID}/install/` and no flag names an external SDK prefix.

- [ ] **Step 1: Extend the build-gate test with an intentionally failing feature-on contract**

  Add a temporary tiny archive fixture and assert that the build gate rejects (a) a generated fragment containing `-laws-cpp-sdk-s3`, (b) an archive path outside the identity-specific `build/aws-sdk-cpp/${AWS_IAM_BUILD_ID}/install` tree, (c) a dynamic AWS library in a probe’s `ldd` output, (d) a stale fragment after manifest/compiler identity changes, and (e) an attempted `AWS_SDK_CPP_ROOT` override.

  ```bash
  expect_failure 'AWS IAM static link fragment contains unrelated service archive: s3' \
    "$build_gate" --fragment "$unrelated_service_fragment"
  expect_failure 'AWS IAM static link fragment archive escapes vendor build tree' \
    "$build_gate" --fragment "$escaped_archive_fragment"
  ```

- [ ] **Step 2: Run the static-build gate to establish RED**

  Run:

  ```bash
  PROXYSQL40=1 PROXYSQLAWSIAM=1 make -j build_src
  bash test/infra/control/check-vendored-aws-sdk-build.bash
  ```

  Expected: the build either asks for an external SDK or the new test fails because no offline vendor extraction/configuration/static fragment exists.

- [ ] **Step 3: Replace external discovery with an identity-scoped offline static build**

  Remove all `AWS_SDK_CPP_ROOT`, `find_package(AWSSDK ...)` against host prefixes, package discovery, and openSUSE-package assumptions from `common_mk/aws_sdk_cpp_flags.mk` and its CMake helpers.  Calculate the feature-on identity from:

  ```text
  bundle SHA-256 + revision-manifest SHA-256 + CMake option list + C/C++ compiler path/version
  + target architecture + OpenSSL/curl/zlib include/library paths
  ```

  Set `AWS_IAM_BUILD_ID` to the 64-hex SHA-256 of that canonical identity
  record.  Under a process lock keyed by this value, run `verify-bundle.bash`,
  extract to `build/aws-sdk-cpp/${AWS_IAM_BUILD_ID}/source/`, and configure
  only the extracted root:

  ```cmake
  -DBUILD_SHARED_LIBS=OFF
  -DBUILD_ONLY=core;rds
  -DBUILD_DEPS=ON
  -DENABLE_TESTING=OFF
  -DAUTORUN_UNIT_TESTS=OFF
  -DCPP_STANDARD=17
  -DUSE_CRT_HTTP_CLIENT=OFF
  -DENFORCE_SUBMODULE_VERSIONS=OFF
  -DCMAKE_INSTALL_PREFIX=${AWS_IAM_BUILD_ID}/install
  ```

  The `ENFORCE_SUBMODULE_VERSIONS=OFF` exception is allowed only because the validator has already checked the committed archive digest and recursive revision manifest before extraction; document that connection next to the option.  Build and install only the configured static targets.  Generate a temporary CMake link-probe target linked to `AWS::aws-cpp-sdk-rds`, capture its exact ordered archive and system-library arguments, validate them, and atomically publish a shell-quoted immutable make fragment.  The fragment must list only `core`, `rds`, their required CRT/AWS C archives under the private install tree, and existing system link flags.

  Feature-off must only update a stable disabled mode stamp; it must not execute the validator, tar, CMake, or SDK compilation.  A changed mode/identity forces the affected ProxySQL objects to rebuild; an unchanged actual or dry-run invocation schedules zero compile/archive/link commands.

- [ ] **Step 4: Wire dependency ordering and static link consumption**

  Add an explicit `aws_sdk_cpp_vendor` dependency target used only when `PROXYSQLAWSIAM=1`; make all IAM-bearing `lib`/`src` object and final-link targets depend on the generated fragment/archive set before compilation/linking.  Use explicit archive paths, not `-laws-cpp-sdk-*`, and put `$(AWS_IAM_STATIC_ARCHIVES)` before `$(AWS_IAM_SYSTEM_LIBS)` in the final link order.  Do not alter non-IAM target flags.

  The expected final source-link shape is:

  ```make
  $(CXX) ... $(PROXYSQL_OBJECTS) $(AWS_IAM_STATIC_ARCHIVES) \
      $(EXISTING_SYSTEM_LIBS) $(AWS_IAM_SYSTEM_LIBS) -o src/proxysql
  ```

- [ ] **Step 5: Verify normal/feature-on mode transitions and static linkage**

  Run from a clean feature-mode transition only if timestamps prove it is required:

  ```bash
  PROXYSQL40=1 make -j clean
  PROXYSQL40=1 make -j
  PROXYSQL40=1 PROXYSQLAWSIAM=1 make -j
  bash test/infra/control/check-vendored-aws-sdk-build.bash
  bash test/infra/control/check-aws-iam-linkage-test.bash
  test/infra/control/check-aws-iam-linkage.bash src/proxysql
  nm -C src/proxysql | grep -F 'Aws::RDS::RDSClient::GenerateConnectAuthToken'
  ldd src/proxysql | grep -E 'aws-cpp-sdk|aws-c-|aws-crt-cpp|libs2n|aws-lc' && exit 1 || true
  PROXYSQL40=1 PROXYSQLAWSIAM=1 make -j -n | grep -E '(^| )(g\+\+|ar|ranlib|cmake)' && exit 1 || true
  ```

  Expected: SDK-free build has no AWS references; feature-on build succeeds offline from the committed bundle, passes linkage audit, has the required static symbol, no AWS dynamic DSO, and an unchanged feature-on dry run is a no-op.

- [ ] **Step 6: Commit the build-system migration**

  Run `git diff --check`, ensure no external discovery files remain referenced, and commit:

  ```bash
  rg -n 'AWS_SDK_CPP_ROOT|find_package\(AWSSDK|Cloud:/Tools|aws-sdk-cpp-devel' \
    common_mk cmake deps lib src Makefile && exit 1 || true
  git add common_mk/aws_sdk_cpp_flags.mk deps/Makefile lib/Makefile src/Makefile Makefile \
    cmake/aws-sdk-cpp test/infra/control/check-vendored-aws-sdk-build.bash \
    test/infra/control/check-aws-iam-linkage.bash test/infra/control/check-aws-iam-linkage-test.bash
  git rm cmake/aws-sdk-cpp/CMakeLists.txt cmake/aws-sdk-cpp/DiscoverAwsSdk.cmake
  git commit -m "build: statically link vendored AWS SDK"
  ```

### Task 4: Repair CI, test registration, linkage policy, and documentation

**Files:**
- Modify: `.github/workflows/CI-aws-iam.yml`
- Modify: `test/tap/groups/groups.json`
- Modify: `test/infra/control/check-aws-iam-linkage.bash`
- Modify: `test/infra/control/check-aws-iam-linkage-test.bash`
- Modify: `test/infra/control/check-vendored-aws-sdk-build.bash`
- Modify: `doc/aws_iam_database_authentication.md`
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-08-13-vendored-aws-sdk-static-design.md`
- Create: `test/infra/control/check-aws-iam-ci-policy.bash`

**Interfaces:**
- Consumes: generated `AWS_IAM_STATIC_ARCHIVES`/identity fragment, group runner schema, feature-on daemon produced by Task 3, and the existing protected real-AWS preflight/self-hosted contract.
- Produces: a six-job YAML workflow with full history, a vendored static SDK job, portable diagnostics, complete group registration, and docs that describe the actual in-tree operator/build contract.

- [ ] **Step 1: Add failing workflow-policy and group-registration checks**

  `check-aws-iam-ci-policy.bash` must parse the workflow with Python/PyYAML and assert every checkout has `fetch-depth: 0` and `fetch-tags: true`; the feature-on job never runs a package manager AWS SDK install; all `make` strings include `PROXYSQL40=1` and `-j`; missing-bundle diagnostics use `grep -F`; and every known IAM/TLS/metrics test source is present in `groups.json`.

  Include the exact currently omitted registrations:

  ```text
  aws_iam_completion_queue_unit-t
  aws_iam_connection_config_unit-t
  aws_iam_connection_secret_unit-t
  aws_iam_failure_unit-t
  aws_iam_kill_helper_unit-t
  aws_iam_policy_unit-t
  aws_iam_pool_unit-t
  aws_iam_session_state_unit-t
  aws_iam_token_manager_unit-t
  mariadb_tls_server_name_unit-t
  test_aws_iam_backend_auth-t
  test_aws_iam_metrics-t
  ```

- [ ] **Step 2: Run policy checks to capture the known CI RED state**

  Run:

  ```bash
  bash test/infra/control/check-aws-iam-ci-policy.bash
  python3 test/tap/groups/check_groups.py test/tap/groups/groups.json
  ```

  Expected: fail for shallow checkout, `rg` use, external system-SDK/openSUSE job, and missing test registrations.

- [ ] **Step 3: Replace external-SDK CI with vendored static CI**

  In `.github/workflows/CI-aws-iam.yml`:

  - add `fetch-depth: 0`, `fetch-tags: true`, and `lfs: true` to every checkout that builds or audits the vendored SDK;
  - retain an SDK-free job that verifies feature-off linkage rejection with `grep -F`;
  - replace `aws-enabled-system-sdk-build` with an Ubuntu vendored-static job that runs `PROXYSQL40=1 PROXYSQLAWSIAM=1 make -j`, `check-vendored-aws-sdk-build.bash`, the static linkage audit, IAM unit tests, and the controlled TLS/auth-switch target;
  - replace the empty external-prefix test with a missing/modified committed-bundle diagnostic test and an exact expected message;
  - retain fake-provider ASan/TSan jobs and the protected preflight/self-hosted real-AWS job without relabeling controlled TLS coverage as real RDS;
  - do not install `aws-sdk-cpp-*` packages, add openSUSE repositories, or run Docker solely to obtain the SDK.

  Use portable shell patterns:

  ```bash
  if ldd src/proxysql | grep -F 'aws-cpp-sdk'; then
      echo 'static AWS SDK build unexpectedly has an AWS DSO dependency' >&2
      exit 1
  fi
  ```

- [ ] **Step 4: Register tests and make the linkage audit static-aware**

  Add all twelve missing test identifiers to their appropriate unit/TAP groups without changing unrelated group membership.  Extend `check-aws-iam-linkage.bash` so a feature-on result requires: vendor manifest/digest match, every AWS archive under the generated identity install tree, core/rds and no unrelated service, required static `GenerateConnectAuthToken` symbol, no AWS DSO, and distinct bundle `LICENSE`/`NOTICE`.  Feature-off remains an exact rejected state.

  Expand `check-aws-iam-linkage-test.bash` fixtures to prove archive injection, stale identity, missing bundle attribution, external prefix, and AWS DSO all fail.

- [ ] **Step 5: Update operator and maintainer documentation**

  Replace all external package/root instructions with the pinned in-tree source contract:

  ```markdown
  PROXYSQL40=1 PROXYSQLAWSIAM=1 make -j
  ```

  State that this builds the committed `1.11.869` source bundle offline and statically links only AWS `core`/`rds` plus needed CRT archives.  Document source attribution files, static-link audit, standard AWS credential-provider chain, unchanged TLS hostname verification, SDK-off `support_not_compiled`, and the fact that real RDS verification needs a separately configured protected runner.  Remove the external package-notice release block and `AWS_SDK_CPP_ROOT` references.

- [ ] **Step 6: Run local static policy and documentation gates**

  Run:

  ```bash
  bash test/infra/control/check-aws-iam-ci-policy.bash
  bash test/infra/control/check-aws-iam-linkage-test.bash
  bash test/infra/control/check-vendored-aws-sdk-build.bash
  python3 test/tap/groups/check_groups.py test/tap/groups/groups.json
  python3 - <<'PY'
  import pathlib, yaml
  yaml.safe_load(pathlib.Path('.github/workflows/CI-aws-iam.yml').read_text())
  print('workflow parses')
  PY
  rg -n 'AWS_SDK_CPP_ROOT|openSUSE system AWS SDK|Cloud:/Tools|aws-sdk-cpp-devel' \
    README.md doc .github/workflows/CI-aws-iam.yml && exit 1 || true
  ```

  Expected: all policy, parser, linkage fixture, vendor fixture, and group checks pass; docs contain no external SDK installation/root contract.

- [ ] **Step 7: Commit CI and documentation corrections**

  ```bash
  git diff --check
  git add .github/workflows/CI-aws-iam.yml test/tap/groups/groups.json \
    test/infra/control/check-aws-iam-ci-policy.bash \
    test/infra/control/check-aws-iam-linkage.bash \
    test/infra/control/check-aws-iam-linkage-test.bash \
    test/infra/control/check-vendored-aws-sdk-build.bash \
    doc/aws_iam_database_authentication.md README.md \
    docs/superpowers/specs/2026-08-13-vendored-aws-sdk-static-design.md
  git commit -m "ci: validate vendored AWS IAM SDK builds"
  ```

### Task 5: Complete static feature-on verification, independent review, and PR update

**Files:**
- Modify: `.superpowers/sdd/2026-08-12-aws-iam-database-auth/task-14-report.md`
- Modify: `docs/superpowers/specs/2026-08-13-vendored-aws-sdk-static-design.md` only if verification exposes an exact design correction

**Interfaces:**
- Consumes: Task 1 session lease, Task 2 committed source bundle, Task 3 generated static build fragment/linkage checker, and Task 4 workflow/group/documentation changes.
- Produces: a review-backed verification record and an updated `feature/aws-iam-database-auth` branch pushed to PR #6048.  GitHub review threads remain untouched unless separately authorized.

- [ ] **Step 1: Build and run both SDK-free and vendored feature-on matrices**

  Run the normal SDK-free matrix first:

  ```bash
  PROXYSQL40=1 make -j clean
  PROXYSQL40=1 make -j
  bash test/infra/control/check-aws-iam-linkage.bash src/proxysql; test $? -eq 1
  ```

  Then run the vendor-static matrix:

  ```bash
  PROXYSQL40=1 PROXYSQLAWSIAM=1 make -j
  PROXYSQL40=1 PROXYSQLAWSIAM=1 make -C test/tap/tests/unit -j \
    aws_iam_policy_unit-t aws_iam_connection_config_unit-t \
    aws_iam_token_manager_unit-t aws_iam_connection_secret_unit-t \
    aws_iam_completion_queue_unit-t aws_iam_session_state_unit-t \
    aws_iam_pool_unit-t aws_iam_failure_unit-t aws_iam_kill_helper_unit-t \
    mariadb_tls_server_name_unit-t
  test/tap/tests/unit/aws_iam_policy_unit-t
  test/tap/tests/unit/aws_iam_connection_config_unit-t
  test/tap/tests/unit/aws_iam_token_manager_unit-t
  test/tap/tests/unit/aws_iam_connection_secret_unit-t
  test/tap/tests/unit/aws_iam_completion_queue_unit-t
  test/tap/tests/unit/aws_iam_session_state_unit-t
  test/tap/tests/unit/aws_iam_pool_unit-t
  test/tap/tests/unit/aws_iam_failure_unit-t
  test/tap/tests/unit/aws_iam_kill_helper_unit-t
  test/tap/tests/unit/mariadb_tls_server_name_unit-t
  PROXYSQL40=1 PROXYSQLAWSIAM=1 make -C test/tap/tests -j test_aws_iam_backend_auth-t test_aws_iam_metrics-t
  test/tap/tests/test_aws_iam_backend_auth-t
  test/tap/tests/test_aws_iam_metrics-t
  ```

  Expected: feature-off is AWS-free and rejects feature-on linkage requirements; feature-on passes all listed IAM/TLS/protocol/metrics tests using the static bundle.

- [ ] **Step 2: Run sanitizer, no-op, and static-link evidence gates**

  Run one justified sanitizer transition per sanitizer:

  ```bash
  PROXYSQL40=1 make -j clean
  NOJEMALLOC=1 WITHASAN=1 PROXYSQL40=1 PROXYSQLAWSIAM=1 make -j build_lib_debug
  ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 test/tap/tests/unit/aws_iam_session_state_unit-t
  ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 test/tap/tests/unit/aws_iam_token_manager_unit-t
  PROXYSQL40=1 make -j clean
  NOJEMALLOC=1 WITHTSAN=1 PROXYSQL40=1 PROXYSQLAWSIAM=1 make -j build_lib_debug
  TSAN_OPTIONS=halt_on_error=1 test/tap/tests/unit/aws_iam_session_state_unit-t
  TSAN_OPTIONS=halt_on_error=1 test/tap/tests/unit/aws_iam_completion_queue_unit-t
  PROXYSQL40=1 make -j clean
  PROXYSQL40=1 PROXYSQLAWSIAM=1 make -j
  PROXYSQL40=1 PROXYSQLAWSIAM=1 make -j -n | grep -E '(^| )(g\+\+|ar|ranlib|cmake)' && exit 1 || true
  test/infra/control/check-aws-iam-linkage.bash src/proxysql
  ```

  Expected: no ASan/LSan/TSan diagnostics; feature-on repeat dry-run has no build commands; linkage check confirms required static symbol and no AWS DSO.

- [ ] **Step 3: Conduct security, source-bundle, and final-diff audits**

  Run:

  ```bash
  git diff --check v3.0...HEAD
  git diff --check
  rg -n --hidden -g '!deps/aws-sdk-cpp/aws-sdk-cpp-1.11.869-with-crt.tar.gz' \
    '(AKIA[0-9A-Z]{16}|aws_secret_access_key|credential_process|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|GenerateConnectAuthToken\([^)]*token)' \
    . ':!.git'
  deps/aws-sdk-cpp/verify-bundle.bash deps/aws-sdk-cpp
  bash test/infra/control/check-vendored-aws-sdk-build.bash
  ```

  If outer `git diff --check` reports context-marker spaces inside the
  committed Connector/C patch file, prove the patch still applies through the
  existing dependency target, then report those nested-diff warnings rather
  than corrupting valid patch context:

  ```bash
  PROXYSQL40=1 make -C deps -j mariadb_client
  PROXYSQL40=1 make -C test/tap/tests/unit -j mariadb_tls_server_name_unit-t
  test/tap/tests/unit/mariadb_tls_server_name_unit-t
  ```

- [ ] **Step 4: Request an independent code review and address only verified findings**

  Submit the complete diff for independent review with this evidence request:

  ```text
  Review the session lease lifetime, offline vendored bundle integrity, static archive ordering/no-DSO audit, feature-off isolation, CI checkout/groups/portable shell changes, and credentials/logging exposure. Report only Critical/Important findings with file and line evidence.
  ```

  For each finding, reproduce it with the smallest failing test or command before changing code, add regression coverage, rerun the affected matrix, and request re-review.  Do not post GitHub replies or resolve threads without separate user authorization.

- [ ] **Step 5: Record evidence, commit, push, and verify PR checks**

  Write `task-14-report.md` with exact command/result status, bundle filename/digests, archive/DSO/static-symbol evidence, sanitizer results, review disposition, and explicit real-RDS limitations.  Then run:

  ```bash
  git diff --check
  git add .superpowers/sdd/2026-08-12-aws-iam-database-auth/task-14-report.md
  git commit -m "docs: record vendored AWS IAM verification"
  git push origin feature/aws-iam-database-auth
  gh pr checks 6048 --watch --fail-fast
  ```

  Expected: branch pushes only after all local gates and independent review are green.  Report CI failures with their job/log evidence; do not claim success until the required checks finish.

## Plan Self-Review

### Spec coverage

- Pinned `1.11.869`, recursively expanded source-only tarball, manifest, digest, and attributions: Task 2.
- Offline identity-scoped static `core`/`rds`/CRT build and no AWS dynamic dependencies: Task 3.
- Feature-off isolation and the mandatory static symbol/no-DSO contract: Tasks 3 and 5.
- Session lease remediation from the Gitar review: Task 1.
- Full-history checkout, portable diagnostic, group registration, and removal of external openSUSE package discovery: Task 4.
- Operator documentation, review, exact evidence, and only-then push: Tasks 4 and 5.
- Real-RDS non-claim: Global Constraints and Task 5.

### Placeholder scan

The prohibited placeholder vocabulary from the plan-writing rules is absent.  Every implementation task names concrete files, contracts, tests, expected RED/GREEN behavior, and a commit command.

### Type consistency

`AwsIamTokenSourceLease` is the existing move-only type returned by `acquire_global_aws_iam_token_source()` and is used consistently in Task 1.  `AWS_IAM_STATIC_ARCHIVES`, `AWS_IAM_SYSTEM_LIBS`, and `build/aws-sdk-cpp/${AWS_IAM_BUILD_ID}/aws-sdk-cpp.mk` are introduced in Task 3 and consumed by Tasks 3–5.  `verify-bundle.bash ${BUNDLE_DIR}` is created in Task 2 before later tasks consume it.
