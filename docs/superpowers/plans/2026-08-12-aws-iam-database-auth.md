# AWS IAM Database Authentication for MySQL Backends Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let opted-in MySQL backend users authenticate from ProxySQL to RDS/Aurora with short-lived AWS IAM database tokens while ordinary users and SDK-free builds retain their current behavior.

**Architecture:** Keep policy parsing, connection validation, token caching, and session state SDK-independent. A process-wide optional AWS adapter signs tokens on two bounded background threads and returns them through worker-owned completion inboxes. A fresh IAM connection waits in a dedicated session state, then hands a move-only token directly to the existing nonblocking MariaDB Connector/C handshake; established pooled connections retain only their authentication mode, never the token.

**Tech Stack:** C++17, ProxySQL MySQL session/pool code, MariaDB Connector/C 3.3.8, AWS SDK for C++ 1.9+ (`core` and `rds`), CMake package discovery, GNU Make, OpenSSL cleansing/TLS, nlohmann/json, prometheus-cpp, TAP tests, ASan, and TSan.

## Global Constraints

- Follow the approved design in `docs/superpowers/specs/2026-08-12-aws-iam-database-auth-design.md`.
- Scope is ProxySQL-to-backend MySQL/MariaDB protocol authentication. Do not add frontend IAM authentication, PostgreSQL support, monitor-account IAM authentication, Secrets Manager, or per-user `AssumeRole`.
- Backend opt-in is exactly `mysql_users.attributes = {"backend_auth":{"type":"aws_iam"}}`; absence means password mode and any present-but-invalid object means invalid/fail closed.
- Region is exactly `mysql_hostgroup_attributes.hostgroup_settings.aws_iam_region` and must equal the region label in the configured real RDS/Aurora endpoint.
- IAM requires TCP, `use_ssl=1`, non-empty CA trust, `MYSQL_OPT_SSL_ENFORCE`, `MYSQL_OPT_SSL_VERIFY_SERVER_CERT`, the static `mysql_clear_password` plugin, and hostname verification against the configured endpoint rather than the resolved IP.
- Never fall back from IAM to a password. A non-empty backend-row password is ignored and warned about once per loaded row.
- Never write generated tokens into `mysql_users`, cluster state, the frontend `userinfo`, or long-lived `MySQL_Connection_userinfo::password`.
- Generated tokens and AWS credentials must never appear in logs, client errors, stats, metrics, core diagnostic strings, or test failure output.
- Cache keys are exactly `(configured endpoint, port, region, database user)`. Tokens are locally valid for 15 minutes and reusable only while at least two minutes remain.
- Provider defaults are two threads, 1,024 queued distinct keys, five-second session wait, conditional generation invalidation, and bounded coalesced waiters.
- The default build must not include AWS headers, link AWS libraries, initialize the SDK, or start provider threads.
- `PROXYSQLAWSIAM=1` requires a system-installed AWS SDK for C++ 1.9 or newer. Prefer its shared libraries for release packages, but preserve complete CMake-discovered transitive link requirements when only static system libraries are available. Do not download or vendor it.
- Preserve unrelated user changes. Run each task's focused test before its commit and run the final matrix before declaring completion.

---

### Task 1: Add the backend authentication policy model and parser

**Files:**

- Create: `include/MySQL_Backend_Auth.h`
- Create: `lib/MySQL_Backend_Auth.cpp`
- Modify: `lib/MySQL_Authentication.cpp`
- Create: `test/tap/tests/unit/aws_iam_policy_unit-t.cpp`
- Modify: `lib/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: mapped backend username plus the `attributes` returned by `GloMyAuth->lookup(username, USERNAME_BACKEND, {false, false, true})`.
- Produces:

```cpp
enum class MySQLBackendAuthType : uint8_t {
    PASSWORD,
    AWS_IAM,
    INVALID,
};

struct MySQLBackendAuthPolicy {
    MySQLBackendAuthType type{MySQLBackendAuthType::INVALID};
    std::string database_user;
    std::string failure_code;
    bool ignored_password{false};
};

MySQLBackendAuthPolicy parse_mysql_backend_auth_policy(
    std::string_view database_user,
    std::string_view attributes,
    bool backend_password_is_nonempty);

MySQLBackendAuthPolicy resolve_mysql_backend_auth_policy(
    MySQL_Authentication& authentication,
    const char* mapped_backend_username);

const char* mysql_backend_auth_type_name(MySQLBackendAuthType type);
```

- `failure_code` is one of `backend_user_not_found`, `attributes_not_object`, `backend_auth_not_object`, `type_missing`, `type_not_string`, or `type_unsupported`; it contains no raw JSON or credential material.

- [ ] **Step 1: Write the failing parser/resolver tests**

Cover these exact cases in `aws_iam_policy_unit-t.cpp`:

```text
absent or empty attributes                  -> PASSWORD
{}                                          -> PASSWORD
{"backend_auth":{"type":"aws_iam"}}      -> AWS_IAM
IAM row with non-empty password             -> AWS_IAM + ignored_password=true
JSON scalar/array                           -> INVALID attributes_not_object
backend_auth scalar/array/null              -> INVALID backend_auth_not_object
backend_auth object without type            -> INVALID type_missing
non-string type                             -> INVALID type_not_string
unknown or differently-cased type           -> INVALID type_unsupported
missing/inactive USERNAME_BACKEND lookup     -> INVALID backend_user_not_found
```

Also assert that returned diagnostics never contain the recognizable fake strings `FAKE_AWS_SECRET`, `FAKE_SESSION_TOKEN`, or the raw malformed JSON.

- [ ] **Step 2: Run the test and confirm it fails**

```bash
make -C test/tap/tests/unit aws_iam_policy_unit-t
./test/tap/tests/unit/aws_iam_policy_unit-t
```

Expected: compilation fails because `MySQL_Backend_Auth.h` and its symbols do not exist.

- [ ] **Step 3: Implement the parser and centralized backend lookup**

Use nlohmann/json with non-throwing parse or a caught `json::exception`. Duplicate only `attributes` during `lookup`, call `free_account_details()` on every path, and treat a missing backend account as invalid. Do not inspect the frontend account's attributes or password.

In `MySQL_Authentication::add()`, after the backend row is parsed for a runtime load, emit one warning when that row resolves to IAM and has a non-empty password. Include only the username and the instruction to clear the unused backend password; never print the password. Do not warn from the per-connection resolver, which would flood logs.

Compile this file unconditionally so an SDK-free binary still recognizes an IAM policy and can reject it explicitly later.

- [ ] **Step 4: Run the focused test**

```bash
make -C lib -j2
make -C test/tap/tests/unit aws_iam_policy_unit-t
./test/tap/tests/unit/aws_iam_policy_unit-t
```

Expected: all TAP assertions pass.

- [ ] **Step 5: Commit the policy model**

```bash
git add include/MySQL_Backend_Auth.h lib/MySQL_Backend_Auth.cpp lib/MySQL_Authentication.cpp lib/Makefile \
  test/tap/tests/unit/aws_iam_policy_unit-t.cpp test/tap/tests/unit/Makefile
git commit -m "feat(mysql): parse backend IAM authentication policy"
```

### Task 2: Normalize hostgroup region and validate IAM connection tuples

**Files:**

- Modify: `include/Base_HostGroups_Manager.h`
- Modify: `lib/BaseHGC.cpp`
- Modify: `lib/MySQL_HostGroups_Manager.cpp`
- Create: `include/Aws_Iam_Types.h`
- Modify: `include/MySQL_Backend_Auth.h`
- Modify: `lib/MySQL_Backend_Auth.cpp`
- Create: `test/tap/tests/unit/aws_iam_connection_config_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/tests/test_mysql_hostgroup_attributes-1-t.cpp`
- Modify: `test/tap/tests/mysql_hostgroup_attributes_config_file-t.cpp`
- Modify: `test/tap/tests/test_cluster_sync-t.cpp`

**Interfaces:**

- Add `char* aws_iam_region` to `BaseHGC::attributes`; initialize, free, and reset it with the existing attribute strings.
- Define the cache/configuration key in `Aws_Iam_Types.h` so validation, the token manager, connection code, and tests share one SDK-independent type:

```cpp
struct AwsIamTokenKey {
    std::string endpoint;
    uint16_t port;
    std::string region;
    std::string database_user;
    bool operator==(const AwsIamTokenKey&) const;
};
```

- Add:

```cpp
enum class AwsIamConnectionConfigStatus : uint8_t {
    OK,
    SUPPORT_NOT_COMPILED,
    MISSING_REGION,
    REGION_ENDPOINT_MISMATCH,
    INVALID_ENDPOINT,
    UNIX_SOCKET_NOT_ALLOWED,
    TLS_REQUIRED,
    CA_TRUST_REQUIRED,
};

struct AwsIamConnectionConfigInput {
    std::string database_user;
    std::string configured_endpoint;
    uint16_t port;
    std::string region;
    bool use_ssl;
    std::string ssl_ca;
    std::string ssl_capath;
    bool support_compiled;
};

struct AwsIamConnectionConfigResult {
    AwsIamConnectionConfigStatus status;
    AwsIamTokenKey key;
    std::string failure_code;
};

AwsIamConnectionConfigResult validate_mysql_aws_iam_connection(
    const AwsIamConnectionConfigInput& input);
```

- Real endpoints must be DNS names with a recognized partition suffix: `.rds.amazonaws.com`, `.rds.amazonaws.com.cn`, `.rds.c2s.ic.gov`, or `.rds.sc2s.sgov.gov`. The DNS label immediately before `.rds` must equal `aws_iam_region`. Reject IPv4, IPv6, empty host, a trailing dot, Unix sockets (`port == 0`), and custom CNAMEs.

- [ ] **Step 1: Write the failing hostgroup and tuple tests**

Test valid RDS instance, Aurora cluster, reader, custom-cluster, China, GovCloud, ISO, and ISOB endpoint shapes. Test every enum failure independently, including endpoint/region mismatch, `use_ssl=0`, missing both CA fields, port zero, IP literals, and a custom CNAME.

Extend the hostgroup TAP tests to load, save, reload, and cluster-sync:

```json
{"aws_iam_region":"us-east-1"}
```

and to reject non-string, empty, and whitespace-containing values without retaining a previous region.

- [ ] **Step 2: Confirm the tests fail**

```bash
make -C test/tap/tests/unit aws_iam_connection_config_unit-t
./test/tap/tests/unit/aws_iam_connection_config_unit-t
```

Expected: compilation fails because the config types and hostgroup field do not exist.

- [ ] **Step 3: Parse and own the region in active MySQL hostgroup code**

Update `init_myhgc_hostgroup_settings()` in `lib/MySQL_HostGroups_Manager.cpp`, not the disabled MySQL implementation under `#if 0` in `lib/Base_HostGroups_Manager.cpp`. Accept only a non-empty JSON string whose bytes are ASCII letters, digits, and hyphens; store a duplicate on `MyHGC::attributes.aws_iam_region`. Log hostgroup ID and the redacted field error, never the complete JSON document.

- [ ] **Step 4: Implement pure tuple validation**

Perform checks in this order so the failure code is deterministic: support, region, port, endpoint syntax/suffix, endpoint-region equality, TLS, CA. On success populate the exact token key `(configured_endpoint, port, region, database_user)`.

- [ ] **Step 5: Run focused and persistence tests**

```bash
make -C lib -j2
make -C test/tap/tests/unit aws_iam_connection_config_unit-t
./test/tap/tests/unit/aws_iam_connection_config_unit-t
make -C test/tap/tests test_mysql_hostgroup_attributes-1-t mysql_hostgroup_attributes_config_file-t test_cluster_sync-t
```

Expected: unit assertions pass; integration binaries build. Run the three integration binaries in the standard TAP environment and confirm their new region round-trip assertions pass.

- [ ] **Step 6: Commit connection configuration**

```bash
git add include/Base_HostGroups_Manager.h lib/BaseHGC.cpp lib/MySQL_HostGroups_Manager.cpp \
  include/Aws_Iam_Types.h \
  include/MySQL_Backend_Auth.h lib/MySQL_Backend_Auth.cpp \
  test/tap/tests/unit/aws_iam_connection_config_unit-t.cpp test/tap/tests/unit/Makefile \
  test/tap/tests/test_mysql_hostgroup_attributes-1-t.cpp \
  test/tap/tests/mysql_hostgroup_attributes_config_file-t.cpp test/tap/tests/test_cluster_sync-t.cpp
git commit -m "feat(mysql): validate IAM backend connection configuration"
```

### Task 3: Implement secure token values and the bounded token manager

**Files:**

- Create: `include/Aws_Iam_Token_Manager.h`
- Create: `lib/Aws_Iam_Token_Manager.cpp`
- Create: `test/tap/tests/unit/aws_iam_token_manager_unit-t.cpp`
- Modify: `lib/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

```cpp
class SecureString {
public:
    using CleanseFn = void (*)(void*, size_t);
    SecureString();
    explicit SecureString(std::string_view, CleanseFn = OPENSSL_cleanse);
    SecureString(SecureString&&) noexcept;
    SecureString& operator=(SecureString&&) noexcept;
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;
    ~SecureString();
    SecureString clone() const;
    const char* c_str() const;
    size_t size() const;
    bool empty() const;
    void clear();
};

enum class AwsIamStatus : uint8_t {
    OK,
    SUPPORT_NOT_COMPILED,
    INVALID_CONFIG,
    PROVIDER_ERROR,
    CREDENTIAL_PROVIDER_ERROR,
    QUEUE_FULL,
    WAITER_LIMIT,
    TIMEOUT,
    CANCELED,
    SHUTDOWN,
};

struct AwsIamRedactedFailure {
    std::string category;
    std::string aws_error_code;
    std::string request_id;
};

struct AwsIamTokenResult {
    AwsIamStatus status;
    SecureString token;
    std::chrono::steady_clock::time_point expires_at;
    uint64_t generation;
    AwsIamRedactedFailure failure;
};

struct AwsIamSignResult {
    AwsIamStatus status;
    SecureString token;
    AwsIamRedactedFailure failure;
};

class AwsIamTokenSigner {
public:
    virtual AwsIamSignResult sign(const AwsIamTokenKey&) = 0;
    virtual ~AwsIamTokenSigner() = default;
};

struct AwsIamCompletion {
    uint64_t opaque_id;
    AwsIamTokenResult result;
};

class AwsIamCompletionSink {
public:
    virtual void post(AwsIamCompletion&&) = 0;
    virtual ~AwsIamCompletionSink() = default;
};

struct AwsIamRequestHandle { uint64_t value; };

struct AwsIamStatsSnapshot {
    uint64_t token_requests;
    uint64_t token_cache_hits;
    uint64_t token_refresh_successes;
    uint64_t token_refresh_failures;
    uint64_t credential_provider_failures;
    uint64_t queue_rejections;
    uint64_t backend_connection_successes;
    uint64_t backend_connection_failures;
    uint64_t token_cache_entries;
    uint64_t in_flight_generations;
    uint64_t queued_generations;
    uint64_t waiting_sessions;
};

class AwsIamTokenSource {
public:
    virtual AwsIamRequestHandle request(
        const AwsIamTokenKey&, uint64_t opaque_id,
        std::weak_ptr<AwsIamCompletionSink>) = 0;
    virtual AwsIamTokenResult request_blocking(
        const AwsIamTokenKey&, std::chrono::steady_clock::time_point deadline) = 0;
    virtual void cancel(AwsIamRequestHandle) = 0;
    virtual void invalidate(const AwsIamTokenKey&, uint64_t generation) = 0;
    virtual void record_backend_connection(bool success) = 0;
    virtual AwsIamStatsSnapshot snapshot() const = 0;
    virtual ~AwsIamTokenSource() = default;
};
```

`AwsIamTokenManagerConfig` defaults to two workers, 1,024 pending distinct keys, a two-minute minimum remaining lifetime, a 15-minute generated lifetime, and constructor-supplied total/per-key waiter ceilings no larger than `mysql-max_connections`. It also accepts a monotonic clock and deterministic jitter source for tests.

- [ ] **Step 1: Write deterministic failing tests with a fake signer and clock**

Cover:

- all four key fields partition the cache;
- hit at more than two minutes remaining and refresh at exactly two minutes;
- 15-minute expiry uses the monotonic generation point;
- 100 concurrent same-key requests produce one signer call and distinct move-only result buffers;
- 1,025 distinct misses reject the last request when the first 1,024 remain pending;
- per-key and total waiter caps reject without growing the completion list;
- cancel-before-sign, cancel-during-sign, late completion, blocking timeout, and shutdown;
- conditional invalidation does not remove a newer generation;
- LRU eviction cleanses the evicted entry;
- provider failure uses bounded exponential backoff with deterministic jitter and later recovers;
- custom `CleanseFn` observes zeroed bytes on clear, move assignment, replacement, and destruction;
- fake secrets never appear in failure objects.

- [ ] **Step 2: Confirm the token-manager test fails**

```bash
make -C test/tap/tests/unit aws_iam_token_manager_unit-t
./test/tap/tests/unit/aws_iam_token_manager_unit-t
```

Expected: compilation fails because the manager interfaces do not exist.

- [ ] **Step 3: Implement the smallest thread-safe manager**

Use one mutex for cache/in-flight/waiter bookkeeping and a condition variable for the two signing workers. Queue one job per distinct key after coalescing. Never call a signer or completion sink while holding the manager mutex. Clone a successful token separately for the cache and every live waiter, erase canceled waiters, and cleanse results whose weak sink expired.

Store only redacted failure category/code/request ID. Do not retain SDK exception messages. Bound exponential backoff at five seconds and clear a key's backoff after a successful generation.

- [ ] **Step 4: Run the unit test repeatedly and under TSan**

```bash
make -C lib -j2
make -C test/tap/tests/unit aws_iam_token_manager_unit-t
for run in 1 2 3 4 5; do ./test/tap/tests/unit/aws_iam_token_manager_unit-t; done
make clean
NOJEMALLOC=1 WITHTSAN=1 make build_deps_debug -j2
NOJEMALLOC=1 WITHTSAN=1 make build_lib_debug -j2
NOJEMALLOC=1 WITHTSAN=1 make -C test/tap/tests/unit aws_iam_token_manager_unit-t
TSAN_OPTIONS=halt_on_error=1 ./test/tap/tests/unit/aws_iam_token_manager_unit-t
```

Expected: every TAP run passes and TSan reports no race.

- [ ] **Step 5: Commit the token manager**

```bash
git add include/Aws_Iam_Token_Manager.h lib/Aws_Iam_Token_Manager.cpp lib/Makefile \
  test/tap/tests/unit/aws_iam_token_manager_unit-t.cpp test/tap/tests/unit/Makefile
git commit -m "feat(mysql): add bounded IAM token manager"
```

### Task 4: Add optional AWS SDK discovery, signer, and process lifetime

**Files:**

- Create: `cmake/aws-sdk-cpp/CMakeLists.txt`
- Create: `common_mk/aws_sdk_cpp_flags.mk`
- Create: `include/Aws_Iam_Sdk.h`
- Create: `lib/Aws_Iam_Sdk.cpp`
- Create: `test/infra/control/check-aws-iam-build-gate.bash`
- Modify: `.gitignore`
- Modify: `Makefile`
- Modify: `include/makefiles_paths.mk`
- Modify: `lib/Makefile`
- Modify: `src/Makefile`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `src/main.cpp`
- Modify: `test/tap/test_helpers/test_globals.cpp`

**Interfaces:**

```cpp
struct AwsIamRuntimeConfig {
    size_t max_total_waiters;
    size_t max_waiters_per_key;
};

std::unique_ptr<AwsIamTokenSource> create_aws_iam_token_source(
    const AwsIamRuntimeConfig& config);

extern AwsIamTokenSource* GloAwsIamTokenSource;
```

- With `PROXYSQLAWSIAM` unset, the factory returns a no-thread source whose requests produce `SUPPORT_NOT_COMPILED`.
- With `PROXYSQLAWSIAM=1`, the factory owns exactly one `Aws::SDKOptions`, calls `Aws::InitAPI()` before constructing a standard-chain `Aws::RDS::RDSClient`, and calls `Aws::ShutdownAPI()` only after the manager workers and regional clients are destroyed.
- The signer calls exactly:

```cpp
rds_client.GenerateConnectAuthToken(
    key.endpoint.c_str(), key.region.c_str(), key.port,
    key.database_user.c_str());
```

An empty returned token is `CREDENTIAL_PROVIDER_ERROR`; the adapter copies no AWS credential fields into its result.

- [ ] **Step 1: Write the failing build-gate test**

`check-aws-iam-build-gate.bash` must perform these assertions, and must use a trap to remove every temporary directory it creates:

```bash
make -C lib clean
make -C lib -j2
! nm -C lib/libproxysql.a | grep -q 'Aws::'

fake_root=$(mktemp -d)
if PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$fake_root" make -C lib 2>"$fake_root/error"; then
  exit 1
fi
grep -F 'AWS SDK for C++ 1.9 or newer with core and rds is required' "$fake_root/error"
```

When a real SDK is supplied through `AWS_SDK_CPP_ROOT`, it additionally checks that generated flags contain `aws-cpp-sdk-rds`, `aws-cpp-sdk-core`, and the discovered SDK version, but no service library such as S3, STS, EC2, or Secrets Manager.

- [ ] **Step 2: Confirm the build-gate test fails**

```bash
bash test/infra/control/check-aws-iam-build-gate.bash
```

Expected: FAIL because the feature gate and discovery error do not exist.

- [ ] **Step 3: Implement CMake metadata discovery**

`cmake/aws-sdk-cpp/CMakeLists.txt` must:

```cmake
cmake_minimum_required(VERSION 3.13)
project(proxysql_aws_sdk_discovery LANGUAGES NONE)
find_package(AWSSDK 1.9 REQUIRED COMPONENTS core rds)
```

Create its parent once before applying the new file:

```bash
mkdir -p cmake/aws-sdk-cpp
```

Generate `build/aws-sdk-cpp/aws-sdk-cpp.mk` atomically with quoted `AWS_IAM_CPPFLAGS`, `AWS_IAM_LDFLAGS`, `AWS_IAM_LIBS`, `AWS_IAM_SDK_VERSION`, and `AWS_IAM_SDK_SHARED`. Use `${AWSSDK_INCLUDE_DIRS}` and `${AWSSDK_LIB_DIR}` from the package. Clear the macro's scratch list and call `AWSSDK_DETERMINE_LIBS_TO_LINK()` for the `core;rds` component list so a static-only system install retains the ordered common-runtime and platform dependencies; use `${AWSSDK_LINK_LIBRARIES}` for a shared install. `common_mk/aws_sdk_cpp_flags.mk` remakes and includes this fragment only when `PROXYSQLAWSIAM=1`; pass `AWS_SDK_CPP_ROOT` as `CMAKE_PREFIX_PATH`. Ignore only `build/aws-sdk-cpp/` in `.gitignore`.

Export `PROXYSQLAWSIAM` at the top level. Append `-DPROXYSQLAWSIAM` and discovered includes to `lib`, `src`, and unit-test compile flags, and append discovered dynamic link flags after ProxySQL's `-Wl,-Bdynamic` section.

- [ ] **Step 4: Implement SDK-on and SDK-off factories**

Keep every AWS include inside `#ifdef PROXYSQLAWSIAM` in `lib/Aws_Iam_Sdk.cpp`. Create one default-credential-chain RDS client per region lazily under a mutex. The no-SDK branch must compile with no AWS headers and create no worker thread.

- [ ] **Step 5: Wire process initialization and shutdown**

Initialize the global token source after daemonization and the MySQL authentication module, but before `MySQL_Threads_Handler` starts worker threads. Set both waiter limits from the runtime `mysql-max_connections` value. During shutdown, stop/join MySQL workers first, then destroy the source so all completion inboxes are closed before `Aws::ShutdownAPI()`.

Update `test/tap/test_helpers/test_globals.cpp` with the null global used by isolated unit binaries.

- [ ] **Step 6: Verify feature-off, deliberate failure, and feature-on builds**

```bash
bash test/infra/control/check-aws-iam-build-gate.bash
make clean
make build_deps -j2
make build_src -j2
ldd src/proxysql | grep -v aws-cpp-sdk
PROXYSQLAWSIAM=1 make build_src -j2
ldd src/proxysql | grep -E 'aws-cpp-sdk-(rds|core)'
```

Expected: the default binary has no AWS dependency; the fake root fails with the exact diagnostic; on a prepared SDK host the feature binary lists `rds` and `core` and no unrelated AWS service DSO. If the system package is installed under a nonstandard prefix, set `AWS_SDK_CPP_ROOT` to that package's installation prefix, never to a repository-local SDK copy.

- [ ] **Step 7: Commit the build gate and adapter**

```bash
git add .gitignore Makefile include/makefiles_paths.mk cmake/aws-sdk-cpp/CMakeLists.txt \
  common_mk/aws_sdk_cpp_flags.mk include/Aws_Iam_Sdk.h lib/Aws_Iam_Sdk.cpp \
  lib/Makefile src/Makefile src/main.cpp test/tap/tests/unit/Makefile \
  test/tap/test_helpers/test_globals.cpp test/infra/control/check-aws-iam-build-gate.bash
git commit -m "build: add optional AWS IAM SDK adapter"
```

### Task 5: Separate MariaDB Connector/C network and TLS names

**Files:**

- Create: `deps/mariadb-client-library/tls_server_name.patch`
- Modify: `deps/Makefile`
- Create: `test/tap/tests/unit/mariadb_tls_server_name_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Add connector option `MARIADB_OPT_TLS_SERVER_NAME` accepting `const char*`.
- Add connector helper:

```c
const char *ma_tls_get_server_name(MYSQL *mysql);
```

It returns `options.extension->tls_server_name` when non-empty, otherwise `mysql->host`.

- [ ] **Step 1: Write the failing connector option test**

The unit test initializes `MYSQL`, sets `MARIADB_OPT_TLS_SERVER_NAME` to `db.cluster-abc.us-east-1.rds.amazonaws.com`, gets it back with `mysql_get_optionv`, asserts a copied value survives mutation of the caller buffer, and closes the handle. It also asserts an unset option falls back to the existing host behavior through `ma_tls_get_server_name()`.

- [ ] **Step 2: Confirm the test fails to compile**

```bash
make -C test/tap/tests/unit mariadb_tls_server_name_unit-t
```

Expected: compilation fails because the option and helper are undefined.

- [ ] **Step 3: Patch the bundled connector**

The patch must modify these upstream files after extraction:

```text
include/mysql.h
include/ma_common.h
include/ma_tls.h
libmariadb/ma_tls.c
libmariadb/mariadb_lib.c
libmariadb/secure/openssl.c
libmariadb/secure/gnutls.c
libmariadb/secure/ma_schannel.c
```

Add `char* tls_server_name` to `st_mysql_options_extension`; implement set/get using the connector's existing extended string macros; cleanse/free it in `mysql_options_free`; and replace hostname/SNI certificate uses in the listed TLS backends with `ma_tls_get_server_name(mysql)`. Do not change the address handed to `mysql_real_connect_start()`.

For OpenSSL, call `SSL_set_tlsext_host_name()` with the helper result before `SSL_connect()` and use the same value for `X509_check_host()`/CN fallback. For GnuTLS, call `gnutls_server_name_set()` before the handshake and use the same value in `gnutls_certificate_verify_peers3()`. For Schannel, use it in both `InitializeSecurityContext()` and `schannel_verify_server_certificate()`. If the option is unset, all three paths receive `mysql->host`, preserving current behavior.

Apply `tls_server_name.patch` in `deps/Makefile` immediately after `mysql.h.patch` and before building `mariadbclient`.

- [ ] **Step 4: Rebuild and test Connector/C**

```bash
make -C deps mariadb_client
make -C test/tap/tests/unit mariadb_tls_server_name_unit-t
./test/tap/tests/unit/mariadb_tls_server_name_unit-t
```

Expected: the connector builds and every option ownership/fallback assertion passes.

- [ ] **Step 5: Commit the connector extension**

```bash
git add deps/mariadb-client-library/tls_server_name.patch deps/Makefile \
  test/tap/tests/unit/mariadb_tls_server_name_unit-t.cpp test/tap/tests/unit/Makefile
git commit -m "deps: add MariaDB TLS server-name override"
```

### Task 6: Add ephemeral IAM handshake credentials to MySQL connections

**Files:**

- Modify: `include/mysql_connection.h`
- Modify: `lib/mysql_connection.cpp`
- Create: `test/tap/tests/unit/aws_iam_connection_secret_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

```cpp
struct MySQLAwsIamIdentity {
    AwsIamTokenKey key;
    uint64_t token_generation{0};
    uint8_t fresh_token_retries{0};
    SecureString handshake_token;
};

void MySQL_Connection::set_backend_auth_type(MySQLBackendAuthType);
MySQLBackendAuthType MySQL_Connection::backend_auth_type() const;
void MySQL_Connection::attach_aws_iam_token(
    const AwsIamTokenKey&, AwsIamTokenResult&&);
void MySQL_Connection::clear_aws_iam_handshake_secret();
bool MySQL_Connection::has_aws_iam_handshake_secret() const;
```

- [ ] **Step 1: Write failing connection-secret tests**

Assert that IAM mode:

- uses the attached token instead of `userinfo->password` in `connect_start()`;
- passes the configured endpoint to `MARIADB_OPT_TLS_SERVER_NAME` while `mysql_real_connect_start()` still receives the DNS-cache IP;
- enables SSL enforce, server certificate verification, and cleartext plugin;
- rejects a Unix socket before connector startup;
- supports a token longer than 1 KiB without truncation;
- cleanses the ProxySQL buffer and `MYSQL::passwd` after terminal success, terminal error, timeout, explicit clear, and destructor;
- never changes the frontend connection's `userinfo->password`.

Instrument connector calls through the existing unit-test seam or a link-time fake; do not add production test-only environment variables.

- [ ] **Step 2: Confirm the test fails**

```bash
make -C test/tap/tests/unit aws_iam_connection_secret_unit-t
./test/tap/tests/unit/aws_iam_connection_secret_unit-t
```

Expected: compilation fails because the identity and credential methods do not exist.

- [ ] **Step 3: Implement handshake-only credential ownership**

Store the authentication mode independently of `userinfo`. In IAM mode choose `handshake_token.c_str()` as `auth_password`, set all three connector options, and set the verification name before `mysql_real_connect_start()`. Preserve existing password/sha1/ed25519 behavior byte-for-byte in password mode.

At `ASYNC_CONNECT_END`, `ASYNC_CONNECT_TIMEOUT`, and destruction, call one idempotent cleanup routine. When `mysql->passwd` is non-null, call `OPENSSL_cleanse(mysql->passwd, strlen(mysql->passwd))`, call `free(mysql->passwd)`, then set it to null so Connector/C cannot double-free it. Never enable connector auto-reconnect for an IAM connection.

- [ ] **Step 4: Run focused tests under ASan**

```bash
make -C lib -j2
make -C test/tap/tests/unit aws_iam_connection_secret_unit-t
./test/tap/tests/unit/aws_iam_connection_secret_unit-t
make clean
NOJEMALLOC=1 WITHASAN=1 make build_deps_debug -j2
NOJEMALLOC=1 WITHASAN=1 make build_lib_debug -j2
NOJEMALLOC=1 WITHASAN=1 make -C test/tap/tests/unit aws_iam_connection_secret_unit-t
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ./test/tap/tests/unit/aws_iam_connection_secret_unit-t
```

Expected: TAP passes; ASan reports no leak, double free, or use-after-free.

- [ ] **Step 5: Commit ephemeral connection credentials**

```bash
git add include/mysql_connection.h lib/mysql_connection.cpp \
  test/tap/tests/unit/aws_iam_connection_secret_unit-t.cpp test/tap/tests/unit/Makefile
git commit -m "feat(mysql): attach ephemeral IAM handshake tokens"
```

### Task 7: Add the worker completion inbox and waiting session state

**Files:**

- Modify: `include/proxysql_structs.h`
- Modify: `include/MySQL_Thread.h`
- Modify: `lib/MySQL_Thread.cpp`
- Modify: `include/MySQL_Session.h`
- Modify: `lib/MySQL_Session.cpp`
- Create: `test/tap/tests/unit/aws_iam_completion_queue_unit-t.cpp`
- Create: `test/tap/tests/unit/aws_iam_session_state_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Add `WAITING_AWS_IAM_TOKEN` immediately after `AUTHENTICATING_BACKEND_FOR_CLIENT` in `session_status`.
- Add a shared, independently lived `AwsIamWorkerInbox : AwsIamCompletionSink` containing only a mutex, bounded deque, closed flag, and an owned `dup()` of the worker's write-pipe FD. It must never contain a session or connection pointer. `close()` marks the inbox closed under its mutex, closes the duplicate exactly once, and causes later posts to cleanse/drop their result.
- Add owner-thread methods:

```cpp
uint64_t MySQL_Thread::register_aws_iam_waiter(MySQL_Session*);
void MySQL_Thread::cancel_aws_iam_waiter(uint64_t opaque_id);
void MySQL_Thread::drain_aws_iam_completions();

int MySQL_Session::handler_again___status_WAITING_AWS_IAM_TOKEN();
void MySQL_Session::cancel_aws_iam_wait();
```

`MySQL_Thread` owns `unordered_map<uint64_t, MySQL_Session*> aws_iam_waiters`; only the worker reads or writes it. Provider threads see only `opaque_id` and a weak inbox.

- [ ] **Step 1: Write failing inbox tests**

Test multi-producer posting, one pipe wake for a transition from empty to non-empty, bounded overflow cleansing, close-then-late-post cleansing, FIFO drain, and destruction while producers hold expired weak pointers. Run the producer test 100 times.

- [ ] **Step 2: Write failing state-machine tests with a fake source**

Cover cache-hit completion, delayed completion, provider error, queue rejection, five-second deadline, existing backend-acquisition deadline winning first, frontend disconnect while waiting, late completion, shutdown, and selected-server retention. Assert the selected fresh connection remains attached from request through connect and no alternate server is chosen after completion.

- [ ] **Step 3: Confirm both tests fail**

```bash
make -C test/tap/tests/unit aws_iam_completion_queue_unit-t aws_iam_session_state_unit-t
./test/tap/tests/unit/aws_iam_completion_queue_unit-t
./test/tap/tests/unit/aws_iam_session_state_unit-t
```

Expected: compilation fails because the inbox and state are absent.

- [ ] **Step 4: Implement owner-worker completion delivery**

Drain the completion inbox after consuming the existing control pipe and before `process_all_sessions()`. For each completion, erase and look up `opaque_id` in the worker map; if absent, cleanse/drop. If present, move the result into the session and let the session handler validate state before resuming.

On session teardown, timeout, or state abandonment: erase the owner map entry, call `GloAwsIamTokenSource->cancel(handle)`, destroy the held fresh connection, and clear result material. Close the inbox only after canceling its registered waiters.

- [ ] **Step 5: Integrate fresh connection acquisition**

At the start of `handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection()`, resolve the mapped backend policy before local/global pool lookup. Password mode follows the existing path. Invalid mode sends the generic backend connection error. IAM mode may reuse a compatible established connection; for a fresh `fd == -1` connection, retain it, validate the concrete tuple, register the waiter, request the token, push the current resume state, and enter `WAITING_AWS_IAM_TOKEN` instead of calling `myconn->handler(0)`.

On success, attach the moved token and enter the existing `CONNECTING_SERVER` path. On failure, report the generic client error and log only username, hostgroup, configured endpoint, region, failure category/code/request ID.

- [ ] **Step 6: Run state tests under TSan**

```bash
make -C lib -j2
make -C test/tap/tests/unit aws_iam_completion_queue_unit-t aws_iam_session_state_unit-t
./test/tap/tests/unit/aws_iam_completion_queue_unit-t
./test/tap/tests/unit/aws_iam_session_state_unit-t
NOJEMALLOC=1 WITHTSAN=1 make -C test/tap/tests/unit aws_iam_completion_queue_unit-t
TSAN_OPTIONS=halt_on_error=1 ./test/tap/tests/unit/aws_iam_completion_queue_unit-t
```

Expected: all TAP assertions pass and TSan is clean.

- [ ] **Step 7: Commit asynchronous session integration**

```bash
git add include/proxysql_structs.h include/MySQL_Thread.h lib/MySQL_Thread.cpp \
  include/MySQL_Session.h lib/MySQL_Session.cpp \
  test/tap/tests/unit/aws_iam_completion_queue_unit-t.cpp \
  test/tap/tests/unit/aws_iam_session_state_unit-t.cpp test/tap/tests/unit/Makefile
git commit -m "feat(mysql): wait asynchronously for IAM backend tokens"
```

### Task 8: Make authentication mode part of pool identity and forbid IAM reset/change-user

**Files:**

- Modify: `include/mysql_connection.h`
- Modify: `lib/mysql_connection.cpp`
- Modify: `lib/MySrvConnList.cpp`
- Modify: `lib/MySQL_Thread.cpp`
- Modify: `lib/MySQL_HostGroups_Manager.cpp`
- Modify: `lib/MySQL_Session.cpp`
- Modify: `test/tap/tests/unit/connection_pool_unit-t.cpp`
- Create: `test/tap/tests/unit/aws_iam_pool_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

```cpp
bool MySQL_Connection::backend_auth_compatible(
    const char* requested_username,
    MySQLBackendAuthType requested_type) const;

bool MySQL_Connection::requires_CHANGE_USER(
    const MySQL_Connection* client_conn,
    MySQLBackendAuthType requested_type) const;
```

- [ ] **Step 1: Write failing pool identity tests**

Create established connections with the matrix `(same/different username) x (PASSWORD/AWS_IAM)` and assert only exact username+mode matches are reusable. Advance the fake clock beyond 15 minutes and assert an already established IAM connection remains reusable. Switch the backend policy at runtime in both directions and assert old-mode pool entries are skipped and lazily destroyed.

Test that an IAM connection selected for `CHANGING_USER_SERVER`, `RESETTING_CONNECTION`, reset queue processing, or `destroy_MyConn_from_pool()` is destroyed and replaced by a fresh connection rather than invoking `mysql_change_user`.

- [ ] **Step 2: Confirm pool tests fail**

```bash
make -C test/tap/tests/unit connection_pool_unit-t aws_iam_pool_unit-t
./test/tap/tests/unit/aws_iam_pool_unit-t
```

Expected: at least the cross-mode reuse and reset assertions fail.

- [ ] **Step 3: Thread the requested mode through local and global pool selection**

Pass the session's resolved policy to `MySQL_Thread::get_MyConn_local()` and `MySrvConnList::get_random_MyConn()`. Reject and lazy-destroy a candidate whose recorded mode differs. Preserve the existing session-variable scoring after the mode check.

When runtime users reload, do not synchronously scan every live connection. The next checkout observes the new resolved policy and drains mismatches; idle reset processing must also delete IAM entries instead of change-user reset.

- [ ] **Step 4: Short-circuit reset and change-user states**

Before `async_change_user`, detect if the current or requested identity is IAM. Destroy the backend and return through the fresh acquisition path. Apply the same rule to same-user resets. Add assertions in the IAM branch so future code cannot call `change_user_start()` with a cleared IAM credential.

- [ ] **Step 5: Run focused and existing pool regressions**

```bash
make -C lib -j2
make -C test/tap/tests/unit connection_pool_unit-t aws_iam_pool_unit-t
./test/tap/tests/unit/connection_pool_unit-t
./test/tap/tests/unit/aws_iam_pool_unit-t
make -C test/tap/tests test_passthrough_auth_pool_reuse-t reg_test_3504-change_user-t
```

Expected: all unit tests pass and existing pass-through/change-user binaries build and pass in their normal TAP environment.

- [ ] **Step 6: Commit pool behavior**

```bash
git add include/mysql_connection.h lib/mysql_connection.cpp lib/MySrvConnList.cpp \
  lib/MySQL_Thread.cpp lib/MySQL_HostGroups_Manager.cpp lib/MySQL_Session.cpp \
  test/tap/tests/unit/connection_pool_unit-t.cpp \
  test/tap/tests/unit/aws_iam_pool_unit-t.cpp test/tap/tests/unit/Makefile
git commit -m "feat(mysql): isolate IAM connections in backend pools"
```

### Task 9: Implement IAM-specific 1045 retry and detached kill connections

**Files:**

- Modify: `include/MySQL_Session.h`
- Modify: `lib/MySQL_Session.cpp`
- Create: `test/tap/tests/unit/aws_iam_failure_unit-t.cpp`
- Create: `test/tap/tests/unit/aws_iam_kill_helper_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Extend `KillArgs` with `MySQLBackendAuthType`, configured endpoint, region, and database user. Do not populate its password field for IAM mode.
- Add one per-acquisition IAM retry flag and preserve the failed connection's exact `AwsIamTokenKey` plus generation until invalidation is decided.

- [ ] **Step 1: Write failing retry/redaction tests**

Feed `handler_again___status_CONNECTING_SERVER()` these outcomes:

```text
IAM 1045, first generated token     -> conditional invalidate + one new-token retry
IAM 1045, retry token               -> generic failure, no third attempt
IAM 1045 from generation N after N+1 cached -> N+1 remains cached
IAM TLS/transport error             -> no token invalidation
password-mode 1045                  -> existing retry/error behavior unchanged
```

Assert the client error does not contain endpoint, region, AWS code, backend MySQL text, token, access key, or session token. Assert the operator diagnostic contains only username, hostgroup, endpoint, region, redacted category, AWS error code/request ID, and a clock-skew hint on the repeated fresh-token 1045.

- [ ] **Step 2: Write failing kill-helper tests**

Use a fake blocking token source and link-time connector fake to prove query kill and connection kill obtain their own current token, enforce TLS/hostname verification, do not reuse the original handshake token, respect the helper deadline, and cleanse all copies. Verify password-mode helpers are unchanged.

- [ ] **Step 3: Confirm both tests fail**

```bash
make -C test/tap/tests/unit aws_iam_failure_unit-t aws_iam_kill_helper_unit-t
./test/tap/tests/unit/aws_iam_failure_unit-t
./test/tap/tests/unit/aws_iam_kill_helper_unit-t
```

Expected: the IAM retry and helper assertions fail.

- [ ] **Step 4: Add the bounded 1045 branch before generic connect retries**

In the terminal connect failure branch, handle IAM before the normal retry loop. Capture errno before cleanup. For the first 1045, call `invalidate(key, generation)`, destroy the failed connection, set the one-retry flag, and re-enter acquisition with normal multi-server retry budget disabled for this IAM retry. For all other IAM failures, send error 9002/`HY000` with a fixed generic message and destroy the connection. Never pass `mysql_error()` to the client in IAM mode.

- [ ] **Step 5: Resolve kill-helper policy inside the detached helper**

Construct `KillArgs` from mode metadata without a token. In `kill_query_thread()`, IAM mode builds the same validated key, calls `request_blocking()` with the helper deadline, configures the connector exactly like a normal IAM connection, connects, issues `KILL`, and cleanses the result and `MYSQL::passwd`. Token waits remain in the already-detached helper thread, never the MySQL worker.

- [ ] **Step 6: Run focused failure tests**

```bash
make -C lib -j2
make -C test/tap/tests/unit aws_iam_failure_unit-t aws_iam_kill_helper_unit-t
./test/tap/tests/unit/aws_iam_failure_unit-t
./test/tap/tests/unit/aws_iam_kill_helper_unit-t
```

Expected: all retry ceiling, conditional invalidation, helper, and redaction assertions pass.

- [ ] **Step 7: Commit failure and auxiliary paths**

```bash
git add include/MySQL_Session.h lib/MySQL_Session.cpp \
  test/tap/tests/unit/aws_iam_failure_unit-t.cpp \
  test/tap/tests/unit/aws_iam_kill_helper_unit-t.cpp test/tap/tests/unit/Makefile
git commit -m "feat(mysql): bound IAM auth retries and kill helpers"
```

### Task 10: Export fixed IAM stats and Prometheus metrics

**Files:**

- Modify: `include/Aws_Iam_Token_Manager.h`
- Modify: `lib/Aws_Iam_Token_Manager.cpp`
- Modify: `lib/ProxySQL_Admin_Stats.cpp`
- Modify: `lib/MySQL_Session.cpp`
- Create: `test/tap/tests/test_aws_iam_metrics-t.cpp`
- Modify: `test/tap/tests/Makefile`

**Interfaces:**

The public `stats_mysql_global` names are exactly:

```text
AwsIam_Token_requests
AwsIam_Token_cache_hits
AwsIam_Token_refresh_successes
AwsIam_Token_refresh_failures
AwsIam_Credential_provider_failures
AwsIam_Queue_rejections
AwsIam_Backend_connection_successes
AwsIam_Backend_connection_failures
AwsIam_Token_cache_entries
AwsIam_In_flight_generations
AwsIam_Queued_generations
AwsIam_Waiting_sessions
```

Prometheus metric names are exactly:

```text
proxysql_mysql_aws_iam_token_requests_total
proxysql_mysql_aws_iam_token_cache_hits_total
proxysql_mysql_aws_iam_token_refresh_successes_total
proxysql_mysql_aws_iam_token_refresh_failures_total
proxysql_mysql_aws_iam_credential_provider_failures_total
proxysql_mysql_aws_iam_queue_rejections_total
proxysql_mysql_aws_iam_backend_connection_successes_total
proxysql_mysql_aws_iam_backend_connection_failures_total
proxysql_mysql_aws_iam_token_cache_entries
proxysql_mysql_aws_iam_in_flight_generations
proxysql_mysql_aws_iam_queued_generations
proxysql_mysql_aws_iam_waiting_sessions
```

No metric has labels.

- [ ] **Step 1: Write the failing metrics test**

The TAP test injects a fake source, drives one miss/success, one hit, one refresh failure, one credential-provider failure, one queue rejection, one backend success, and one backend failure. It queries `stats_mysql_global` and `/metrics`, checks exact values/names, checks all gauges return to zero after cleanup, and rejects username, endpoint, region, token, access key, or profile-name labels/text.

- [ ] **Step 2: Confirm it fails**

```bash
make -C test/tap/tests test_aws_iam_metrics-t
```

Expected: the binary or assertions fail because IAM monitoring rows do not exist.

- [ ] **Step 3: Register and update metrics**

Create the prometheus-cpp counter/gauge families once with the process registry during source initialization. Maintain counters atomically at the event sites and compute gauges from manager/session state. Append the snapshot rows in `ProxySQL_Admin::stats___mysql_global()` when the global source exists; the SDK-off stub returns zero rows with the same names so dashboards are build-independent.

- [ ] **Step 4: Run metrics tests and existing Prometheus regressions**

```bash
make -C lib -j2
make -C test/tap/tests test_aws_iam_metrics-t test_passthrough_auth_metrics-t test_prometheus_metrics-t
./test/tap/tests/test_aws_iam_metrics-t
```

Expected: IAM metric assertions pass in the test harness and existing metric names remain unchanged.

- [ ] **Step 5: Commit observability**

```bash
git add include/Aws_Iam_Token_Manager.h lib/Aws_Iam_Token_Manager.cpp \
  lib/ProxySQL_Admin_Stats.cpp lib/MySQL_Session.cpp \
  test/tap/tests/test_aws_iam_metrics-t.cpp test/tap/tests/Makefile
git commit -m "feat(stats): expose AWS IAM backend auth metrics"
```

### Task 11: Add controlled TLS/protocol and end-to-end regression coverage

**Files:**

- Create: `test/deps/aws_iam_mysql_server/Makefile`
- Create: `test/deps/aws_iam_mysql_server/aws_iam_mysql_server.cpp`
- Create: `test/tap/tests/test_aws_iam_backend_auth-t.cpp`
- Create: `test/tap/tests/test_aws_iam_backend_auth-t.env`
- Modify: `test/tap/tests/Makefile`
- Modify: `test/tap/tests/test_cluster_sync-t.cpp`

**Interfaces:**

- The controlled server accepts one MySQL connection, advertises `CLIENT_SSL` and `mysql_clear_password`, upgrades to TLS with test certificates, captures the clear-password payload only after `SSL_accept()`, and reports the observed username/token length through a local control pipe. It supports modes `success`, `access_denied`, `wrong_hostname`, `untrusted_ca`, `delay_handshake`, and `close_transport`.
- The server binds a loopback address while its certificate SAN and configured ProxySQL server name use `db.cluster-test.us-east-1.rds.amazonaws.com`; `/etc/hosts` or the test DNS seam resolves that name to loopback without configuring an alias as the ProxySQL endpoint.
- The end-to-end test runs an IAM-enabled ProxySQL binary with harmless, recognizable AWS credentials supplied through the SDK's normal environment provider. Token generation is local SigV4 signing; the controlled server captures but does not validate the signature. Unit tests from Tasks 3, 7, 8, and 9 continue to use the injected fake source and clock for timing, saturation, and exact-generation assertions.

- [ ] **Step 1: Write the failing end-to-end TAP test**

Start ProxySQL with `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` set to test-only values and with metadata access disabled. Cover:

- valid token is sent through `mysql_clear_password` only after TLS establishment;
- a 2 KiB token arrives byte-for-byte;
- socket connects to loopback while certificate verification uses the configured RDS hostname;
- `use_ssl=0`, no CA, wrong hostname, untrusted CA, IP endpoint, CNAME endpoint, wrong region, malformed policy, unknown policy, and SDK-off source fail before token transmission;
- ordinary password users never call the fake source and cleartext auth remains disabled;
- IAM and password users coexist in one hostgroup without cross-mode reuse;
- established IAM pool reuse, reset/change-user reconnect, the 1045 one-retry ceiling, and IAM kill helpers;
- a slow `credential_process` profile proves another ordinary client session remains responsive while the IAM request waits, then frontend disconnect and shutdown leave no live waiter;
- user attributes and hostgroup region survive save/load and cluster sync while token text never appears in cluster payloads.

- [ ] **Step 2: Confirm the protocol test fails**

```bash
make -C test/deps/aws_iam_mysql_server
make -C test/tap/tests test_aws_iam_backend_auth-t
./test/tap/tests/test_aws_iam_backend_auth-t
```

Expected: the test fails until the controlled server and complete session behavior are wired.

- [ ] **Step 3: Implement the minimal controlled server**

Create the source directory before adding files:

```bash
mkdir -p test/deps/aws_iam_mysql_server
```

Implement only this packet sequence: protocol-10 handshake, SSLRequest, TLS upgrade, auth-switch request for `mysql_clear_password`, NUL-terminated response capture, then OK or ERR 1045. Refuse/cancel if any non-TLS clear-password bytes arrive. Use repository test certificates generated by the existing test certificate helper and never commit a private key.

- [ ] **Step 4: Make all protocol and coexistence cases pass**

```bash
make -C test/deps/aws_iam_mysql_server clean all
make -C test/tap/tests test_aws_iam_backend_auth-t test_passthrough_auth_e2e-t test_passthrough_auth_pool_reuse-t
./test/tap/tests/test_aws_iam_backend_auth-t
```

Expected: every IAM assertion passes and both existing pass-through tests pass in the standard TAP environment.

- [ ] **Step 5: Run security tests under sanitizers**

```bash
make clean
NOJEMALLOC=1 WITHASAN=1 make build_deps_debug -j2
NOJEMALLOC=1 WITHASAN=1 make build_src_debug -j2
NOJEMALLOC=1 WITHASAN=1 make -C test/tap/tests test_aws_iam_backend_auth-t
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ./test/tap/tests/test_aws_iam_backend_auth-t

make clean
NOJEMALLOC=1 WITHTSAN=1 make build_deps_debug -j2
NOJEMALLOC=1 WITHTSAN=1 make build_src_debug -j2
NOJEMALLOC=1 WITHTSAN=1 make -C test/tap/tests test_aws_iam_backend_auth-t
TSAN_OPTIONS=halt_on_error=1 ./test/tap/tests/test_aws_iam_backend_auth-t
```

Expected: no ASan/LSan or TSan report.

- [ ] **Step 6: Commit protocol/regression coverage**

```bash
git add test/deps/aws_iam_mysql_server/Makefile \
  test/deps/aws_iam_mysql_server/aws_iam_mysql_server.cpp \
  test/tap/tests/test_aws_iam_backend_auth-t.cpp \
  test/tap/tests/test_aws_iam_backend_auth-t.env test/tap/tests/Makefile \
  test/tap/tests/test_cluster_sync-t.cpp
git commit -m "test(mysql): cover IAM backend authentication end to end"
```

### Task 12: Document operations, CI matrix, AWS integration, and release checks

**Files:**

- Create: `doc/aws_iam_database_authentication.md`
- Create: `test/infra/control/check-aws-iam-linkage.bash`
- Create: `.github/workflows/CI-aws-iam.yml`
- Modify: `doc/README.md`
- Modify: `docs/superpowers/specs/2026-08-12-aws-iam-database-auth-design.md`

**Interfaces:**

- CI has four jobs: default SDK-free build, AWS-enabled build with the distro's system `libaws-sdk-cpp-dev` package, deliberate missing-SDK failure, and fake-provider ASan/TSan tests. An opt-in job guarded by AWS integration secrets runs against a real IAM-enabled RDS/Aurora MySQL endpoint.
- `check-aws-iam-linkage.bash <binary>` exits zero for a shared release build only if `ldd`/`otool -L` shows `aws-cpp-sdk-rds` and `aws-cpp-sdk-core`, no unrelated AWS service DSO, and the generated discovery metadata reports AWS SDK 1.9+. For a static-only development host it instead verifies `AWS_IAM_SDK_SHARED=0`, rejects every `aws-cpp-sdk-*` entry in generated `AWS_IAM_LIBS` except `rds` and `core`, confirms `nm -C` finds `Aws::RDS::RDSClient::GenerateConnectAuthToken` in the final binary, and prints that dynamic linkage remains required for the release-package job.

- [ ] **Step 1: Write the failing linkage/release check**

The script checks a feature-on binary, records the discovered SDK version, verifies the system package owns Apache-2.0 `LICENSE` and `NOTICE` material, and rejects unexpected AWS service libraries. It prints paths/versions but never environment credentials. Static-only development builds may pass the generated-library/symbol branch, but the release CI job must exercise and pass the shared-library branch.

- [ ] **Step 2: Run it against default and feature builds**

```bash
if test/infra/control/check-aws-iam-linkage.bash src/proxysql; then exit 1; fi
PROXYSQLAWSIAM=1 make build_src -j2
test/infra/control/check-aws-iam-linkage.bash src/proxysql
```

Expected: default binary is rejected as not IAM-enabled; prepared feature binary passes.

- [ ] **Step 3: Write the operator guide**

Document these concrete items:

1. Install a system AWS SDK for C++ 1.9+ development package and build with `PROXYSQLAWSIAM=1`; use `AWS_SDK_CPP_ROOT` only for a nonstandard system prefix.
2. The SDK is Apache-2.0 and ProxySQL is GPL-3.0-or-later; record the exact linked SDK version and its `LICENSE`/`NOTICE` during packaging.
3. Grant the ProxySQL workload `rds-db:connect` for the database-user ARN; explain the standard environment/profile/web-identity/ECS/EC2 provider chain and that all DB users share the process identity.
4. Create the MySQL user with `AWSAuthenticationPlugin` and `REQUIRE SSL`.
5. Install/rotate the Amazon RDS CA bundle.
6. Configure the real RDS endpoint, `use_ssl=1`, CA settings, `aws_iam_region`, and split frontend/backend user rows.
7. Load users, servers, SSL params, and hostgroup attributes to runtime.
8. Verify the exact Task 10 stats/metrics, canary rollout, generic client failure behavior, redacted logs, and clock-skew diagnostic.
9. State all non-goals and the no-password-fallback guarantee.

Use complete SQL examples from the approved spec and add rollback SQL that removes the IAM backend row or changes it to a separate password-mode backend row before reloading runtime.

- [ ] **Step 4: Add CI and optional real-AWS tests**

The ordinary CI jobs use only the fake signer and controlled TLS server. The opt-in job requires `AWS_REGION`, `RDS_ENDPOINT`, `RDS_PORT`, `RDS_DB_USER`, `RDS_CA_FILE`, and temporary workload credentials supplied by CI OIDC; it verifies success, denied `rds-db:connect`, nonexistent user, wrong region, credential rotation, refresh, and RDS CA validation. It must skip cleanly when the integration environment is absent and must not print tokens or AWS environment values.

- [ ] **Step 5: Mark acceptance evidence in the approved spec**

Append an `Implementation verification` section linking each acceptance criterion to its focused test, CI job, and operator-guide section. Do not change the approved behavioral decisions.

- [ ] **Step 6: Run documentation, CI syntax, and release checks**

```bash
python3 -c 'import yaml; yaml.safe_load(open(".github/workflows/CI-aws-iam.yml", encoding="utf-8"))'
bash test/infra/control/check-aws-iam-build-gate.bash
test/infra/control/check-aws-iam-linkage.bash src/proxysql
forbidden_pattern='FAKE_AWS_SECRET|FAKE_SESSION_TOKEN|TO''DO|TB''D'
if rg -n "$forbidden_pattern" \
  doc/aws_iam_database_authentication.md .github/workflows/CI-aws-iam.yml; then
  exit 1
fi
git diff --check
```

Expected: YAML parses, build/link checks pass on the feature host, secret/placeholder search returns no matches, and whitespace check passes.

- [ ] **Step 7: Commit documentation and CI**

```bash
git add doc/aws_iam_database_authentication.md doc/README.md \
  test/infra/control/check-aws-iam-linkage.bash .github/workflows/CI-aws-iam.yml \
  docs/superpowers/specs/2026-08-12-aws-iam-database-auth-design.md
git commit -m "docs: add AWS IAM database authentication guide"
```

### Task 13: Run the complete verification matrix

**Files:**

- Modify only if verification reveals a defect: files owned by Tasks 1-12 and the matching focused test.

- [ ] **Step 1: Verify the SDK-free build and regressions**

```bash
make clean
make build_deps -j2
make build_src -j2
bash test/infra/control/check-aws-iam-build-gate.bash
make -C test/tap/tests/unit -j2
(cd test/tap/tests/unit && for test_bin in *-t; do
  if test -x "$test_bin"; then "./$test_bin" || exit 1; fi
done)
make -C test/tap/tests test_aws_iam_backend_auth-t test_aws_iam_metrics-t \
  test_passthrough_auth_e2e-t test_passthrough_auth_pool_reuse-t \
  reg_test_3504-change_user-t test_cluster_sync-t
git diff --check
```

Expected: default build and all unit/focused regression binaries pass; no AWS DSO is linked.

- [ ] **Step 2: Verify the AWS-enabled build on the prepared SDK host**

```bash
make clean
PROXYSQLAWSIAM=1 make build_deps -j2
PROXYSQLAWSIAM=1 make build_src -j2
PROXYSQLAWSIAM=1 make -C test/tap/tests/unit -j2
(cd test/tap/tests/unit && for test_bin in *-t; do
  if test -x "$test_bin"; then "./$test_bin" || exit 1; fi
done)
test/infra/control/check-aws-iam-linkage.bash src/proxysql
```

Expected: build and unit suite pass; linkage contains only AWS `rds` and `core` service DSOs plus their system runtime dependencies.

- [ ] **Step 3: Verify deliberate SDK failure**

```bash
fake_root=$(mktemp -d)
trap 'rm -rf -- "$fake_root"' EXIT
if PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$fake_root" make -C lib 2>"$fake_root/error"; then
  exit 1
fi
grep -F 'AWS SDK for C++ 1.9 or newer with core and rds is required' "$fake_root/error"
```

Expected: command fails early with the exact operator diagnostic.

- [ ] **Step 4: Run fake-provider ASan and TSan suites**

```bash
make clean
NOJEMALLOC=1 WITHASAN=1 make build_deps_debug -j2
NOJEMALLOC=1 WITHASAN=1 make build_src_debug -j2
NOJEMALLOC=1 WITHASAN=1 make -C test/tap/tests/unit \
  aws_iam_token_manager_unit-t aws_iam_connection_secret_unit-t \
  aws_iam_completion_queue_unit-t aws_iam_session_state_unit-t
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ./test/tap/tests/unit/aws_iam_token_manager_unit-t
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ./test/tap/tests/unit/aws_iam_connection_secret_unit-t
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ./test/tap/tests/unit/aws_iam_completion_queue_unit-t
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ./test/tap/tests/unit/aws_iam_session_state_unit-t

make clean
NOJEMALLOC=1 WITHTSAN=1 make build_deps_debug -j2
NOJEMALLOC=1 WITHTSAN=1 make build_src_debug -j2
NOJEMALLOC=1 WITHTSAN=1 make -C test/tap/tests/unit \
  aws_iam_token_manager_unit-t aws_iam_completion_queue_unit-t aws_iam_session_state_unit-t
TSAN_OPTIONS=halt_on_error=1 ./test/tap/tests/unit/aws_iam_token_manager_unit-t
TSAN_OPTIONS=halt_on_error=1 ./test/tap/tests/unit/aws_iam_completion_queue_unit-t
TSAN_OPTIONS=halt_on_error=1 ./test/tap/tests/unit/aws_iam_session_state_unit-t
```

Expected: no sanitizer report.

- [ ] **Step 5: Run the opt-in real AWS integration suite**

```bash
PROXYSQLAWSIAM=1 RUN_AWS_IAM_INTEGRATION=1 \
  ./test/tap/tests/test_aws_iam_backend_auth-t
```

Expected: on authorized infrastructure, successful IAM connection, denial, wrong user/region, credential rotation, refresh, and real RDS CA cases pass. Outside that infrastructure, do not claim this step passed; record it as intentionally not run.

- [ ] **Step 6: Review the complete diff and commit verification-only fixes**

```bash
git status --short
git diff --stat origin/v3.0...HEAD
git diff --check
forbidden_pattern='TO''DO|TB''D|FAKE_AWS_SECRET|FAKE_SESSION_TOKEN'
if rg -n "$forbidden_pattern" \
  include/Aws_Iam_* include/MySQL_Backend_Auth.h lib/Aws_Iam_* \
  lib/MySQL_Backend_Auth.cpp doc/aws_iam_database_authentication.md; then
  exit 1
fi
```

Expected: no placeholders or fake secret literals in production/docs, no whitespace errors, and only planned files changed. If verification required code changes, add a failing focused assertion first, fix only that defect, rerun the focused and affected regression tests, and use a commit message that names the corrected behavior.
