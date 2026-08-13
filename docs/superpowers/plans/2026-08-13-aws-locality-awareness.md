# AWS Locality-Aware Backend Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prefer eligible RDS/Aurora backends in the ProxySQL process's AWS Region or Availability Zone using temporary selection weights, without changing configured/runtime server weights.

**Architecture:** MySQL core parses policy, owns refresh/cache state, publishes immutable selection snapshots, and projects diagnostics. The general `aws` plugin owns the shared AWS SDK runtime, IMDSv2 and RDS calls, and an asynchronous metadata provider installed through the plugin ABI. Both global and thread-local connection selection retain one core snapshot and use one pure effective-weight helper; no hot path calls the plugin or performs network work.

**Tech Stack:** C++17, ProxySQL plugin ABI, AWS SDK for C++ 1.11.869 (`core` and `rds`), vendored libcurl, nlohmann JSON, SQLite stats runtime views, TAP unit/integration tests, ASan and TSan.

## Global Constraints

- Build tier is selected only with `PROXYSQL40=1`; there is no AWS-specific build flag.
- Invoke builds with `make -j`; never hard-code `-j` inside a Makefile recipe.
- The AWS SDK remains statically linked only into `plugins/aws/ProxySQL_Aws_Plugin.so`; the ProxySQL daemon and `libproxysql.a` remain free of AWS SDK symbols and DSOs.
- The AWS SDK release stays pinned to the existing vendored 1.11.869 LFS tarball and uses ProxySQL's vendored dependencies.
- Locality never changes `mysql_servers.weight`, `runtime_mysql_servers.weight`, saved configuration, or ProxySQL Cluster checksums.
- `mysql-aws_locality_awareness` is the only global control; Region, AZ, and account identity are node-local discoveries, never synchronized variables.
- Policy lives at `mysql_hostgroup_attributes.hostgroup_settings.aws.locality_awareness`.
- Multipliers are finite JSON numbers satisfying `1.0 <= same_region_multiplier <= same_az_multiplier <= 10.0`.
- Default refresh is 300 seconds; default stale TTL is 1800 seconds; accepted bounds are `30 <= refresh <= 86400` and `refresh <= stale_ttl <= 604800`.
- Every failure is fail-neutral and all logged/provider failure data is fixed-category and redacted.
- `stats_mysql_aws_locality` exists only when the AWS plugin loads successfully and querying it never performs network discovery.

---

## File Structure

- `include/Aws_Locality_Types.h`: SDK-free provider request/result, policy, endpoint identity, classification, diagnostics, and interfaces.
- `include/Aws_Locality_Manager.h`: provider lease/registry plus the core manager public API.
- `lib/Aws_Locality_Manager.cpp`: parsing helpers, endpoint recognition, classification, arithmetic, registry lifetime, scheduler/cache, immutable publication, and diagnostic snapshots.
- `include/ProxySQL_Plugin.h`, `lib/ProxySQL_PluginManager.cpp`: ABI-6 provider installation, core snapshot projection callback, and service wiring.
- `include/MySQL_HostGroups_Manager.h`, `lib/MySQL_HostGroups_Manager.cpp`: manager ownership, hostgroup policy storage, reload registration, and diagnostics projection.
- `include/MySQL_Thread.h`, `lib/MySQL_Thread.cpp`, `lib/Admin_FlushVariables.cpp`: `mysql-aws_locality_awareness` lifecycle and manager enable/disable notification.
- `lib/MyHGC.cpp`: global Hostgroup Manager effective weighting.
- `lib/MySQL_Thread.cpp`: locality-aware parent-server selection for the thread-local connection cache.
- `plugins/aws/src/aws_plugin.cpp`: shared SDK runtime and capability installation.
- `plugins/aws/src/aws_locality_provider.h`, `plugins/aws/src/aws_locality_provider.cpp`: bounded provider, IMDSv2/environment discovery, paginated RDS discovery, normalization, and cancellation.
- `plugins/aws/Makefile`, `lib/Makefile`: new compilation units and dependencies.
- `test/tap/tests/unit/aws_locality_policy_unit-t.cpp`: policy, DNS recognition, classification, and arithmetic.
- `test/tap/tests/unit/aws_locality_manager_unit-t.cpp`: cache, refresh, generation, stale, cancellation, and concurrency.
- `test/tap/tests/unit/aws_locality_selection_unit-t.cpp`: global and local-cache selection behavior.
- `test/tap/tests/unit/aws_locality_plugin_unit-t.cpp`: fake discovery backend exercising provider queue/normalization and environment fallback.
- `test/tap/tests/unit/aws_locality_stats_unit-t.cpp`: plugin-conditional table lifecycle and query-time projection.
- `test/tap/tests/unit/Makefile`, `test/tap/groups/groups.json`: targets and CI groups.
- `doc/aws-locality-awareness.md`, `README.md`: operator configuration, permissions, behavior, and diagnostics.

---

### Task 1: SDK-Free Policy, Classification, and Weight Arithmetic

**Files:**
- Create: `include/Aws_Locality_Types.h`
- Create: `include/Aws_Locality_Manager.h`
- Create: `lib/Aws_Locality_Manager.cpp`
- Modify: `lib/Makefile`
- Create: `test/tap/tests/unit/aws_locality_policy_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Produces `AwsLocalityPolicy parse_aws_locality_policy(const nlohmann::json&, uint32_t hostgroup_id, AwsLocalityPolicyError&)`.
- Produces `AwsEndpointCandidate recognize_rds_endpoint(uint32_t, std::string_view, uint16_t)`.
- Produces `AwsLocalityClass classify_aws_locality(const AwsLocalLocation&, const AwsBackendLocation&)`.
- Produces `uint64_t aws_locality_effective_weight(int64_t configured_weight, double multiplier)`.

- [ ] **Step 1: Write the failing policy and arithmetic test**

  Use literal cases for defaults, explicit timing, missing required multipliers, wrong JSON types, NaN-like invalid values, `1.0`/`10.0` bounds, ordering, truncation, zero, and `uint64_t` saturation. Include official instance/cluster/reader/custom endpoint names in standard, GovCloud, and China partitions, plus custom CNAME/RDS Proxy/arbitrary-host negatives.

  ```cpp
  AwsLocalityPolicyError error;
  const auto policy = parse_aws_locality_policy(json::parse(
      R"({"same_region_multiplier":2.5,"same_az_multiplier":4.75})"), 10, error);
  ok(policy.valid && policy.refresh_interval_seconds == 300 &&
     policy.stale_ttl_seconds == 1800, "valid policy uses timing defaults");
  ok(aws_locality_effective_weight(3, 2.5) == 7,
     "effective weight truncates toward zero");
  ```

- [ ] **Step 2: Run the focused target and verify RED**

  Run: `PROXYSQL40=1 make -C test/tap/tests/unit -j aws_locality_policy_unit-t`

  Expected: compilation fails only because the new locality types/functions are absent.

- [ ] **Step 3: Implement the minimal pure model**

  Define SDK-free enums and structs with owned strings:

  ```cpp
  enum class AwsEndpointType : uint8_t { unknown, instance, cluster, reader, custom };
  enum class AwsLocalityClass : uint8_t { unknown, remote, same_region, same_az };
  enum class AwsLocalityMetadataStatus : uint8_t { disabled, pending, fresh, stale, expired, error };

  struct AwsLocalityPolicy {
      bool valid{false};
      double same_region_multiplier{1.0};
      double same_az_multiplier{1.0};
      uint32_t refresh_interval_seconds{300};
      uint32_t stale_ttl_seconds{1800};
  };
  ```

  Normalize hostnames by ASCII-lowercasing and removing one trailing dot. Recognition extracts only candidate Region/partition and never claims authoritative endpoint type. Use `long double` for multiplication, truncate toward zero, preserve zero, and saturate at `uint64_t::max()`.

- [ ] **Step 4: Run focused GREEN and existing parser/selection regressions**

  Run: `PROXYSQL40=1 make -C test/tap/tests/unit -j aws_locality_policy_unit-t server_selection_unit-t aws_iam_policy_unit-t`

  Expected: all TAP plans pass with no warnings or SDK references in the focused locality binary.

- [ ] **Step 5: Commit**

  ```bash
  git add include/Aws_Locality_Types.h include/Aws_Locality_Manager.h \
    lib/Aws_Locality_Manager.cpp lib/Makefile \
    test/tap/tests/unit/aws_locality_policy_unit-t.cpp \
    test/tap/tests/unit/Makefile test/tap/groups/groups.json
  git commit -m "feat(mysql): parse AWS locality policies"
  ```

---

### Task 2: Provider Registry, Refresh Manager, and Immutable Snapshots

**Files:**
- Modify: `include/Aws_Locality_Types.h`
- Modify: `include/Aws_Locality_Manager.h`
- Modify: `lib/Aws_Locality_Manager.cpp`
- Create: `test/tap/tests/unit/aws_locality_manager_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes Task 1 policy/candidate/classification types.
- Produces `AwsMetadataProvider`, `AwsMetadataCompletionSink`, `AwsMetadataProviderLease`, `install_global_aws_metadata_provider()`, `acquire_global_aws_metadata_provider()`, and `shutdown_global_aws_metadata_provider()`.
- Produces `MySQLAwsLocalityManager::{configure,set_enabled,snapshot,diagnostic_rows,shutdown}`.

- [ ] **Step 1: Write a fake-provider manager test**

  Exercise a real manager against a deterministic provider that retains request IDs/generations and posts complete normalized results. Cover local discovery followed by coalesced regional requests, duplicate endpoints across hostgroups, shortest refresh interval, pending/fresh/stale/expired/error states, endpoint-not-found, provider absence, enable/disable/re-enable, invalid reload removal, late-generation rejection, cancel, provider replacement, and shutdown drain.

  ```cpp
  class FakeAwsMetadataProvider final : public AwsMetadataProvider {
  public:
      AwsMetadataRequestHandle request(const AwsMetadataRequest& request,
          std::weak_ptr<AwsMetadataCompletionSink> sink) override;
      void cancel(AwsMetadataRequestHandle handle) override;
  };
  ```

  Use an injected steady/wall clock; no sleeps for freshness assertions. Verify monotonic age calculations and wall-clock diagnostic timestamps independently. Add a deterministic callback-vs-shutdown test and a 100-repeat multi-producer publication test.

- [ ] **Step 2: Run and verify RED**

  Run: `PROXYSQL40=1 make -C test/tap/tests/unit -j aws_locality_manager_unit-t`

  Expected: compile failure on the absent provider/manager APIs.

- [ ] **Step 3: Implement the provider registry and lease**

  Mirror the proven IAM lease/drain contract, but keep a separate generic metadata registry. Installation transfers provider ownership plus an optional retained module handle. Shutdown disables new leases, waits for active leases, calls provider shutdown/destructor, and only then `dlclose()`s the retained module reference.

- [ ] **Step 4: Implement manager scheduling and publication**

  `configure()` receives a copied vector of hostgroup policy/backend identities and advances a generation. A lazy scheduler thread exists only while enabled with at least one valid policy. It requests local identity and coalesces endpoint scans by Region, never holding the manager mutex across provider calls. Completions update mutable cache state under the manager mutex, then build and atomically publish `std::shared_ptr<const AwsLocalitySnapshot>` objects. Selection snapshots contain no mutable locks or plugin pointers.

- [ ] **Step 5: Run focused GREEN and TSan**

  Run:

  ```bash
  PROXYSQL40=1 make -C test/tap/tests/unit -j aws_locality_manager_unit-t
  PROXYSQL40=1 NOJEMALLOC=1 WITHTSAN=1 make -C test/tap/tests/unit -j aws_locality_manager_unit-t
  TSAN_OPTIONS=halt_on_error=1 test/tap/tests/unit/aws_locality_manager_unit-t
  ```

  Expected: full TAP plan passes and TSan reports no race.

- [ ] **Step 6: Commit**

  ```bash
  git add include/Aws_Locality_Types.h include/Aws_Locality_Manager.h \
    lib/Aws_Locality_Manager.cpp test/tap/tests/unit/aws_locality_manager_unit-t.cpp \
    test/tap/tests/unit/Makefile test/tap/groups/groups.json
  git commit -m "feat(mysql): manage asynchronous AWS locality metadata"
  ```

---

### Task 3: MySQL Variable and Hostgroup Reload Integration

**Files:**
- Modify: `include/Base_HostGroups_Manager.h`
- Modify: `include/MySQL_HostGroups_Manager.h`
- Modify: `include/MySQL_Thread.h`
- Modify: `lib/BaseHGC.cpp`
- Modify: `lib/MySQL_HostGroups_Manager.cpp`
- Modify: `lib/MySQL_Thread.cpp`
- Modify: `lib/Admin_FlushVariables.cpp`
- Create: `test/tap/tests/unit/aws_locality_config_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes `MySQLAwsLocalityManager::configure()` and `set_enabled()`.
- Produces `MyHGC::attributes.aws_locality_policy` and `MySQL_HostGroups_Manager::refresh_aws_locality_configuration()`.
- Produces the dynamic boolean variable `mysql-aws_locality_awareness`, default `false`, only in `PROXYSQL40`.

- [ ] **Step 1: Write failing configuration lifecycle tests**

  Initialize real hostgroup attributes from JSON and assert valid policy installation, exact defaults/bounds, malformed field rejection without full JSON logging, and removal of the prior policy after invalid reload. Exercise `MySQL_Threads_Handler::{set_variable,get_variable,commit}` for false/true parsing and notify a real manager after `LOAD` semantics. Compare `runtime_mysql_servers` and checksum input before/after metadata completions.

- [ ] **Step 2: Run and verify RED**

  Run: `PROXYSQL40=1 make -C test/tap/tests/unit -j aws_locality_config_unit-t`

  Expected: compile failure on missing variable/policy fields and refresh method.

- [ ] **Step 3: Add the variable and policy storage**

  Register `aws_locality_awareness` in the existing bool variable table, default it false, copy it to worker variables, and expose it as `mysql-aws_locality_awareness`. Compile all feature behavior under `PROXYSQL40`. Add an owned policy value to `MyHGC` and reset it on every attributes reload before parsing.

- [ ] **Step 4: Wire load boundaries**

  At the end of `MySQL_HostGroups_Manager::commit()`, while server/hostgroup state is stable, copy valid policies and backend identities and call `configure()` after releasing the HGM lock. After MySQL variable commit and lock release, call `set_enabled()` once with the master value. Never include discovered data in generated tables/checksums.

- [ ] **Step 5: Run focused GREEN and existing config regressions**

  Run: `PROXYSQL40=1 make -C test/tap/tests/unit -j aws_locality_config_unit-t aws_iam_connection_config_unit-t hostgroups_unit-t cluster_sync_unit-t`

- [ ] **Step 6: Commit**

  ```bash
  git add include/Base_HostGroups_Manager.h include/MySQL_HostGroups_Manager.h \
    include/MySQL_Thread.h lib/BaseHGC.cpp lib/MySQL_HostGroups_Manager.cpp \
    lib/MySQL_Thread.cpp lib/Admin_FlushVariables.cpp \
    test/tap/tests/unit/aws_locality_config_unit-t.cpp \
    test/tap/tests/unit/Makefile test/tap/groups/groups.json
  git commit -m "feat(mysql): load AWS locality configuration"
  ```

---

### Task 4: Global and Thread-Local Weighted Selection

**Files:**
- Modify: `include/Aws_Locality_Manager.h`
- Modify: `include/MySQL_HostGroups_Manager.h`
- Modify: `lib/MyHGC.cpp`
- Modify: `lib/MySQL_Thread.cpp`
- Create: `test/tap/tests/unit/aws_locality_selection_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes immutable `AwsLocalitySnapshot` and `effective_weight(hostgroup,host,port,configured_weight)`.
- Produces identical server-level weighted selection semantics in `MyHGC::get_random_MySrvC()` and `MySQL_Thread::get_MyConn_local()`.

- [ ] **Step 1: Write failing global/local selection tests**

  Use real `MyHGC`, `MySrvC`, and cached `MySQL_Connection` fixtures. Publish literal same-AZ/same-Region/remote/unknown metadata for weights 10/20/30 and multipliers 4.0/2.0; assert deterministic effective weights 40/40/30. Verify same-AZ requires matching account, cluster/reader/custom receive only Region bias, stale remains active, expired is neutral, and configured weights never change.

  For local cache, place multiple connections on one remote parent and one connection on one local parent. Run seeded selections and prove probability follows parent weights, not connection count. Include health, GTID, lag, auth compatibility, session state, and backoff exclusions before locality.

- [ ] **Step 2: Run and verify RED**

  Run: `PROXYSQL40=1 make -C test/tap/tests/unit -j aws_locality_selection_unit-t`

  Expected: locality distribution assertions fail while legacy controls pass.

- [ ] **Step 3: Integrate global selection**

  Preserve the entire existing eligibility scan. Retain one snapshot before candidate evaluation only when the thread-local master flag and hostgroup policy are active. Store a parallel `uint64_t` effective-weight array, use a saturating 64-bit sum, and run the existing lottery over those values. The inactive path retains current branches and configured-weight arithmetic.

- [ ] **Step 4: Integrate local-cache selection**

  Keep the existing first-match implementation unchanged when locality is inactive. When active, scan compatible eligible connections, group candidate indices by `MySrvC*`, calculate one effective weight per parent, choose a parent with the same helper/lottery, then remove one best compatible connection belonging to that parent. Do not allocate/call plugins on the inactive path; reuse bounded stack storage before falling back to a vector for unusually large candidate sets.

- [ ] **Step 5: Run focused GREEN and pool regressions**

  Run: `PROXYSQL40=1 make -C test/tap/tests/unit -j aws_locality_selection_unit-t server_selection_unit-t aws_iam_pool_unit-t connection_pool_unit-t`

- [ ] **Step 6: Commit**

  ```bash
  git add include/Aws_Locality_Manager.h include/MySQL_HostGroups_Manager.h \
    lib/MyHGC.cpp lib/MySQL_Thread.cpp \
    test/tap/tests/unit/aws_locality_selection_unit-t.cpp \
    test/tap/tests/unit/Makefile test/tap/groups/groups.json
  git commit -m "feat(mysql): apply AWS locality during backend selection"
  ```

---

### Task 5: AWS Plugin Metadata Provider

**Files:**
- Create: `plugins/aws/src/aws_locality_provider.h`
- Create: `plugins/aws/src/aws_locality_provider.cpp`
- Modify: `plugins/aws/src/aws_plugin.cpp`
- Modify: `plugins/aws/Makefile`
- Modify: `include/ProxySQL_Plugin.h`
- Modify: `lib/ProxySQL_PluginManager.cpp`
- Create: `test/tap/tests/unit/aws_locality_plugin_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes Task 2 `AwsMetadataProvider` and ownership callbacks.
- Produces ABI-6 services `install_aws_metadata_provider` and the `aws_locality` advertised plugin capability.
- Produces `AwsSdkMetadataProvider`, with an injectable `AwsLocalityDiscoveryBackend` for deterministic tests.

- [ ] **Step 1: Write the failing provider test**

  Drive the real bounded queue/provider with a fake discovery backend. Assert full request/result fields, two-worker bound, queue rejection, cancellation, deadline rejection before/after work, no callback after shutdown, redacted categories, and generation/opaque ID preservation. Test environment precedence (`AWS_REGION`, `AWS_DEFAULT_REGION`, `AWS_AVAILABILITY_ZONE`, `AWS_ACCOUNT_ID`) and partial fallback using scoped environment restoration.

  Build literal normalized response fixtures for RDS instances, Aurora instances, cluster writer/reader/custom endpoints, missing ports, duplicate pages, Multi-AZ/failover changes, and endpoint-not-found. Never assert on fake call existence alone; assert emitted normalized results.

- [ ] **Step 2: Run and verify RED**

  Run: `PROXYSQL40=1 make -C test/tap/tests/unit -j aws_locality_plugin_unit-t`

  Expected: compilation fails on missing provider/backend types.

- [ ] **Step 3: Extend the ABI and shared SDK lifetime**

  Increment the plugin ABI maximum/current version to 6 and append metadata-provider installation to `ProxySQL_PluginServices`. Wire it only during plugin init. Refactor the plugin so IAM signer/token source and locality provider each retain a `std::shared_ptr<AwsSdkRuntime>`; `Aws::InitAPI` occurs once and `Aws::ShutdownAPI` occurs only after both core-owned capabilities drain.

- [ ] **Step 4: Implement local discovery**

  Use IMDSv2 token `PUT /latest/api/token` with a bounded TTL header, then `GET /latest/dynamic/instance-identity/document` with the token. Use ProxySQL's vendored libcurl already linked into the plugin, enforce link-local target/timeouts/response bounds, and parse only `region`, `availabilityZone`, and `accountId`. On IMDS failure, apply the exact environment fallback order. Never log the document, token, account ID, raw curl error, or environment values.

- [ ] **Step 5: Implement paginated RDS discovery**

  Maintain regional `Aws::RDS::RDSClient` instances under a client-map mutex. Issue paginated `DescribeDBInstances`, `DescribeDBClusters`, and `DescribeDBClusterEndpoints` requests until marker exhaustion or deadline/cancellation. Normalize only authoritative endpoint addresses and supplied ports. Map SDK errors to fixed categories (`access_denied`, `throttled`, `timeout`, `invalid_response`, `provider_unavailable`) and discard raw messages. Rate-limit logs by stable Region/endpoint/category keys without including raw responses or account identity.

- [ ] **Step 6: Run focused GREEN, plugin loader, and secret scans**

  Run:

  ```bash
  PROXYSQL40=1 make -C test/tap/tests/unit -j aws_locality_plugin_unit-t aws_plugin_load_unit-t
  PROXYSQL40=1 make -C plugins/aws -j
  nm -C plugins/aws/ProxySQL_Aws_Plugin.so > /tmp/proxysql-aws-plugin-nm.txt
  ldd plugins/aws/ProxySQL_Aws_Plugin.so > /tmp/proxysql-aws-plugin-ldd.txt
  ```

  Assert the plugin has locality symbols, has no AWS/CRT shared-library dependencies, and test/log output contains none of the fixture credentials/account IDs/tokens.

- [ ] **Step 7: Commit**

  ```bash
  git add plugins/aws/src/aws_locality_provider.h plugins/aws/src/aws_locality_provider.cpp \
    plugins/aws/src/aws_plugin.cpp plugins/aws/Makefile include/ProxySQL_Plugin.h \
    lib/ProxySQL_PluginManager.cpp test/tap/tests/unit/aws_locality_plugin_unit-t.cpp \
    test/tap/tests/unit/Makefile test/tap/groups/groups.json
  git commit -m "feat(aws): discover RDS locality metadata"
  ```

---

### Task 6: Plugin-Conditional Stats Table

**Files:**
- Modify: `include/ProxySQL_Plugin.h`
- Modify: `lib/ProxySQL_PluginManager.cpp`
- Modify: `include/MySQL_HostGroups_Manager.h`
- Modify: `lib/MySQL_HostGroups_Manager.cpp`
- Modify: `plugins/aws/src/aws_plugin.cpp`
- Create: `test/tap/tests/unit/aws_locality_stats_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Produces the plugin-owned `stats_mysql_aws_locality` schema and runtime-view registration.
- Produces ABI service `refresh_mysql_aws_locality_stats(SQLite3DB*)`, callable by the plugin's static refresh callback.
- Consumes `MySQLAwsLocalityManager::diagnostic_rows()`.

- [ ] **Step 1: Write failing table lifecycle/projection tests**

  Bootstrap Admin with no AWS plugin and assert `SELECT * FROM stats_mysql_aws_locality` returns `no such table`. Bootstrap through the real AWS plugin schema-registration phase and assert the exact 17-column schema exists. Publish manager rows for pending/fresh/stale/expired/error/disabled, query through `ProxySQL_Admin` twice across a generation swap, and assert each result is a complete single-generation snapshot.

  Use a provider request counter to prove querying the table issues zero metadata requests. Assert writes are rejected and no disk/config table/checksum contains the name.

- [ ] **Step 2: Run and verify RED**

  Run: `PROXYSQL40=1 make -C test/tap/tests/unit -j aws_locality_stats_unit-t`

  Expected: plugin-loaded table query fails because the schema/callback is absent.

- [ ] **Step 3: Register schema and refresh callback**

  In `register_schemas`, register only a stats-db table:

  ```sql
  CREATE TABLE stats_mysql_aws_locality (
    hostgroup_id INT NOT NULL, hostname VARCHAR NOT NULL, port INT NOT NULL,
    endpoint_type VARCHAR NOT NULL, configured_weight INT NOT NULL,
    effective_weight INT NOT NULL, local_region VARCHAR NOT NULL,
    local_az VARCHAR NOT NULL, backend_region VARCHAR NOT NULL,
    backend_az VARCHAR NOT NULL, account_match VARCHAR NOT NULL,
    locality VARCHAR NOT NULL, active_multiplier REAL NOT NULL,
    metadata_status VARCHAR NOT NULL, last_success_timestamp INT NOT NULL,
    last_attempt_timestamp INT NOT NULL, last_error_category VARCHAR NOT NULL,
    PRIMARY KEY(hostgroup_id, hostname, port))
  ```

  The plugin callback invokes the core service. Core retains one diagnostics snapshot, executes `BEGIN; DELETE; INSERT...; COMMIT`, and never calls the provider. With the master off, preserve cached text but force multiplier 1.0/effective configured/status disabled. No valid policies means zero rows.

- [ ] **Step 4: Run focused GREEN and lifecycle regressions**

  Run: `PROXYSQL40=1 make -C test/tap/tests/unit -j aws_locality_stats_unit-t aws_plugin_load_unit-t plugin_runtime_views_unit-t test_aws_iam_metrics-t`

- [ ] **Step 5: Commit**

  ```bash
  git add include/ProxySQL_Plugin.h lib/ProxySQL_PluginManager.cpp \
    include/MySQL_HostGroups_Manager.h lib/MySQL_HostGroups_Manager.cpp \
    plugins/aws/src/aws_plugin.cpp test/tap/tests/unit/aws_locality_stats_unit-t.cpp \
    test/tap/tests/unit/Makefile test/tap/groups/groups.json
  git commit -m "feat(stats): expose AWS locality decisions"
  ```

---

### Task 7: Operator Documentation and Final Verification

**Files:**
- Create: `doc/aws-locality-awareness.md`
- Modify: `README.md`
- Modify: `.github/workflows/CI-aws.yml`
- Modify: `docs/superpowers/specs/2026-08-13-aws-locality-awareness-design.md` only if implementation review exposes an approved contract correction.

**Interfaces:**
- Consumes all preceding production/test behavior.
- Produces operator documentation and CI gates; no new runtime API.

- [ ] **Step 1: Write operator documentation**

  Document the variable, JSON example, numeric/timing bounds, integer truncation, non-cumulative tiers, instance-vs-cluster AZ behavior, account requirement, environment fallback, EC2/EKS credential delivery, exact read-only RDS IAM policy, stale/fail-neutral behavior, and plugin-conditional stats table. State explicitly that displayed/runtime configured weights never change.

- [ ] **Step 2: Extend established container CI**

  Add the five locality tests to the existing AWS workflow's established ProxySQL build container. Preserve `actions/checkout` LFS hydration, pass `PROXYSQL40=1 make -j` from workflow invocations, and do not install compiler/development dependencies directly onto the GitHub runner.

- [ ] **Step 3: Run the complete normal regression gate**

  Run:

  ```bash
  PROXYSQL40=1 make -j clean
  PROXYSQL40=1 make -j
  PROXYSQL40=1 make -C test/tap/tests/unit -j
  ```

  Execute every generated unit binary and record TAP totals. Run all existing AWS IAM, connection-pool, hostgroup, cluster/checksum, plugin lifecycle/runtime-view, controlled TLS, and metrics targets explicitly.

- [ ] **Step 4: Run sanitizer gates**

  Build and run policy, manager, config, selection, plugin, stats, and affected IAM/pool tests under ASan+LSan. Run manager, selection, provider, stats, and plugin lifecycle concurrency tests under TSan. Restore normal artifacts afterward using `PROXYSQL40=1 make -j clean && PROXYSQL40=1 make -j`.

- [ ] **Step 5: Run linkage/security/final-diff gates**

  Capture `nm` and `ldd` output to files before grepping. Prove daemon/archive contain no `Aws::` symbols and daemon/plugin have no AWS/CRT DSOs; prove plugin contains expected static SDK/locality symbols. Scan the combined diff/test output for credentials, tokens, account IDs, raw AWS errors, and unredacted fixture markers. Run `git diff --check` and validate the vendored archive remains unmodified.

  If an externally provisioned AWS integration runner, credentials, and RDS endpoints are configured, run one instance-endpoint and one cluster/reader-endpoint locality test. Otherwise record the optional gate as `NOT RUN`; never substitute fake-provider coverage and label it real AWS verification.

- [ ] **Step 6: Request independent review and fix all Critical/Important findings**

  Provide the reviewer the approved design, this plan, base SHA, head SHA, exact verification evidence, and explicit non-goals. For every valid finding, write a focused failing test before the production correction, then rerun affected and full gates.

- [ ] **Step 7: Commit documentation/CI and prepare handoff**

  ```bash
  git add doc/aws-locality-awareness.md README.md .github/workflows/CI-aws.yml
  git commit -m "docs: document AWS locality awareness"
  ```

  Do not push or open/retarget a PR until the user requests publication.
