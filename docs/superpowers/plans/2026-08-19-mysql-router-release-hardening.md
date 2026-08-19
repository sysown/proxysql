# MySQL Router Plugin Release Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the complete three-topology `mysql_router` implementation into a supportable ProxySQL 4.0 release with an explicit MySQL 8.4-and-newer matrix, fault/security/concurrency coverage, upgrades, packaging, and one reproducible release gate.

**Architecture:** Treat compatibility as executable data rather than an open-ended version comparison. Each supported Server/Shell line provisions real AdminAPI topologies and runs the same contract suite; fault, sanitizer, migration, scale, and package jobs exercise orthogonal risks while preserving the plugin's 8.4 Router feature advertisement.

**Tech Stack:** C++17, ProxySQL 4.0, MySQL Server/Shell 8.4/9.7/26.7, Docker Compose, TAP, Bash, Python 3, ASAN, UBSAN, TSAN, libFuzzer, GNU Make, DEB/RPM packaging.

**Spec:** `docs/superpowers/specs/2026-08-19-mysql-router-plugin-design.md`

## Global Constraints

- This plan begins only after the chassis, plugin-foundation, topology-expansion, and takeover plans dated 2026-08-19 are green.
- Minimum supported MySQL Server and Shell contract is 8.4.0; metadata schema 2.2 remains the minimum.
- As of 2026-08-19, test the maintained 8.4 LTS line, the final 9.7 innovation line, and current 26.7 line; Shell 26.7 is the forward client because Oracle discontinued Shell 8.4/9.7 series and documents it as compatible with supported Server 8.4, 9.7, and 26.7.
- Keep Router compatibility advertisement at `8.4.0` across newer Server/Shell lines until a separately designed feature contract is implemented.
- Reject a metadata shape not represented by a passing adapter fixture; never silently treat an unknown shape as 2.4.
- The first supported plugin release requires all three topologies, existing-Router takeover, stock Shell APIs, ports 6446/6447/6450, native ProxySQL routing, and ownership isolation.
- Do not add MySQL X, Routing Guidelines, REST, Router packet forwarding, or per-connection Router semantics.
- No test may print or archive passwords, verifiers, key material, or unredacted credential-bearing SQL.
- A release gate fails on a skipped required matrix cell, missing test executable, sanitizer finding, data-race report, leaked worker, partial config generation, or changed Router takeover input.
- Keep ProxySQL 3.x build/tests unchanged and ensure `PROXYSQL40=1` is explicit in every plugin build.

---

## File Map

- `plugins/mysql_router/compatibility.source.json`: reviewed Server/Shell artifact coordinates and metadata expectations.
- `plugins/mysql_router/compatibility.json`: generated, digest-locked Server/Shell/metadata contract matrix.
- `test/tap/tests/mysql_router/compatibility_matrix.py`: schema validation and matrix expansion.
- `test/tap/docker-compose-mysql-router.yml`, `test/tap/docker/mysql-router/`: pinned topology infrastructure.
- `test/tap/tests/test_mysql_router_compatibility-t.cpp`: common real-product contract runner.
- `test/tap/tests/unit/mysql_router_faults_unit-t.cpp`: deterministic transport/publisher/clock failures.
- `test/tap/tests/fuzz/mysql_router_*_fuzzer.cpp`: URI, INI, state, keyring, metadata JSON, and option parsers.
- `test/tap/tests/test_mysql_router_scale-t.cpp`, `test_mysql_router_soak-t.cpp`: scale, concurrency, and long-run recovery.
- `plugins/mysql_router/src/schema_migrations.cpp`, `include/mysql_router_schema.h`: versioned local schema migrations.
- `test/tap/tests/test_mysql_router_upgrade-t.cpp`: ProxySQL/plugin and metadata upgrades, re-bootstrap, replacement, and uninstall.
- `Makefile`, package entrypoints/specs, workflows: build/install the plugin and run release gates.
- `doc/mysql-router-plugin-support.md`: public matrix, lifecycle, exclusions, and compatibility policy.

### Task 1: Encode and validate the MySQL 8.4-and-newer compatibility matrix

**Files:**

- Create: `plugins/mysql_router/compatibility.json`
- Create: `plugins/mysql_router/compatibility.source.json`
- Create: `test/tap/tests/mysql_router/compatibility_matrix.py`
- Create: `test/tap/tests/mysql_router/test_compatibility_matrix.py`
- Modify: `plugins/mysql_router/src/metadata_factory.cpp`
- Modify: `plugins/mysql_router/src/status.cpp`

**Interfaces:**

- Consumes: adapter names and metadata capability shapes.
- Produces: a validated compatibility manifest and runtime `compatibility_status` (`supported`, `unsupported_shape`, `below_minimum`).

- [ ] **Step 1: Write the manifest schema test first**

  Require unique IDs, valid versions, exactly three topologies per release cell, an adapter name, Router contract, and immutable artifact digests:

  ```python
  required_ids = {"floor-8.4.0", "lts-8.4.11", "innovation-9.7.1", "current-26.7.0"}
  assert {row["id"] for row in matrix["cells"]} == required_ids
  for row in matrix["cells"]:
      assert row["topologies"] == ["innodb_cluster", "replica_set", "cluster_set"]
      assert row["router_contract"] == "8.4.0"
      assert row["metadata_adapter"] in {"metadata-2.2", "metadata-2.3", "metadata-2.4"}
      assert re.fullmatch(r"sha256:[0-9a-f]{64}", row["server_digest"])
      assert re.fullmatch(r"[0-9a-f]{64}", row["shell_sha256"])
      assert row["server_ref"].startswith(
          "container-registry.oracle.com/mysql/community-server:")
      assert row["shell_url"].startswith((
          "https://dev.mysql.com/get/Downloads/MySQL-Shell/",
          "https://downloads.mysql.com/archives/get/p/43/file/"))
  ```

- [ ] **Step 2: Add the four explicit source cells**

  Populate `compatibility.source.json` with these reviewed coordinates; `shell_url` is deliberately repeated so each cell is self-contained:

  ```json
  {
    "minimum_server": "8.4.0",
    "minimum_shell": "8.4.0",
    "router_contract": "8.4.0",
    "cells": [
      {"id":"floor-8.4.0","server":"8.4.0","server_ref":"container-registry.oracle.com/mysql/community-server:8.4.0","shell":"8.4.0","shell_url":"https://downloads.mysql.com/archives/get/p/43/file/mysql-shell-8.4.0-linux-glibc2.17-x86-64bit.tar.gz","metadata_adapter":"metadata-2.2","topologies":["innodb_cluster","replica_set","cluster_set"]},
      {"id":"lts-8.4.11","server":"8.4.11","server_ref":"container-registry.oracle.com/mysql/community-server:8.4.11","shell":"26.7.0","shell_url":"https://dev.mysql.com/get/Downloads/MySQL-Shell/mysql-shell-26.7.0-linux-glibc2.28-x86-64bit.tar.gz","metadata_adapter":"metadata-2.4","topologies":["innodb_cluster","replica_set","cluster_set"]},
      {"id":"innovation-9.7.1","server":"9.7.1","server_ref":"container-registry.oracle.com/mysql/community-server:9.7.1","shell":"26.7.0","shell_url":"https://dev.mysql.com/get/Downloads/MySQL-Shell/mysql-shell-26.7.0-linux-glibc2.28-x86-64bit.tar.gz","metadata_adapter":"metadata-2.4","topologies":["innodb_cluster","replica_set","cluster_set"]},
      {"id":"current-26.7.0","server":"26.7.0","server_ref":"container-registry.oracle.com/mysql/community-server:26.7.0","shell":"26.7.0","shell_url":"https://dev.mysql.com/get/Downloads/MySQL-Shell/mysql-shell-26.7.0-linux-glibc2.28-x86-64bit.tar.gz","metadata_adapter":"metadata-2.4","topologies":["innodb_cluster","replica_set","cluster_set"]}
    ]
  }
  ```

  The coordinates come from Oracle's [8.4 release notes](https://dev.mysql.com/doc/relnotes/mysql/8.4/en/), [9.7 release notes](https://dev.mysql.com/doc/relnotes/mysql/9.7/en/), [26.7 release notes](https://dev.mysql.com/doc/relnotes/mysql/26.7/en/), [Shell download archive](https://dev.mysql.com/downloads/shell/), and [Shell 26.7 compatibility notice](https://dev.mysql.com/doc/relnotes/mysql-shell/26.7/en/).

- [ ] **Step 3: Run the Python test and establish RED**

  ```bash
  python3 -m unittest -v \
    test.tap.tests.mysql_router.test_compatibility_matrix
  ```

  Expected RED: manifest/parser modules do not exist.

- [ ] **Step 4: Implement strict manifest parsing**

  Implement `compatibility_matrix.py lock` to resolve each OCI manifest with `skopeo inspect`, download each Shell archive with `curl --fail --location`, compute its SHA-256, extract it, and verify `mysqlsh --version` equals the declared version. It writes a canonical `compatibility.json` containing all source fields plus `server_digest` and `shell_sha256`; it refuses redirects outside `dev.mysql.com`/`downloads.mysql.com`, duplicate final URLs with conflicting hashes, or a mutable image reference without a resolved digest. Generate the reviewed lock file with:

  ```bash
  python3 test/tap/tests/mysql_router/compatibility_matrix.py lock \
    --source plugins/mysql_router/compatibility.source.json \
    --output plugins/mysql_router/compatibility.json
  python3 test/tap/tests/mysql_router/compatibility_matrix.py verify \
    plugins/mysql_router/compatibility.json
  ```

  Commit both source and locked manifests together. Reject unknown keys, missing digests, duplicate cells, versions below minimum, unsupported topology names, or a cell whose expected adapter is not compiled. `--list` prints one shell-safe tab-separated row per `(cell,topology)` without credentials.

- [ ] **Step 5: Expose negotiated compatibility in status**

  Add status fields `server_version`, `shell_contract_floor`, `metadata_declared_version`, `metadata_shape_hash`, `metadata_adapter`, and `compatibility_status`. Compute the shape hash from sorted required view/column names, not row data.

- [ ] **Step 6: Run manifest and metadata-factory tests**

  ```bash
  python3 -m unittest -v \
    test.tap.tests.mysql_router.test_compatibility_matrix
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_metadata_factory_unit-t -B
  test/tap/tests/unit/mysql_router_metadata_factory_unit-t
  ```

  Expected GREEN: manifest validation and adapter selection pass.

- [ ] **Step 7: Commit the compatibility contract**

  ```bash
  git add plugins/mysql_router/compatibility.source.json \
    plugins/mysql_router/compatibility.json \
    plugins/mysql_router/src/metadata_factory.cpp \
    plugins/mysql_router/src/status.cpp \
    test/tap/tests/mysql_router/compatibility_matrix.py \
    test/tap/tests/mysql_router/test_compatibility_matrix.py
  git commit -m "test(mysql-router): define supported MySQL matrix"
  ```

### Task 2: Provision every compatibility cell and run one common contract

**Files:**

- Create: `test/tap/docker-compose-mysql-router.yml`
- Create: `test/tap/docker/mysql-router/Dockerfile`
- Create: `test/tap/docker/mysql-router/entrypoint.sh`
- Create: `test/tap/tests/test_mysql_router_compatibility-t.cpp`
- Create: `test/tap/tests/mysql_router/run_contract.js`
- Modify: `test/tap/tests/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**

- Consumes: one expanded compatibility row and official pinned artifacts.
- Produces: `mysql-router-compat` TAP group with 12 mandatory cells.

- [ ] **Step 1: Add matrix cardinality and handoff tests**

  The test harness must assert `4 release cells * 3 topologies = 12` declared cases, unique container/project names, digest-pinned images, and a result file for every case. Missing/duplicate/skipped result is a failure.

- [ ] **Step 2: Build isolated version-selectable infrastructure**

  Pass only these non-secret inputs:

  ```text
  MYSQL_ROUTER_MATRIX_ID
  MYSQL_SERVER_IMAGE_AT_DIGEST
  MYSQL_SHELL_IMAGE_AT_DIGEST
  MYSQL_ROUTER_TOPOLOGY
  ```

  Create topology-specific server counts/networks and health checks. Generate passwords inside the isolated project and mount them as mode-0600 files, never environment variables printed by Compose.

- [ ] **Step 3: Run one floor cell to establish infrastructure RED/GREEN**

  ```bash
  MYSQL_ROUTER_MATRIX_ID=floor-8.4.0 \
  MYSQL_ROUTER_TOPOLOGY=innodb_cluster \
  WORKSPACE="$(pwd)" INFRA_ID="router-floor-${USER}" \
    TAP_GROUP=mysql-router-compat \
    test/scripts/run-tests-isolated.bash -k test_mysql_router_compatibility-t
  ```

  Expected first RED: fixture provisioning is incomplete. Expected GREEN after implementation: one case passes and writes its signed result JSON.

- [ ] **Step 4: Implement the common stock-Shell contract script**

  For the selected topology: create it, bootstrap the plugin, start ProxySQL, run `listRouters`, `routerOptions`, `routingOptions`, one supported `setRoutingOption`, and `setupRouterAccount`; test 6446/6447/6450; perform one role/target transition; test operator ownership isolation; remove a disposable Router registration; and emit versions/metadata shape/results.

- [ ] **Step 5: Run all 12 matrix cases**

  ```bash
  python3 test/tap/tests/mysql_router/compatibility_matrix.py --list |
  while IFS=$'\t' read -r matrix_id topology server_image shell_image; do
    MYSQL_ROUTER_MATRIX_ID="$matrix_id" \
    MYSQL_ROUTER_TOPOLOGY="$topology" \
    MYSQL_SERVER_IMAGE_AT_DIGEST="$server_image" \
    MYSQL_SHELL_IMAGE_AT_DIGEST="$shell_image" \
    WORKSPACE="$(pwd)" INFRA_ID="router-${matrix_id}-${topology}-${USER}" \
      TAP_GROUP=mysql-router-compat \
      test/scripts/run-tests-isolated.bash \
        -k test_mysql_router_compatibility-t || exit 1
  done
  python3 test/tap/tests/mysql_router/compatibility_matrix.py \
    --verify-results test/tap/results/mysql-router-compat
  ```

  Expected GREEN: 12 declared, 12 executed, 12 passed, 0 skipped.

- [ ] **Step 6: Commit the real-product matrix**

  ```bash
  git add test/tap/docker-compose-mysql-router.yml \
    test/tap/docker/mysql-router test/tap/groups/groups.json \
    test/tap/tests/Makefile test/tap/tests/test_mysql_router_compatibility-t.cpp \
    test/tap/tests/mysql_router/run_contract.js
  git commit -m "test(mysql-router): run MySQL compatibility matrix"
  ```

### Task 3: Inject failures across metadata, health, secrets, and publication

**Files:**

- Create: `test/tap/tests/unit/mysql_router_faults_unit-t.cpp`
- Create: `test/tap/tests/test_mysql_router_fault_recovery-t.cpp`
- Create: `test/tap/tests/mysql_router/fault_proxy.py`
- Modify: `plugins/mysql_router/src/reconciler.cpp`
- Modify: `plugins/mysql_router/src/metadata_client.cpp`
- Modify: `plugins/mysql_router/src/status.cpp`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/tests/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**

- Consumes: injectable clocks/transports/publisher failure points and real TCP fault proxy.
- Produces: deterministic rollback/stale-state recovery coverage.

- [ ] **Step 1: Add the complete unit fault table**

  Inject each fault before/after every remote query and publisher phase:

  ```text
  connect timeout; TLS verify failure; mid-result EOF; malformed row;
  schema_version=0.0.0 upgrade window; unsupported shape; topology UUID change;
  GR/replication health timeout; account result truncation; secret tag corruption;
  Admin staging failure; HGM failure; Auth failure; QPro failure; interface failure;
  registration deleted; stop during blocked refresh; clock rollback/large jump
  ```

  Assert active topology/user generations, gates, persisted rows, metrics, and error coalescing after every fault.

- [ ] **Step 2: Run the unit target and observe new assertion failures**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 mysql_router_faults_unit-t -B
  test/tap/tests/unit/mysql_router_faults_unit-t
  ```

  Expected RED: uncovered fault transitions fail; no production change is accepted until each has a deterministic expected state.

- [ ] **Step 3: Implement upgrade-window and backoff behavior**

  Treat metadata `0.0.0` as an in-progress upgrade: retain last desired metadata, continue live health, suppress repeated logs, and retry with capped exponential backoff `250ms,500ms,1s,2s,5s`. Reset to configured refresh interval after one success. An unsupported nonzero shape closes gates at first bootstrap but retains an existing generation during runtime and reports `unsupported_shape`.

- [ ] **Step 4: Implement cancellation-safe I/O**

  Bound connect/read/write calls by config timeouts, pass a stop token through retry loops, and join within `connect_timeout + 1s`. Never hold plugin status, Admin, HGM, Auth, or QPro locks while blocking on network I/O.

- [ ] **Step 5: Add real network/metadata fault scenarios**

  The TCP proxy supports close-after-N-bytes, latency, blackhole, one-way reset, and recovery. The integration test applies each to metadata while data traffic continues, corrupts a disposable secret then restores it, temporarily renames a required metadata view inside a rollback transaction/session fixture, and verifies recovery to a new complete generation.

- [ ] **Step 6: Run unit and isolated fault suites**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 mysql_router_faults_unit-t -B
  test/tap/tests/unit/mysql_router_faults_unit-t
  WORKSPACE="$(pwd)" INFRA_ID="mysql-router-faults-${USER}" \
    TAP_GROUP=mysql-router-faults \
    test/scripts/run-tests-isolated.bash -k test_mysql_router_fault_recovery-t
  ```

  Expected GREEN: every injected fault preserves a complete generation and recovers without restart where specified.

- [ ] **Step 7: Commit fault recovery coverage**

  ```bash
  git add plugins/mysql_router/src/metadata_client.cpp \
    plugins/mysql_router/src/reconciler.cpp plugins/mysql_router/src/status.cpp \
    test/tap/groups/groups.json test/tap/tests/Makefile \
    test/tap/tests/unit/Makefile test/tap/tests/unit/mysql_router_faults_unit-t.cpp \
    test/tap/tests/test_mysql_router_fault_recovery-t.cpp \
    test/tap/tests/mysql_router/fault_proxy.py
  git commit -m "test(mysql-router): harden refresh failure recovery"
  ```

### Task 4: Fuzz and sanitize every untrusted import/metadata parser

**Files:**

- Create: `test/tap/tests/fuzz/mysql_router_uri_fuzzer.cpp`
- Create: `test/tap/tests/fuzz/mysql_router_config_fuzzer.cpp`
- Create: `test/tap/tests/fuzz/mysql_router_state_fuzzer.cpp`
- Create: `test/tap/tests/fuzz/mysql_router_keyring_fuzzer.cpp`
- Create: `test/tap/tests/fuzz/mysql_router_options_fuzzer.cpp`
- Create: `test/tap/tests/fuzz/corpus/mysql_router/`
- Create: `test/tap/tests/fuzz/Makefile`
- Modify: `.github/workflows/CI-unit-tests-asan-coverage.yml`

**Interfaces:**

- Consumes: pure bounded parser entry points.
- Produces: libFuzzer targets and ASAN/UBSAN regression corpus.

- [ ] **Step 1: Expose byte-span parser seams without filesystem side effects**

  Each reader gets a pure overload accepting `std::span<const uint8_t>` plus an explicit base path/limits object. File readers remain thin wrappers that perform secure open/fstat and pass bytes to the same parser.

- [ ] **Step 2: Add seed corpus and dictionary tokens**

  Seed valid/invalid URIs, three INIs, three state files, keyring/master-key samples, and Router option JSON. Add dictionaries for section names, `MRKF`, `MRKR`, metadata keys, URI schemes, and supported option values; never include real/test passwords beyond the public fixture value already committed.

- [ ] **Step 3: Build fuzz targets with clang sanitizers**

  ```bash
  make -C test/tap/tests/fuzz PROXYSQL40=1 \
    CXX=clang++ SANITIZERS=address,undefined mysql_router_fuzzers -B
  ```

  Expected GREEN build: five executables link with libFuzzer.

- [ ] **Step 4: Run bounded local fuzz smoke**

  ```bash
  for f in test/tap/tests/fuzz/mysql_router_*_fuzzer; do
    "$f" -max_total_time=60 -timeout=5 \
      test/tap/tests/fuzz/corpus/mysql_router/"$(basename "$f")" || exit 1
  done
  ```

  Expected GREEN: no crash, timeout, OOM, sanitizer error, or generated input above parser limits.

- [ ] **Step 5: Add malicious identity/value unit cases**

  Add router names, hostnames, labels, usernames, JSON strings, and attributes containing quotes, backslashes, NUL, Unicode, 1 MiB values, SQL comment markers, and control bytes. Assert prepared statements or rejection, bounded/redacted logs, and no generated SQL containing the raw malicious value.

- [ ] **Step 6: Add the fuzzer smoke to sanitizer CI**

  Build `PROXYSQL40=1`, run each target for 60 seconds, upload only crashing inputs, and fail on sanitizer diagnostics. Keep the existing workflow's unrelated matrix unchanged.

- [ ] **Step 7: Commit parser hardening**

  ```bash
  git add .github/workflows/CI-unit-tests-asan-coverage.yml \
    plugins/mysql_router test/tap/tests/fuzz test/tap/tests/unit
  git commit -m "test(mysql-router): fuzz untrusted control-plane inputs"
  ```

### Task 5: Verify concurrency, scale, and zero query-path plugin overhead

**Files:**

- Create: `test/tap/tests/test_mysql_router_scale-t.cpp`
- Create: `test/tap/tests/test_mysql_router_soak-t.cpp`
- Create: `test/tap/tests/mysql_router/generate_accounts.sql`
- Create: `test/tap/tests/mysql_router/measure_refresh.py`
- Create: `test/tap/groups/mysql-router-scale/env.sh`
- Create: `test/tap/groups/mysql-router-soak/env.sh`
- Modify: `test/tap/groups/groups.json`
- Modify: `test/tap/tests/Makefile`

**Interfaces:**

- Consumes: real plugin worker, native query processor/data path, large account/topology fixtures, and TSAN build.
- Produces: documented performance ceilings and race/leak-free soak results.

- [ ] **Step 1: Define measurable acceptance ceilings**

  On the reference CI runner:

  ```text
  100 topology endpoints: topology compile+publish p99 <= 250 ms
  10,000 account variants / 5,000 usernames: user refresh p99 <= 2 s
  Admin/HGM/Auth/QPro critical-section hold p99 <= 50 ms
  steady-state RSS growth over 24 h <= 2%
  plugin-disabled vs plugin-enabled idle topology: QPS and p99 regression <= 2%
  worker stop after cancellation <= connect_timeout + 1 s
  ```

  Store raw timings and environment metadata; fail only after five warm iterations and twenty measured iterations.

- [ ] **Step 2: Add a scale test with concurrent traffic/Admin reads**

  While refreshing 10,000 account variants and changing 100 endpoints, run 64 client workers on 6446/6447/6450 plus Admin SELECTs from every runtime/stats table. Assert every client observes only old or new generations, never missing Auth/HG cross-products, and every ceiling above.

- [ ] **Step 3: Prove the plugin adds no per-query hook**

  Assert `ProxySQL_PluginManager::has_query_hook(mysql)==false` for `mysql_router`. Compare baseline ProxySQL native hostgroup/rule traffic to the same config generated by the plugin; metric/query traces must show no plugin callback on COM_QUERY.

- [ ] **Step 4: Run scale under the isolated harness**

  ```bash
  WORKSPACE="$(pwd)" INFRA_ID="mysql-router-scale-${USER}" \
    TAP_GROUP=mysql-router-scale \
    test/scripts/run-tests-isolated.bash -k test_mysql_router_scale-t
  ```

  Expected GREEN: all generation invariants and ceilings pass.

- [ ] **Step 5: Run a 24-hour TSAN soak**

  Cycle metadata loss, GR/ReplicaSet/ClusterSet role changes, Shell option changes, account rotations, Admin reads, forced reconciles, plugin shutdown/start, and 128 clients. Use `TSAN_OPTIONS=halt_on_error=1`; collect RSS/thread/fd counts hourly.

  ```bash
  WORKSPACE="$(pwd)" INFRA_ID="mysql-router-soak-${USER}" \
    TAP_GROUP=mysql-router-soak MYSQL_ROUTER_SOAK_SECONDS=86400 \
    test/scripts/run-tests-isolated.bash -k test_mysql_router_soak-t
  ```

  Expected GREEN: no TSAN report, deadlock, fd/thread growth, generation inversion, or RSS growth above 2%.

- [ ] **Step 6: Commit scale and soak gates**

  ```bash
  git add test/tap/groups test/tap/tests/Makefile \
    test/tap/tests/test_mysql_router_scale-t.cpp \
    test/tap/tests/test_mysql_router_soak-t.cpp \
    test/tap/tests/mysql_router/generate_accounts.sql \
    test/tap/tests/mysql_router/measure_refresh.py
  git commit -m "test(mysql-router): add scale and concurrency gates"
  ```

### Task 6: Version plugin schemas and test upgrades, replacement, and uninstall

**Files:**

- Create: `plugins/mysql_router/include/mysql_router_schema.h`
- Create: `plugins/mysql_router/src/schema_migrations.cpp`
- Create: `test/tap/tests/unit/mysql_router_schema_migrations_unit-t.cpp`
- Create: `test/tap/tests/test_mysql_router_upgrade-t.cpp`
- Modify: `plugins/mysql_router/src/admin_schema.cpp`
- Modify: `plugins/mysql_router/src/bootstrap.cpp`
- Modify: `plugins/mysql_router/src/plugin.cpp`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/tests/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**

- Consumes: existing plugin tables, ownership ledger, registration, secrets, and scoped publisher.
- Produces: schema version 1 migrations, idempotent re-bootstrap/replacement, and explicit confirmed uninstall.

- [ ] **Step 1: Add migration ledger and rollback tests**

  Materialize:

  ```sql
  CREATE TABLE mysql_router_schema_version (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    version INTEGER NOT NULL,
    dirty INTEGER NOT NULL CHECK(dirty IN (0,1))
  );
  ```

  Test empty install to v1, repeated v1 open, unknown future version rejection, dirty flag rejection, injected DDL failure rollback, and configdb/admindb version agreement.

- [ ] **Step 2: Run migration tests and observe RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_schema_migrations_unit-t -B
  ```

  Expected RED: migration runner is absent.

- [ ] **Step 3: Implement transactional ordered migrations**

  `register_schemas` declares the latest shape for new databases. `init` reads versions, applies named `Migration{from,to,sql,verify}` entries under `BEGIN IMMEDIATE`, verifies invariants, sets dirty=0, and commits. A failure leaves the previous version/data and closes plugin gates without preventing Admin/6033 startup.

- [ ] **Step 4: Test supported upgrade/re-bootstrap paths**

  Cover: ProxySQL 3.x config/database to 4.0 with plugin not loaded; fresh plugin bootstrap; plugin binary v1 restart; idempotent same-topology re-bootstrap; metadata 2.2→2.4 upgrade including 0.0.0 window; Server 8.4→9.7→26.7; Shell 8.4→26.7; and takeover state across plugin upgrade.

- [ ] **Step 5: Test explicit topology replacement**

  `--replace-topology` requires bootstrap administrator credentials and exact confirmation `--replace-topology=<old-topology-uuid>`. Publish the new topology first under newly allocated owned groups, then atomically switch stable groups, remove old owned objects/secrets, and update registration. A failure leaves the old topology operational.

- [ ] **Step 6: Add confirmed uninstall action**

  Register `--uninstall-mysql-router=<topology-uuid>` as a plugin early action. It closes gates, removes only ownership-ledger hostgroups/servers/users/rules/interfaces, deletes local plugin rows/secrets, and removes the remote registration only when bootstrap admin credentials are explicitly supplied. Without remote credentials, leave the registration and report it. Never touch unmanaged objects.

- [ ] **Step 7: Run upgrade/uninstall isolation checks**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_schema_migrations_unit-t plugin_mysql_config_unit-t -B
  test/tap/tests/unit/mysql_router_schema_migrations_unit-t
  test/tap/tests/unit/plugin_mysql_config_unit-t
  WORKSPACE="$(pwd)" INFRA_ID="mysql-router-upgrade-${USER}" \
    TAP_GROUP=mysql-router-upgrade \
    test/scripts/run-tests-isolated.bash -k test_mysql_router_upgrade-t
  ```

  Expected GREEN: upgrades preserve service, replacement rolls back safely, uninstall removes exactly owned objects, and ProxySQL 3.x tests remain unchanged.

- [ ] **Step 8: Commit lifecycle hardening**

  ```bash
  git add plugins/mysql_router test/tap/groups/groups.json \
    test/tap/tests/Makefile test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_schema_migrations_unit-t.cpp \
    test/tap/tests/test_mysql_router_upgrade-t.cpp
  git commit -m "feat(mysql-router): version plugin lifecycle and cleanup"
  ```

### Task 7: Package the plugin and verify a clean-host experience

**Files:**

- Modify: `Makefile`
- Modify: `docker/images/proxysql/deb-compliant/entrypoint/entrypoint.bash`
- Modify: `docker/images/proxysql/rhel-compliant/entrypoint/entrypoint.bash`
- Modify: `docker/images/proxysql/rhel-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec`
- Modify: `docker/images/proxysql/suse-compliant/entrypoint/entrypoint.bash`
- Modify: `docker/images/proxysql/suse-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec`
- Modify: `docker/images/proxysql/tarball-compliant/entrypoint/entrypoint.bash`
- Create: `test/tap/tests/test_mysql_router_package-t.cpp`
- Create: `test/tap/tests/mysql_router/package_smoke.sh`
- Modify: `test/tap/tests/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**

- Consumes: built `proxysql_mysql_router.so` and name resolver.
- Produces: DEB/RPM/tarball installations where `--load-plugin=mysql_router` works without an absolute path.

- [ ] **Step 1: Add package-content tests**

  Require mode/ownership and paths:

  ```text
  /usr/lib/proxysql/plugins/proxysql_mysql_router.so 0755 root:root
  /usr/share/doc/proxysql/mysql-router-plugin.md 0644 root:root
  /usr/share/doc/proxysql/mysql-router-plugin-takeover.md 0644 root:root
  ```

  The plugin is shipped by default with ProxySQL 4.0 packages but is activated only by config/CLI/bootstrap.

- [ ] **Step 2: Build and inspect DEB/RPM/tarball artifacts**

  ```bash
  make PROXYSQL40=1 debian12 almalinux9 tarball-almalinux9
  dpkg-deb -c binaries/proxysql_*debian12*.deb | \
    grep -F /usr/lib/proxysql/plugins/proxysql_mysql_router.so
  rpm -qlp binaries/proxysql-*almalinux9*.rpm | \
    grep -F /usr/lib/proxysql/plugins/proxysql_mysql_router.so
  tar -tzf binaries/proxysql-*-linux-*.tar.gz | \
    grep -F /lib/proxysql/proxysql_mysql_router.so
  ```

  Expected GREEN: all three artifact types contain/resolve the plugin.

- [ ] **Step 3: Verify bootstrap persists normal plugin loading**

  On a clean package install, bootstrap once with the CLI selector, then inspect persisted config to assert `mysql_router` is in the plugin module list exactly once. Restart using only the service unit; the plugin loads, reconciles, and opens 6446/6447/6450 without an extra command-line option.

- [ ] **Step 4: Verify kill switch and failed-plugin recovery**

  Start with `--no-plugins`: no Router option/plugin schema/action/listener loads and 6032/6033 remain available. Corrupt a copy of the plugin `.so`, start normally and observe a clear load failure, then use `--no-plugins` to recover Admin access without deleting configuration.

- [ ] **Step 5: Run clean-host package smoke**

  ```bash
  WORKSPACE="$(pwd)" INFRA_ID="mysql-router-package-${USER}" \
    TAP_GROUP=mysql-router-package \
    test/scripts/run-tests-isolated.bash -k test_mysql_router_package-t
  ```

  Expected GREEN: install/bootstrap/restart/kill-switch smoke passes in a fresh container.

- [ ] **Step 6: Commit package integration**

  ```bash
  git add Makefile \
    docker/images/proxysql/deb-compliant/entrypoint/entrypoint.bash \
    docker/images/proxysql/rhel-compliant/entrypoint/entrypoint.bash \
    docker/images/proxysql/rhel-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec \
    docker/images/proxysql/suse-compliant/entrypoint/entrypoint.bash \
    docker/images/proxysql/suse-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec \
    docker/images/proxysql/tarball-compliant/entrypoint/entrypoint.bash \
    test/tap/groups/groups.json \
    test/tap/tests/Makefile test/tap/tests/test_mysql_router_package-t.cpp \
    test/tap/tests/mysql_router/package_smoke.sh
  git commit -m "build(mysql-router): package ProxySQL Router plugin"
  ```

### Task 8: Publish support policy and wire the mandatory CI release gate

**Files:**

- Create: `doc/mysql-router-plugin-support.md`
- Create: `.github/workflows/CI-mysql-router.yml`
- Create: `test/tap/tests/mysql_router/verify_release_gate.py`
- Create: `test/tap/tests/mysql_router/test_verify_release_gate.py`
- Modify: `doc/mysql-router-plugin.md`
- Modify: `README.md`

**Interfaces:**

- Consumes: all implementation/test/package artifacts.
- Produces: public support matrix and a CI job that cannot pass with missing required evidence.

- [ ] **Step 1: Document the support matrix and forward policy**

  State the four tested cells, three topologies, metadata adapter/shape hash, stock Shell APIs, takeover, Classic endpoints, native routing semantics, account plugins, platforms, and exact exclusions. A future Server/Shell release is unsupported until its artifact digest, observed metadata shape, and 12-topology/API assertions are added and green.

- [ ] **Step 2: Add release-evidence validation tests**

  `verify_release_gate.py` requires signed JSON results for chassis units, plugin units, importer units, 12 compatibility cases, fault recovery, ASAN/UBSAN fuzz, TSAN soak, scale, upgrade, takeover, and DEB/RPM/container smoke. It rejects stale commit SHA, duplicate test ID, skip, missing timing, failed redaction scan, or source-file hash drift.

- [ ] **Step 3: Run validator unit tests and establish RED/GREEN**

  ```bash
  python3 -m unittest -v \
    test.tap.tests.mysql_router.test_verify_release_gate
  ```

  Expected GREEN after implementation: good synthetic evidence passes and each individually corrupted fixture fails with the named reason.

- [ ] **Step 4: Wire CI jobs with explicit dependencies**

  Define jobs `build-v4`, `chassis-units`, `router-units`, `compatibility-matrix`, `faults`, `fuzz-sanitizers`, `tsan-soak`, `scale`, `upgrade-takeover`, `packages`, and final `release-gate`. The final job downloads every evidence artifact and runs only the validator; it has `needs` on all prior jobs and `if: always()` so a missing artifact cannot be hidden.

- [ ] **Step 5: Run the local pre-merge subset**

  ```bash
  make PROXYSQL40=1 -C plugins/mysql_router clean all
  make -C test/tap/tests/unit PROXYSQL40=1 unit_tests -B
  for group in mysql-router-ic mysql-router-rs mysql-router-cs \
    mysql-router-shell mysql-router-takeover mysql-router-faults \
    mysql-router-upgrade mysql-router-package; do
    WORKSPACE="$(pwd)" INFRA_ID="${group}-${USER}" TAP_GROUP="$group" \
      test/scripts/run-tests-isolated.bash || exit 1
  done
  python3 test/tap/tests/mysql_router/verify_release_gate.py \
    --evidence test/tap/results
  ```

  Expected GREEN: unit/integration subset passes and evidence validator reports every required non-soak category present. Full CI supplies matrix, fuzz, scale, and 24-hour soak evidence.

- [ ] **Step 6: Commit support policy and release gate**

  ```bash
  git add .github/workflows/CI-mysql-router.yml README.md \
    doc/mysql-router-plugin.md doc/mysql-router-plugin-support.md \
    test/tap/tests/mysql_router/verify_release_gate.py \
    test/tap/tests/mysql_router/test_verify_release_gate.py
  git commit -m "ci(mysql-router): enforce supported release gate"
  ```
