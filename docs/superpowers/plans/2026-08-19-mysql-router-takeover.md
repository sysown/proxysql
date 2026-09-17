# Existing MySQL Router Takeover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Import an existing MySQL Router 8.4 deployment into `mysql_router`, adopt its metadata identity and Classic ports, migrate readable credentials, and start ProxySQL in its place without modifying or deleting Router files.

**Architecture:** A plugin-owned one-shot action parses Router INI, dynamic-state JSON, and local keyring inputs into a typed import candidate and report. It verifies remote metadata identity and service-account privileges before feeding the same bootstrap/compiler pipeline used by a new deployment; all source files remain read-only rollback artifacts.

**Tech Stack:** C++17, ProxySQL plugin ABI 8, MySQL Router 8.4 INI/state/keyring formats, OpenSSL EVP AES-256-CBC compatibility reader, chassis AES-256-GCM secret store, SQLite, MariaDB Connector/C, TAP, GNU Make, MySQL Shell 8.4.

**Spec:** `docs/superpowers/specs/2026-08-19-mysql-router-plugin-design.md`

## Global Constraints

- This plan depends on the chassis, plugin-foundation, and topology-expansion plans dated 2026-08-19.
- Import only MySQL Router 8.4-or-newer configuration contracts; fail with a precise version/shape error for unsupported older layouts.
- Open every Router input read-only; never rewrite, rename, chmod, truncate, remove, or create a sibling file.
- Preserve the existing `v2_routers.router_id`, address, router name, Shell-owned options, and topology association when identity validation succeeds.
- Require the old Router to be stopped before committing takeover; a bound Classic port aborts import.
- Import only Classic writer, reader, and R/W-split intent. Report X routes, REST sections, Routing Guidelines, and Router-specific sharing/access-mode semantics as unsupported or translated; never silently discard them.
- Translate endpoint intent to ProxySQL-native hostgroups and query rules; do not emulate Router packet forwarding or connection pinning.
- Migrate a readable metadata password directly into the chassis secret store and cleanse compatibility-decryption buffers.
- Never assume an adopted Router account can read application-account definitions or grant itself privileges.
- If account-sync privilege is missing, require a separately provisioned plugin account or explicit bootstrap-administrator credentials for a narrow grant.
- Produce an imported/translated/unresolved outcome for every relevant config section and referenced file.
- Never expose source passwords, decrypted key material, verifiers, or keyring ciphertext through import reports, logs, Admin tables, status JSON, or metrics.

---

## File Map

- `plugins/mysql_router/include/mysql_router_import.h`: import candidate, outcomes, credential mode, and orchestration API.
- `plugins/mysql_router/src/router_config_reader.cpp`: bounded INI/include parser and supported section translator.
- `plugins/mysql_router/src/router_state_reader.cpp`: strict dynamic-state JSON reader.
- `plugins/mysql_router/src/router_keyring_reader.cpp`: read-only MRKF/MRKR compatibility decoder.
- `plugins/mysql_router/src/import_identity.cpp`: metadata row, topology, account, and privilege validation.
- `plugins/mysql_router/src/import.cpp`: idempotent import journal and bootstrap/compiler handoff.
- `plugins/mysql_router/src/admin_schema.cpp`, `src/status.cpp`: import report persistence/projection.
- `test/tap/tests/fixtures/mysql_router/`: sanitized 8.4 config, state, master-key, and keyring fixtures for all three topology types.
- `test/tap/tests/unit/mysql_router_import_*_unit-t.cpp`: parser, crypto, identity, and transaction tests.
- `test/tap/tests/test_mysql_router_takeover-t.cpp`: real Router-to-ProxySQL port/identity acceptance test.

### Task 1: Register import CLI and parse Router configuration safely

**Files:**

- Create: `plugins/mysql_router/include/mysql_router_import.h`
- Create: `plugins/mysql_router/src/router_config_reader.cpp`
- Create: `test/tap/tests/unit/mysql_router_import_config_unit-t.cpp`
- Create: `test/tap/tests/fixtures/mysql_router/innodb_cluster/mysqlrouter.conf`
- Create: `test/tap/tests/fixtures/mysql_router/replicaset/mysqlrouter.conf`
- Create: `test/tap/tests/fixtures/mysql_router/clusterset/mysqlrouter.conf`
- Modify: `plugins/mysql_router/src/bootstrap_options.cpp`
- Modify: `plugins/mysql_router/src/plugin.cpp`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: ABI-v8 CLI registry and early-action context.
- Produces:
  - `ImportOptions parse_import_options(...)`
  - `RouterConfig RouterConfigReader::read(const std::filesystem::path&)`
  - `std::vector<ImportOutcome> RouterConfigReader::outcomes()`.

- [ ] **Step 1: Register the exact takeover CLI surface**

  Add:

  ```text
  --import-mysqlrouter PATH
  --import-keyring-key-fd FD
  --import-admin USER@HOST[:PORT]
  --import-admin-password-fd FD
  --import-account-mode adopt|repair|replace
  --import-service-account USER
  --import-report text|json
  --force
  ```

  `--bootstrap` and `--import-mysqlrouter` are mutually exclusive. `repair` requires both import-admin flags; `replace` requires import-admin flags plus `--import-service-account`; `adopt` rejects those repair-only values to avoid ambiguous authority.

- [ ] **Step 2: Add bounded-file and INI grammar tests**

  Cover: regular file, empty file, file over 4 MiB, embedded NUL, CRLF, duplicate key, duplicate singleton metadata-cache section, comments, quoted/unquoted values, relative/default paths, `!include`, include cycle, include depth above 8, nonregular FIFO, and unreadable file. Resolve includes relative to the containing file and record every canonical source path.

- [ ] **Step 3: Assert supported section extraction**

  Require typed values from `[DEFAULT]`, exactly one `[metadata_cache:*]`, and every `[routing:*]`:

  ```cpp
  is(config.metadata.router_id, 14u, "router_id imported");
  is(config.metadata.user, "mysql_router14_abcd", "metadata user imported");
  is(config.defaults.dynamic_state, expected_state, "state path resolved");
  is(config.defaults.keyring_path, expected_keyring, "keyring path resolved");
  is(config.classic_routes.size(), 3u, "three Classic routes discovered");
  ok(config.x_routes.size() == 2, "X routes retained for unresolved report");
  ```

- [ ] **Step 4: Run the parser test to establish RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_import_config_unit-t -B
  ```

  Expected RED: import option and Router config reader symbols are absent.

- [ ] **Step 5: Implement descriptor-relative, read-only file access**

  Open the root with `O_RDONLY|O_CLOEXEC`, verify `S_ISREG`, cap bytes before allocation, and capture `(device,inode,size,mtime,sha256)` for the report. Open relative references through their canonical parent directory. Detect an include cycle by `(device,inode)`, not only path text.

- [ ] **Step 6: Implement a strict section model**

  ```cpp
  struct RouterConfig {
    RouterDefaults defaults;
    RouterMetadataCache metadata;
    std::vector<RouterRoute> classic_routes;
    std::vector<RouterRoute> x_routes;
    std::vector<RouterUnsupportedSection> unsupported;
    std::vector<SourceFileIdentity> sources;
  };
  ```

  Reject duplicate values that would alter identity or paths. Retain unknown sections/keys as unresolved outcomes with redacted values for keys containing `password`, `key`, `secret`, or `token`.

- [ ] **Step 7: Run parser tests and verify fixture immutability**

  ```bash
  before=$(sha256sum test/tap/tests/fixtures/mysql_router/*/mysqlrouter.conf)
  make -C test/tap/tests/unit PROXYSQL40=1 mysql_router_import_config_unit-t -B
  test/tap/tests/unit/mysql_router_import_config_unit-t
  after=$(sha256sum test/tap/tests/fixtures/mysql_router/*/mysqlrouter.conf)
  test "$before" = "$after"
  ```

  Expected GREEN: TAP exits 0 and fixture hashes are identical.

- [ ] **Step 8: Commit import CLI and config parser**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_import_config_unit-t.cpp \
    test/tap/tests/fixtures/mysql_router
  git commit -m "feat(mysql-router): parse existing Router configuration"
  ```

### Task 2: Parse dynamic state and translate Classic routes

**Files:**

- Create: `plugins/mysql_router/src/router_state_reader.cpp`
- Create: `test/tap/tests/unit/mysql_router_import_state_unit-t.cpp`
- Create: `test/tap/tests/unit/mysql_router_import_routes_unit-t.cpp`
- Create: `test/tap/tests/fixtures/mysql_router/innodb_cluster/state.json`
- Create: `test/tap/tests/fixtures/mysql_router/replicaset/state.json`
- Create: `test/tap/tests/fixtures/mysql_router/clusterset/state.json`
- Modify: `plugins/mysql_router/include/mysql_router_import.h`
- Modify: `plugins/mysql_router/src/router_config_reader.cpp`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: Router 8.4 dynamic-state schema and parsed routing sections.
- Produces:
  - `RouterDynamicState RouterStateReader::read(path)`
  - `ImportedListenerProfile translate_classic_routes(const RouterConfig&)`.

- [ ] **Step 1: Add strict dynamic-state schema tests**

  Accept:

  ```json
  {
    "version": "1.0.0",
    "metadata-cache": {
      "group-replication-id": "cluster-uuid",
      "cluster-metadata-servers": ["mysql://db1:3306", "mysql://db2:3306"],
      "view-id": 9
    }
  }
  ```

  and the ClusterSet form with `clusterset-id`. A ClusterSet state may also
  carry `group-replication-id` for its member cluster; validate that pair
  against the topology instead of rejecting it. Reject neither ID, duplicate
  endpoint, password-bearing URI, non-MySQL scheme, port overflow, unknown
  top-level key, missing list, empty list, or file above 1 MiB.

- [ ] **Step 2: Add Classic route translation tests**

  Classify only `protocol=classic` metadata-cache routes:

  ```text
  role=PRIMARY -> writer
  role=SECONDARY -> reader
  role=PRIMARY_AND_SECONDARY + access_mode=read_only -> reader
  role=PRIMARY_AND_SECONDARY + access_mode=auto -> rw_split
  ```

  Require a unique bind address/port per intent. Translate `routing_strategy` and `connection_sharing` into a report note because native ProxySQL pooling/routing replaces them. Mark `protocol=x`, static destination lists, socket-only routes, and guideline route selectors unresolved in this release.

- [ ] **Step 3: Run state/route tests to establish RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_import_state_unit-t mysql_router_import_routes_unit-t -B
  ```

  Expected RED: state reader and route translator are absent.

- [ ] **Step 4: Implement bounded JSON parsing and identity mapping**

  Reuse the repository JSON parser with duplicate-key rejection enabled. Map `group-replication-id` to an InnoDB Cluster or ReplicaSet candidate pending metadata verification; map `clusterset-id` directly to ClusterSet. Treat `view-id` only as a diagnostic hint, never as proof that the state is current.

- [ ] **Step 5: Translate listener endpoints into plugin config**

  Use imported addresses/ports when all three intents exist. If R/W split is absent, add the standard 6450 endpoint and report it as translated. If RW/RO are absent or ambiguous, leave the candidate unresolved and require explicit native bootstrap instead of guessing.

- [ ] **Step 6: Run state/route tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_import_state_unit-t mysql_router_import_routes_unit-t -B
  test/tap/tests/unit/mysql_router_import_state_unit-t
  test/tap/tests/unit/mysql_router_import_routes_unit-t
  ```

  Expected GREEN: all three topology fixtures decode and every unsupported route produces an outcome row.

- [ ] **Step 7: Commit state and route translation**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_import_state_unit-t.cpp \
    test/tap/tests/unit/mysql_router_import_routes_unit-t.cpp \
    test/tap/tests/fixtures/mysql_router
  git commit -m "feat(mysql-router): translate Router state and routes"
  ```

### Task 3: Decode local MySQL Router keyrings read-only

**Files:**

- Create: `plugins/mysql_router/src/router_keyring_reader.cpp`
- Create: `plugins/mysql_router/include/router_keyring_format.h`
- Create: `test/tap/tests/unit/mysql_router_import_keyring_unit-t.cpp`
- Create: `test/tap/tests/fixtures/mysql_router/innodb_cluster/master.key`
- Create: `test/tap/tests/fixtures/mysql_router/innodb_cluster/keyring`
- Modify: `plugins/mysql_router/include/mysql_router_import.h`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: Router `MRKF\0` master-key file, `MRKR` keyring file, optional raw key FD, and OpenSSL AES-256-CBC.
- Produces: `SecureBytes RouterKeyringReader::read_password(const RouterKeyringInput&, std::string_view metadata_user)`.

- [ ] **Step 1: Add known-answer compatibility fixtures**

  Generate fixtures once with MySQL Router 8.4's own keyring implementation for metadata user `mysql_router14_abcd` and test password `router-fixture-password`. Commit the binary files plus `SHA256SUMS` and a non-secret README naming the upstream generator/version.

- [ ] **Step 2: Add binary format and corruption tests**

  Assert valid round-trip, wrong user, wrong raw key, bad `MRKF\0`, bad `MRKR`, truncated length, oversized entry count, invalid PKCS#7 padding, wrong internal signature `0x043d4d0a`, unsupported keyring format version, non-private source permissions, and source symlink replacement between config parse/read.

- [ ] **Step 3: Run the keyring test and establish RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_import_keyring_unit-t -B
  ```

  Expected RED: compatibility reader is absent.

- [ ] **Step 4: Implement the master-key file decoder**

  Parse little-endian 32-bit lengths with checked arithmetic. Read the clear 32-byte scramble from the MRKR header. Find the MRKF entry whose ID matches the canonical keyring path, with the original config spelling as the fallback. AES-256-CBC decrypt its value using the header scramble and Router's fixed IV:

  ```cpp
  constexpr uint8_t kRouterIv[16] = {
    0x39,0x62,0x9f,0x52,0x7f,0x76,0x9a,0xae,
    0xcd,0xca,0xf7,0x04,0x65,0x8e,0x5d,0x88
  };
  ```

- [ ] **Step 5: Implement the keyring decoder**

  Verify `MRKR`, skip/read the header, AES-256-CBC decrypt the remaining bytes with the recovered 32-byte master key and same IV, then parse internal signature, format version, entry map, and the `password` attribute for the exact metadata username. Cap entries at 4096, attributes at 64 per entry, strings at 64 KiB, and total file at 16 MiB.

- [ ] **Step 6: Support explicit key FD and unsupported providers**

  When `--import-keyring-key-fd` is present, read exactly one key line and use it instead of MRKF. If config refers to `master_key_reader`/external provider and no FD is supplied, return unresolved `external key provider requires --import-keyring-key-fd`; do not execute an arbitrary Router helper command.

- [ ] **Step 7: Store migrated secret and cleanse compatibility buffers**

  Immediately pass the recovered password to chassis `put_secret(owner='mysql_router', name='metadata:<uuid>')`. Cleanse the password, master key, scramble-derived plaintext, decrypted keyring block, and FD buffer on success/failure.

- [ ] **Step 8: Run keyring, secret-store, and immutability checks**

  ```bash
  before=$(sha256sum test/tap/tests/fixtures/mysql_router/innodb_cluster/{master.key,keyring})
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_import_keyring_unit-t plugin_secrets_unit-t -B
  test/tap/tests/unit/mysql_router_import_keyring_unit-t
  test/tap/tests/unit/plugin_secrets_unit-t
  after=$(sha256sum test/tap/tests/fixtures/mysql_router/innodb_cluster/{master.key,keyring})
  test "$before" = "$after"
  ```

  Expected GREEN: both TAP binaries exit 0 and binary fixture hashes remain unchanged.

- [ ] **Step 9: Commit the read-only compatibility reader**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_import_keyring_unit-t.cpp \
    test/tap/tests/fixtures/mysql_router/innodb_cluster
  git commit -m "feat(mysql-router): import Router keyring credentials"
  ```

### Task 4: Validate and adopt metadata identity and service-account authority

**Files:**

- Create: `plugins/mysql_router/src/import_identity.cpp`
- Create: `test/tap/tests/unit/mysql_router_import_identity_unit-t.cpp`
- Modify: `plugins/mysql_router/include/mysql_router_import.h`
- Modify: `plugins/mysql_router/src/router_registration.cpp`
- Modify: `plugins/mysql_router/src/bootstrap.cpp`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: parsed router ID/name/address/user, dynamic topology ID/endpoints, migrated or prompted secret, and metadata adapter.
- Produces: `AdoptedRouterIdentity validate_import_identity(...)` and `AccountAuthority validate_import_account(...)`.

- [ ] **Step 1: Add identity mismatch tests**

  Cover exact match plus: missing router ID, wrong address/name, wrong topology UUID, registration attached to another ClusterSet, metadata username attribute mismatch, duplicate address/name row, state seed from another topology, and Router version below 8.4. Every mismatch fails before local ownership/config changes.

- [ ] **Step 2: Add account-mode tests**

  `adopt` succeeds only when the account can connect and has metadata read/update, GR/replication health, and column-level account-definition reads. `repair` uses the explicit import admin solely to grant missing narrow privileges. `replace` creates/validates the separate service account and updates only the adopted Router row's `MetadataUser` attribute.

- [ ] **Step 3: Run identity tests and observe RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_import_identity_unit-t -B
  ```

  Expected RED: import identity/account validator is absent.

- [ ] **Step 4: Verify the remote Router row and topology association**

  Query `v2_routers WHERE router_id=?`, compare normalized host address and exact router name, then read the topology through the selected adapter. For Cluster/ReplicaSet require matching `cluster_id`; for ClusterSet require matching `clusterset_id`. The state file ID and remote association must agree.

- [ ] **Step 5: Validate grants by exercising prepared statements**

  Connect as the adopted service account and run one read-only statement from each required privilege family plus a transaction that updates `last_check_in` and rolls back. Run the exact account-definition SELECT with `LIMIT 0`. Return structured missing capabilities rather than parsing localized `SHOW GRANTS` text.

- [ ] **Step 6: Repair or replace only with explicit authority**

  Reuse the narrow grant list from native bootstrap. For `repair`, grant only missing entries to the adopted account. For `replace`, create/validate the specified new account, store its secret, update `MetadataUser`, and leave the old Router account intact for rollback.

- [ ] **Step 7: Preserve the registration identity while changing product contract**

  Update the adopted row in place: keep router ID/address/name/options/topology fields, set product `ProxySQL`, contract `8.4.0`, Classic endpoints, custom real-version attributes, and remove X/guideline attributes. Never insert a second row.

- [ ] **Step 8: Run identity/bootstrap/registration tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_import_identity_unit-t mysql_router_bootstrap_unit-t \
    mysql_router_registration_unit-t -B
  test/tap/tests/unit/mysql_router_import_identity_unit-t
  test/tap/tests/unit/mysql_router_bootstrap_unit-t
  test/tap/tests/unit/mysql_router_registration_unit-t
  ```

  Expected GREEN: all adoption modes are explicit and no test inserts a second registration.

- [ ] **Step 9: Commit identity and privilege adoption**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_import_identity_unit-t.cpp
  git commit -m "feat(mysql-router): adopt Router metadata identity"
  ```

### Task 5: Make takeover idempotent, port-safe, and fully reported

**Files:**

- Create: `plugins/mysql_router/src/import.cpp`
- Create: `test/tap/tests/unit/mysql_router_import_unit-t.cpp`
- Modify: `plugins/mysql_router/src/admin_schema.cpp`
- Modify: `plugins/mysql_router/src/status.cpp`
- Modify: `plugins/mysql_router/src/plugin.cpp`
- Modify: `plugins/mysql_router/include/mysql_router_import.h`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: config/state/keyring candidate, adopted identity, standard hostgroup/compiler/bootstrap journal, and scoped publisher.
- Produces: `ImportResult MysqlRouterImporter::run(const ImportOptions&)` plus `stats_mysql_router_import` rows.

- [ ] **Step 1: Define report schema and redaction tests**

  Use:

  ```sql
  CREATE TABLE stats_mysql_router_import (
    import_id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    source_path TEXT NOT NULL,
    section_name TEXT NOT NULL,
    item_name TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN ('imported','translated','unresolved')),
    detail TEXT NOT NULL
  );
  ```

  Assert every parsed relevant key/section and referenced file receives at least one row; scan text/JSON/Admin output for fixture passwords, master key, authentication strings, and raw ciphertext.

- [ ] **Step 2: Add port-conflict and crash-resume tests**

  Bind each candidate TCP port and assert import fails before metadata/local mutation. Then inject failure after identity update, secret migration, hostgroup allocation, local config staging, and scoped publication. Re-running must converge to one identity, one role mapping per role, one secret, and one complete config generation.

- [ ] **Step 3: Run importer tests and observe RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 mysql_router_import_unit-t -B
  ```

  Expected RED: importer orchestration/report persistence is missing.

- [ ] **Step 4: Probe listener availability before remote mutation**

  For every imported TCP endpoint, create a socket with `SO_REUSEADDR=0`, bind the exact address/port, and close it. Treat `EADDRINUSE` as `old Router or another process is still listening`. For wildcard IPv4/IPv6, check dual-stack conflicts explicitly. Repeat immediately before local config commit to narrow the race.

- [ ] **Step 5: Use the bootstrap journal with import-specific phases**

  Persist:

  ```text
  import_parsed
  identity_validated
  credentials_ready
  registration_adopted
  local_configured
  complete
  ```

  Record source file identities and import mode alongside the journal. On resume, re-hash files; require `--force` to continue if any input changed, and rerun identity/port checks even when unchanged.

- [ ] **Step 6: Feed the normal topology/compiler pipeline**

  Allocate the topology's managed role set, configure imported Classic addresses/ports plus a translated 6450 if missing, compile current effective topology/users, and apply one complete generation. Original Router route strategies become explanatory report rows; native ProxySQL rules remain authoritative.

- [ ] **Step 7: Emit a concise safe completion summary**

  Text output contains adopted Router label/ID, topology type/UUID, three Classic endpoints, account mode, counts by outcome, unresolved section names, and source paths. JSON contains the same fields. Neither includes config values marked sensitive.

- [ ] **Step 8: Run all importer units**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_import_config_unit-t mysql_router_import_state_unit-t \
    mysql_router_import_routes_unit-t mysql_router_import_keyring_unit-t \
    mysql_router_import_identity_unit-t mysql_router_import_unit-t -B
  for t in test/tap/tests/unit/mysql_router_import_*_unit-t; do "$t" || exit 1; done
  ```

  Expected GREEN: all importer units exit 0 and redaction scans pass.

- [ ] **Step 9: Commit takeover orchestration/reporting**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_import_unit-t.cpp
  git commit -m "feat(mysql-router): complete idempotent Router takeover"
  ```

### Task 6: Prove stop-Router/start-ProxySQL takeover on the same ports

**Files:**

- Create: `test/tap/tests/test_mysql_router_takeover-t.cpp`
- Create: `test/tap/tests/mysql_router/takeover_assert.js`
- Modify: `test/tap/tests/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**

- Consumes: MySQL Router 8.4 binary, MySQL Shell 8.4, InnoDB Cluster fixture, built plugin, and isolated runner.
- Produces: end-to-end drop-in takeover acceptance.

- [ ] **Step 1: Bootstrap and exercise real MySQL Router**

  Use the stock Router binary to bootstrap `router-takeover` on 6446/6447/6450. Record its `router_id`, Shell `listRouters()` result, config/state/keyring hashes, and successful application traffic through each Classic endpoint.

- [ ] **Step 2: Prove live-Router conflict is rejected**

  While Router is running, invoke ProxySQL import. Assert nonzero exit, an `EADDRINUSE`-class message, unchanged metadata registration, no plugin managed hostgroups/users, and unchanged source hashes.

- [ ] **Step 3: Stop Router and import without editing its files**

  Stop the Router process cleanly, invoke:

  ```bash
  proxysql --load-plugin=mysql_router \
    --import-mysqlrouter "${ROUTER_DIR}/mysqlrouter.conf" \
    --import-account-mode repair \
    --import-admin "root@${MYSQL84_SEED}" \
    --import-admin-password-fd 9 9<"${PASSFILE}"
  ```

  Assert exit 0, adopted router ID, all source hashes unchanged, and imported/translated/unresolved report rows.

- [ ] **Step 4: Start ProxySQL and assert the same public contract**

  Start normally with `--load-plugin=mysql_router`. Connect the unchanged application configuration to 6446/6447/6450, run write/read/transaction cases, and assert ProxySQL native query digest/pool stats increase.

- [ ] **Step 5: Assert unmodified Shell sees one adopted identity**

  Run `listRouters()`, `routerOptions()`, `routingOptions()`, and `setRoutingOption()` through stock Shell. Assert the original router ID/label remains, product is now ProxySQL, version is 8.4.0, and no duplicate row exists.

- [ ] **Step 6: Assert rollback artifacts remain usable**

  Stop ProxySQL, verify the Router config/state/keyring/master-key hashes again, then start the original Router and prove it can still read its files and metadata account. Stop it after the assertion so the test leaves no listener behind.

- [ ] **Step 7: Run the isolated takeover group**

  ```bash
  WORKSPACE="$(pwd)" INFRA_ID="mysql-router-takeover-${USER}" \
    TAP_GROUP=mysql-router-takeover \
    test/scripts/run-tests-isolated.bash -k test_mysql_router_takeover-t
  ```

  Expected GREEN: conflict, takeover, Shell identity, native routing, file immutability, and rollback-start assertions all pass.

- [ ] **Step 8: Commit takeover acceptance coverage**

  ```bash
  git add test/tap/groups/groups.json test/tap/tests/Makefile \
    test/tap/tests/test_mysql_router_takeover-t.cpp \
    test/tap/tests/mysql_router/takeover_assert.js
  git commit -m "test(mysql-router): prove existing Router takeover"
  ```

### Task 7: Document migration outcomes and operator choices

**Files:**

- Modify: `doc/mysql-router-plugin.md`
- Create: `doc/mysql-router-plugin-takeover.md`

**Interfaces:**

- Consumes: completed importer behavior.
- Produces: an operational takeover/rollback runbook.

- [ ] **Step 1: Document preflight and exact commands**

  Cover file backups, current Router/Shell 8.4 verification, account-mode choice, live port-conflict check, stop/import/start, status/report queries, application smoke tests, and rollback start.

- [ ] **Step 2: Document the translation matrix**

  Include:

  | Router input | Outcome |
  |---|---|
  | metadata identity/user/seeds | imported |
  | Classic RW/RO/RW-split address/port | imported |
  | route strategy/connection sharing/access mode | translated to native ProxySQL behavior |
  | missing R/W-split route | translated to standard 6450 |
  | X routes | unresolved, unsupported |
  | Routing Guidelines | unresolved, unsupported |
  | REST configuration | unresolved, unsupported |
  | local readable keyring | imported into chassis secret store |
  | external key provider | unresolved until key FD/account replacement |

- [ ] **Step 3: Document account modes and least privilege**

  Explain `adopt`, `repair`, and `replace`, including why the standard Router account may lack column-level `mysql.user` read. State that no account can self-grant and that the original account is not dropped.

- [ ] **Step 4: Verify docs commands against CLI help and tests**

  ```bash
  ./src/proxysql --load-plugin=mysql_router --help > /tmp/proxysql-router-help.txt
  for option in --import-mysqlrouter --import-account-mode --import-admin \
    --import-admin-password-fd --import-keyring-key-fd; do
    grep -F -- "$option" /tmp/proxysql-router-help.txt || exit 1
  done
  test/tap/tests/unit/mysql_router_import_config_unit-t
  test/tap/tests/unit/mysql_router_import_unit-t
  ```

  Expected GREEN: every documented option is in help and both units exit 0.

- [ ] **Step 5: Commit takeover documentation**

  ```bash
  git add doc/mysql-router-plugin.md doc/mysql-router-plugin-takeover.md
  git commit -m "docs(mysql-router): add Router takeover runbook"
  ```
