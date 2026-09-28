# MySQL Router Plugin Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `proxysql_mysql_router.so` with native bootstrap, unmodified MySQL Shell 8.4 registration, InnoDB Cluster and read-replica discovery, managed users, and Router-compatible Classic endpoints backed by ProxySQL-native routing.

**Architecture:** The plugin converts AdminAPI metadata plus live Group Replication observations into immutable `DesiredTopology`, `ObservedHealth`, and `EffectiveTopology` values. A compiler maps each validated effective generation onto persisted, plugin-owned hostgroups, users, interfaces, and baseline query rules through the generic ABI-8 scoped publisher; ProxySQL continues to own the data plane.

**Tech Stack:** C++17, ProxySQL plugin ABI 8, MariaDB Connector/C, MySQL 8.4 metadata schema 2.2, SQLite, OpenSSL, prometheus-cpp, TAP, GNU Make, MySQL Shell 8.4.

**Spec:** `docs/superpowers/specs/2026-08-19-mysql-router-plugin-design.md`

## Global Constraints

- This plan depends on `docs/superpowers/plans/2026-08-19-mysql-router-chassis-foundation.md` and is built only with `PROXYSQL40=1`.
- Public identity is exactly: plugin `mysql_router`, library `proxysql_mysql_router.so`, selector `--load-plugin=mysql_router`, configuration namespace `mysql_router.*`, and metric prefix `proxysql_mysql_router_*`.
- Support MySQL Server and unmodified MySQL Shell 8.4 or newer; reject MySQL Server below 8.4 and metadata schema 1.x.
- Treat metadata schema 2.2 as the first adapter; reject an unimplemented metadata shape before publishing any generation.
- Advertise `product_name='ProxySQL'` and Router contract `version='8.4.0'`; record real ProxySQL/plugin versions only in custom attributes.
- Add Classic endpoints 6446, 6447, and 6450 while preserving 6033 and every operator-defined interface.
- Do not add MySQL X endpoints, Routing Guidelines, REST endpoints, Router connection pinning, or Router packet-forwarding semantics.
- Route 6446 to a stable writer hostgroup, 6447 to a stable reader hostgroup, and 6450 through native ProxySQL query rules.
- Allocate hostgroups dynamically and persist role-to-ID mappings; never assume a hard-coded ID is free.
- Own every row in the persisted managed-hostgroup set and correct/delete drift there; never mutate any other hostgroup.
- Own only plugin-created users and tagged baseline rules; preserve operator users and unrelated rules, including collision winners.
- Keep topology and user generations separate so an account refresh failure cannot delay failover.
- Keep credentials in the chassis secret store; status and stats tables never expose passwords or verifiers.

---

## File Map

- `plugins/mysql_router/Makefile`: build the in-tree ABI-8 shared library.
- `plugins/mysql_router/include/mysql_router_types.h`: immutable topology, health, options, account, generation, and error types.
- `plugins/mysql_router/include/mysql_router_metadata.h`, `src/metadata_client.cpp`, `src/metadata_v2_2.cpp`: metadata transport and schema-2.2 adapter.
- `plugins/mysql_router/include/mysql_router_bootstrap.h`, `src/bootstrap.cpp`: CLI action, credential prompt, journal, account, and registration state machine.
- `plugins/mysql_router/include/mysql_router_config.h`, `src/config_store.cpp`: plugin configuration and persisted identity.
- `plugins/mysql_router/include/mysql_router_compiler.h`, `src/hostgroup_allocator.cpp`, `src/config_compiler.cpp`: collision-free ownership mapping and native ProxySQL desired-state plan.
- `plugins/mysql_router/include/mysql_router_users.h`, `src/user_sync.cpp`: MySQL account normalization and plugin-user ownership.
- `plugins/mysql_router/include/mysql_router_reconciler.h`, `src/reconciler.cpp`, `src/gr_health.cpp`: refresh worker and atomic generation publication.
- `plugins/mysql_router/include/mysql_router_admin.h`, `src/admin_schema.cpp`, `src/status.cpp`, `src/metrics.cpp`: tables, views, commands, status JSON, and metrics.
- `plugins/mysql_router/include/mysql_router_plugin.h`, `src/plugin.cpp`: ABI entry point and lifecycle wiring only.
- `test/tap/tests/unit/mysql_router_*_unit-t.cpp`: deterministic component tests using fake transports and in-memory DBs.
- `test/tap/tests/test_mysql_router_innodb_cluster-t.cpp`: real MySQL 8.4, Shell, endpoint, and failover acceptance test.
- `Makefile`, `test/tap/tests/unit/Makefile`: build/install/clean and unit registrations.

### Task 1: Scaffold the ABI-8 plugin, private schema, and status surface

**Files:**

- Create: `plugins/mysql_router/Makefile`
- Create: `plugins/mysql_router/include/mysql_router_plugin.h`
- Create: `plugins/mysql_router/include/mysql_router_types.h`
- Create: `plugins/mysql_router/include/mysql_router_admin.h`
- Create: `plugins/mysql_router/src/plugin.cpp`
- Create: `plugins/mysql_router/src/admin_schema.cpp`
- Create: `plugins/mysql_router/src/status.cpp`
- Create: `plugins/mysql_router/src/metrics.cpp`
- Create: `test/tap/tests/unit/mysql_router_plugin_load_unit-t.cpp`
- Create: `test/tap/tests/unit/mysql_router_admin_schema_unit-t.cpp`
- Modify: `Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: `ProxySQL_PluginDescriptor` ABI 8, schema/runtime-view registration, Admin command registration, and shared Prometheus registry.
- Produces: `MysqlRouterContext& mysql_router_context()`, plugin schemas, required runtime/stats views, and a loadable `proxysql_mysql_router.so`.

- [ ] **Step 1: Add load and descriptor assertions**

  In `mysql_router_plugin_load_unit-t.cpp`, load the built `.so` through `ProxySQL_PluginManager` and assert:

  ```cpp
  ok(descriptor->name && std::string(descriptor->name) == "mysql_router",
     "plugin identifier is mysql_router");
  ok(descriptor->abi_version == 8, "plugin targets chassis ABI 8");
  ok(descriptor->register_schemas && descriptor->register_cli_options &&
     descriptor->early_action && descriptor->runtime_ready,
     "all required lifecycle callbacks are present");
  ```

- [ ] **Step 2: Add exact table-definition assertions**

  Require these persistent plugin tables in both Admin's in-memory and config databases where indicated:

  ```sql
  CREATE TABLE mysql_router_config (
    config_key TEXT PRIMARY KEY,
    config_value TEXT NOT NULL
  );
  CREATE TABLE mysql_router_instance (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    topology_type TEXT NOT NULL,
    topology_uuid TEXT NOT NULL,
    cluster_id TEXT,
    clusterset_id TEXT,
    router_id INTEGER NOT NULL,
    router_name TEXT NOT NULL,
    router_address TEXT NOT NULL,
    metadata_user TEXT NOT NULL,
    metadata_schema TEXT NOT NULL,
    advertised_version TEXT NOT NULL,
    topology_generation INTEGER NOT NULL DEFAULT 0,
    user_generation INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE mysql_router_hostgroups (
    role TEXT NOT NULL,
    scope_uuid TEXT NOT NULL,
    hostgroup_id INTEGER NOT NULL UNIQUE,
    PRIMARY KEY(role, scope_uuid)
  );
  CREATE TABLE mysql_router_users (
    username TEXT PRIMARY KEY,
    source_fingerprint TEXT NOT NULL,
    auth_plugin TEXT NOT NULL,
    state TEXT NOT NULL,
    last_error TEXT NOT NULL DEFAULT '',
    generation INTEGER NOT NULL
  );
  CREATE TABLE mysql_router_bootstrap_journal (
    topology_uuid TEXT PRIMARY KEY,
    router_name TEXT NOT NULL,
    phase TEXT NOT NULL,
    router_id INTEGER,
    updated_at INTEGER NOT NULL,
    last_error TEXT NOT NULL DEFAULT ''
  );
  ```

  Register these four runtime tables in admindb and three history tables in statsdb. Keep the definitions byte-for-byte stable in the schema assertions:

  ```sql
  CREATE TABLE runtime_mysql_router_status (
    status_key TEXT PRIMARY KEY,
    status_value TEXT NOT NULL
  );
  CREATE TABLE runtime_mysql_router_topology (
    topology_generation INTEGER NOT NULL,
    cluster_uuid TEXT NOT NULL,
    instance_uuid TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    instance_kind TEXT NOT NULL,
    desired_role TEXT NOT NULL,
    observed_state TEXT NOT NULL,
    effective_role TEXT NOT NULL,
    last_observed_at INTEGER NOT NULL,
    PRIMARY KEY(instance_uuid, endpoint)
  );
  CREATE TABLE runtime_mysql_router_hostgroups (
    role TEXT NOT NULL,
    scope_uuid TEXT NOT NULL,
    hostgroup_id INTEGER NOT NULL,
    server_count INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    PRIMARY KEY(role, scope_uuid)
  );
  CREATE TABLE runtime_mysql_router_users (
    username TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    auth_plugin TEXT NOT NULL,
    last_error TEXT NOT NULL,
    generation INTEGER NOT NULL
  );
  CREATE TABLE stats_mysql_router_refresh (
    refresh_id INTEGER PRIMARY KEY,
    started_at INTEGER NOT NULL,
    completed_at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    result TEXT NOT NULL,
    from_generation INTEGER NOT NULL,
    to_generation INTEGER NOT NULL,
    error_code TEXT NOT NULL,
    error_message TEXT NOT NULL
  );
  CREATE TABLE stats_mysql_router_errors (
    error_id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    code TEXT NOT NULL,
    message TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
  );
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

- [ ] **Step 3: Run new tests to establish RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_plugin_load_unit-t mysql_router_admin_schema_unit-t -B
  ```

  Expected RED: the plugin directory, shared object, and schemas do not exist.

- [ ] **Step 4: Define the lifecycle-only context**

  Keep `plugin.cpp` free of metadata policy:

  ```cpp
  struct MysqlRouterContext {
    ProxySQL_PluginServices* services {nullptr};
    std::unique_ptr<MysqlRouterConfigStore> config;
    std::unique_ptr<MysqlRouterReconciler> reconciler;
    std::atomic<bool> started {false};
    std::atomic<bool> runtime_ready {false};
    std::mutex status_mutex;
    MysqlRouterStatus status;
  };
  ```

  `register_schemas()` only registers tables, views, and exact Admin commands. `init()` loads persisted plugin state. `start()` constructs a paused worker. `runtime_ready()` performs the first synchronous refresh and releases the worker. `stop()` joins it and clears gates.

- [ ] **Step 5: Register status tables and command spellings**

  Register:

  ```text
  LOAD MYSQL ROUTER CONFIG TO RUNTIME
  SAVE MYSQL ROUTER CONFIG FROM RUNTIME
  MYSQL ROUTER RECONCILE
  ```

  Runtime-view callbacks replace their destination table in one SQLite transaction. `runtime_mysql_router_users` columns are `username,state,auth_plugin,last_error,generation`; there is no password column.

- [ ] **Step 6: Register the initial metric families**

  Create these exact metrics once in `init()`:

  ```text
  proxysql_mysql_router_metadata_available
  proxysql_mysql_router_refresh_total{kind,result}
  proxysql_mysql_router_generation{kind}
  proxysql_mysql_router_managed_servers{role,state}
  proxysql_mysql_router_writer_changes_total
  proxysql_mysql_router_drift_corrections_total
  proxysql_mysql_router_unresolved_users
  proxysql_mysql_router_stale_seconds
  ```

- [ ] **Step 7: Wire build, clean, install, and test rules**

  Follow `plugins/mysqlx/Makefile` for tier flags and hidden visibility, but link only required Connector/C, SSL/crypto, SQLite, prometheus, pthread, and core symbols. Extend top-level release/debug/clean/install targets. Install the file as `/usr/lib/proxysql/plugins/proxysql_mysql_router.so` with mode 0755.

- [ ] **Step 8: Build and run scaffold tests**

  ```bash
  make PROXYSQL40=1 -C plugins/mysql_router clean all
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_plugin_load_unit-t mysql_router_admin_schema_unit-t -B
  test/tap/tests/unit/mysql_router_plugin_load_unit-t
  test/tap/tests/unit/mysql_router_admin_schema_unit-t
  ```

  Expected GREEN: the `.so` exports only `proxysql_plugin_descriptor_v1`, both tests exit 0, and all required table names are registered in the correct DB kind.

- [ ] **Step 9: Commit the plugin shell**

  ```bash
  git add Makefile plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_plugin_load_unit-t.cpp \
    test/tap/tests/unit/mysql_router_admin_schema_unit-t.cpp
  git commit -m "feat(mysql-router): scaffold ProxySQL 4.0 plugin"
  ```

### Task 2: Parse Router-compatible bootstrap input without leaking credentials

**Files:**

- Create: `plugins/mysql_router/include/mysql_router_bootstrap.h`
- Create: `plugins/mysql_router/include/mysql_router_config.h`
- Create: `plugins/mysql_router/src/bootstrap_options.cpp`
- Create: `plugins/mysql_router/src/config_store.cpp`
- Create: `test/tap/tests/unit/mysql_router_bootstrap_options_unit-t.cpp`
- Modify: `plugins/mysql_router/src/plugin.cpp`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: ABI-8 CLI registry and parsed-option action context.
- Produces:
  - `BootstrapOptions parse_bootstrap_options(const ProxySQL_PluginEarlyActionContext&)`
  - `MetadataEndpoint parse_metadata_uri(std::string_view)`
  - `SecureBytes read_bootstrap_password(const BootstrapOptions&)`.

- [ ] **Step 1: Test the exact CLI surface and URI grammar**

  Register and test:

  ```text
  -B, --bootstrap USER@HOST[:PORT]
  --router-name NAME
  --account USER
  --account-create if-not-exists|always|never
  --account-host HOST_PATTERN
  --password-retries N
  --bootstrap-password-fd FD
  --force
  --replace-topology
  --conf-bind-address ADDRESS
  --conf-base-port PORT
  --conf-use-sockets
  --conf-skip-tcp
  --ssl-ca --ssl-capath --ssl-cert --ssl-key --ssl-cipher --ssl-crl --ssl-crlpath
  --ssl-mode DISABLED|PREFERRED|REQUIRED|VERIFY_CA|VERIFY_IDENTITY
  ```

  Assert IPv4, bracketed IPv6, default 3306, percent-decoded usernames, conflicting socket/TCP flags, port overflow, invalid account policy, and rejection of any URI containing a password.

- [ ] **Step 2: Run the parser test to establish RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_bootstrap_options_unit-t -B
  ```

  Expected RED: parser types are undefined.

- [ ] **Step 3: Define owned option values**

  ```cpp
  struct BootstrapOptions {
    bool requested {false};
    MetadataEndpoint seed;
    std::string router_name;
    std::string service_account;
    AccountCreatePolicy account_create {AccountCreatePolicy::if_not_exists};
    std::string account_host {"%"};
    unsigned password_retries {20};
    std::optional<int> password_fd;
    bool force {false};
    bool replace_topology {false};
    ListenerProfile listeners;
    TlsOptions tls;
  };
  ```

  Defaults are bind address `0.0.0.0`, base port 6446, with RO at base+1 and R/W split at base+4. The advertised standard values are therefore 6446, 6447, and 6450.

- [ ] **Step 4: Implement secure password acquisition**

  For `--bootstrap-password-fd`, use `fcntl(F_GETFL)` to validate an open readable descriptor, read at most 4096 bytes, strip one trailing newline, and never log bytes. Otherwise open `/dev/tty`, disable `ECHO` with `termios`, prompt `Please enter MySQL password for <user>: `, restore terminal flags through RAII, and cleanse the buffer after use.

- [ ] **Step 5: Persist non-secret config through `MysqlRouterConfigStore`**

  Implement typed getters over `mysql_router_config`; permit only keys declared in this enum:

  ```cpp
  enum class MysqlRouterConfigKey {
    refresh_interval_ms,
    connect_timeout_ms,
    read_timeout_ms,
    bind_address,
    rw_port,
    ro_port,
    rw_split_port,
    metadata_ssl_mode
  };
  ```

  Defaults are 2000, 5000, 30000, `0.0.0.0`, 6446, 6447, 6450, and `PREFERRED`. Validate before replacing the in-memory config snapshot.

- [ ] **Step 6: Build and run parser/config tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_bootstrap_options_unit-t mysql_router_admin_schema_unit-t -B
  test/tap/tests/unit/mysql_router_bootstrap_options_unit-t
  test/tap/tests/unit/mysql_router_admin_schema_unit-t
  ```

  Expected GREEN: invalid inputs return explicit errors, URI passwords are rejected, and no captured log contains the test password.

- [ ] **Step 7: Commit bootstrap parsing**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_bootstrap_options_unit-t.cpp
  git commit -m "feat(mysql-router): parse secure bootstrap options"
  ```

### Task 3: Model metadata 2.2 InnoDB Cluster and live GR health

**Files:**

- Create: `plugins/mysql_router/include/mysql_router_metadata.h`
- Create: `plugins/mysql_router/src/metadata_client.cpp`
- Create: `plugins/mysql_router/src/metadata_v2_2.cpp`
- Create: `plugins/mysql_router/src/gr_health.cpp`
- Create: `test/tap/tests/unit/mysql_router_metadata_v2_2_unit-t.cpp`
- Create: `test/tap/tests/unit/mysql_router_gr_health_unit-t.cpp`
- Modify: `plugins/mysql_router/include/mysql_router_types.h`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: Connector/C result sets and metadata schema 2.2 views.
- Produces:
  - `MetadataCapabilities probe_metadata(IMetadataSession&)`
  - `DesiredTopology MetadataV2_2::read_innodb_cluster(...)`
  - `ObservedHealth GrHealthReader::read(...)`
  - `EffectiveTopology evaluate_innodb_cluster(...)`.

- [ ] **Step 1: Define immutable model types and invariants**

  Add:

  ```cpp
  enum class TopologyType { innodb_cluster, replica_set, cluster_set };
  enum class InstanceKind { gr_member, read_replica };
  enum class DesiredRole { writer, reader };
  enum class HealthState { online, recovering, unreachable, offline };

  struct DesiredInstance {
    std::string instance_uuid;
    std::string cluster_uuid;
    std::string label;
    MysqlEndpoint classic;
    InstanceKind kind;
    JsonValue attributes;
  };

  struct DesiredTopology {
    MetadataVersion metadata_version;
    TopologyType type;
    std::string topology_uuid;
    std::string topology_name;
    std::vector<DesiredInstance> instances;
    RouterOptions options;
  };
  ```

  Constructors reject duplicate UUIDs/endpoints, empty topology UUID, invalid ports, a non-2.x version, and instance rows referring to another cluster.

- [ ] **Step 2: Add scripted-session metadata tests**

  Script exact 2.2 queries for:

  ```sql
  SELECT major, minor, patch FROM mysql_innodb_cluster_metadata.schema_version;
  SELECT cluster_id, instance_id, instance_type, cluster_name, cluster_type
    FROM mysql_innodb_cluster_metadata.v2_this_instance;
  SELECT c.cluster_id, c.cluster_name, c.group_name, i.instance_id,
         i.mysql_server_uuid, i.label, i.endpoint, i.attributes, i.instance_type
    FROM mysql_innodb_cluster_metadata.v2_gr_clusters AS c
    JOIN mysql_innodb_cluster_metadata.v2_instances AS i
      ON i.cluster_id=c.cluster_id
   WHERE c.cluster_id=?;
  SELECT router_options FROM mysql_innodb_cluster_metadata.v2_router_options
   WHERE router_id=?;
  ```

  Cover `instance_type='group-member'`, `instance_type='read-replica'`, missing endpoint, duplicate UUID, metadata 1.0 rejection, 2.2 acceptance, and 2.3 rejection until its adapter is delivered.

- [ ] **Step 3: Add GR observation/evaluation tests**

  Parse:

  ```sql
  SELECT member_id, member_host, member_port, member_state, member_role,
         @@group_replication_single_primary_mode
    FROM performance_schema.replication_group_members
   WHERE channel_name='group_replication_applier';
  ```

  Combine it with `@@global.read_only`, `@@global.super_read_only`, and reachability. Assert one writable ONLINE PRIMARY, ONLINE SECONDARY readers, RECOVERING exclusion, quorum calculation, asynchronous read replicas never treated as GR members, and no writer if `super_read_only=1`.

- [ ] **Step 4: Run the two unit targets and observe RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_metadata_v2_2_unit-t mysql_router_gr_health_unit-t -B
  ```

  Expected RED: model and adapter files are missing.

- [ ] **Step 5: Implement a transport-neutral metadata session**

  ```cpp
  class IMetadataSession {
  public:
    virtual ~IMetadataSession() = default;
    virtual QueryResult query(std::string_view sql,
                              const std::vector<SqlValue>& params) = 0;
    virtual ExecResult execute(std::string_view sql,
                               const std::vector<SqlValue>& params) = 0;
    virtual ServerVersion server_version() const = 0;
  };
  ```

  The Connector/C implementation must use prepared statements for values, set connect/read/write timeouts, configure TLS from `TlsOptions`, and retain no bootstrap administrator password after connection teardown.

- [ ] **Step 6: Implement capability probing and the 2.2 adapter**

  Probe version plus required views/columns from `information_schema`. The returned capability set includes `router_options_view=true`, `router_stats=false`, and `routing_guidelines=false` for 2.2. Parse `read_only_targets` values `secondaries|read_replicas|all`, `unreachable_quorum_allowed_traffic` values `none|read|all`, and nullable nonnegative `stats_updates_frequency`; reject an unknown value without replacing the active options.

- [ ] **Step 7: Implement live health and effective-role policy**

  Use metadata for identity and membership, GR observations for eligibility, and the Router option for quorum-loss reads. The pure evaluator returns stable route-facing writer/readers plus internal GR/read-replica roles; it performs no SQL and logs nothing.

- [ ] **Step 8: Run metadata and health tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_metadata_v2_2_unit-t mysql_router_gr_health_unit-t -B
  test/tap/tests/unit/mysql_router_metadata_v2_2_unit-t
  test/tap/tests/unit/mysql_router_gr_health_unit-t
  ```

  Expected GREEN: all scripted queries are consumed exactly once and every model invariant passes.

- [ ] **Step 9: Commit metadata and health models**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_metadata_v2_2_unit-t.cpp \
    test/tap/tests/unit/mysql_router_gr_health_unit-t.cpp
  git commit -m "feat(mysql-router): read InnoDB Cluster metadata"
  ```

### Task 4: Implement idempotent bootstrap account and Shell-visible registration

**Files:**

- Create: `plugins/mysql_router/src/bootstrap.cpp`
- Create: `plugins/mysql_router/src/router_registration.cpp`
- Create: `test/tap/tests/unit/mysql_router_bootstrap_unit-t.cpp`
- Create: `test/tap/tests/unit/mysql_router_registration_unit-t.cpp`
- Modify: `plugins/mysql_router/include/mysql_router_bootstrap.h`
- Modify: `plugins/mysql_router/include/mysql_router_metadata.h`
- Modify: `plugins/mysql_router/src/plugin.cpp`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: parsed bootstrap options, schema-2.2 adapter, ABI secret store, configdb, and metadata writer connection.
- Produces:
  - `BootstrapResult MysqlRouterBootstrap::run(const BootstrapOptions&)`
  - `RouterRegistration register_or_adopt_router(...)`
  - resumable phases `discovered`, `account_ready`, `registered`, `local_configured`, `complete`.

- [ ] **Step 1: Write state-machine and SQL-contract tests**

  Script bootstrap through every phase, then inject a disconnect after each remote mutation and re-run. Assert one service account and one `(address,router_name)` registration after every retry. Assert `--replace-topology` is required when persisted `topology_uuid` differs.

  Require registration values:

  ```cpp
  is(product_name, "ProxySQL", "Shell sees ProxySQL product name");
  is(version, "8.4.0", "Shell feature gate sees implemented Router contract");
  is(json["RWEndpoint"], "6446", "RW endpoint advertised");
  is(json["ROEndpoint"], "6447", "RO endpoint advertised");
  is(json["RWSplitEndpoint"], "6450", "R/W split endpoint advertised");
  ok(!json.contains("RWXEndpoint") && !json.contains("ROXEndpoint"),
     "X endpoints are not advertised");
  ok(!json.contains("SupportedRoutingGuidelinesVersion"),
     "Routing Guidelines capability is not advertised");
  ```

- [ ] **Step 2: Run bootstrap tests and observe RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_bootstrap_unit-t mysql_router_registration_unit-t -B
  ```

  Expected RED: bootstrap and registration implementations do not exist.

- [ ] **Step 3: Create or validate the metadata service account**

  Generate `mysql_router<router_id>_<12 lowercase alnum>` when `--account` is absent. Use `caching_sha2_password` and a 32-byte random password. Apply these grants to each requested host pattern:

  ```sql
  GRANT SELECT, EXECUTE ON mysql_innodb_cluster_metadata.* TO ?@?;
  GRANT INSERT, UPDATE, DELETE ON mysql_innodb_cluster_metadata.v2_routers TO ?@?;
  GRANT SELECT ON performance_schema.replication_group_members TO ?@?;
  GRANT SELECT ON performance_schema.replication_group_member_stats TO ?@?;
  GRANT SELECT ON performance_schema.global_variables TO ?@?;
  GRANT SELECT (User,Host,plugin,authentication_string,account_locked,
                password_expired,ssl_type)
    ON mysql.user TO ?@?;
  ```

  Quote identifiers/accounts with Connector/C escaping, never string concatenation. `always` fails if any target account exists, `never` fails if absent, and `if-not-exists` validates every grant on reuse.

- [ ] **Step 4: Register or update `v2_routers` idempotently**

  First select by case-insensitive address plus exact router name. Insert only when absent; on duplicate key, reselect. Update attributes with `JSON_SET(COALESCE(attributes,JSON_OBJECT()),...)`, set `cluster_id`, set `clusterset_id=NULL`, product/version, and retain Shell-owned `options` untouched.

  Custom attributes are `ProxySQLVersion`, `ProxySQLPluginVersion`, and `ProxySQLTopologyUUID`. Set `bootstrapTargetType='cluster'`, `MetadataUser`, and the three endpoints. Do not set guideline or X keys.

- [ ] **Step 5: Persist secrets and bootstrap progress safely**

  Store the service password as owner `mysql_router`, name `metadata:<topology_uuid>`. Commit local identity, endpoint config, and journal phase only after the remote phase succeeds. On retry, validate the topology UUID and registration row before advancing.

- [ ] **Step 6: Wire `early_action()`**

  Return `not_requested` when `--bootstrap` is absent. A successful bootstrap returns `exit_success` after printing only router label, topology UUID/type, assigned endpoints, and the command needed for normal startup. Any error updates the journal with a redacted message and returns `exit_failure`.

- [ ] **Step 7: Run bootstrap and registration tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_bootstrap_unit-t mysql_router_registration_unit-t \
    mysql_router_bootstrap_options_unit-t -B
  test/tap/tests/unit/mysql_router_bootstrap_unit-t
  test/tap/tests/unit/mysql_router_registration_unit-t
  test/tap/tests/unit/mysql_router_bootstrap_options_unit-t
  ```

  Expected GREEN: retries converge, all secrets are redacted, and Shell-owned Router options remain byte-equivalent JSON.

- [ ] **Step 8: Commit native bootstrap and registration**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_bootstrap_unit-t.cpp \
    test/tap/tests/unit/mysql_router_registration_unit-t.cpp
  git commit -m "feat(mysql-router): bootstrap and register InnoDB Cluster"
  ```

### Task 5: Allocate hostgroups and compile native Classic routing

**Files:**

- Create: `plugins/mysql_router/include/mysql_router_compiler.h`
- Create: `plugins/mysql_router/src/hostgroup_allocator.cpp`
- Create: `plugins/mysql_router/src/config_compiler.cpp`
- Create: `test/tap/tests/unit/mysql_router_hostgroup_allocator_unit-t.cpp`
- Create: `test/tap/tests/unit/mysql_router_config_compiler_unit-t.cpp`
- Modify: `plugins/mysql_router/src/bootstrap.cpp`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: live core snapshots, `EffectiveTopology`, persisted plugin mappings, and ABI `apply_mysql_config`.
- Produces:
  - `ManagedHostgroups HostgroupAllocator::load_or_allocate(...)`
  - `ProxySQL_PluginMysqlConfigPlan ConfigCompiler::compile_topology(...)`.

- [ ] **Step 1: Test collision-free allocation and stable reuse**

  Require these role names for one InnoDB Cluster:

  ```text
  route_writer
  route_reader
  gr_writer
  gr_backup_writer
  gr_reader
  gr_offline
  async_reader
  async_offline
  ```

  Seed arbitrary occupied hostgroups across the search range, allocate eight free IDs, persist them, and assert the next run returns the same mapping even if lower IDs become free. Reject a persisted mapping that collides with another plugin owner.

- [ ] **Step 2: Test the exact baseline rules and interfaces**

  The compiled plan must retain operator interfaces and add `0.0.0.0:6446`, `:6447`, and `:6450`. Allocate collision-free rule IDs and persist these five tagged intents in strict rule-ID order, so both writer guards stop evaluation before the broad read rule:

  ```text
  mysql_router:classic-rw        proxy_port=6446 -> route_writer, apply=1
  mysql_router:classic-ro        proxy_port=6447 -> route_reader, apply=1
  mysql_router:split-locking     proxy_port=6450, locking SELECT -> route_writer, apply=1
  mysql_router:split-unsafe-read proxy_port=6450, SELECT INTO or user-variable assignment -> route_writer, apply=1
  mysql_router:split-read        proxy_port=6450, safe read -> route_reader, apply=1
  ```

  Compile the guards from anchored, case-insensitive `match_digest` expressions. `split-locking` covers `FOR UPDATE`, `FOR SHARE`, and `LOCK IN SHARE MODE`; `split-unsafe-read` covers `SELECT ... INTO` and `@var := ...`. `split-read` then matches the remaining `SELECT`/`WITH` digests. Tests assert all five comments, their order, proxy port, destination, and `apply=1`.

  Managed users default to `route_writer` with `transaction_persistent=1`, so BEGIN/writes/ambiguous statements use the writer and a transaction remains on its first chosen backend.

- [ ] **Step 3: Run allocator/compiler tests and observe RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_hostgroup_allocator_unit-t \
    mysql_router_config_compiler_unit-t -B
  ```

  Expected RED: allocator and compiler symbols are missing.

- [ ] **Step 4: Implement deterministic allocation**

  Search IDs 8000 through 8999, skipping every hostgroup present in server, replication, group-replication, galera, aurora, and ownership snapshots. Reserve all required roles in one configdb transaction. If fewer than eight IDs are available, fail before writing any mapping.

- [ ] **Step 5: Compile stable and internal memberships**

  Duplicate eligible GR servers into both internal role groups and the stable route-facing group. Put asynchronous read replicas only in `async_reader`/`async_offline` and `route_reader`; never place them in a GR mapping. Emit `mysql_group_replication_hostgroups` only for the four internal GR groups. Status/comment values include topology UUID, role, and generation.

- [ ] **Step 6: Compile conservative native split rules**

  Use case-insensitive digest patterns:

  ```regex
  ^SELECT.*(?:FOR UPDATE|FOR SHARE|LOCK IN SHARE MODE)(?:\s|$)
  ^(?:SELECT|SHOW|DESCRIBE|DESC|EXPLAIN)(?:\s|$)
  ```

  The locking rule has the lower rule ID. Do not match stored procedure calls, writes, `SELECT ... INTO`, statements containing user-variable assignment, or statements ProxySQL classifies as unsafe. Operators can precede these rule IDs with their own rules.

- [ ] **Step 7: Publish the bootstrap generation**

  During bootstrap, compile topology generation 1 with closed listener gates, call `apply_mysql_config`, then persist `local_configured`. A publisher collision or validation error leaves the gates closed and the journal resumable.

- [ ] **Step 8: Run allocator/compiler and chassis publisher tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_hostgroup_allocator_unit-t \
    mysql_router_config_compiler_unit-t plugin_mysql_config_unit-t -B
  test/tap/tests/unit/mysql_router_hostgroup_allocator_unit-t
  test/tap/tests/unit/mysql_router_config_compiler_unit-t
  test/tap/tests/unit/plugin_mysql_config_unit-t
  ```

  Expected GREEN: all ownership boundaries, rule ordering, and stable allocation assertions pass.

- [ ] **Step 9: Commit native hostgroup compilation**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_hostgroup_allocator_unit-t.cpp \
    test/tap/tests/unit/mysql_router_config_compiler_unit-t.cpp
  git commit -m "feat(mysql-router): compile native Classic routing"
  ```

### Task 6: Synchronize application users without taking operator ownership

**Files:**

- Create: `plugins/mysql_router/include/mysql_router_users.h`
- Create: `plugins/mysql_router/src/user_sync.cpp`
- Create: `test/tap/tests/unit/mysql_router_user_sync_unit-t.cpp`
- Modify: `plugins/mysql_router/src/config_compiler.cpp`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: authoritative writer `mysql.user` rows, current user snapshot, `mysql_router_users`, and the route-writer hostgroup.
- Produces:
  - `AccountSnapshot UserSynchronizer::read(IMetadataSession&)`
  - `ManagedUserGeneration UserSynchronizer::normalize(...)`
  - user rows for a separate `apply_mysql_config` generation.

- [ ] **Step 1: Add account normalization tests**

  Cover:

  ```text
  one caching_sha2_password variant -> managed active user
  identical user@host variants -> one managed active user
  conflicting verifier variants -> unresolved, no published change for username
  locked/expired-only variants -> inactive managed user
  mysql_native_password -> supported through native hash-learning path
  auth_socket/LDAP/PAM -> unresolved unsupported plugin
  pre-existing unowned username -> collision, operator row preserved
  previously owned username removed remotely -> deleted locally
  released username -> ownership removed and local row preserved
  ```

- [ ] **Step 2: Run the user test and establish RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_user_sync_unit-t -B
  ```

  Expected RED: `UserSynchronizer` is undefined.

- [ ] **Step 3: Read one complete account snapshot**

  Execute in a repeatable-read transaction on the current topology writer:

  ```sql
  SELECT User, Host, plugin, authentication_string, account_locked,
         password_expired, ssl_type
    FROM mysql.user
   WHERE User <> ''
     AND User NOT IN ('mysql.infoschema','mysql.session','mysql.sys', ?)
   ORDER BY User, Host;
  ```

  Abort the user refresh if the query or result decoding is incomplete. Do not change the active user generation on abort.

- [ ] **Step 4: Normalize by ProxySQL's username key**

  Hash each variant's auth plugin, verifier, lock/expiry, and TLS requirement into `source_fingerprint`. Collapse only identical active variants. For a conflict, retain any previous working managed row for that username but mark it unresolved in `runtime_mysql_router_users`; a new conflicting username is not inserted.

- [ ] **Step 5: Materialize supported auth rows**

  For `$A$` caching SHA-2 verifiers, set `password` to the verifier and allow ProxySQL's documented full-auth path to learn the backend cleartext at runtime. For `mysql_native_password`, use the existing hash path. Set `default_hostgroup=route_writer`, `transaction_persistent=1`, `frontend=1`, `backend=1`, and comment `mysql_router:<topology_uuid>:<username>`.

- [ ] **Step 6: Add an explicit release mechanism**

  Treat `state='released'` in `mysql_router_users` as operator ownership. The synchronizer excludes it from desired owned users, and the chassis publisher removes only its ownership ledger entry without deleting the current `mysql_users` row. An operator releases a name with:

  ```sql
  UPDATE mysql_router_users SET state='released' WHERE username='app';
  MYSQL ROUTER RECONCILE;
  ```

- [ ] **Step 7: Run user and passthrough-auth tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_user_sync_unit-t caching_sha2_rsa_unit-t \
    plugin_mysql_config_unit-t -B
  test/tap/tests/unit/mysql_router_user_sync_unit-t
  test/tap/tests/unit/caching_sha2_rsa_unit-t
  test/tap/tests/unit/plugin_mysql_config_unit-t
  ```

  Expected GREEN: user ownership tests pass and existing caching SHA-2 behavior remains green.

- [ ] **Step 8: Commit managed-user synchronization**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_user_sync_unit-t.cpp
  git commit -m "feat(mysql-router): synchronize managed MySQL users"
  ```

### Task 7: Reconcile topology, users, options, and registration continuously

**Files:**

- Create: `plugins/mysql_router/include/mysql_router_reconciler.h`
- Create: `plugins/mysql_router/src/reconciler.cpp`
- Create: `test/tap/tests/unit/mysql_router_reconciler_unit-t.cpp`
- Modify: `plugins/mysql_router/src/plugin.cpp`
- Modify: `plugins/mysql_router/src/status.cpp`
- Modify: `plugins/mysql_router/src/metrics.cpp`
- Modify: `plugins/mysql_router/src/router_registration.cpp`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: persisted identity/secret, adapters, health reader, compiler, user synchronizer, listener gates, and config publisher.
- Produces: `ReconcileResult MysqlRouterReconciler::refresh(RefreshRequest)` and a stoppable periodic worker.

- [ ] **Step 1: Add deterministic state-transition tests**

  Use a fake clock/session/publisher and assert:

  ```text
  startup valid -> topology generation N+1, user generation M+1, gates ready
  metadata outage -> desired generation retained, live health can shun server
  GR primary change -> topology generation advances, users do not refresh early
  account query failure -> topology advances, user generation retained
  incomplete topology -> no publication
  router row deleted -> gates close, registration_missing status set
  options changed -> next poll applies supported policy
  repeated identical warning -> one transition log, incremented counter only
  stop -> worker joins before plugin unload
  ```

- [ ] **Step 2: Run the reconciler test and observe RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_reconciler_unit-t -B
  ```

  Expected RED: reconciler implementation is absent.

- [ ] **Step 3: Implement separate topology and user schedules**

  `refresh_interval_ms` drives metadata/health. User refresh defaults to 30 seconds and runs immediately after first valid topology. `MYSQL ROUTER RECONCILE` requests both and waits using the Admin mutex handoff callbacks; it returns both generation numbers and collision count.

- [ ] **Step 4: Implement last-metadata/current-health behavior**

  Persist the last complete desired topology as normalized rows in the plugin's config tables. On metadata failure, reevaluate those instances with new health but do not add/remove identities or change Router options. If health cannot validate a writer, publish no eligible stable writer. Honor `unreachable_quorum_allowed_traffic`: `none` empties writer/readers, `read` permits safe readers only, `all` retains live eligible roles while marking the degraded policy in status.

- [ ] **Step 5: Check registration and supported Router options every poll**

  Read the plugin's row from `v2_routers` plus merged `v2_router_options`. If absent, close 6446/6447/6450 gates and do not recreate it automatically. Consume only `read_only_targets`, `unreachable_quorum_allowed_traffic`, and `stats_updates_frequency`; preserve tags without routing effect and report a non-null guideline option as unsupported.

- [ ] **Step 6: Check in and update statistics at the requested frequency**

  For schema 2.2, update `v2_routers.last_check_in` and the existing registration attributes/version. Interpret null `stats_updates_frequency` as 0 (disabled), otherwise update no more frequently than the configured seconds. A check-in failure degrades metadata status but does not roll back a valid routing generation.

- [ ] **Step 7: Open listeners only after first complete runtime refresh**

  `runtime_ready()` sets all three gates closed with reason `initial topology validation in progress`, calls synchronous topology and user refresh, starts live health polling, then sets gates ready only if topology identity, at least one metadata endpoint, and publication succeeded. A missing writer does not block the reader gate; keep 6446/6450 available so native ProxySQL returns its ordinary no-backend error while 6447 can serve readers.

- [ ] **Step 8: Populate status/stats and transition metrics**

  Status includes topology type/UUID, metadata version, contract 8.4.0, router ID/label, hostgroup mapping, generations, last-success timestamps, stale duration, collisions, unsupported auth plugins, unsupported Router options, and registration state. Upsert repeated transitions into `stats_mysql_router_errors` by `(kind,code,message)`, incrementing `occurrence_count` and updating `last_seen`; new transitions allocate `error_id` and set both timestamps. Redact every message before lookup or insertion.

- [ ] **Step 9: Run reconciler and adjacent suites**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_reconciler_unit-t mysql_router_config_compiler_unit-t \
    mysql_router_user_sync_unit-t mysql_router_plugin_load_unit-t -B
  test/tap/tests/unit/mysql_router_reconciler_unit-t
  test/tap/tests/unit/mysql_router_config_compiler_unit-t
  test/tap/tests/unit/mysql_router_user_sync_unit-t
  test/tap/tests/unit/mysql_router_plugin_load_unit-t
  ```

  Expected GREEN: all state transitions are deterministic and teardown completes without a live thread.

- [ ] **Step 10: Commit continuous reconciliation**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_reconciler_unit-t.cpp
  git commit -m "feat(mysql-router): reconcile topology and users"
  ```

### Task 8: Prove unmodified Shell and Classic endpoints against MySQL 8.4

**Files:**

- Create: `test/tap/tests/test_mysql_router_innodb_cluster-t.cpp`
- Create: `test/tap/tests/mysql_router/innodb_cluster_setup.js`
- Create: `test/tap/tests/mysql_router/assert_shell_contract.js`
- Create: `test/tap/tests/mysql_router/innodb_cluster_teardown.js`
- Modify: `test/tap/tests/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**

- Consumes: three MySQL 8.4 instances with Group Replication, MySQL Shell 8.4+, the built plugin, and the isolated TAP runner.
- Produces: one end-to-end acceptance binary for bootstrap, Shell visibility, read replicas, endpoint routing, user sync, and primary failover.

- [ ] **Step 1: Create an idempotent Shell topology fixture**

  Use unmodified `mysqlsh --js` to create a three-member InnoDB Cluster, add one asynchronous read replica when the installed 8.4 minor supports it, create `app_reader`/`app_writer`, and print a JSON fixture containing topology UUID, endpoints, primary UUID, and read-replica UUID. Skip only when `mysqlsh --version` is below 8.4 or the test environment explicitly lacks four server slots.

- [ ] **Step 2: Bootstrap ProxySQL through its public executable**

  Invoke:

  ```bash
  proxysql --load-plugin=mysql_router \
    --bootstrap "root@${MYSQL84_SEED}" \
    --bootstrap-password-fd 9 \
    --router-name proxysql-e2e 9<"${PASSFILE}"
  ```

  Assert exit 0, no password in stdout/stderr/process command capture, one `v2_routers` row, and persisted plugin identity/hostgroups.

- [ ] **Step 3: Assert the Shell contract without patches or wrappers**

  Run `cluster.listRouters()`, `cluster.routerOptions()`, `cluster.routingOptions()`, `cluster.setRoutingOption('host::proxysql-e2e','read_only_targets','all')`, and `cluster.setupRouterAccount(...)`. Parse native Shell JSON output and assert ProxySQL, version 8.4.0, ports 6446/6447/6450, no X endpoints, and no advertised guideline support.

- [ ] **Step 4: Assert native endpoint behavior**

  Connect with the synchronized application user:

  ```text
  6446: SELECT @@server_uuid repeatedly -> current primary only
  6447: SELECT @@server_uuid repeatedly -> eligible readers, never writer
  6450: SELECT @@server_uuid -> eligible reader
  6450: BEGIN; INSERT; SELECT @@server_uuid; COMMIT -> writer for transaction
  6450: SELECT ... FOR UPDATE -> writer
  6033: existing operator route -> unchanged
  ```

  Query `stats_mysql_query_digest`/connection-pool tables to show ProxySQL parsing and pooling handled traffic.

- [ ] **Step 5: Exercise primary failover and metadata loss**

  Stop the primary, wait for Shell/GR election, and assert 6446/6450 writes converge to the new primary without rule replacement. Then block metadata access while leaving data connections alive; assert the last topology remains, unhealthy nodes are shunned, status becomes stale, and 6033/Admin remain reachable.

- [ ] **Step 6: Exercise drift correction and ownership boundaries**

  Insert a bogus server into a managed hostgroup, an operator server into hostgroup 77, an operator user, and an operator query rule. Force reconcile. Assert the bogus managed row is deleted and all three operator objects survive unchanged.

- [ ] **Step 7: Run through the isolated harness**

  ```bash
  WORKSPACE="$(pwd)" INFRA_ID="mysql-router-ic-${USER}" \
    TAP_GROUP=mysql-router-ic \
    test/scripts/run-tests-isolated.bash -k test_mysql_router_innodb_cluster-t
  ```

  Expected GREEN: the TAP binary exits 0; Shell commands are unmodified upstream commands and all three Classic endpoint contracts pass.

- [ ] **Step 8: Commit the InnoDB Cluster acceptance test**

  ```bash
  git add test/tap/groups/groups.json test/tap/tests/Makefile \
    test/tap/tests/test_mysql_router_innodb_cluster-t.cpp \
    test/tap/tests/mysql_router
  git commit -m "test(mysql-router): cover InnoDB Cluster integration"
  ```

### Task 9: Document the supported foundation and run its full gate

**Files:**

- Create: `doc/mysql-router-plugin.md`
- Modify: `README.md`

**Interfaces:**

- Consumes: the complete InnoDB Cluster foundation.
- Produces: operator bootstrap/runbook, explicit support boundary, and a reproducible verification record.

- [ ] **Step 1: Document installation and lifecycle**

  Include build/install, `--load-plugin=mysql_router`, secure bootstrap, normal restart, endpoint table, MySQL Shell commands, managed-hostgroup ownership, user collisions/release, status/stats queries, and plugin disable behavior.

- [ ] **Step 2: State the initial exclusions exactly**

  Document: no X protocol, no Routing Guidelines, no Router REST API, no Router packet-forward parity, no modified MySQL Shell, metadata 2.2 only at this milestone, and InnoDB Cluster/read replicas only until the topology-expansion plan lands.

- [ ] **Step 3: Run all plugin units and the real acceptance test**

  ```bash
  make PROXYSQL40=1 -C plugins/mysql_router clean all
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_plugin_load_unit-t mysql_router_admin_schema_unit-t \
    mysql_router_bootstrap_options_unit-t mysql_router_metadata_v2_2_unit-t \
    mysql_router_gr_health_unit-t mysql_router_bootstrap_unit-t \
    mysql_router_registration_unit-t mysql_router_hostgroup_allocator_unit-t \
    mysql_router_config_compiler_unit-t mysql_router_user_sync_unit-t \
    mysql_router_reconciler_unit-t -B
  for t in test/tap/tests/unit/mysql_router_*_unit-t; do "$t" || exit 1; done
  WORKSPACE="$(pwd)" INFRA_ID="mysql-router-ic-${USER}" \
    TAP_GROUP=mysql-router-ic \
    test/scripts/run-tests-isolated.bash -k test_mysql_router_innodb_cluster-t
  ```

  Expected GREEN: every unit binary and the isolated acceptance test exit 0.

- [ ] **Step 4: Commit documentation**

  ```bash
  git add README.md doc/mysql-router-plugin.md
  git commit -m "docs(mysql-router): document native Router integration"
  ```
