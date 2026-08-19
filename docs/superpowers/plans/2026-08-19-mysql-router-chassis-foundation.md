# ProxySQL 4.0 MySQL Router Chassis Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the ProxySQL 4.0 plugin chassis so a plugin can own Router-compatible bootstrap options, store credentials securely, reconcile a bounded slice of native MySQL configuration atomically, and make its listeners available only after runtime initialization.

**Architecture:** Keep the core generic: it discovers named plugins before the definitive CLI parse, lets ABI-v6 plugins register options and run one-shot actions after Admin schema creation, and adds later ABI contracts for secret storage, scoped MySQL configuration publication, runtime readiness, and listener gates. The `mysql_router` plugin will consume these contracts; no topology or MySQL Shell policy enters core.

**Tech Stack:** C++17, ProxySQL plugin ABI, ezOptionParser, libconfig, SQLite, OpenSSL EVP AES-256-GCM, ProxySQL Admin/HGM/Auth/Query Processor APIs, TAP, GNU Make.

**Spec:** `docs/superpowers/specs/2026-08-19-mysql-router-plugin-design.md`

## Global Constraints

- Build every change in this plan only under `PROXYSQL40`; ProxySQL 3.x behavior and ABI remain unchanged.
- Compile the legacy Group Replication bootstrap options, state, and execution out of ProxySQL 4.0 with `#ifndef PROXYSQL40`.
- Keep `--no-plugins` as an unconditional kill switch; it must prevent discovery, option registration, schema registration, actions, initialization, and start callbacks.
- Resolve a plugin name only beneath an explicit plugin directory; reject path separators, `..`, empty names, and names outside `[A-Za-z0-9_]+`.
- Preserve ABI 1-5 plugins through tail-appended descriptor/service fields and version-gated reads.
- Never expose plaintext secrets through SQLite tables, Admin results, status JSON, logs, process arguments echoed by ProxySQL, or metrics.
- The scoped publisher may delete every `mysql_servers` row in declared owned hostgroups, but it must not mutate a server in any other hostgroup.
- The scoped publisher may update/delete only users it previously recorded as plugin-owned; a pre-existing operator row sharing the username or either `mysql_users` uniqueness key is a collision and remains untouched.
- The scoped publisher may update/delete only query rules recorded as plugin-owned and tagged with the exact owner prefix; unrelated query rules remain untouched.
- A failed publication must retain the last complete runtime generation; no partially published server, user, rule, or interface generation is allowed.
- Admin port 6032 and default MySQL port 6033 remain independent of plugin listener readiness.

---

## File Map

- `include/ProxySQL_Plugin.h`: append ABI-v6/v7/v8 descriptor and service types.
- `include/ProxySQL_PluginCLI.h`, `lib/ProxySQL_PluginCLI.cpp`: safe pre-scan, plugin-name resolution, CLI option registry, and parsed-option view.
- `include/ProxySQL_PluginSecrets.h`, `lib/ProxySQL_PluginSecrets.cpp`: encrypted plugin secret store and plugin-service trampolines.
- `include/ProxySQL_PluginConfig.h`, `lib/ProxySQL_PluginConfig.cpp`: typed desired-state plan, ownership ledger, validation, and atomic native MySQL publication.
- `include/ProxySQL_PluginListenerGate.h`, `lib/ProxySQL_PluginListenerGate.cpp`: thread-safe listener readiness registry.
- `include/ProxySQL_PluginManager.h`, `lib/ProxySQL_PluginManager.cpp`: split discovery from schema registration and dispatch new lifecycle callbacks.
- `lib/ProxySQL_GloVars.cpp`, `include/proxysql_glovars.hpp`, `src/main.cpp`: remove 4.0 legacy bootstrap, perform two-pass startup, and place runtime-ready before listeners.
- `include/MySQL_Thread.h`, `lib/MySQL_Thread.cpp`: reject accepts on a closed plugin-managed listener gate.
- `include/proxysql_admin.h`, `lib/ProxySQL_Admin.cpp`: expose one core-owned publication seam that reuses existing load-to-runtime paths.
- `Makefile`, `test/tap/tests/unit/Makefile`: compile the new chassis sources and tests.
- `test/tap/test_helpers/fake_plugin.cpp`: exercise every added ABI phase without relying on `mysql_router`.

### Task 1: Remove the legacy bootstrap surface from ProxySQL 4.0

**Files:**

- Modify: `lib/ProxySQL_GloVars.cpp:330-405`
- Modify: `lib/ProxySQL_GloVars.cpp:480-535`
- Modify: `include/proxysql_glovars.hpp`
- Modify: `src/main.cpp:2250-2910`
- Modify: `test/tap/tests/unit/glovars_unit-t.cpp`

**Interfaces:**

- Consumes: the existing `PROXYSQL40` build tier.
- Produces: a 4.0 executable with no core-owned `--bootstrap`, `--account*`, `--conf-*`, or bootstrap SSL option; 3.x retains the current option set and execution path byte-for-byte outside preprocessor lines.

- [ ] **Step 1: Add compile-tier option registration assertions**

  Extend `glovars_unit-t.cpp` with a helper that renders `GloVars.opt->getUsage()` and make the tier expectation explicit:

  ```cpp
  const std::string usage = rendered_usage(GloVars.opt);
  #ifdef PROXYSQL40
  ok(usage.find("--bootstrap") == std::string::npos,
     "ProxySQL 4.0 core does not register legacy bootstrap options");
  ok(usage.find("--account-create") == std::string::npos,
     "ProxySQL 4.0 core does not register legacy account options");
  #else
  ok(usage.find("--bootstrap") != std::string::npos,
     "ProxySQL 3.x retains legacy bootstrap options");
  #endif
  ```

- [ ] **Step 2: Run the test in both tiers and record the 4.0 failure**

  ```bash
  make -C test/tap/tests/unit glovars_unit-t -B
  test/tap/tests/unit/glovars_unit-t
  make -C test/tap/tests/unit PROXYSQL40=1 glovars_unit-t -B
  test/tap/tests/unit/glovars_unit-t
  ```

  Expected RED: the 3.x binary passes; the 4.0 binary reports that `--bootstrap` and `--account-create` are still present.

- [ ] **Step 3: Guard option registration and option processing**

  Wrap the complete bootstrap option block in the constructor and the complete bootstrap assignment block in `process_opts_pre()`:

  ```cpp
  #ifndef PROXYSQL40
  // Existing bootstrap option registrations remain unchanged here.
  #endif /* !PROXYSQL40 */
  ```

  Apply the same guard to bootstrap-only fields in `ProxySQL_GlobalVariables`, their constructor initialization, reset, and destructor cleanup. Do not guard the generic backend TLS variables used by normal ProxySQL operation.

- [ ] **Step 4: Guard bootstrap execution and helpers**

  In `src/main.cpp`, wrap `bootstrap_info_t`, bootstrap-only SQL constants/helpers, and the call that enters bootstrap mode with `#ifndef PROXYSQL40`. Give phase 2 an empty 4.0-safe input type rather than retaining bootstrap state:

  ```cpp
  #ifdef PROXYSQL40
  struct bootstrap_info_t {};
  #endif
  ```

- [ ] **Step 5: Rebuild and run both tier tests**

  ```bash
  make -C test/tap/tests/unit glovars_unit-t -B
  test/tap/tests/unit/glovars_unit-t
  make -C test/tap/tests/unit PROXYSQL40=1 glovars_unit-t -B
  test/tap/tests/unit/glovars_unit-t
  ```

  Expected GREEN: both TAP programs exit 0, with opposite tier assertions for the legacy option.

- [ ] **Step 6: Commit the isolated removal**

  ```bash
  git add include/proxysql_glovars.hpp lib/ProxySQL_GloVars.cpp src/main.cpp \
    test/tap/tests/unit/glovars_unit-t.cpp
  git commit -m "refactor(v4): remove legacy bootstrap from core"
  ```

### Task 2: Discover named plugins before the definitive CLI parse

**Files:**

- Create: `include/ProxySQL_PluginCLI.h`
- Create: `lib/ProxySQL_PluginCLI.cpp`
- Create: `test/tap/tests/unit/plugin_cli_unit-t.cpp`
- Modify: `include/ProxySQL_Plugin.h`
- Modify: `include/ProxySQL_PluginManager.h`
- Modify: `lib/ProxySQL_PluginManager.cpp`
- Modify: `include/proxysql_glovars.hpp`
- Modify: `lib/ProxySQL_GloVars.cpp`
- Modify: `src/main.cpp:740-870`
- Modify: `Makefile`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/test_helpers/fake_plugin.cpp`

**Interfaces:**

- Consumes: `ez::ezOptionParser`, the existing `plugins=(...)` libconfig setting, and `ProxySQL_PluginManager::load(path, err)`.
- Produces:
  - `ProxySQL_PluginDiscovery proxysql_prescan_plugins(int argc, const char* const* argv, const char* default_config, const char* default_plugin_dir)`
  - `bool ProxySQL_PluginManager::register_cli_options(ez::ezOptionParser&, std::string&)`
  - ABI 6 descriptor callback `bool (*register_cli_options)(ProxySQL_PluginCLIRegistry*)`
  - core options `--plugin-dir PATH` and repeatable `--load-plugin NAME_OR_PATH`.

- [ ] **Step 1: Define the ABI-v6 option registration types**

  Append these declarations to `ProxySQL_Plugin.h`; retain every existing field in its current order:

  ```cpp
  struct ProxySQL_PluginCLIOptionDef {
    const char* short_name;       // empty or e.g. "-B"
    const char* long_name;        // e.g. "--bootstrap"
    uint8_t value_count;          // 0 or 1
    bool required;
    const char* help;
  };

  struct ProxySQL_PluginCLIRegistry {
    void* opaque;
    bool (*add)(void* opaque, const ProxySQL_PluginCLIOptionDef& option,
                const char** error);
  };

  using proxysql_plugin_register_cli_options_cb =
    bool (*)(ProxySQL_PluginCLIRegistry*);
  ```

  Set `PROXYSQL_PLUGIN_ABI_VERSION` and `_MAX` to `6u`, and append `register_cli_options` after `register_schemas` in `ProxySQL_PluginDescriptor`. Manager code may read it only when `abi_version >= 6`.

- [ ] **Step 2: Write resolver and duplicate-option tests**

  Cover these exact cases in `plugin_cli_unit-t.cpp`:

  ```cpp
  ok(resolve_plugin("mysql_router", "/opt/proxysql/plugins", err) ==
       "/opt/proxysql/plugins/proxysql_mysql_router.so", "name resolves below plugin dir");
  ok(resolve_plugin("/tmp/custom.so", "/opt/proxysql/plugins", err) ==
       "/tmp/custom.so", "explicit absolute path remains supported");
  ok(resolve_plugin("../escape", "/opt/proxysql/plugins", err).empty(),
     "relative traversal is rejected");
  ok(!registry.add({"-B", "--bootstrap", 1, false, "first"}, err) ||
     !registry.add({"", "--bootstrap", 1, false, "duplicate"}, err),
     "duplicate long option is rejected");
  ```

  Also pre-scan `-cFILE`, `-c FILE`, `--config FILE`, `-D DIR`, `--plugin-dir DIR`, repeated `--load-plugin`, config-file `plugins`, and `--no-plugins`.

- [ ] **Step 3: Run the new unit target to verify it is red**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 plugin_cli_unit-t -B
  ```

  Expected RED: compilation fails because `ProxySQL_PluginCLI.h` and resolver symbols do not exist.

- [ ] **Step 4: Implement safe name resolution and the narrow pre-scan**

  Define the discovery result without borrowing argv storage:

  ```cpp
  struct ProxySQL_PluginDiscovery {
    bool disabled {false};
    std::string config_file;
    std::string datadir;
    std::string plugin_dir;
    std::vector<std::string> module_paths;
    std::string error;
  };
  ```

  Use `realpath()` for an existing plugin directory and candidate. Verify that a named candidate's canonical parent starts with `plugin_dir + '/'`. Absolute `.so` paths remain supported for the existing config contract; relative strings containing `/` are rejected. Deduplicate canonical paths while preserving first occurrence.

- [ ] **Step 5: Split plugin discovery from Phase B**

  Replace the combined helper with three explicit calls:

  ```cpp
  bool proxysql_discover_configured_plugins(
      std::unique_ptr<ProxySQL_PluginManager>& manager,
      const std::vector<std::string>& modules, std::string& err);
  bool proxysql_register_configured_plugin_cli(
      ProxySQL_PluginManager* manager, ez::ezOptionParser& parser,
      std::string& err);
  bool proxysql_register_configured_plugin_schemas(
      ProxySQL_PluginManager* manager, std::string& err);
  ```

  Discovery only calls `dlopen` and reads descriptors. It installs the active manager only after every module loads. Phase B preserves its existing per-plugin rollback behavior.

- [ ] **Step 6: Register plugin options before calling `GloVars.parse()` once**

  Reorder `ProxySQL_Main_process_global_variables()`:

  ```cpp
  const ProxySQL_PluginDiscovery found = proxysql_prescan_plugins(
      argc, argv, GloVars.config_file, PROXYSQL_DEFAULT_PLUGIN_DIR);
  if (!found.error.empty()) startup_fatal(found.error);
  GloVars.no_plugins = found.disabled;
  GloVars.plugin_modules = found.module_paths;
  if (!found.disabled) {
    discover_plugins_or_exit(found.module_paths);
    register_plugin_cli_or_exit(*GloVars.opt);
  }
  GloVars.parse(argc, argv);       // the only definitive parse
  GloVars.process_opts_pre();
  ```

  Change phase 2's `LoadConfiguredPlugins()` into `RegisterConfiguredPluginSchemas()`; it must use the already discovered manager and must not `dlopen` a second time.

- [ ] **Step 7: Extend the fake plugin and lifecycle assertions**

  For ABI 6, make the fake plugin register `--fake-plugin-action VALUE`. Assert that `--help` includes it, its parsed value is available later, ABI 5 fake descriptors are never read past `register_schemas`, and `--no-plugins` leaves help free of the fake option.

- [ ] **Step 8: Build and run the focused suite**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    plugin_cli_unit-t plugin_config_unit-t plugin_manager_unit-t \
    plugin_lifecycle_unit-t glovars_unit-t -B
  test/tap/tests/unit/plugin_cli_unit-t
  test/tap/tests/unit/plugin_config_unit-t
  test/tap/tests/unit/plugin_manager_unit-t
  test/tap/tests/unit/plugin_lifecycle_unit-t
  test/tap/tests/unit/glovars_unit-t
  ```

  Expected GREEN: all five TAP programs exit 0.

- [ ] **Step 9: Commit plugin discovery and CLI registration**

  ```bash
  git add Makefile include/ProxySQL_Plugin.h include/ProxySQL_PluginCLI.h \
    include/ProxySQL_PluginManager.h include/proxysql_glovars.hpp \
    lib/ProxySQL_PluginCLI.cpp lib/ProxySQL_PluginManager.cpp \
    lib/ProxySQL_GloVars.cpp src/main.cpp test/tap/tests/unit/Makefile \
    test/tap/tests/unit/plugin_cli_unit-t.cpp \
    test/tap/test_helpers/fake_plugin.cpp
  git commit -m "feat(plugin): register named plugin CLI options"
  ```

### Task 3: Run plugin-owned one-shot actions after Admin schema creation

**Files:**

- Modify: `include/ProxySQL_Plugin.h`
- Modify: `include/ProxySQL_PluginCLI.h`
- Modify: `include/ProxySQL_PluginManager.h`
- Modify: `lib/ProxySQL_PluginCLI.cpp`
- Modify: `lib/ProxySQL_PluginManager.cpp`
- Modify: `src/main.cpp:1560-1640`
- Modify: `test/tap/tests/unit/plugin_lifecycle_unit-t.cpp`
- Modify: `test/tap/test_helpers/fake_plugin.cpp`

**Interfaces:**

- Consumes: ABI-v6 CLI registration and live Phase-D database handles.
- Produces:
  - `ProxySQL_PluginEarlyActionResult { not_requested, continue_startup, exit_success, exit_failure }`
  - descriptor callback `ProxySQL_PluginEarlyActionResult (*early_action)(const ProxySQL_PluginEarlyActionContext&)`
  - `ProxySQL_PluginManager::run_early_actions(...)`.

- [ ] **Step 1: Add lifecycle tests for action ordering and exit semantics**

  Configure the fake plugin to log each phase. Assert these sequences:

  ```text
  fake_plugin:register_cli
  fake_plugin:register_schemas
  core:admin_ready
  fake_plugin:early_action
  fake_plugin:init
  fake_plugin:start
  ```

  An `exit_success` action must omit `init` and `start` and return process exit code 0. An `exit_failure` action must omit them and return nonzero. A plugin with ABI 5 must skip the action phase.

- [ ] **Step 2: Run the lifecycle test and observe the missing action phase**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 plugin_lifecycle_unit-t -B
  test/tap/tests/unit/plugin_lifecycle_unit-t
  ```

  Expected RED: assertions cannot find `fake_plugin:early_action`.

- [ ] **Step 3: Define an owned parsed-option context**

  Add callback-based reads so a plugin cannot retain an ezOptionParser pointer:

  ```cpp
  struct ProxySQL_PluginEarlyActionContext {
    void* option_context;
    bool (*is_set)(void*, const char* long_name);
    bool (*get_string)(void*, const char* long_name, std::string& value);
    const char* config_file;
    const char* datadir;
    ProxySQL_PluginServices* services;
  };
  ```

  Append `early_action` after `register_cli_options` in the ABI-v6 descriptor. Read both new fields only for ABI 6.

- [ ] **Step 4: Dispatch actions after Admin is live and before `init_all()`**

  In phase 2, use this order:

  ```cpp
  RegisterConfiguredPluginSchemas();
  ProxySQL_Main_init_Admin_module(bootstrap_info);
  const auto action = RunConfiguredPluginEarlyActions();
  if (action == ProxySQL_PluginEarlyActionResult::exit_success) exit(EXIT_SUCCESS);
  if (action == ProxySQL_PluginEarlyActionResult::exit_failure) exit(EXIT_FAILURE);
  InitConfiguredPlugins();
  StartConfiguredPlugins();
  ```

  If more than one plugin requests an action, execute in configured order and stop on the first exit result. A callback exception becomes `exit_failure` and names the plugin without printing option values.

- [ ] **Step 5: Re-run lifecycle and manager tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    plugin_lifecycle_unit-t plugin_manager_unit-t plugin_cli_unit-t -B
  test/tap/tests/unit/plugin_lifecycle_unit-t
  test/tap/tests/unit/plugin_manager_unit-t
  test/tap/tests/unit/plugin_cli_unit-t
  ```

  Expected GREEN: all phase-order and legacy-ABI assertions pass.

- [ ] **Step 6: Commit the one-shot lifecycle phase**

  ```bash
  git add include/ProxySQL_Plugin.h include/ProxySQL_PluginCLI.h \
    include/ProxySQL_PluginManager.h lib/ProxySQL_PluginCLI.cpp \
    lib/ProxySQL_PluginManager.cpp src/main.cpp \
    test/tap/tests/unit/plugin_lifecycle_unit-t.cpp \
    test/tap/test_helpers/fake_plugin.cpp
  git commit -m "feat(plugin): add early action lifecycle phase"
  ```

### Task 4: Add an authenticated encrypted plugin secret store

**Files:**

- Create: `include/ProxySQL_PluginSecrets.h`
- Create: `lib/ProxySQL_PluginSecrets.cpp`
- Create: `test/tap/tests/unit/plugin_secrets_unit-t.cpp`
- Modify: `include/ProxySQL_Plugin.h`
- Modify: `lib/ProxySQL_PluginManager.cpp`
- Modify: `lib/ProxySQL_Admin.cpp`
- Modify: `Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: OpenSSL `EVP_aes_256_gcm`, `RAND_bytes`, the ProxySQL datadir, and configdb.
- Produces ABI-v7 service callbacks:
  - `ProxySQL_PluginSecretResult (*put_secret)(const char* owner, const char* name, const uint8_t* bytes, size_t length)`
  - `ProxySQL_PluginSecretResult (*get_secret)(const char* owner, const char* name, std::vector<uint8_t>& plaintext)`
  - `ProxySQL_PluginSecretResult (*erase_secret)(const char* owner, const char* name)`.

- [ ] **Step 1: Add secret-store schema and crypto tests**

  Test a temporary datadir and in-memory configdb for:

  ```cpp
  ok(store.put("mysql_router", "metadata_password", bytes("s3cret")),
     "secret is encrypted and stored");
  ok(store.get("mysql_router", "metadata_password", out) && as_string(out) == "s3cret",
     "secret round-trips");
  ok(ciphertext_column(db) != "s3cret", "database never contains plaintext");
  ok(key_file_mode(datadir) == 0600, "master key is owner-readable only");
  ok(!store.get("../bad", "metadata_password", out), "invalid owner rejected");
  ok(!tampered_store.get("mysql_router", "metadata_password", out),
     "GCM authentication rejects modified ciphertext");
  ```

  Add tests for first-create `O_CREAT|O_EXCL|O_NOFOLLOW`, wrong key length, symlink refusal, atomic replacement, erase, and `OPENSSL_cleanse` through an injectable cleanse observer.

- [ ] **Step 2: Run the secret test and observe the missing implementation**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 plugin_secrets_unit-t -B
  ```

  Expected RED: compilation fails because `ProxySQL_PluginSecrets.h` is absent.

- [ ] **Step 3: Materialize the core-owned encrypted table**

  Add this configdb table through the existing Admin standard-table definition path:

  ```sql
  CREATE TABLE IF NOT EXISTS proxysql_plugin_secrets (
    owner TEXT NOT NULL,
    secret_name TEXT NOT NULL,
    nonce BLOB NOT NULL CHECK(length(nonce)=12),
    ciphertext BLOB NOT NULL,
    tag BLOB NOT NULL CHECK(length(tag)=16),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(owner, secret_name)
  )
  ```

  Owner and secret names must match `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}` before any SQL is prepared.

- [ ] **Step 4: Implement AES-256-GCM with bound associated data**

  Generate a 32-byte master key at `<datadir>/proxysql-plugin-secrets.key`. Encrypt with a fresh 12-byte nonce and bind this associated data:

  ```cpp
  const std::string aad = owner + "\0" + secret_name + "\0proxysql-plugin-secret-v1";
  ```

  Write database values with prepared statements inside `BEGIN IMMEDIATE`; decrypt only after tag verification. Cleanse the stack key copy, plaintext staging buffers, and replaced output buffers on every return path.

- [ ] **Step 5: Append ABI-v7 services and wire manager trampolines**

  Set ABI current/max to `7u`. Append the three callbacks to `ProxySQL_PluginServices`; older plugin structs remain a valid prefix. Phase B callbacks return `not_available`; early action, init, start, and runtime callbacks use the live store.

- [ ] **Step 6: Run crypto and lifecycle regression tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    plugin_secrets_unit-t plugin_manager_unit-t plugin_lifecycle_unit-t -B
  test/tap/tests/unit/plugin_secrets_unit-t
  test/tap/tests/unit/plugin_manager_unit-t
  test/tap/tests/unit/plugin_lifecycle_unit-t
  ```

  Expected GREEN: all processes exit 0; an SQLite dump of the test table contains no test plaintext.

- [ ] **Step 7: Commit the secret service**

  ```bash
  git add Makefile include/ProxySQL_Plugin.h include/ProxySQL_PluginSecrets.h \
    lib/ProxySQL_PluginSecrets.cpp lib/ProxySQL_PluginManager.cpp \
    lib/ProxySQL_Admin.cpp test/tap/tests/unit/Makefile \
    test/tap/tests/unit/plugin_secrets_unit-t.cpp
  git commit -m "feat(plugin): add encrypted secret storage"
  ```

### Task 5: Add runtime-ready callbacks and listener readiness gates

**Files:**

- Create: `include/ProxySQL_PluginListenerGate.h`
- Create: `lib/ProxySQL_PluginListenerGate.cpp`
- Create: `test/tap/tests/unit/plugin_listener_gate_unit-t.cpp`
- Modify: `include/ProxySQL_Plugin.h`
- Modify: `include/ProxySQL_PluginManager.h`
- Modify: `lib/ProxySQL_PluginManager.cpp`
- Modify: `include/MySQL_Thread.h`
- Modify: `lib/MySQL_Thread.cpp:5300-5410`
- Modify: `src/main.cpp:1660-1760`
- Modify: `Makefile`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/tests/unit/plugin_lifecycle_unit-t.cpp`
- Modify: `test/tap/test_helpers/fake_plugin.cpp`

**Interfaces:**

- Consumes: initialized HGM, Auth, Query Processor, MySQL Threads Handler, and plugin `start()` state.
- Produces ABI-v8 contracts:
  - descriptor callback `bool (*runtime_ready)(ProxySQL_PluginRuntimeContext*)`
  - service callback `bool (*set_listener_gate)(const ProxySQL_PluginListenerGate&)`
  - `ProxySQL_PluginListenerGateRegistry::lookup(address, port)`.

- [ ] **Step 1: Add gate registry and lifecycle-order tests**

  Use these exact states:

  ```cpp
  enum class ProxySQL_PluginListenerState : uint8_t { closed = 0, ready = 1 };
  struct ProxySQL_PluginListenerGate {
    const char* owner;
    const char* address;
    uint16_t port;
    ProxySQL_PluginListenerState state;
    const char* reason;
  };
  ```

  Assert owner-isolated updates, exact address/port lookup, wildcard address matching for `0.0.0.0` and `::`, reason copying, concurrent readers, and automatic removal during manager teardown. Lifecycle logs must place `runtime_ready` after the core HGM/Auth/QPro/MTH marker and before the core `listeners_started` marker.

- [ ] **Step 2: Run the tests to establish RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    plugin_listener_gate_unit-t plugin_lifecycle_unit-t -B
  ```

  Expected RED: the gate types and runtime-ready dispatch do not exist.

- [ ] **Step 3: Implement a copy-owning gate registry**

  Store keys as `(normalized_address, port)` under `std::shared_mutex`. Store owner and reason as `std::string`, not borrowed pointers. Reject ports 6032 and 6033, empty owners, and attempts by one owner to replace another owner's gate.

- [ ] **Step 4: Append ABI-v8 runtime fields**

  Set ABI current/max to `8u`. Append `runtime_ready` to the descriptor and `set_listener_gate` to services. Define:

  ```cpp
  struct ProxySQL_PluginRuntimeContext {
    ProxySQL_PluginServices* services;
    uint64_t startup_monotonic_us;
  };
  ```

  `start()` remains in its current phase for ABI compatibility. The `mysql_router` plugin's worker may start paused; `runtime_ready()` performs its synchronous first reconciliation and releases the worker only after a complete publication.

- [ ] **Step 5: Dispatch runtime readiness immediately before listener validation/start**

  In phase 3, invoke the new callback after Auth, HGM, Query Processor, and MySQL Threads Handler exist, but before `validate_module_listener_conflicts()` and `GloMTH->start_listeners()`. A callback failure logs the plugin as degraded and continues startup so Admin and 6033 stay reachable; its gates remain closed.

- [ ] **Step 6: Enforce closed gates at accept time**

  In `MySQL_Thread::listener_handle_new_connection`, inspect the accepted listener's `ifi->address` and `ifi->port` before allocating a session:

  ```cpp
  const auto gate = proxysql_plugin_listener_gate_lookup(ifi->address, ifi->port);
  if (gate && gate->state == ProxySQL_PluginListenerState::closed) {
    proxy_warning("Plugin listener %s:%u is not ready: %s\n",
                  ifi->address, ifi->port, gate->reason.c_str());
    close(c);
    return;
  }
  ```

  Rate-limit the warning to once per gate per 30 seconds and expose a rejected-accept counter through the registry snapshot.

- [ ] **Step 7: Run gate, socket, and lifecycle tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    plugin_listener_gate_unit-t plugin_lifecycle_unit-t \
    mysqlx_protocol_socket_unit-t -B
  test/tap/tests/unit/plugin_listener_gate_unit-t
  test/tap/tests/unit/plugin_lifecycle_unit-t
  test/tap/tests/unit/mysqlx_protocol_socket_unit-t
  ```

  Expected GREEN: a closed test gate accepts then closes without a handshake, a ready gate reaches the normal handshake path, and unrelated ports behave unchanged.

- [ ] **Step 8: Commit runtime readiness and gates**

  ```bash
  git add Makefile include/ProxySQL_Plugin.h \
    include/ProxySQL_PluginListenerGate.h include/ProxySQL_PluginManager.h \
    include/MySQL_Thread.h lib/ProxySQL_PluginListenerGate.cpp \
    lib/ProxySQL_PluginManager.cpp lib/MySQL_Thread.cpp src/main.cpp \
    test/tap/tests/unit/Makefile \
    test/tap/tests/unit/plugin_listener_gate_unit-t.cpp \
    test/tap/tests/unit/plugin_lifecycle_unit-t.cpp \
    test/tap/test_helpers/fake_plugin.cpp
  git commit -m "feat(plugin): gate listeners on runtime readiness"
  ```

### Task 6: Publish scoped native MySQL configuration as one generation

**Files:**

- Create: `include/ProxySQL_PluginConfig.h`
- Create: `lib/ProxySQL_PluginConfig.cpp`
- Create: `test/tap/tests/unit/plugin_mysql_config_unit-t.cpp`
- Modify: `include/ProxySQL_Plugin.h`
- Modify: `include/proxysql_admin.h`
- Modify: `lib/ProxySQL_Admin.cpp`
- Modify: `lib/ProxySQL_PluginManager.cpp`
- Modify: `Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: Admin `mysql_servers_wrlock()`, `load_mysql_servers_to_runtime()`, user Auth load/save paths, `load_mysql_query_rules_to_runtime()`, and MySQL variable load path.
- Produces:
  - `ProxySQL_PluginMysqlConfigPlan`
  - `ProxySQL_PluginMysqlConfigResult`
  - service callback `ProxySQL_PluginMysqlConfigResult (*apply_mysql_config)(const ProxySQL_PluginMysqlConfigPlan&)`
  - real implementations for the three existing snapshot callbacks.

- [ ] **Step 1: Define owned plan row types**

  Add owned-value structs to `ProxySQL_PluginConfig.h`; all strings are copied before the callback returns:

  ```cpp
  struct ProxySQL_PluginMysqlServerRow {
    int hostgroup_id;
    const char* hostname;
    uint16_t port;
    uint16_t gtid_port;
    int status;
    int weight;
    int compression;
    int max_connections;
    int max_replication_lag;
    bool use_ssl;
    unsigned int max_latency_ms;
    const char* comment;
  };

  struct ProxySQL_PluginMysqlUserRow {
    const char* username;
    const char* password;
    bool active;
    bool use_ssl;
    int default_hostgroup;
    const char* default_schema;
    bool schema_locked;
    bool transaction_persistent;
    bool fast_forward;
    bool frontend;
    bool backend;
    int max_connections;
    const char* attributes;
    const char* comment;
  };

  struct ProxySQL_PluginMysqlRuleRow {
    int rule_id;
    bool active;
    int proxy_port;
    const char* match_digest;
    const char* match_pattern;
    bool negate_match_pattern;
    const char* re_modifiers;
    int destination_hostgroup;
    bool apply;
    const char* comment;
  };

  struct ProxySQL_PluginMysqlReplicationHostgroupRow {
    int writer_hostgroup;
    int reader_hostgroup;
    const char* check_type;
    const char* comment;
  };

  struct ProxySQL_PluginMysqlGroupReplicationHostgroupRow {
    int writer_hostgroup;
    int backup_writer_hostgroup;
    int reader_hostgroup;
    int offline_hostgroup;
    bool active;
    int max_writers;
    int writer_is_also_reader;
    int max_transactions_behind;
    const char* comment;
  };

  struct ProxySQL_PluginMysqlHostgroupAttributesRow {
    int hostgroup_id;
    int max_num_online_servers;
    int autocommit;
    int free_connections_pct;
    const char* init_connect;
    bool multiplex;
    bool connection_warming;
    int throttle_connections_per_sec;
    const char* ignore_session_variables;
    const char* hostgroup_settings;
    const char* servers_defaults;
    const char* comment;
  };

  struct ProxySQL_PluginMysqlConfigPlan {
    const char* owner;
    uint64_t generation;
    const int* owned_hostgroups;
    size_t owned_hostgroup_count;
    const ProxySQL_PluginMysqlServerRow* servers;
    size_t server_count;
    const ProxySQL_PluginMysqlReplicationHostgroupRow* replication_hostgroups;
    size_t replication_hostgroup_count;
    const ProxySQL_PluginMysqlGroupReplicationHostgroupRow* group_replication_hostgroups;
    size_t group_replication_hostgroup_count;
    const ProxySQL_PluginMysqlHostgroupAttributesRow* hostgroup_attributes;
    size_t hostgroup_attribute_count;
    const ProxySQL_PluginMysqlUserRow* users;
    size_t user_count;
    const ProxySQL_PluginMysqlRuleRow* rules;
    size_t rule_count;
    const char* const* interfaces;
    size_t interface_count;
  };
  ```

  Keep these fields in the same semantic order and type domain as the current Admin schemas in `ProxySQL_Admin_Tables_Definitions.h`; the publisher binds every field explicitly rather than relying on `SELECT *` column order.

- [ ] **Step 2: Write ownership, collision, and rollback tests**

  Seed hostgroups 10/20 (operator), 8100/8101 (plugin), operator user `app`, an unowned colliding user `router_meta`, operator rule 5, and owned rule 9000. Apply a generation owning only 8100/8101 and assert:

  ```cpp
  ok(server_count(8100) == 1 && server_count(8101) == 2,
     "owned hostgroups are replaced exactly");
  ok(server_count(10) == 1 && server_count(20) == 1,
     "operator hostgroups are untouched");
  ok(user_password("app") == "operator", "unrelated operator user survives");
  ok(user_password("router_meta") == "operator",
     "unowned username collision is preserved");
  ok(result.collisions.size() == 1, "collision is returned to the plugin");
  ok(rule_exists(5), "operator rule survives");
  ok(active_generation("mysql_router") == 12, "complete generation is recorded");
  ```

  Add failure injection after each of: Admin SQL staging, HGM publication, Auth publication, rule publication, and interface publication. Every failure must restore generation 12 in Admin and every runtime module.

- [ ] **Step 3: Run the unit target and verify RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 plugin_mysql_config_unit-t -B
  ```

  Expected RED: typed plan and publisher symbols do not exist.

- [ ] **Step 4: Add the ownership ledger**

  Materialize this core table in configdb and admindb:

  ```sql
  CREATE TABLE IF NOT EXISTS proxysql_plugin_owned_objects (
    owner TEXT NOT NULL,
    object_type TEXT NOT NULL CHECK(object_type IN
      ('hostgroup','mysql_user','mysql_query_rule','mysql_interface')),
    object_key TEXT NOT NULL,
    generation INTEGER NOT NULL,
    PRIMARY KEY(owner, object_type, object_key)
  )
  ```

  Hostgroup keys are decimal IDs; user keys are usernames (the plan permits one normalized row per username); rule keys are decimal IDs; interface keys are normalized `address:port` values.

- [ ] **Step 5: Validate the complete plan before taking runtime locks**

  Reject duplicate owned hostgroups, any server outside the owned set, hostgroups outside `1..999999`, duplicate server keys, duplicate usernames, rule comments without prefix `<owner>:`, duplicate rule IDs, ports outside `1..65535`, interfaces 6032/6033, generation 0, or a generation not greater than the ledger's active generation. Detect collisions against both actual `mysql_users` uniqueness constraints and return all of them without modifying data.

- [ ] **Step 6: Stage and publish under the Admin MySQL lock**

  Implement `ProxySQL_Admin::apply_plugin_mysql_config()` with this order. Use Admin's existing SQLite connection where persistent config is attached as `disk`, so `main.*`, `disk.*`, and the ownership ledger participate in one SQLite transaction:

  ```text
  validate and deep-copy plan
  acquire locks in canonical order: Admin mysql_servers, HGM, Auth, QPro, MTH
  capture affected Admin rows and module snapshots while those locks are held
  BEGIN IMMEDIATE on admindb (persistent config is the attached disk schema)
  replace every server/mapping/attribute row in owned hostgroups
  upsert/delete only ledger-owned users and rules
  merge owned interfaces with operator interfaces
  write the next ownership ledger without committing
  load staged servers into HGM
  load staged users into Auth
  load staged rules into Query Processor
  load staged mysql-interfaces into MySQL Threads Handler
  COMMIT the single main-plus-disk SQLite transaction
  publish active generation
  release locks in reverse order: MTH, QPro, Auth, HGM, Admin mysql_servers
  ```

  Hold all five module locks across every runtime swap and the SQLite commit so another thread cannot observe a cross-module partial generation. Add under-lock load variants so the publisher does not recursively acquire the same mutexes. On a module or commit error, restore each captured runtime snapshot in reverse order, roll back the one SQLite transaction, and release the locks in reverse order. Refactor existing void load helpers only as far as needed to return `{success,error}`; keep their Admin SQL command behavior unchanged.

- [ ] **Step 7: Implement real snapshot callbacks**

  Under the corresponding module locks, return owned `SQLite3_result` copies of `runtime_mysql_users`, `runtime_mysql_servers`, and `runtime_mysql_group_replication_hostgroups`. Document that the caller owns and deletes each non-null result. Phase B still returns null.

- [ ] **Step 8: Expose the publisher as the final ABI-v8 service**

  Append `apply_mysql_config` after `set_listener_gate` without another ABI bump; ABI 8 was introduced with the complete final service tail in Task 5. During Task 5, initialize this slot to a rejecting stub, then replace it here with the live Admin trampoline.

- [ ] **Step 9: Run the focused suite**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    plugin_mysql_config_unit-t plugin_manager_unit-t \
    plugin_lifecycle_unit-t hostgroups_unit-t -B
  test/tap/tests/unit/plugin_mysql_config_unit-t
  test/tap/tests/unit/plugin_manager_unit-t
  test/tap/tests/unit/plugin_lifecycle_unit-t
  test/tap/tests/unit/hostgroups_unit-t
  ```

  Expected GREEN: ownership boundaries and every injected rollback point pass; adjacent HGM behavior remains green.

- [ ] **Step 10: Commit atomic scoped publication**

  ```bash
  git add Makefile include/ProxySQL_Plugin.h include/ProxySQL_PluginConfig.h \
    include/proxysql_admin.h lib/ProxySQL_PluginConfig.cpp \
    lib/ProxySQL_PluginManager.cpp lib/ProxySQL_Admin.cpp \
    test/tap/tests/unit/Makefile \
    test/tap/tests/unit/plugin_mysql_config_unit-t.cpp
  git commit -m "feat(plugin): publish scoped MySQL config generations"
  ```

### Task 7: Verify the complete generic chassis contract

**Files:**

- Create: `test/tap/tests/unit/plugin_router_chassis_contract_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `doc/plugin-chassis/REVIEW_GUIDE.md`

**Interfaces:**

- Consumes: ABI 8 discovery, option, action, secret, runtime-ready, listener-gate, snapshot, and config publication APIs.
- Produces: one fake-plugin contract test and operator-facing ABI documentation that the `mysql_router` plugin plan can treat as its stable dependency.

- [ ] **Step 1: Add one end-to-end fake-plugin contract test**

  In one process, load the ABI-8 fake by name, parse `--fake-plugin-action bootstrap`, register schema, create Admin DBs, store a secret, run the action, initialize/start, apply generation 1, close the fake port gate, invoke runtime-ready, apply generation 2, open the gate, read all snapshots, and stop. Assert the exact callback order and that unrelated seeded rows survive.

- [ ] **Step 2: Run it once with the action continuing startup**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    plugin_router_chassis_contract_unit-t -B
  test/tap/tests/unit/plugin_router_chassis_contract_unit-t
  ```

  Expected GREEN: the TAP binary exits 0 and reports a single active generation.

- [ ] **Step 3: Document the ABI availability matrix**

  Add this table to `doc/plugin-chassis/REVIEW_GUIDE.md`:

  | ABI | Descriptor tail | Service tail |
  |---:|---|---|
  | 6 | `register_cli_options`, `early_action` | parsed options through action context |
  | 7 | unchanged | encrypted secret callbacks |
  | 8 | `runtime_ready` | listener gate, scoped MySQL config publisher, live snapshots |

  Document callback ordering, result ownership, no-plugins behavior, and the closed-gate accept behavior.

- [ ] **Step 4: Run all plugin chassis units**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    plugin_config_unit-t plugin_cli_unit-t plugin_dispatch_unit-t \
    plugin_manager_unit-t plugin_registry_unit-t plugin_lifecycle_unit-t \
    plugin_runtime_views_unit-t plugin_secrets_unit-t \
    plugin_listener_gate_unit-t plugin_mysql_config_unit-t \
    plugin_router_chassis_contract_unit-t -B
  for t in plugin_config_unit-t plugin_cli_unit-t plugin_dispatch_unit-t \
    plugin_manager_unit-t plugin_registry_unit-t plugin_lifecycle_unit-t \
    plugin_runtime_views_unit-t plugin_secrets_unit-t \
    plugin_listener_gate_unit-t plugin_mysql_config_unit-t \
    plugin_router_chassis_contract_unit-t; do
    "test/tap/tests/unit/$t" || exit 1
  done
  ```

  Expected GREEN: every binary exits 0 with no TAP `not ok` line.

- [ ] **Step 5: Commit the contract test and documentation**

  ```bash
  git add doc/plugin-chassis/REVIEW_GUIDE.md test/tap/tests/unit/Makefile \
    test/tap/tests/unit/plugin_router_chassis_contract_unit-t.cpp
  git commit -m "test(plugin): lock Router chassis contract"
  ```
