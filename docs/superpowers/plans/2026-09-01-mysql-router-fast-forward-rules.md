# MySQL Router Fast-Forward Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish `switch_to_fast_forward` atomically on the MySQL Router plugin's 6446 and 6447 query rules while keeping 6450 query-aware and preserving ABI-8 plugin compatibility.

**Architecture:** Add an ABI-9 tail service whose V2 plan wraps the unchanged ABI-8 MySQL configuration plan and supplies query-rule attributes in a separate rule-ID-indexed array. Reuse the existing scoped publisher transaction and runtime rollback, then make the real Router compiler and reconciler consume only the V2 path.

**Tech Stack:** C++17, ProxySQL plugin ABI 8/9, SQLite, nlohmann JSON, ProxySQL native query processor, TAP, GNU Make, MySQL 8.4, unmodified MySQL Shell 8.4.

**Spec:** `docs/superpowers/specs/2026-09-01-mysql-router-fast-forward-rules-design.md`

## Global Constraints

- Build this feature only under `PROXYSQL40`; do not expose plugin-chassis symbols in ordinary v3.x builds.
- Keep `ProxySQL_PluginMysqlRuleRow`, `ProxySQL_PluginMysqlConfigPlan`, and `ProxySQL_PluginServices::apply_mysql_config` byte-for-byte compatible with ABI 8.
- Add the new service only at the tail of `ProxySQL_PluginServices`, and accept existing supported ABI versions after advancing the maximum to 9.
- Enable `{"switch_to_fast_forward":true}` only on Router-generated 6446 and 6447 rules.
- Keep all three Router-generated 6450 rules free of `switch_to_fast_forward`.
- Do not change the existing `COM_QUERY` command boundary.
- Do not modify MySQL packet handling, compression, EOF negotiation, replication commands, prepared-statement handling, or fast-forward transport code.
- Preserve operator-owned query rules and allow lower-ID `apply=1` rules to override Router defaults.
- Build and load the real `proxysql_mysql_router.so` for acceptance; use the contract fake only for ABI compatibility.
- Every new commit must include a detailed body describing behavior, safety properties, and verification.

---

## File Map

- `include/ProxySQL_Plugin.h`: ABI version and additive V2 service-table callback.
- `include/ProxySQL_PluginConfig.h`: V2 rule-attributes row, V2 plan, and standalone publisher declaration.
- `include/proxysql_admin.h`, `lib/ProxySQL_Admin.cpp`: live Admin V2 service wrapper.
- `lib/ProxySQL_PluginManager.cpp`: live and Phase-B V2 service wiring.
- `lib/ProxySQL_PluginConfig.cpp`: V2 plan copy, validation, staging, and shared atomic publication.
- `plugins/mysql_router/include/mysql_router_compiler.h`: owned compiled attributes and V2 plan storage.
- `plugins/mysql_router/src/config_compiler.cpp`: endpoint-specific default attributes.
- `plugins/mysql_router/src/bootstrap.cpp`: bootstrap and reconciliation publication through V2.
- `plugins/mysql_router/src/plugin.cpp`: Router descriptor ABI 9.
- `test/tap/tests/unit/plugin_lifecycle_unit-t.cpp`: older ABI compatibility and service-tail gating.
- `test/tap/tests/unit/plugin_mysql_config_unit-t.cpp`: V2 validation, storage, runtime, and rollback.
- `test/tap/tests/unit/mysql_router_plugin_load_unit-t.cpp`: real plugin ABI/service contract.
- `test/tap/tests/unit/mysql_router_config_compiler_unit-t.cpp`: exact Router rule attributes.
- `test/tap/tests/unit/plugin_router_chassis_contract_unit-t.cpp`: ABI-8 publisher compatibility.
- `test/tap/tests/test_mysql_router_innodb_cluster-t.cpp`: real-plugin endpoint acceptance.
- `doc/plugin-chassis/ABI.md`, `doc/plugin-chassis/REVIEW_GUIDE.md`, `doc/PLUGIN_API.md`: ABI-9 contract.
- `doc/mysql-router-plugin.md`, `README.md`: operator installation, endpoint, ownership, and support boundary.

### Task 1: Rebuild the Router branch on current remote v3.0

**Files:**

- No source-file edits.
- Preserve commits affecting `test/tap/tests/test_mysql_router_innodb_cluster-t.cpp` and both design/plan documents.

**Interfaces:**

- Consumes: current `origin/v3.0`, `origin/agent/mysql-router-plugin`, Task 8 commit `1db2f8d42`, and the approved design/plan commits.
- Produces: `agent/mysql-router-plugin` with one explicit v3.0 merge, no duplicate local PR-6156 replay series, and a recoverable backup ref.

- [ ] **Step 1: Fetch and prove the expected starting graph**

  ```bash
  git fetch origin v3.0 agent/mysql-router-plugin
  git status --porcelain=v1 --untracked-files=all
  git log --oneline --decorate -12
  git merge-base --is-ancestor 6eeeff5e2 origin/v3.0
  ```

  Expected: the worktree is clean, PR 6156's merge commit is an ancestor of
  `origin/v3.0`, and the local tip contains Task 8 plus the approved documents.

- [ ] **Step 2: Create recoverable refs and resolve the documentation commits**

  ```bash
  git branch backup/mysql-router-plugin-pre-v3-sync-20260901 HEAD
  router_spec_commit=$(git rev-list -1 backup/mysql-router-plugin-pre-v3-sync-20260901 -- \
    docs/superpowers/specs/2026-09-01-mysql-router-fast-forward-rules-design.md)
  router_plan_commit=$(git rev-list -1 backup/mysql-router-plugin-pre-v3-sync-20260901 -- \
    docs/superpowers/plans/2026-09-01-mysql-router-fast-forward-rules.md)
  test -n "$router_spec_commit" && test -n "$router_plan_commit"
  ```

  Expected: both variables resolve to commits reachable through the named
  backup branch.

- [ ] **Step 3: Build the integration branch and merge v3.0**

  ```bash
  git switch -c integrate/mysql-router-plugin-v3-sync origin/agent/mysql-router-plugin
  git merge --no-ff origin/v3.0 \
    -m "Merge remote v3.0 into mysql-router-plugin" \
    -m "Bring the Router work onto the v3.0 line containing merged PR 6156 and its compilation fixes." \
    -m "The local PR-6156 replay commits are intentionally omitted because their reviewed upstream originals are already present through v3.0. Router-specific work is replayed separately after this merge."
  ```

  Resolve conflicts by preserving current `origin/v3.0` behavior first and
  retaining only Router-specific additions from the feature branch. Do not
  reintroduce any local PR-6156 replay diff.

- [ ] **Step 4: Replay only Router-specific work and approved documents**

  ```bash
  git cherry-pick 1db2f8d42
  git cherry-pick "$router_spec_commit"
  git cherry-pick "$router_plan_commit"
  ```

  Expected: Task 8 retains its detailed original commit body; both document
  commits are present after the merge.

- [ ] **Step 5: Verify the graph before moving the feature branch**

  ```bash
  git merge-base --is-ancestor origin/v3.0 HEAD
  git log --oneline --decorate --graph origin/agent/mysql-router-plugin..HEAD
  for duplicate_subject in \
    'docs: design fast-forward handoff safety' \
    'docs: plan fast-forward handoff safety' \
    'test: expose unsafe query-rule fast-forward handoffs' \
    'fix(mysql): finalize query state before fast-forward handoff' \
    'fix(mysql): exclude COM_FIELD_LIST from fast-forward action' \
    'test: satisfy fast-forward TAP lint' \
    'fix(mysql): reset fast-forward query output'; do
      git log --first-parent --format='%s' origin/agent/mysql-router-plugin..HEAD | \
        grep -Fx "$duplicate_subject" && exit 1 || true
  done
  git diff --check origin/v3.0...HEAD
  ```

  Expected: `origin/v3.0` is an ancestor, none of the seven duplicate local
  hashes appears in the new range, and the diff is clean.

- [ ] **Step 6: Move the local feature branch only after verification**

  ```bash
  git branch -f agent/mysql-router-plugin HEAD
  git switch agent/mysql-router-plugin
  git branch -d integrate/mysql-router-plugin-v3-sync
  git status --short --branch
  ```

  Expected: the worktree is on `agent/mysql-router-plugin`, the backup branch
  remains available, and no remote ref has been rewritten.

### Task 2: Add the ABI-9 V2 service without changing ABI 8

**Files:**

- Modify: `include/ProxySQL_Plugin.h`
- Modify: `include/ProxySQL_PluginConfig.h`
- Modify: `include/proxysql_admin.h`
- Modify: `lib/ProxySQL_Admin.cpp`
- Modify: `lib/ProxySQL_PluginManager.cpp`
- Modify: `test/tap/tests/unit/plugin_lifecycle_unit-t.cpp`
- Modify: `test/tap/tests/unit/plugin_router_chassis_contract_unit-t.cpp`

**Interfaces:**

- Consumes: unchanged `ProxySQL_PluginMysqlConfigPlan` and
  `ProxySQL_PluginServices::apply_mysql_config`.
- Produces: `ProxySQL_PluginMysqlRuleAttributesRow`,
  `ProxySQL_PluginMysqlConfigPlanV2`, and
  `ProxySQL_PluginServices::apply_mysql_config_v2`.

- [ ] **Step 1: Add failing ABI and service-table assertions**

  In `plugin_lifecycle_unit-t.cpp`, assert:

  ```cpp
  ok(PROXYSQL_PLUGIN_ABI_VERSION == 9u &&
     PROXYSQL_PLUGIN_ABI_VERSION_MAX == 9u,
     "the chassis advertises additive ABI 9");
  ok(services->apply_mysql_config != nullptr &&
     services->apply_mysql_config_v2 != nullptr,
     "the live ABI-9 service table exposes both publisher generations");
  ```

  Keep an ABI-8 descriptor fixture and prove it loads, initializes, publishes
  through `apply_mysql_config`, and never needs the V2 callback.

- [ ] **Step 2: Build to establish RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    plugin_lifecycle_unit-t plugin_router_chassis_contract_unit-t -B
  ```

  Expected RED: ABI version remains 8 and `apply_mysql_config_v2` plus the V2
  types do not exist.

- [ ] **Step 3: Define the additive public types**

  Append to `ProxySQL_PluginConfig.h` without editing ABI-8 structs:

  ```cpp
  struct ProxySQL_PluginMysqlRuleAttributesRow {
      int rule_id;
      const char* attributes;
  };

  struct ProxySQL_PluginMysqlConfigPlanV2 {
      ProxySQL_PluginMysqlConfigPlan base;
      const ProxySQL_PluginMysqlRuleAttributesRow* rule_attributes;
      size_t rule_attribute_count;
  };
  ```

  Declare:

  ```cpp
  ProxySQL_PluginMysqlConfigResult proxysql_apply_plugin_mysql_config_v2(
      SQLite3DB& admindb,
      const ProxySQL_PluginMysqlConfigPlanV2& plan,
      const ProxySQL_PluginConfigRuntimeHooks& runtime);
  ```

- [ ] **Step 4: Append and wire the ABI-9 callback**

  Advance both ABI constants to `9u` and append this as the final
  `ProxySQL_PluginServices` field:

  ```cpp
  ProxySQL_PluginMysqlConfigResult (*apply_mysql_config_v2)(
      const ProxySQL_PluginMysqlConfigPlanV2& plan);
  ```

  Add `ProxySQL_Admin::apply_plugin_mysql_config_v2`, the global Admin wrapper,
  the live manager assignment, and a Phase-B rejecting stub. The rejecting
  result matches the existing Phase-B publisher rejection:

  ```cpp
  {false, 0, "MySQL configuration publication is not available", {}}
  ```

- [ ] **Step 5: Run ABI compatibility tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    plugin_lifecycle_unit-t plugin_router_chassis_contract_unit-t -B
  test/tap/tests/unit/plugin_lifecycle_unit-t
  test/tap/tests/unit/plugin_router_chassis_contract_unit-t
  ```

  Expected GREEN: ABI 9 services are present while the ABI-8 contract fake
  still completes its existing publication and lifecycle assertions.

- [ ] **Step 6: Commit the ABI surface with a detailed body**

  ```bash
  git add include/ProxySQL_Plugin.h include/ProxySQL_PluginConfig.h \
    include/proxysql_admin.h lib/ProxySQL_Admin.cpp lib/ProxySQL_PluginManager.cpp \
    test/tap/tests/unit/plugin_lifecycle_unit-t.cpp \
    test/tap/tests/unit/plugin_router_chassis_contract_unit-t.cpp
  git commit -m "feat(plugin): add versioned MySQL rule attributes service" \
    -m "Introduce an ABI-9 tail callback and V2 plan that carries query-rule attributes separately by rule ID. Keep the ABI-8 rule row, base plan, and publisher callback unchanged so existing plugins retain their compiled row stride." \
    -m "Wire live and schema-registration service tables, preserve ABI-8 lifecycle and publication coverage, and reject V2 publication before Admin becomes available."
  ```

### Task 3: Publish V2 rule attributes atomically

**Files:**

- Modify: `lib/ProxySQL_PluginConfig.cpp`
- Modify: `test/tap/tests/unit/plugin_mysql_config_unit-t.cpp`

**Interfaces:**

- Consumes: `ProxySQL_PluginMysqlConfigPlanV2` from Task 2 and existing
  `ProxySQL_PluginConfigRuntimeHooks`.
- Produces: `proxysql_apply_plugin_mysql_config_v2(...)` with the same locking,
  generation, collision, snapshot, rollback, and exception boundary as V1.

- [ ] **Step 1: Add focused V2 RED cases**

  Extend the publisher fixture with:

  ```cpp
  ProxySQL_PluginMysqlRuleAttributesRow rule_attributes[] {
      {9000, "{\"switch_to_fast_forward\":true}"},
  };
  ProxySQL_PluginMysqlConfigPlanV2 v2 {fixture.plan, rule_attributes, 1};
  ```

  Assert one successful generation has the exact JSON in:

  ```sql
  SELECT attributes FROM main.mysql_query_rules WHERE rule_id=9000;
  SELECT attributes FROM disk.mysql_query_rules WHERE rule_id=9000;
  SELECT attributes FROM runtime_mysql_query_rules WHERE rule_id=9000;
  ```

  Add independent rejection cases for a null array with non-zero count,
  duplicate rule ID, unknown rule ID, null value, malformed JSON, JSON array,
  and JSON scalar. Each must leave the lock trace empty and main/disk/runtime
  state unchanged.

- [ ] **Step 2: Add replacement, removal, collision, and rollback RED cases**

  Publish generation 2 with attributes changed to `{}` and prove all three
  tiers change together. Remove the managed rule in generation 3 and prove an
  unrelated operator rule and its attributes remain byte-for-byte unchanged.
  Inject failure at `ProxySQL_PluginConfigStage::interfaces` after the rules
  stage and prove the previous managed attributes return in main, disk, and
  the live query processor.

- [ ] **Step 3: Run the publisher test to establish RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 plugin_mysql_config_unit-t -B
  test/tap/tests/unit/plugin_mysql_config_unit-t
  ```

  Expected RED: the V2 entry point is absent or managed rules still publish an
  empty attributes string.

- [ ] **Step 4: Copy and validate V2 attributes before locking**

  Add `std::string attributes;` to the private `Rule` value. Keep V1
  `copy_plan()` assigning it empty. Add a V2 copier that first copies
  `source.base`, then verifies the attributes array and maps each entry to one
  copied rule.

  Parse with `nlohmann::json::parse(value, nullptr, false)` and require
  `document.is_object()`. Errors identify `rule_id` only:

  ```text
  mysql query rule attributes reference an unknown rule_id: 9009
  duplicate mysql query rule attributes for rule_id: 9000
  mysql query rule attributes must be a JSON object for rule_id: 9000
  ```

- [ ] **Step 5: Bind attributes in scoped staging**

  Replace the rule insert's hard-coded empty literal with a bound value:

  ```sql
  INSERT INTO <schema>.mysql_query_rules
    (rule_id,active,flagIN,proxy_port,match_digest,match_pattern,
     negate_match_pattern,re_modifiers,destination_hostgroup,apply,attributes,comment)
  VALUES (?6,?7,0,?8,NULLIF(?1,''),NULLIF(?2,''),?9,NULLIF(?3,''),
          ?10,?11,?4,?5)
  ```

  Bind `row.attributes` and `row.comment` as copied strings. Do not add a
  post-commit UPDATE.

- [ ] **Step 6: Share the existing publication implementation**

  Refactor only the pre-lock copy boundary so V1 and V2 both call the same
  `apply_plugin_mysql_config_impl(SQLite3DB&, OwnedPlan, hooks)` transaction.
  Preserve the existing catch-all result:

  ```text
  plugin publication failed before lock acquisition
  ```

  V2 must use the same runtime snapshots and reverse-stage restore as V1.

- [ ] **Step 7: Run publisher and adjacent lifecycle tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    plugin_mysql_config_unit-t plugin_router_chassis_contract_unit-t \
    plugin_manager_unit-t plugin_lifecycle_unit-t -B
  test/tap/tests/unit/plugin_mysql_config_unit-t
  test/tap/tests/unit/plugin_router_chassis_contract_unit-t
  test/tap/tests/unit/plugin_manager_unit-t
  test/tap/tests/unit/plugin_lifecycle_unit-t
  ```

  Expected GREEN: all V2 cases pass and existing V1 plans remain unchanged.

- [ ] **Step 8: Commit the atomic publisher with a detailed body**

  ```bash
  git add lib/ProxySQL_PluginConfig.cpp test/tap/tests/unit/plugin_mysql_config_unit-t.cpp
  git commit -m "feat(plugin): publish managed query-rule attributes atomically" \
    -m "Validate ABI-9 rule attributes before lock acquisition, copy them into the owned publication plan, and bind them during the existing main/disk staging transaction." \
    -m "Reuse the established runtime snapshot and reverse-stage rollback path so managed attributes advance or restore with the same generation as servers, users, rules, interfaces, and ownership ledgers. Preserve the ABI-8 empty-attributes behavior and operator-owned rules."
  ```

### Task 4: Generate Router fast-forward defaults through ABI 9

**Files:**

- Modify: `plugins/mysql_router/include/mysql_router_compiler.h`
- Modify: `plugins/mysql_router/src/config_compiler.cpp`
- Modify: `plugins/mysql_router/src/bootstrap.cpp`
- Modify: `plugins/mysql_router/src/plugin.cpp`
- Modify: `test/tap/tests/unit/mysql_router_config_compiler_unit-t.cpp`
- Modify: `test/tap/tests/unit/mysql_router_plugin_load_unit-t.cpp`
- Modify: `test/tap/tests/unit/mysql_router_bootstrap_unit-t.cpp`
- Modify: `test/tap/tests/test_mysql_router_innodb_cluster-t.cpp`

**Interfaces:**

- Consumes: live `apply_mysql_config_v2` and `ProxySQL_PluginMysqlConfigPlanV2`.
- Produces: `CompiledMysqlConfig::plan_v2()` and real Router generations whose
  6446/6447 rules carry the fast-forward action, with real-cluster acceptance
  evidence for direct, split, and operator-override routes.

- [ ] **Step 1: Add compiler and plugin-contract RED assertions**

  Add `attributes` checks to the five compiled rules:

  ```cpp
  ok(rw && rw->attributes == "{\"switch_to_fast_forward\":true}" &&
     ro && ro->attributes == "{\"switch_to_fast_forward\":true}",
     "the direct Classic endpoints switch COM_QUERY sessions to fast-forward");
  ok(locking && locking->attributes.empty() &&
     unsafe && unsafe->attributes.empty() && read && read->attributes.empty(),
     "the split endpoint remains query-aware");
  ```

  Assert `plan_v2().rule_attribute_count == 2`, with entries referencing the
  `classic-rw` and `classic-ro` IDs. Compile a non-default listener profile
  and prove the behavior follows the rule intent rather than literal ports.

  In the real load test, require descriptor ABI 9. In bootstrap tests, provide
  a service table where V1 succeeds but V2 is null and assert bootstrap fails
  with `native MySQL configuration services are unavailable`.

  Extend `test_mysql_router_innodb_cluster-t.cpp` before changing production:

  - compare the five `mysql_router:%` rules across main, disk, and runtime;
  - require `{"switch_to_fast_forward":true}` only on the two direct rules;
  - snapshot, set, load, and restore `mysql-show_processlist_extended=2`;
  - keep the 6446 and 6447 connections open and observe each enter
    fast-forward after `SELECT @@server_uuid`;
  - observe 6450 remain at `fast_forward=0` during its existing read, DDL,
    transaction, and locking-read sequence;
  - add a lower-ID `apply=1` operator override for a dedicated user, prove it
    remains query-aware, and compare it byte-for-byte after reconciliation.

- [ ] **Step 2: Build and run to establish RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_config_compiler_unit-t mysql_router_plugin_load_unit-t \
    mysql_router_bootstrap_unit-t -B
  test/tap/tests/unit/mysql_router_config_compiler_unit-t
  make -C test/tap/tests PROXYSQL40=1 test_mysql_router_innodb_cluster-t -B
  INFRA_ID=mysql-router-ff-red-20260901 TAP_GROUP=mysql-router-ic-g1 \
    test/infra/control/ensure-infras.bash
  INFRA_ID=mysql-router-ff-red-20260901 TAP_GROUP=mysql-router-ic-g1 \
    test/infra/control/run-tests-isolated.bash -k '^test_mysql_router_innodb_cluster-t$'
  INFRA_ID=mysql-router-ff-red-20260901 TAP_GROUP=mysql-router-ic-g1 \
    test/infra/control/stop-proxysql-isolated.bash
  ```

  Expected RED: `CompiledRule::attributes`, `plan_v2()`, and the ABI-9 Router
  contract are absent; the real plugin publishes empty attributes and its
  6446/6447 sessions remain outside fast-forward. Always tear down the same
  infrastructure ID after the RED.

- [ ] **Step 3: Add owned compiler storage and V2 plan construction**

  Add:

  ```cpp
  struct CompiledRule {
      // existing fields remain in their current order
      std::string attributes;
  };
  ```

  Add private storage:

  ```cpp
  mutable std::vector<ProxySQL_PluginMysqlRuleAttributesRow> rule_attribute_rows_;
  mutable ProxySQL_PluginMysqlConfigPlanV2 plan_v2_ {};
  ```

  `plan_v2()` first rebuilds the base `plan()`, then adds only non-empty rule
  attributes. All pointed-to strings remain owned by `CompiledMysqlConfig`
  through the synchronous service call.

- [ ] **Step 4: Assign endpoint-specific defaults**

  Extend private `RuleIntent` with `const char* attributes` and define exactly:

  ```cpp
  {"classic-rw", 6446, "^", "route_writer", "{\"switch_to_fast_forward\":true}"},
  {"classic-ro", 6447, "^", "route_reader", "{\"switch_to_fast_forward\":true}"},
  ```

  The three 6450 intents use `""`. Copy `intent.attributes` into every
  `CompiledRule` without special-casing configured port numbers.

- [ ] **Step 5: Require and call the V2 publisher everywhere**

  Change `PluginBootstrapStore::publish_generation()` to require
  `services_.apply_mysql_config_v2` and invoke:

  ```cpp
  const ProxySQL_PluginMysqlConfigResult published =
      services_.apply_mysql_config_v2(config.plan_v2());
  ```

  Bootstrap topology publication, user refresh publication, forced reconcile,
  and background reconcile all pass through this shared method. Do not retain
  a Router fallback to V1 because silently losing the action would change the
  endpoint contract.

- [ ] **Step 6: Run all Router units**

  ```bash
  make PROXYSQL40=1 -C plugins/mysql_router clean all
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_plugin_load_unit-t mysql_router_admin_schema_unit-t \
    mysql_router_bootstrap_options_unit-t mysql_router_metadata_v2_2_unit-t \
    mysql_router_gr_health_unit-t mysql_router_registration_unit-t \
    mysql_router_bootstrap_unit-t mysql_router_hostgroup_allocator_unit-t \
    mysql_router_config_compiler_unit-t mysql_router_user_sync_unit-t \
    mysql_router_reconciler_unit-t -B
  for router_test in test/tap/tests/unit/mysql_router_*_unit-t; do
    "$router_test" || exit 1
  done
  ```

  Expected GREEN: every real Router unit exits zero; the load test reports ABI
  9; compiler tests report exactly two attributes rows.

- [ ] **Step 7: Run the real candidate through InnoDB Cluster**

  ```bash
  INFRA_ID=mysql-router-ff-green-20260901 TAP_GROUP=mysql-router-ic-g1 \
    test/infra/control/ensure-infras.bash
  INFRA_ID=mysql-router-ff-green-20260901 TAP_GROUP=mysql-router-ic-g1 \
    test/infra/control/run-tests-isolated.bash -k '^test_mysql_router_innodb_cluster-t$'
  INFRA_ID=mysql-router-ff-green-20260901 TAP_GROUP=mysql-router-ic-g1 \
    test/infra/control/stop-proxysql-isolated.bash
  ```

  Expected GREEN: the real plugin loads; all prior Shell/topology/user/failover
  assertions pass; the two direct endpoints enter fast-forward; 6450 and the
  lower-ID operator override remain query-aware; rule attributes match across
  main, disk, and runtime.

- [ ] **Step 8: Audit the production plugin export and infrastructure cleanup**

  ```bash
  nm -D --defined-only plugins/mysql_router/proxysql_mysql_router.so
  docker ps -a --format '{{.Names}}' | grep 'mysql-router-ff-' && exit 1 || true
  docker network ls --format '{{.Name}}' | grep 'mysql-router-ff-' && exit 1 || true
  ```

  Expected: `proxysql_plugin_descriptor_v1` is the only plugin-owned exported
  entry point; no test hook or compiler storage symbol is exported; no matching
  container or network remains.

- [ ] **Step 9: Commit Router generation and real acceptance with a detailed body**

  ```bash
  git add plugins/mysql_router/include/mysql_router_compiler.h \
    plugins/mysql_router/src/config_compiler.cpp plugins/mysql_router/src/bootstrap.cpp \
    plugins/mysql_router/src/plugin.cpp \
    test/tap/tests/unit/mysql_router_config_compiler_unit-t.cpp \
    test/tap/tests/unit/mysql_router_plugin_load_unit-t.cpp \
    test/tap/tests/unit/mysql_router_bootstrap_unit-t.cpp \
    test/tap/tests/test_mysql_router_innodb_cluster-t.cpp
  git commit -m "feat(mysql-router): enable fast-forward on direct Classic routes" \
    -m "Compile switch_to_fast_forward into the managed 6446 writer and 6447 reader rules and publish those attributes through the ABI-9 atomic configuration service." \
    -m "Keep all 6450 read/write-split rules query-aware, preserve configurable listener ports and stable rule IDs, and fail startup rather than silently dropping the endpoint action when V2 publication is unavailable." \
    -m "Validate the real plugin against MySQL Shell and InnoDB Cluster, including live fast-forward state, operator override survival, failover, metadata outage, read replicas, and exact main/disk/runtime rule state."
  ```

### Task 5: Document ABI 9 and the supported Router foundation

**Files:**

- Modify: `doc/plugin-chassis/ABI.md`
- Modify: `doc/plugin-chassis/REVIEW_GUIDE.md`
- Modify: `doc/PLUGIN_API.md`
- Create: `doc/mysql-router-plugin.md`
- Modify: `README.md`

**Interfaces:**

- Consumes: completed ABI-9 publisher and real Router behavior.
- Produces: plugin-author ABI reference and operator build/bootstrap/runbook.

- [ ] **Step 1: Update the ABI references**

  Document ABI 9 as an additive `ProxySQL_PluginServices` tail, the unchanged
  ABI-8 structs/callback, the V2 attributes array keyed by base-plan rule ID,
  Phase-B rejection, synchronous pointer lifetime, JSON-object validation,
  and all-or-nothing runtime/storage semantics. Update every stale statement
  that calls ABI 8 current.

- [ ] **Step 2: Write the Router operator guide**

  `doc/mysql-router-plugin.md` must include:

  - `PROXYSQL40=1` build and installed `.so` location;
  - `--load-plugin=mysql_router` bootstrap with password FD;
  - restart and plugin lifecycle;
  - ports 6033, 6446, 6447, and 6450 in a behavior table;
  - 6446/6447 fast-forward after the first `COM_QUERY`;
  - 6450 native read/write splitting and query processing;
  - lower-ID `apply=1` operator overrides;
  - managed hostgroups, user/rule ownership, collisions, and release;
  - status/stats queries and listener-gate behavior;
  - InnoDB Cluster Metadata 2.2 plus asynchronous read-replica scope;
  - Routing Guidelines follow-up issue #6145;
  - explicit current exclusions: X endpoints, takeover, ReplicaSet,
    ClusterSet, and release packaging until their approved plans land.

- [ ] **Step 3: Link the guide from README**

  Add the real MySQL Router plugin beside the existing plugin references,
  distinguish it from the MySQL X plugin, and link `doc/mysql-router-plugin.md`.

- [ ] **Step 4: Run the complete affected unit gate**

  ```bash
  make PROXYSQL40=1 -C plugins/mysql_router clean all
  make -C test/tap/tests/unit PROXYSQL40=1 \
    plugin_mysql_config_unit-t plugin_router_chassis_contract_unit-t \
    plugin_manager_unit-t plugin_lifecycle_unit-t plugin_hostgroups_unit-t \
    mysql_router_plugin_load_unit-t mysql_router_admin_schema_unit-t \
    mysql_router_bootstrap_options_unit-t mysql_router_metadata_v2_2_unit-t \
    mysql_router_gr_health_unit-t mysql_router_registration_unit-t \
    mysql_router_bootstrap_unit-t mysql_router_hostgroup_allocator_unit-t \
    mysql_router_config_compiler_unit-t mysql_router_user_sync_unit-t \
    mysql_router_reconciler_unit-t -B
  for affected_test in \
    plugin_mysql_config_unit-t plugin_router_chassis_contract_unit-t \
    plugin_manager_unit-t plugin_lifecycle_unit-t plugin_hostgroups_unit-t \
    mysql_router_plugin_load_unit-t mysql_router_admin_schema_unit-t \
    mysql_router_bootstrap_options_unit-t mysql_router_metadata_v2_2_unit-t \
    mysql_router_gr_health_unit-t mysql_router_registration_unit-t \
    mysql_router_bootstrap_unit-t mysql_router_hostgroup_allocator_unit-t \
    mysql_router_config_compiler_unit-t mysql_router_user_sync_unit-t \
    mysql_router_reconciler_unit-t; do
      "test/tap/tests/unit/$affected_test" || exit 1
  done
  ```

  Expected GREEN: every binary exits zero with no `not ok` line.

- [ ] **Step 5: Run clean production builds**

  ```bash
  make -C lib clean
  make -C src clean
  make PROXYSQL40=1 build_src -j2
  make -C plugins/mysql_router PROXYSQL40=1 clean all
  ```

  Expected: `src/proxysql` and
  `plugins/mysql_router/proxysql_mysql_router.so` link successfully.

- [ ] **Step 6: Rerun the real acceptance test on the exact candidate**

  ```bash
  INFRA_ID=mysql-router-ff-final-20260901 TAP_GROUP=mysql-router-ic-g1 \
    test/infra/control/ensure-infras.bash
  INFRA_ID=mysql-router-ff-final-20260901 TAP_GROUP=mysql-router-ic-g1 \
    test/infra/control/run-tests-isolated.bash -k '^test_mysql_router_innodb_cluster-t$'
  INFRA_ID=mysql-router-ff-final-20260901 TAP_GROUP=mysql-router-ic-g1 \
    test/infra/control/stop-proxysql-isolated.bash
  ```

  Expected GREEN: one declared, discovered, executed, and passing Router E2E;
  no matching infrastructure remains after teardown.

- [ ] **Step 7: Run final compatibility and hygiene checks**

  ```bash
  git diff --check origin/v3.0...HEAD
  git status --porcelain=v1 --untracked-files=all
  nm -D --defined-only plugins/mysql_router/proxysql_mysql_router.so
  test/infra/control/lint_groups_json.py
  test/infra/control/check_groups.py --source
  test/infra/control/lint_group_coverage.py --strict
  ```

  Expected: clean diff/status, descriptor-only plugin export, sorted group
  manifest, complete source registration, no new missing workflow, and no
  Docker residue from `mysql-router-ff-*` IDs.

- [ ] **Step 8: Commit documentation with a detailed body**

  ```bash
  git add README.md doc/mysql-router-plugin.md doc/PLUGIN_API.md \
    doc/plugin-chassis/ABI.md doc/plugin-chassis/REVIEW_GUIDE.md
  git commit -m "docs(mysql-router): document ABI-9 Router operation" \
    -m "Document the additive query-rule attributes publisher for plugin authors and provide the operator runbook for building, bootstrapping, observing, overriding, and disabling the real MySQL Router plugin." \
    -m "Describe 6446 and 6447 fast-forward defaults, the query-aware 6450 endpoint, ownership boundaries, current InnoDB Cluster scope, Routing Guidelines follow-up #6145, and the remaining topology and packaging milestones."
  ```

- [ ] **Step 9: Record final verification in a detailed completion commit only if tracked evidence changes**

  Do not create an empty evidence commit. If a tracked review guide or report
  needs exact final plan counts, amend that document and commit with:

  ```bash
  git commit -m "test(mysql-router): record fast-forward publication gate" \
    -m "Record exact unit, clean-build, ABI compatibility, real InnoDB Cluster, symbol, manifest, workflow, and teardown results for the final candidate." \
    -m "No production behavior changes are included in this evidence-only commit."
  ```
