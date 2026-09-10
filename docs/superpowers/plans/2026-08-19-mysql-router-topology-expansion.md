# MySQL Router ReplicaSet and ClusterSet Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `mysql_router` from InnoDB Cluster to ReplicaSet and ClusterSet, add capability adapters for the MySQL 8.4 metadata 2.x shapes, and prove all three topologies with unmodified MySQL Shell.

**Architecture:** Preserve one normalized topology pipeline while adding topology-specific metadata and health evaluators. ReplicaSet combines AdminAPI async views with replication-channel health; ClusterSet evaluates every constituent GR cluster, Shell-owned target/invalidation policy, and stable route-facing hostgroups without exposing topology-specific churn to applications.

**Tech Stack:** C++17, ProxySQL plugin ABI 8, MariaDB Connector/C, MySQL 8.4 metadata schemas 2.2/2.3/2.4, Group Replication and asynchronous replication Performance Schema, TAP, GNU Make, MySQL Shell 8.4.

**Spec:** `docs/superpowers/specs/2026-08-19-mysql-router-plugin-design.md`

## Global Constraints

- This plan depends on both the chassis-foundation and plugin-foundation plans dated 2026-08-19.
- The first supported release is not complete until InnoDB Cluster, ReplicaSet, and ClusterSet all pass their acceptance matrices.
- Keep one plugin instance anchored to one topology UUID; a seed address or target-cluster change never changes that anchor.
- Continue to advertise Router contract `8.4.0`, `product_name='ProxySQL'`, Classic ports 6446/6447/6450, no X endpoints, and no Routing Guidelines capability.
- Probe objects and columns before selecting an adapter; never infer compatibility from MySQL Shell's version string.
- Reject metadata 1.x and unknown incompatible 2.x shapes before publication.
- Keep stable `route_writer` and `route_reader` hostgroups across all target, primary, and membership changes.
- Keep per-cluster GR groups and asynchronous ReplicaSet groups separate; never treat a read replica or ReplicaSet member as a GR member.
- Apply supported Router options from metadata on the next refresh without restarting ProxySQL.
- Keep topology and user generations independent and retain last validated metadata during temporary metadata loss.
- Do not add Routing Guidelines parsing or behavior anywhere in this plan.

---

## File Map

- `plugins/mysql_router/include/mysql_router_metadata.h`, `src/metadata_factory.cpp`: capability-based adapter registry.
- `plugins/mysql_router/src/metadata_v2_3.cpp`, `src/metadata_v2_4.cpp`: compatible newer-2.x deltas and router check-in location.
- `plugins/mysql_router/src/metadata_replicaset.cpp`, `src/replicaset_health.cpp`: ReplicaSet desired/live models.
- `plugins/mysql_router/src/metadata_clusterset.cpp`, `src/clusterset_policy.cpp`: ClusterSet graph and Router-option evaluator.
- `plugins/mysql_router/src/config_compiler.cpp`, `src/hostgroup_allocator.cpp`: topology-specific internal hostgroups feeding stable route groups.
- `plugins/mysql_router/src/reconciler.cpp`, `src/router_registration.cpp`: adapter selection, topology refresh, options, check-in, and target change.
- `test/tap/tests/unit/mysql_router_metadata_*_unit-t.cpp`: scripted adapter tests.
- `test/tap/tests/unit/mysql_router_replicaset_*_unit-t.cpp`: async health/policy/compiler tests.
- `test/tap/tests/unit/mysql_router_clusterset_*_unit-t.cpp`: ClusterSet graph/policy/compiler tests.
- `test/tap/tests/test_mysql_router_replicaset-t.cpp`, `test_mysql_router_clusterset-t.cpp`: real Shell 8.4 acceptance programs.

### Task 1: Negotiate metadata 2.x capabilities and add 2.3/2.4 adapters

**Files:**

- Create: `plugins/mysql_router/src/metadata_factory.cpp`
- Create: `plugins/mysql_router/src/metadata_v2_3.cpp`
- Create: `plugins/mysql_router/src/metadata_v2_4.cpp`
- Create: `test/tap/tests/unit/mysql_router_metadata_factory_unit-t.cpp`
- Create: `test/tap/tests/unit/mysql_router_metadata_v2_3_unit-t.cpp`
- Create: `test/tap/tests/unit/mysql_router_metadata_v2_4_unit-t.cpp`
- Modify: `plugins/mysql_router/include/mysql_router_metadata.h`
- Modify: `plugins/mysql_router/src/metadata_v2_2.cpp`
- Modify: `plugins/mysql_router/src/reconciler.cpp`
- Modify: `plugins/mysql_router/src/router_registration.cpp`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: `information_schema` and `schema_version` probing from the foundation.
- Produces:
  - `MetadataShape MetadataProbe::inspect(IMetadataSession&)`
  - `std::unique_ptr<IMetadataAdapter> make_metadata_adapter(const MetadataShape&)`
  - adapters for supported 2.2, 2.3, and 2.4 shapes.

- [ ] **Step 1: Define the complete capability shape**

  ```cpp
  struct MetadataShape {
    MetadataVersion declared_version;
    bool has_v2_router_options;
    bool has_router_stats;
    bool has_routing_guidelines;
    bool has_instance_type;
    bool has_clusterset_views;
    std::set<std::string> v2_router_columns;
  };
  ```

  Require the common 2.2 columns and views. Treat guideline objects as detected-but-unused, not as adapter failure.

- [ ] **Step 2: Add adapter-selection tests**

  Assert:

  ```cpp
  is(adapter_for(shape_2_2()).name(), "metadata-2.2", "2.2 baseline selected");
  is(adapter_for(shape_2_3()).name(), "metadata-2.3", "2.3 adapter selected");
  is(adapter_for(shape_2_4()).name(), "metadata-2.4", "2.4 adapter selected");
  throws_adapter(shape_1_0(), "metadata 1.x is unsupported");
  throws_adapter(shape_missing_v2_instances(), "required view v2_instances is missing");
  throws_adapter(shape_2_5_unknown_breaking(), "unsupported metadata shape 2.5");
  ```

- [ ] **Step 3: Run new adapter tests to establish RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_metadata_factory_unit-t mysql_router_metadata_v2_3_unit-t \
    mysql_router_metadata_v2_4_unit-t -B
  ```

  Expected RED: factory and newer adapter source files are missing.

- [ ] **Step 4: Implement shape probing with bound metadata names**

  Query `information_schema.views` and `information_schema.columns` for the fixed schema `mysql_innodb_cluster_metadata`. Require `v2_this_instance`, `v2_instances`, `v2_gr_clusters`, `v2_ar_clusters`, `v2_ar_members`, `v2_routers`, and `v2_router_options`; require ClusterSet views only when the discovered topology is a ClusterSet.

- [ ] **Step 5: Implement the compatible adapter deltas**

  Reuse pure row decoders through shared functions, not inheritance casts. The 2.3 adapter reads the extended Router attributes but leaves `CurrentRoutingGuideline` and `SupportedRoutingGuidelinesVersion` unset for this plugin. The 2.4 adapter reads/writes check-in through:

  ```sql
  INSERT INTO mysql_innodb_cluster_metadata.router_stats(router_id,last_check_in)
  VALUES(?,NOW(6))
  ON DUPLICATE KEY UPDATE last_check_in=VALUES(last_check_in);
  ```

  The 2.2/2.3 adapters continue updating `v2_routers.last_check_in`.

- [ ] **Step 6: Keep the registration feature contract at 8.4.0**

  When newer metadata has guideline columns, explicitly remove stale guideline attributes from the adopted registration:

  ```sql
  UPDATE mysql_innodb_cluster_metadata.v2_routers
     SET attributes=JSON_REMOVE(COALESCE(attributes,JSON_OBJECT()),
       '$.RWXEndpoint','$.ROXEndpoint','$.CurrentRoutingGuideline',
       '$.SupportedRoutingGuidelinesVersion')
   WHERE router_id=?;
  ```

  Do not delete Shell-owned `options.guideline`; preserve it and report it as unsupported in local status.

- [ ] **Step 7: Run all metadata adapter tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_metadata_v2_2_unit-t mysql_router_metadata_v2_3_unit-t \
    mysql_router_metadata_v2_4_unit-t mysql_router_metadata_factory_unit-t -B
  test/tap/tests/unit/mysql_router_metadata_v2_2_unit-t
  test/tap/tests/unit/mysql_router_metadata_v2_3_unit-t
  test/tap/tests/unit/mysql_router_metadata_v2_4_unit-t
  test/tap/tests/unit/mysql_router_metadata_factory_unit-t
  ```

  Expected GREEN: each shape selects exactly one adapter and emits its expected check-in SQL.

- [ ] **Step 8: Commit capability adapters**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_metadata_factory_unit-t.cpp \
    test/tap/tests/unit/mysql_router_metadata_v2_3_unit-t.cpp \
    test/tap/tests/unit/mysql_router_metadata_v2_4_unit-t.cpp
  git commit -m "feat(mysql-router): negotiate metadata 2.x adapters"
  ```

### Task 2: Read and evaluate ReplicaSet topology and replication health

**Files:**

- Create: `plugins/mysql_router/src/metadata_replicaset.cpp`
- Create: `plugins/mysql_router/src/replicaset_health.cpp`
- Create: `test/tap/tests/unit/mysql_router_metadata_replicaset_unit-t.cpp`
- Create: `test/tap/tests/unit/mysql_router_replicaset_health_unit-t.cpp`
- Modify: `plugins/mysql_router/include/mysql_router_types.h`
- Modify: `plugins/mysql_router/include/mysql_router_metadata.h`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: `v2_this_instance`, `v2_ar_clusters`, `v2_ar_members`, `v2_instances`, and replication Performance Schema.
- Produces:
  - `DesiredTopology MetadataAdapter::read_replicaset(...)`
  - `ObservedHealth ReplicaSetHealthReader::read(...)`
  - `EffectiveTopology evaluate_replicaset(...)`.

- [ ] **Step 1: Add ReplicaSet metadata tests with exact rows**

  Script:

  ```sql
  SELECT c.cluster_id, c.cluster_name, c.view_id, c.async_topology_type,
         m.instance_id, m.member_id, m.member_role, m.master_member_id,
         i.label, i.endpoint, i.attributes
    FROM mysql_innodb_cluster_metadata.v2_ar_clusters AS c
    JOIN mysql_innodb_cluster_metadata.v2_ar_members AS m
      ON m.cluster_id=c.cluster_id AND m.view_id=c.view_id
    JOIN mysql_innodb_cluster_metadata.v2_instances AS i
      ON i.instance_id=m.instance_id
   WHERE c.cluster_id=?
   ORDER BY m.instance_id;
  ```

  Assert exactly one metadata PRIMARY, zero-or-more SECONDARY members, matching `master_member_id`, monotonically selected max `view_id`, and rejection of a cycle, duplicate primary, missing source, or unknown member role.

- [ ] **Step 2: Add live replication-health tests**

  Observe primary `read_only/super_read_only` and, for each replica:

  ```sql
  SELECT channel_name, service_state, source_uuid
    FROM performance_schema.replication_connection_status
   WHERE channel_name=?;
  SELECT service_state, last_error_number
    FROM performance_schema.replication_applier_status_by_coordinator
   WHERE channel_name=?;
  ```

  Bind the ReplicaSet replication-channel name discovered from metadata (MySQL
  Shell defaults it from the ReplicaSet name). Assert source writable only when
  both read-only variables are 0; replica readable only when connection/applier
  are ON, source UUID matches metadata, and no apply error exists;
  unreachable/lagged nodes remain represented but ineligible.

- [ ] **Step 3: Run the tests and establish RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_metadata_replicaset_unit-t \
    mysql_router_replicaset_health_unit-t -B
  ```

  Expected RED: ReplicaSet readers/evaluator do not exist.

- [ ] **Step 4: Extend normalized types without a parallel data model**

  Add `AsyncMemberInfo {member_role,source_uuid,view_id}` as an optional field on `DesiredInstance`. Add `ReplicationHealth {io_running,sql_running,source_uuid,lag_seconds,last_error}` as an optional field on observed instances. Continue using the same `DesiredTopology` and `EffectiveTopology` containers.

- [ ] **Step 5: Implement ReplicaSet policy**

  Map the healthy metadata PRIMARY to writer/source and healthy SECONDARY rows to readers/replicas. Never promote a replica based only on `read_only=0`; wait for AdminAPI metadata to publish a new async view. During temporary metadata loss, a dead source empties the stable writer group while healthy replicas can remain readers.

- [ ] **Step 6: Parse only supported ReplicaSet options**

  Consume nullable nonnegative `stats_updates_frequency`. Preserve `tags` for Shell visibility and ignore a non-null `guideline` with one status warning. Reject ClusterSet- or GR-only options if they appear with the wrong JSON type, but do not apply them.

- [ ] **Step 7: Run metadata and health tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_metadata_replicaset_unit-t \
    mysql_router_replicaset_health_unit-t -B
  test/tap/tests/unit/mysql_router_metadata_replicaset_unit-t
  test/tap/tests/unit/mysql_router_replicaset_health_unit-t
  ```

  Expected GREEN: async view and live channel invariants all pass.

- [ ] **Step 8: Commit the ReplicaSet model**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_metadata_replicaset_unit-t.cpp \
    test/tap/tests/unit/mysql_router_replicaset_health_unit-t.cpp
  git commit -m "feat(mysql-router): model ReplicaSet topology"
  ```

### Task 3: Compile and reconcile ReplicaSet native routing

**Files:**

- Create: `test/tap/tests/unit/mysql_router_replicaset_compiler_unit-t.cpp`
- Modify: `plugins/mysql_router/src/hostgroup_allocator.cpp`
- Modify: `plugins/mysql_router/src/config_compiler.cpp`
- Modify: `plugins/mysql_router/src/bootstrap.cpp`
- Modify: `plugins/mysql_router/src/router_registration.cpp`
- Modify: `plugins/mysql_router/src/reconciler.cpp`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: ReplicaSet effective topology and existing stable route groups/rules.
- Produces: managed roles `rs_source`, `rs_replica`, `rs_offline` and a complete scoped config plan.

- [ ] **Step 1: Add compiler role and ownership tests**

  Bootstrap a ReplicaSet with occupied arbitrary hostgroups and assert five persisted roles: `route_writer`, `route_reader`, `rs_source`, `rs_replica`, `rs_offline`. Assert one source appears in both `rs_source` and `route_writer`, replicas appear in both `rs_replica` and `route_reader`, and an unhealthy member appears only in `rs_offline`.

- [ ] **Step 2: Assert native replication mapping**

  Require one managed `mysql_replication_hostgroups` row:

  ```cpp
  is(mapping.writer_hostgroup, groups.rs_source, "native source group mapped");
  is(mapping.reader_hostgroup, groups.rs_replica, "native replica group mapped");
  is(mapping.check_type, "read_only", "ProxySQL observes read_only role");
  ```

  Stable route groups remain the endpoint destinations and are updated only by the plugin generation.

- [ ] **Step 3: Run the compiler test and observe RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_replicaset_compiler_unit-t -B
  ```

  Expected RED: ReplicaSet role allocation/compilation is absent.

- [ ] **Step 4: Allocate topology-specific roles atomically**

  Reuse the 8000-8999 allocator, but allocate only roles required by the detected topology. On a topology replacement, release old role mappings only after the replacement bootstrap publishes its first generation; normal refresh never changes IDs.

- [ ] **Step 5: Register ReplicaSet metadata identity**

  Set `bootstrapTargetType='cluster'`, `cluster_id=<replicaset UUID>`, `clusterset_id=NULL`, and the same ProxySQL/8.4.0/Classic endpoint attributes. The `product_name`, Router options, and no-X/no-guideline contract remain identical.

- [ ] **Step 6: Integrate the evaluator into bootstrap and refresh**

  Detect `v2_this_instance.cluster_type='ar'`, dispatch to ReplicaSet, store `topology_type='replica_set'`, refresh current view and health, compile, and publish. A view change that changes PRIMARY advances topology generation once; channel flaps with unchanged desired metadata update server status without changing topology identity.

- [ ] **Step 7: Run ReplicaSet and common compiler/reconciler tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_replicaset_compiler_unit-t \
    mysql_router_config_compiler_unit-t mysql_router_reconciler_unit-t -B
  test/tap/tests/unit/mysql_router_replicaset_compiler_unit-t
  test/tap/tests/unit/mysql_router_config_compiler_unit-t
  test/tap/tests/unit/mysql_router_reconciler_unit-t
  ```

  Expected GREEN: both topology compilers share the same stable endpoint contract.

- [ ] **Step 8: Commit ReplicaSet materialization**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_replicaset_compiler_unit-t.cpp
  git commit -m "feat(mysql-router): route ReplicaSet with native hostgroups"
  ```

### Task 4: Prove ReplicaSet bootstrap, Shell operations, and failover

**Files:**

- Create: `test/tap/tests/test_mysql_router_replicaset-t.cpp`
- Create: `test/tap/tests/mysql_router/replicaset_setup.js`
- Create: `test/tap/tests/mysql_router/replicaset_assert.js`
- Create: `test/tap/tests/mysql_router/replicaset_teardown.js`
- Modify: `test/tap/tests/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**

- Consumes: three MySQL 8.4 instances, unmodified Shell, and built plugin.
- Produces: real ReplicaSet acceptance coverage.

- [ ] **Step 1: Create a three-member ReplicaSet fixture**

  Use native Shell JavaScript to create the ReplicaSet and application accounts, and emit topology UUID, source UUID, replica UUIDs, and seed endpoint as JSON.

- [ ] **Step 2: Bootstrap and assert unmodified Shell visibility**

  Bootstrap with the same public ProxySQL command used for InnoDB Cluster. Run `rs.listRouters()`, `rs.routerOptions()`, `rs.routingOptions()`, `rs.setRoutingOption(...,'stats_updates_frequency',1)`, and `rs.setupRouterAccount(...)`. Assert product/version/endpoints and no X/guideline capability.

- [ ] **Step 3: Exercise endpoints and forced switchover**

  Assert writes on 6446/6450 reach the source, reads on 6447 balance replicas, and 6450 safe reads use replicas. Use unmodified Shell `rs.setPrimaryInstance()`; assert the plugin follows the new AdminAPI view, old source becomes a reader, and application rules/hostgroup IDs remain stable.

- [ ] **Step 4: Exercise replica failure and metadata outage**

  Stop one replica and assert it leaves 6447 eligibility. Block metadata, stop the source, and assert no replica is promoted from live variables alone; writer traffic fails closed while remaining readers continue if healthy.

- [ ] **Step 5: Run the isolated ReplicaSet group**

  ```bash
  WORKSPACE="$(pwd)" INFRA_ID="mysql-router-rs-${USER}" \
    TAP_GROUP=mysql-router-rs \
    test/scripts/run-tests-isolated.bash -k test_mysql_router_replicaset-t
  ```

  Expected GREEN: the program exits 0 after Shell switchover and outage assertions.

- [ ] **Step 6: Commit ReplicaSet acceptance coverage**

  ```bash
  git add test/tap/groups/groups.json test/tap/tests/Makefile \
    test/tap/tests/test_mysql_router_replicaset-t.cpp \
    test/tap/tests/mysql_router/replicaset_*.js
  git commit -m "test(mysql-router): cover ReplicaSet integration"
  ```

### Task 5: Read the complete ClusterSet graph and evaluate Router options

**Files:**

- Create: `plugins/mysql_router/src/metadata_clusterset.cpp`
- Create: `plugins/mysql_router/src/clusterset_policy.cpp`
- Create: `test/tap/tests/unit/mysql_router_metadata_clusterset_unit-t.cpp`
- Create: `test/tap/tests/unit/mysql_router_clusterset_policy_unit-t.cpp`
- Modify: `plugins/mysql_router/include/mysql_router_types.h`
- Modify: `plugins/mysql_router/include/mysql_router_metadata.h`
- Modify: `plugins/mysql_router/Makefile`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: `v2_cs_clustersets`, `v2_cs_members`, `v2_gr_clusters`, `v2_instances`, per-cluster GR health, and merged `v2_router_options`.
- Produces:
  - `DesiredTopology MetadataAdapter::read_clusterset(...)`
  - `ClusterSetPolicy parse_clusterset_options(JsonValue)`
  - `EffectiveTopology evaluate_clusterset(...)`.

- [ ] **Step 1: Add graph-decoding tests with exact query shape**

  Script:

  ```sql
  SELECT cs.clusterset_id, cs.domain_name, cs.view_id,
         m.cluster_id, m.cluster_name, m.member_role, m.invalidated,
         m.master_cluster_id, c.group_name, i.instance_id,
         i.mysql_server_uuid, i.label, i.endpoint, i.attributes, i.instance_type
    FROM mysql_innodb_cluster_metadata.v2_cs_clustersets AS cs
    JOIN mysql_innodb_cluster_metadata.v2_cs_members AS m
      ON m.clusterset_id=cs.clusterset_id AND m.view_id=cs.view_id
    JOIN mysql_innodb_cluster_metadata.v2_gr_clusters AS c
      ON c.cluster_id=m.cluster_id
    JOIN mysql_innodb_cluster_metadata.v2_instances AS i
      ON i.cluster_id=c.cluster_id
   WHERE cs.clusterset_id=?
   ORDER BY m.cluster_id,i.instance_id;
  ```

  Assert one PRIMARY cluster, replica clusters, invalidated flag, read replicas kept separate, and rejection of duplicate primary, missing target, mixed ClusterSet IDs, or a member with no instances.

- [ ] **Step 2: Add a complete option-policy truth table**

  Cover `target_cluster='primary'|<cluster UUID>`, `invalidated_cluster_policy='drop_all'|'accept_ro'`, `use_replica_primary_as_rw=true|false`, `read_only_targets='secondaries'|'read_replicas'|'all'`, `unreachable_quorum_allowed_traffic='none'|'read'|'all'`, and nullable `stats_updates_frequency`.

  Required outcomes include:

  | Target state | Policy | Stable writer | Stable readers |
  |---|---|---|---|
  | primary cluster healthy | defaults | target GR primary | selected target readers |
  | replica cluster, `use_replica_primary_as_rw=false` | valid | empty | selected target readers including its primary when safe |
  | replica cluster, `use_replica_primary_as_rw=true` | valid | target cluster primary endpoint | selected target readers |
  | invalidated target | `drop_all` | empty | empty |
  | invalidated target | `accept_ro` | empty | healthy target readers |
  | no quorum | `none` | empty | empty |
  | no quorum | `read` | empty | healthy read candidates |

- [ ] **Step 3: Run ClusterSet model tests and observe RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_metadata_clusterset_unit-t \
    mysql_router_clusterset_policy_unit-t -B
  ```

  Expected RED: ClusterSet graph/policy implementations are absent.

- [ ] **Step 4: Extend the normalized topology with cluster nodes**

  Add:

  ```cpp
  struct DesiredCluster {
    std::string cluster_uuid;
    std::string name;
    std::string group_name;
    ClusterSetRole role;
    bool invalidated;
    std::vector<DesiredInstance> instances;
  };
  ```

  `DesiredTopology.topology_uuid` is the ClusterSet UUID; selected target UUID is policy state, never topology identity.

- [ ] **Step 5: Parse strict Shell-owned option values**

  Missing target defaults to `primary`; missing invalidation policy defaults to `drop_all`; missing `use_replica_primary_as_rw` defaults false; missing read target defaults `secondaries`; missing quorum option defaults `none`. An unknown type/value invalidates the candidate options generation and retains the previous complete policy.

- [ ] **Step 6: Evaluate each cluster's GR health before target policy**

  Reuse the InnoDB Cluster GR evaluator independently per cluster. Then resolve the target against the latest ClusterSet view and apply invalidation/quorum/replica-primary/read-target policy. A `primary` target follows a ClusterSet switchover automatically; a UUID target remains on that UUID across role changes.

- [ ] **Step 7: Run graph and policy tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_metadata_clusterset_unit-t \
    mysql_router_clusterset_policy_unit-t mysql_router_gr_health_unit-t -B
  test/tap/tests/unit/mysql_router_metadata_clusterset_unit-t
  test/tap/tests/unit/mysql_router_clusterset_policy_unit-t
  test/tap/tests/unit/mysql_router_gr_health_unit-t
  ```

  Expected GREEN: all ClusterSet truth-table rows and GR isolation assertions pass.

- [ ] **Step 8: Commit the ClusterSet model and policy**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_metadata_clusterset_unit-t.cpp \
    test/tap/tests/unit/mysql_router_clusterset_policy_unit-t.cpp
  git commit -m "feat(mysql-router): model ClusterSet target policy"
  ```

### Task 6: Compile per-cluster hostgroups and reconcile ClusterSet changes

**Files:**

- Create: `test/tap/tests/unit/mysql_router_clusterset_compiler_unit-t.cpp`
- Modify: `plugins/mysql_router/src/hostgroup_allocator.cpp`
- Modify: `plugins/mysql_router/src/config_compiler.cpp`
- Modify: `plugins/mysql_router/src/bootstrap.cpp`
- Modify: `plugins/mysql_router/src/router_registration.cpp`
- Modify: `plugins/mysql_router/src/reconciler.cpp`
- Modify: `plugins/mysql_router/src/status.cpp`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- Consumes: complete ClusterSet effective topology and stable route groups.
- Produces: persistent per-cluster role groups and atomic target changes without rewriting endpoint rules.

- [ ] **Step 1: Add per-cluster mapping tests**

  For each constituent cluster UUID, allocate roles:

  ```text
  cs:<uuid>:gr_writer
  cs:<uuid>:gr_backup_writer
  cs:<uuid>:gr_reader
  cs:<uuid>:gr_offline
  cs:<uuid>:async_reader
  cs:<uuid>:async_offline
  ```

  Assert `route_writer`/`route_reader` IDs do not change when target moves from cluster A to B, and every per-cluster `mysql_group_replication_hostgroups` mapping refers only to that cluster's servers.

- [ ] **Step 2: Test target, role, and invalidation transitions**

  Compile consecutive generations for: primary target A, explicit target B, ClusterSet switchover B to PRIMARY, B invalidated/drop_all, B invalidated/accept_ro, and B restored. Assert each plan is complete and deletes obsolete membership only inside the full persisted managed set.

- [ ] **Step 3: Run the compiler test and observe RED**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_clusterset_compiler_unit-t -B
  ```

  Expected RED: per-cluster role compilation is absent.

- [ ] **Step 4: Allocate all discovered cluster roles in one transaction**

  Sort cluster UUIDs and role names before allocation so tests/logs are deterministic. Preserve mappings for clusters temporarily absent from an incomplete refresh; release mappings only after a complete metadata view proves the cluster removed and the config generation commits.

- [ ] **Step 5: Register ClusterSet identity correctly**

  Set `bootstrapTargetType='clusterset'`, `clusterset_id=<topology UUID>`, and `cluster_id=NULL` in `v2_routers`. Store selected target only in Shell-owned Router options and local runtime status; never rewrite it during reconciliation.

- [ ] **Step 6: Publish target changes through stable groups**

  Internal per-cluster groups retain their memberships. The compiler copies only eligible target members into stable route groups. Baseline rule IDs and endpoint interfaces are invariant. Increment `proxysql_mysql_router_writer_changes_total` when the stable writer endpoint UUID changes, including change to/from empty.

- [ ] **Step 7: Run ClusterSet/common compiler and reconciler tests**

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    mysql_router_clusterset_compiler_unit-t \
    mysql_router_config_compiler_unit-t mysql_router_reconciler_unit-t -B
  test/tap/tests/unit/mysql_router_clusterset_compiler_unit-t
  test/tap/tests/unit/mysql_router_config_compiler_unit-t
  test/tap/tests/unit/mysql_router_reconciler_unit-t
  ```

  Expected GREEN: target changes affect membership but never route group/rule/interface identities.

- [ ] **Step 8: Commit ClusterSet materialization**

  ```bash
  git add plugins/mysql_router test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mysql_router_clusterset_compiler_unit-t.cpp
  git commit -m "feat(mysql-router): reconcile ClusterSet hostgroups"
  ```

### Task 7: Prove ClusterSet Shell options and topology transitions

**Files:**

- Create: `test/tap/tests/test_mysql_router_clusterset-t.cpp`
- Create: `test/tap/tests/mysql_router/clusterset_setup.js`
- Create: `test/tap/tests/mysql_router/clusterset_assert.js`
- Create: `test/tap/tests/mysql_router/clusterset_teardown.js`
- Modify: `test/tap/tests/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**

- Consumes: two three-member InnoDB Clusters joined as a ClusterSet, Shell 8.4, and built plugin.
- Produces: real target/invalidation/switchover/failover coverage.

- [ ] **Step 1: Build the ClusterSet fixture with unmodified Shell**

  Create primary cluster A, replica cluster B, and ClusterSet `routerCs`; emit ClusterSet UUID, both cluster UUIDs, instance endpoints, and current primary. Create application users through Shell-supported topology operations.

- [ ] **Step 2: Bootstrap against ClusterSet and assert registration**

  Bootstrap from A. Assert `clusterset_id` is set, `cluster_id` is null, product/version/Classic endpoints are visible in `clusterset.listRouters()`, and X/guideline capability is absent.

- [ ] **Step 3: Exercise every supported ClusterSet Router option**

  Use unmodified `clusterset.setRoutingOption()` for target UUID/`primary`, invalidation policy, replica-primary-as-RW, read-only targets, quorum traffic, and stats frequency. After each, force or await refresh and verify `runtime_mysql_router_status`, stable membership, and endpoint behavior match the Task 5 truth table.

- [ ] **Step 4: Exercise switchover and target anchoring**

  With `target_cluster='primary'`, perform Shell ClusterSet switchover and assert stable writer follows the new PRIMARY. With explicit target UUID A, switch roles again and assert routing remains anchored to A and applies replica-target policy.

- [ ] **Step 5: Exercise invalidation and metadata outage**

  Invalidate the explicit target. Verify `drop_all` empties both route groups and `accept_ro` restores only healthy readers. Block metadata and prove the last complete ClusterSet graph remains while current GR health can remove unsafe members.

- [ ] **Step 6: Run the isolated ClusterSet group**

  ```bash
  WORKSPACE="$(pwd)" INFRA_ID="mysql-router-cs-${USER}" \
    TAP_GROUP=mysql-router-cs \
    test/scripts/run-tests-isolated.bash -k test_mysql_router_clusterset-t
  ```

  Expected GREEN: the program exits 0 after all option and topology transitions.

- [ ] **Step 7: Commit ClusterSet acceptance coverage**

  ```bash
  git add test/tap/groups/groups.json test/tap/tests/Makefile \
    test/tap/tests/test_mysql_router_clusterset-t.cpp \
    test/tap/tests/mysql_router/clusterset_*.js
  git commit -m "test(mysql-router): cover ClusterSet integration"
  ```

### Task 8: Lock the three-topology Shell compatibility matrix

**Files:**

- Create: `test/tap/tests/mysql_router/shell_contract_matrix.js`
- Create: `test/tap/tests/test_mysql_router_shell_contract-t.cpp`
- Modify: `test/tap/tests/Makefile`
- Modify: `test/tap/groups/groups.json`
- Modify: `doc/mysql-router-plugin.md`

**Interfaces:**

- Consumes: all three topology fixtures and metadata adapters.
- Produces: one uniform assertion set for Shell APIs and documented per-topology options.

- [ ] **Step 1: Assert common Shell APIs for every topology**

  Run the topology object's `listRouters()`, `routerOptions()`, `routingOptions()`, `setupRouterAccount()`, and `removeRouterMetadata()` against a disposable second ProxySQL registration. Assert the registration disappears and the running plugin detects its own row removal, closes managed gates, and reports `registration_missing` without recreating it.

- [ ] **Step 2: Assert option exposure by topology**

  Require:

  ```text
  InnoDB Cluster: read_only_targets, unreachable_quorum_allowed_traffic, stats_updates_frequency
  ReplicaSet: stats_updates_frequency
  ClusterSet: target_cluster, invalidated_cluster_policy,
              use_replica_primary_as_rw, read_only_targets,
              unreachable_quorum_allowed_traffic, stats_updates_frequency
  ```

  Tags remain visible without routing effect. Guideline is not advertised by the plugin even if the metadata schema supports storing it.

- [ ] **Step 3: Run the compatibility matrix**

  ```bash
  WORKSPACE="$(pwd)" INFRA_ID="mysql-router-shell-${USER}" \
    TAP_GROUP=mysql-router-shell \
    test/scripts/run-tests-isolated.bash -k test_mysql_router_shell_contract-t
  ```

  Expected GREEN: all common APIs and topology-specific option sets pass with the stock Shell binary.

- [ ] **Step 4: Run all three topology groups together**

  ```bash
  for group in mysql-router-ic mysql-router-rs mysql-router-cs mysql-router-shell; do
    WORKSPACE="$(pwd)" INFRA_ID="${group}-${USER}" TAP_GROUP="$group" \
      test/scripts/run-tests-isolated.bash || exit 1
  done
  ```

  Expected GREEN: all four isolated groups exit 0.

- [ ] **Step 5: Update the support table**

  Mark InnoDB Cluster/read replicas, ReplicaSet, ClusterSet, and metadata 2.2/2.3/2.4 as supported for MySQL 8.4. Retain explicit exclusions for X Protocol and Routing Guidelines.

- [ ] **Step 6: Commit the topology matrix**

  ```bash
  git add doc/mysql-router-plugin.md test/tap/groups/groups.json \
    test/tap/tests/Makefile test/tap/tests/test_mysql_router_shell_contract-t.cpp \
    test/tap/tests/mysql_router/shell_contract_matrix.js
  git commit -m "test(mysql-router): lock three-topology Shell contract"
  ```
