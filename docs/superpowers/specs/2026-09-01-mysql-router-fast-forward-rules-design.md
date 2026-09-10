# MySQL Router Fast-Forward Rules — Design

**Status:** Approved design; implementation plan pending
**Date:** 2026-09-01
**Target:** ProxySQL 4.0 (`PROXYSQL40`)
**Plugin:** `mysql_router`

## Summary

The MySQL Router plugin will publish its generated Classic routing rules with
the query-rule `switch_to_fast_forward` action on ports 6446 and 6447. The
read/write-split endpoint on port 6450 will continue using ProxySQL's native
query processor and will not enable fast-forward.

The existing ABI-8 configuration publisher cannot carry the `attributes`
column from `mysql_query_rules`. Its rule-row layout must not be extended in
place because the configuration plan has no row-stride metadata; doing so
would make a new core read beyond rule rows supplied by an existing ABI-8
plugin. ProxySQL will therefore add an ABI-9 publisher entry point with a
versioned plan extension. ABI-8 remains unchanged and supported.

This work changes only configuration publication and Router-generated query
rules. It does not add or alter MySQL packet handling, compression handling,
EOF negotiation, replication commands, prepared-statement handling, or the
fast-forward transport implementation.

## Required behavior

The plugin's five baseline rules retain their current stable ordering and
managed rule IDs:

| Rule | Endpoint | Destination | Published attributes |
|---|---:|---|---|
| `classic-rw` | 6446 | `route_writer` | `{"switch_to_fast_forward":true}` |
| `classic-ro` | 6447 | `route_reader` | `{"switch_to_fast_forward":true}` |
| `split-locking` | 6450 | `route_writer` | none |
| `split-unsafe-read` | 6450 | `route_writer` | none |
| `split-read` | 6450 | `route_reader` | none |

The existing query-rule action is limited to `COM_QUERY`. The Router plugin
does not broaden that command boundary.

Router rules remain in the reserved high-ID range. An operator can place an
earlier `apply=1` rule in front of a Router default to retain normal query
processing, select the same hostgroup, or select another hostgroup. The plugin
does not modify or remove operator-owned rules.

## ABI and publisher design

### ABI compatibility

`PROXYSQL_PLUGIN_ABI_VERSION` and `PROXYSQL_PLUGIN_ABI_VERSION_MAX` advance to
9. The loader continues accepting existing supported ABI versions, including
ABI-8 plugins.

The following ABI-8 types and callbacks remain byte-for-byte unchanged:

- `ProxySQL_PluginMysqlRuleRow`
- `ProxySQL_PluginMysqlConfigPlan`
- `ProxySQL_PluginServices::apply_mysql_config`

ABI-9 adds:

- `ProxySQL_PluginMysqlRuleAttributesRow`, containing `rule_id` and
  `attributes`;
- `ProxySQL_PluginMysqlConfigPlanV2`, containing the ABI-8 base plan plus the
  rule-attributes array and count;
- an additive tail callback,
  `ProxySQL_PluginServices::apply_mysql_config_v2`.

The separate attributes array avoids changing the stride of the existing rule
array. The Router plugin declares ABI 9, checks that the V2 callback is
available, and uses only the V2 publication path. Existing ABI-8 plugins keep
using the original callback.

### Validation

Before acquiring publication locks, the V2 publisher validates that:

- every attributes entry references exactly one rule in the base plan;
- no rule ID appears more than once in the attributes array;
- the attributes pointer is non-null when its count is non-zero;
- each value is a valid JSON object;
- null is normalized to an empty attributes object only when no explicit
  attributes entry exists.

Malformed or ambiguous input fails before any storage or runtime mutation.
The error identifies the offending rule without echoing arbitrary attribute
content.

### Atomic publication

The V2 publisher reuses the existing scoped publication transaction, lock
order, ownership ledger, collision detection, runtime snapshots, and rollback
path. The only data-model extension is that managed rule inserts and updates
include `mysql_query_rules.attributes` in both Admin and disk storage, and the
runtime query-processor load receives that same value.

On failure, main storage, disk storage, the ownership ledger, and the live
query processor return to the prior generation, including the prior rule
attributes. No post-publication SQL patch-up is permitted.

## Router compiler changes

`CompiledRule` gains an owned attributes string. `ConfigCompiler` assigns the
exact Boolean JSON object to `classic-rw` and `classic-ro`; the three split
rules retain an empty attributes string.

`CompiledMysqlConfig` builds the ABI-8 base plan as it does today, then builds
the ABI-9 attributes array for rules with non-empty attributes and exposes a
V2 plan. Bootstrap and reconciliation call `apply_mysql_config_v2` for every
generation so startup and later topology changes have identical semantics.

The compiler owns all strings until the synchronous publisher call returns.

## Testing

Implementation follows test-driven development.

### Compiler tests

- Prove 6446 and 6447 compile with exactly
  `{"switch_to_fast_forward":true}`.
- Prove all 6450 rules compile without the action.
- Prove custom listener ports preserve the same endpoint behavior.
- Prove stable rule ordering and IDs are unchanged.

### Publisher tests

- Publish attributes to main, disk, and live query-processor state.
- Replace and remove a managed rule without touching operator rules.
- Restore the exact previous attributes after an injected later-stage
  publication failure.
- Reject duplicate, unknown-rule, non-object, and malformed attributes before
  mutation.
- Keep the ABI-8 publisher contract green and load an ABI-8 fixture through
  the compatibility path.

The ABI fixture is only a compatibility test. Router acceptance always builds
and loads the real `proxysql_mysql_router.so`.

### Real InnoDB Cluster E2E

Using the existing real MySQL Shell/InnoDB Cluster environment:

- bootstrap and load the real Router plugin;
- verify the generated 6446 and 6447 runtime rules contain the action;
- connect to each endpoint, issue a `COM_QUERY`, and observe the session enter
  fast-forward on the selected writer or reader hostgroup;
- connect to 6450, exercise read and locking/write routing, and observe that
  the session remains under normal query processing;
- reconcile another generation and prove the behavior remains stable;
- prove a lower-ID operator rule can override a Router default and survives
  reconciliation unchanged.

## Documentation

The Router operator guide will document:

- 6446 and 6447 as fast-forward defaults after their first `COM_QUERY`;
- 6450 as the ProxySQL-native query-aware split endpoint;
- the lower-ID operator-rule override mechanism;
- the current InnoDB Cluster/Metadata 2.2 scope and asynchronous read replicas;
- Routing Guidelines as follow-up issue #6145;
- the current exclusions for takeover, ReplicaSet, ClusterSet, X endpoints,
  and release packaging until their existing follow-up plans are implemented.

## Branch integration

Remote `v3.0` now contains PR 6156. Before implementing this design, the
Router branch will be rebuilt through a recoverable integration branch:

1. create a backup ref at the current Router tip;
2. start from `origin/agent/mysql-router-plugin`;
3. merge current `origin/v3.0` with a detailed merge commit;
4. replay the Router Task 8 E2E commit and this design commit;
5. omit the seven local PR-6156 replay commits because their upstream
   originals are already ancestors of `origin/v3.0`;
6. verify the resulting history and tests before moving
   `agent/mysql-router-plugin` to the integration result.

No remote branch is force-pushed as part of this local synchronization.

## Rejected alternatives

### Extend `ProxySQL_PluginMysqlRuleRow` in place

Rejected because an ABI-8 plan carries neither a row size nor a row version.
A new core would index old, shorter rows using the new stride and read invalid
memory.

### Update `mysql_query_rules.attributes` after publication

Rejected because it would fall outside the publisher transaction, ownership
checks, runtime locks, snapshot restoration, and generation ledger. A crash or
error could expose a partially updated generation.

### Implement Router-specific behavior in ProxySQL core

Rejected. The core extension remains a generic versioned configuration
publisher. Port meanings and default attributes stay inside the Router
plugin.
