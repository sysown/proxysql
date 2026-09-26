# MySQL Router plugin: Routing Guidelines (issue #6145) — design

Status: approved direction (hybrid, end-to-end, documented strategy equivalence), 2026-09-17.

## 1. Goal and scope

Let an unmodified MySQL Shell (9.2+) create, update, activate and remove Routing
Guidelines while `proxysql_mysql_router.so` applies equivalent routing to real
client traffic.

This change covers **InnoDB Cluster** (the only topology the plugin supports
today). ReplicaSet and ClusterSet guideline support depend on the plugin's
topology expansion and are follow-ups; the engine is written topology-agnostic
(`clusterRole`, `clusterSetName`, `isClusterInvalidated` are modelled).

Out of scope: X protocol, `$.sql.*` (Router never populates it), per-connection
re-evaluation of already established sessions on guideline change (see §7.4).

## 2. Architecture (hybrid)

```
 MySQL metadata (2.3/2.4)            plugin reconciler (2s)                       data plane
 routing_guidelines  ──read──►  parse+validate (engine) ──► classify servers ──► publish hostgroups
 router_options.guideline                                  per route pools          (atomic plan)
                                                                 │
                                                                 ▼
                                               immutable RoutingSnapshot (atomic shared_ptr)
                                                                 │
 client query ─► MySQL_Session ─► query rules (operator first, plugin baseline 900000+)
                         └─► ABI-10 session route hook ─► plugin evaluates routes (per session, cached
                              in session cookie) ─► remaps plugin baseline destination hostgroup
                              to the route pool hostgroup, or denies (no route)
```

* **Destinations** (`$.server.*`, `$.router.*`) are evaluated by the plugin at reconcile
  time against the live topology; every route gets pools of hostgroups.
* **Routes** (`$.session.*`, `$.router.*`) are evaluated natively per client session
  by the plugin through a new core hook, supporting the full expression language.

## 3. Routing Guidelines specification (what we must be compatible with)

Verified against mysql-server trunk (`router/src/routing_guidelines`) and mysql-shell
master; 9.2.0 introduced the feature, document versions `"1.0"` and `"1.1"` (latest).

### 3.1 Metadata

* Metadata schema >= 2.3.0 has table `mysql_innodb_cluster_metadata.routing_guidelines
  (guideline_id UUID PK, name UNIQUE, guideline JSON, clusterset_id, cluster_id,
  last_update, default_guideline)`.
* Active guideline = `guideline` key (a **guideline_id**, not a name) in
  `routers.options` (per router) > `clustersets.router_options` > `clusters.router_options`.
  Router's query:
  ```sql
  SELECT guideline FROM mysql_innodb_cluster_metadata.routing_guidelines WHERE guideline_id = (
    SELECT COALESCE(RO.router_options->>'$.guideline', CS.router_options->>'$.guideline',
                    CL.router_options->>'$.guideline')
    FROM mysql_innodb_cluster_metadata.v2_router_options RO
    LEFT JOIN mysql_innodb_cluster_metadata.clustersets CS ON RO.clusterset_id = CS.clusterset_id
    LEFT JOIN mysql_innodb_cluster_metadata.clusters CL ON RO.cluster_id = CL.cluster_id
    WHERE RO.router_id = ?)
  ```
* Router compares the fetched text with the last one; empty / `{}` restores the default;
  on parse error it logs and **keeps the previous engine**.
* Router writes `v2_routers.attributes`: `$.SupportedRoutingGuidelinesVersion` (Shell refuses
  `setRoutingOption('guideline', ...)` for routers not advertising a compatible version) and
  `$.CurrentRoutingGuideline` (name or NULL).
* `$.router.*` sources: `v2_routers.address` → hostname, `attributes.RWEndpoint/ROEndpoint/
  RWSplitEndpoint` → port.rw/ro/rw_split, `attributes.LocalCluster` → localCluster,
  `options->'$.tags'` → tags, `router_name` → name. `$.server.tags` = `v2_instances.attributes->'$.tags'`.

### 3.2 Document

* Top level: `version` (string `N.N`, missing ⇒ "1.0"), `destinations` (array, min 1),
  `routes` (array, min 1), optional `name`; **unknown fields are errors at every level**.
* `destinations[]`: `{name, match}` both non-empty strings; duplicate names are errors.
* `routes[]`: required `name`, `match`, `destinations`; optional `enabled` (default true),
  `connectionSharingAllowed` (bool). Duplicate names are errors.
* `routes[].destinations[]`: `classes` (non-empty array of non-empty strings, each a defined
  destination), `strategy` ∈ {`round-robin`, `first-available`}, `priority` (uint64, required
  by schema).
* All errors are collected and reported together with JSON paths
  (e.g. `routes[1].match: type error, ...`).
* Version compatibility: `available <= supported && supported.major - available.major <= 1`.
  We support `"1.1"`.

### 3.3 Expression language

* Lexer: whitespace skipped; numbers via strtod (doubles, unary minus is an operator);
  strings in `'..'` or `".."` with `\` escapes (`\n \t \r \b \0 \Z` translated, other `\x`→`x`);
  variables `$.` + dotted identifiers (letters/digits/_; segments start with letter or `_`);
  keywords `TRUE FALSE NULL AND OR NOT IN LIKE`, function names and role literals
  `PRIMARY SECONDARY READ_REPLICA UNDEFINED REPLICA` are case-insensitive; **any other bare
  identifier is a string literal**. `{` `[` illegal except as a 1.1 tag literal.
  Variable names are case-sensitive.
* Precedence (low→high): `OR`; `AND`; prefix `NOT`; non-assoc `> < >= <= <> = IN LIKE`
  (`exp [NOT] IN (list)`, `exp [NOT] LIKE exp`); `+ -`; `* / %`; unary `-`; `( )`;
  calls `FUNC()`/`FUNC(list)`. No `!=`, no `IS NULL`.
* Types: NUMBER(double), STRING, BOOLEAN, ROLE, NULL. Parse-time checks: arithmetic needs
  NUMBER; `< > <= >=` NUMBER or STRING same type; `= <>` same type unless one is NULL;
  member role vs cluster role is a type error (`PRIMARY`, `UNDEFINED` valid for both);
  IN elements same type as needle; LIKE needs STRING and a literal pattern; whole expression
  must be BOOLEAN. Constant folding at parse time.
* Semantics: string `= <> < <= IN` case-insensitive; ROLE compare case-insensitive;
  runtime type mismatch with NULL ⇒ false (`<>` ⇒ true); with BOOLEAN ⇒ both to bool
  (number≠0, string non-empty, role≠UNDEFINED, NULL=false); otherwise error
  "Incompatible operands". AND/OR short-circuit. Arithmetic with NULL ⇒ NULL; `%` fmod;
  division by zero ⇒ inf/nan. Functions return NULL if any argument is NULL.
  LIKE case-insensitive: `%`/`''` always match; `x%`,`%x`,`%x%` ⇒ startswith/endswith/contains;
  else anchored ECMAScript regex (`%`→`.*`, `_`→`.`, `\%` `\_` literal).
* Functions: `SQRT(NUM)`, `NUMBER(STR)` (strtod, trailing chars error), `IS_IPV4(STR)`,
  `IS_IPV6(STR)` (numeric host, strip `%zone`, reject `[..]`), `REGEXP_LIKE(STR,STR)`
  (ECMAScript icase full match), `SUBSTRING_INDEX(STR,STR,NUM)` (MySQL semantics, delimiter
  case-sensitive), `STARTSWITH/ENDSWITH/CONTAINS(STR,STR)` (case-insensitive),
  `CONCAT(...)` (numbers/booleans converted), `NETWORK(STR,NUM)` (**IPv4 only**, mask 1..32,
  returns network address string), `RESOLVE_V4/RESOLVE_V6(literal STR)` (resolved at load).
* Variables:
  * `$.router.*` (routes and destinations): `port.ro`, `port.rw`, `port.rw_split` NUM;
    `localCluster`, `hostname`, `bindAddress`, `routeName`, `name` STR; `tags.<k>` STR.
  * `$.server.*` (destinations only): `label`, `address`, `uuid`, `clusterName`,
    `clusterSetName` STR; `port`, `version` (MMmmpp) NUM; `memberRole`, `clusterRole` ROLE;
    `isClusterInvalidated` BOOL; `tags.<k>` STR.
  * `$.session.*` (routes only): `targetIP`, `sourceIP`, `user`, `schema` STR; `targetPort`,
    `randomValue` NUM; `connectAttrs.<k>` STR.
  * Unknown non-tag variable ⇒ parse error; unknown tag key ⇒ NULL.
* Tags (1.1): the first literal token after a `$.server.tags.*` / `$.router.tags.*`
  reference is kept as raw JSON text (quoted strings keep `"` quotes); tag values are
  stored as JSON text (`"EU"`, `41`, `true`).

### 3.4 Routing semantics (Router)

1. Routes checked in array order, skipping disabled; first match wins; no match ⇒ the
   connection fails; any route evaluation error ⇒ connection fails.
2. Destination groups stable-sorted by priority; candidates = online members whose classes
   intersect the group's classes (class order, then topology order).
3. A lower-priority group is used only if all earlier groups are empty/failed.
4. `first-available`: always start from the first candidate; `round-robin`: rotate.
5. rw_split port: the route builds a candidate pool, statements are sent to a PRIMARY
   (writes) or read-only member (reads); the pool must contain the needed kind.
6. `connectionSharingAllowed` overrides connection sharing.

## 4. ProxySQL mapping (documented equivalence)

| Router | ProxySQL |
|---|---|
| route pool at connect | per-route hostgroups published by the plugin at reconcile time |
| priority fallback | the **first priority group with at least one online member** at reconcile time; re-evaluated on every refresh (default 2 s) and on health changes |
| `round-robin` | all pool members weight 1 (ProxySQL weighted random load balancing) |
| `first-available` | members weighted in candidate order: first 10000000, then decreasing by powers of 100 (min 1); ProxySQL selects the first online member practically always and falls back immediately when it is shunned |
| route selection per backend connect | route selected once per client session (first statement), cached in the session; re-selected if the guideline generation changes |
| no route matches | the statement fails through the query-rule `error_msg` path (`ERROR 1148 (42000): MySQL Router plugin: no Routing Guideline route matches this session`); the session stays open (ProxySQL cannot fail at handshake time) |
| empty pool | statement fails with `... route '<name>' has no available destinations` |
| `connectionSharingAllowed` | reported in explain view; ProxySQL multiplexing rules unchanged |
| rw_split port pool | writer hostgroup = PRIMARY members of the first group containing an online PRIMARY; reader hostgroup = non-PRIMARY members of the first group containing one, else the writer members |
| `$.session.targetPort` | the ProxySQL listener port the client connected to |
| `$.session.targetIP` | the plugin's configured `bind_address` |
| `$.session.schema` | the session's current schema at route selection |

Every difference is shown in `runtime_mysql_router_guideline_routes.notes`.

## 5. Precedence with operator query rules

* Operator-owned `mysql_query_rules` are never modified and are evaluated first (plugin
  baseline rules use rule_ids 900000-900999, i.e. after operator rules with lower ids).
* The route hook only remaps a destination hostgroup that equals the plugin-owned
  `route_writer` or `route_reader` hostgroup (i.e. what the plugin baseline rules or
  managed users' default hostgroup selected). Any other destination chosen by an operator
  rule is left unchanged.
* With no active valid guideline the hook is a no-op: behaviour is exactly today's.

## 6. Components and interfaces

### 6.1 Engine (`plugins/mysql_router/src/routing_guidelines*.cpp`, `plugins/mysql_router/include/mysql_router_routing_guidelines.h`)

Pure C++17, depends only on nlohmann json and `<regex>`; no ProxySQL headers, so it is unit
tested in isolation.

```cpp
namespace mysql_router::rg {
enum class MemberRole { undefined, primary, secondary, read_replica };
enum class ClusterRole { undefined, primary, replica };
enum class Strategy { round_robin, first_available };
struct Error { std::string path; std::string message; };
struct RouterInfo { uint16_t port_ro{0}, port_rw{0}, port_rw_split{0};
  std::string local_cluster, hostname, bind_address, route_name, name;
  std::map<std::string,std::string> tags; /* raw JSON text values */ };
struct ServerInfo { std::string label, address, uuid, cluster_name, cluster_set_name;
  uint16_t port{0}; uint32_t version{0}; MemberRole member_role{MemberRole::undefined};
  ClusterRole cluster_role{ClusterRole::undefined}; bool is_cluster_invalidated{false};
  std::map<std::string,std::string> tags; };
struct SessionInfo { std::string target_ip, source_ip, user, schema; uint16_t target_port{0};
  double random_value{0}; std::map<std::string,std::string> connect_attrs; };
struct DestinationGroup { std::vector<std::string> classes; Strategy strategy; uint64_t priority; };
struct Route { std::string name, match; bool enabled{true};
  std::optional<bool> connection_sharing_allowed; std::vector<DestinationGroup> groups; /* stable sorted */ };
struct Destination { std::string name, match; };
class Guideline {  // immutable after parse
 public:
  static std::shared_ptr<const Guideline> parse(std::string_view json, std::vector<Error>& errors);
  const std::string& name() const; const std::string& version() const;
  const std::vector<Destination>& destinations() const; const std::vector<Route>& routes() const;
  bool uses_router_route_name_in_destinations() const;
  // class names (destination order) matching the server; errors appended
  std::vector<std::string> classify(const ServerInfo&, const RouterInfo&, std::vector<Error>&) const;
  // index of first enabled matching route, nullopt if none; any error => nullopt + errors
  std::optional<size_t> match_route(const SessionInfo&, const RouterInfo&, std::vector<Error>&) const;
};
constexpr const char* kSupportedVersion = "1.1";
}
```

### 6.2 Core ABI-10: MySQL session route hook

`include/ProxySQL_Plugin.h`: bump layout version to 10, add tail service
`register_mysql_route_hook`.

```cpp
struct ProxySQL_PluginConnectAttr { const char* key; const char* value; };
struct ProxySQL_PluginRouteHookPayload {
  const char* user; const char* schema; const char* client_ip; int client_port;
  const char* proxy_ip; int proxy_port;               // listener the client connected to
  const ProxySQL_PluginConnectAttr* connect_attrs; size_t connect_attrs_count;
  int destination_hostgroup;                          // after query rules (default hostgroup if -1)
  uint64_t session_cookie;                            // opaque per-session state, 0 initially
};
enum class ProxySQL_PluginRouteHookAction : uint8_t { unchanged = 0, set_hostgroup = 1, deny = 2 };
struct ProxySQL_PluginRouteHookResult { ProxySQL_PluginRouteHookAction action; int hostgroup;
  uint64_t session_cookie; std::string message; };
using proxysql_plugin_route_hook_cb = ProxySQL_PluginRouteHookResult (*)(const ProxySQL_PluginRouteHookPayload&);
bool (*register_mysql_route_hook)(proxysql_plugin_route_hook_cb);  // init phase only, one hook
```

`MySQL_Session` calls it right after the query processor in the COM_QUERY,
COM_STMT_PREPARE and COM_STMT_EXECUTE paths, when a hook is registered (lock-free atomic
fast path). The session cookie is reset to 0 on COM_CHANGE_USER and COM_RESET_CONNECTION,
so the route is selected again for the new identity. `set_hostgroup` overwrites
`qpo->destination_hostgroup`; `deny` returns an error to the client for that statement.
The session stores the returned cookie.

### 6.3 Plugin integration

* `probe_metadata`: accept 2.2.x, 2.3.x and 2.4.x; `routing_guidelines` capability for >= 2.3.
* Guideline read (capability only) with Router's COALESCE query plus `guideline_id`, `name`.
* Registration check-in writes `$.SupportedRoutingGuidelinesVersion = "1.1"` and
  `$.CurrentRoutingGuideline` (active valid guideline name or JSON null) when >= 2.3.
* Hostgroups: 8 baseline roles unchanged plus 3 per route (`rg:<route>:all|writer|reader`),
  allocated in the 8000-8999 band through `mysql_router_hostgroups`; stale route hostgroups
  released on republish.
* `RoutingSnapshot` (immutable, `std::atomic<std::shared_ptr<const RoutingSnapshot>>`):
  generation, guideline, listener ports, route pools, baseline route hostgroups, member counts.
* Tables:
  * `runtime_mysql_router_guideline` (guideline_id, name, version, state
    `none|active|invalid|stale`, generation, last_error, last_update).
  * `runtime_mysql_router_guideline_routes` (route_order, route_name, enabled, match,
    selected_priority, classes, strategy, all_hostgroup, writer_hostgroup, reader_hostgroup,
    members, connection_sharing_allowed, notes).
  * `runtime_mysql_router_guideline_destinations` (server_uuid, endpoint, member_role, classes).
  * Errors in `stats_mysql_router_errors` with kinds `guideline_parse`, `guideline_validation`,
    `guideline_evaluation`, `guideline_publication`.
* Failure policy: an invalid/unsupported document never replaces the last valid generation
  (state `stale` + error); with no previous valid generation the guideline is not applied
  (state `invalid`, baseline behaviour, error recorded). Metadata outage keeps the last valid
  generation. Guideline removal (`guideline` option null) ⇒ state `none`, route hostgroups
  released, hook becomes a no-op.
* Unsupported (fail closed, explicit error): `$.router.routeName` inside destinations,
  more routes than hostgroup capacity, document version > 1.1 or < 1.0.

## 7. Testing

1. Engine unit tests (`test/tap/tests/unit/mysql_router_routing_guidelines_unit-t.cpp`):
   lexer, precedence, typing, functions, tags 1.0/1.1, document validation errors with paths,
   classification, route matching; include Shell default guideline documents.
2. Core hook unit test (dispatch, fast path) + plugin mapping unit tests (pools, weights,
   fallback, remap precedence, cookie reuse).
3. E2E (`mysql-router-ic-rg-g1`): MySQL 8.4 sandbox cluster created with **unmodified MySQL
   Shell 9.x** (metadata 2.3+), production plugin, Shell-created guideline(s), real client
   traffic on RW / RO / RW-split ports matching and not matching predicates (user, source,
   connect attribute), guideline modification and removal convergence, invalid update keeps
   last generation, operator rules unchanged, explain view contents.
4. Known limitation 7.4: existing client sessions keep their cached route until the next
   statement after a generation change (then re-selected); Router instead disconnects
   affected connections.
