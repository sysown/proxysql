# MySQL X Plugin Design For ProxySQL

## Status

Drafted through brainstorming and narrowed to:

- hybrid config model
- dual-mode accounts
- in-process plugin loaded with ProxySQL
- same-process execution with clean extension API
- plugin-owned worker threads
- umbrella architecture plus implementation-ready slices 1-2


## 1. Objective

Design MySQL X Protocol support for ProxySQL such that:

- it can ship as a separately loadable plugin rather than as tightly embedded core code
- it supports deep integration rather than Router-style passthrough only
- it preserves reuse of canonical ProxySQL concepts where their semantics are shared
- it keeps protocol-specific complexity isolated from the classic MySQL frontend/backend code paths

This design covers four subprojects:

1. frontend `mysqlx` termination
2. backend `mysqlx` connectivity
3. X-aware policy engine
4. X-based Group Replication notifications

This document is implementation-ready for subprojects 1 and 2, and architectural for 3 and 4.


## 2. Scope

### In scope for slices 1-2

- plugin boundary and extension API
- plugin-owned listeners and worker threads
- frontend X handshake and authentication termination
- dual-mode identity resolution using `mysql_users` and `mysqlx_users`
- backend X session establishment
- backend identity mapping modes
- route and hostgroup integration
- per-session binding of future policy state
- plugin stats and admin surface needed to operate the feature

### Out of scope for immediate implementation

- full X rule grammar and enforcement implementation
- query/document rewrite semantics
- pooling and multiplexing beyond explicit initial boundaries
- X-based Group Replication notification delivery
- broad protocol-neutral refactoring of ProxySQL core
- hot-unload of the plugin


## 3. Design Principles

- Keep X Protocol semantics out of ProxySQL core.
- Reuse core only for generic infrastructure and shared runtime state.
- Keep the plugin operationally integrated but implementation-isolated.
- Prefer explicit protocol-specific surfaces over overloading classic MySQL concepts beyond recognition.
- Preserve a path to future evolution without forcing a large core refactor first.


## 4. Chosen Direction

### 4.1 Architectural choice

Use a thin-core plugin with shared generic services.

ProxySQL core exposes a narrow, versioned extension API. The plugin owns:

- `mysqlx` listeners
- `mysqlx` worker threads
- frontend X protocol state
- backend X protocol state
- identity merge and auth logic
- route selection policy
- X message parsing and classification
- X policy enforcement
- `mysqlx` stats

Core provides:

- plugin lifecycle
- listener registration or polling integration hooks
- config snapshot and subscription APIs
- access to shared topology state
- logging
- stats/admin registration
- optional generic transport helpers if they are truly protocol-neutral

### 4.2 Config model choice

Use a hybrid config surface.

Shared:

- `mysql_users`
- `mysql_servers`
- replication and Group Replication hostgroup state

`mysqlx`-specific:

- `mysqlx_users`
- `mysqlx_routes`
- `mysqlx_rules`
- `mysqlx_policy_profiles`
- `mysqlx` stats tables

### 4.3 Account model choice

Use dual-mode accounts.

- `mysql_users` is canonical.
- `mysqlx_users` contains X-specific overrides only.


## 5. Module Boundary

### 5.1 Plugin loading model

The plugin is loaded at ProxySQL startup through a versioned plugin interface.

Phase 1 assumes:

- load at startup
- disable or restart to upgrade
- no true dynamic unload while active sessions exist

This avoids unsafe lifetime problems while still preserving plugin separability.

### 5.2 Core extension API

The core-facing API should be intentionally small and protocol-neutral.

Required surfaces:

- `plugin_init()`, `plugin_start()`, `plugin_stop()`, `plugin_status()`
- listener registration API
- event-loop registration API or a socket registration API for plugin-owned loops
- snapshot access for:
  - `mysql_users`
  - `mysqlx_users`
  - `mysql_servers`
  - `mysql_replication_hostgroups`
  - `mysql_group_replication_hostgroups`
  - relevant global variables
- subscription or version-tracking for config refresh
- hostgroup destination lookup helpers
- logging API
- metrics and admin table registration API

Explicitly not exposed:

- classic `MySQL_Protocol`
- classic `MySQL_Session`
- classic `MySQL_Connection`
- MariaDB Connector-C async state machine

### 5.3 Worker model

The plugin has its own worker threads.

Reasons:

- X handshake/auth/parser behavior differs substantially from classic MySQL.
- Reusing MySQL worker threads would couple the plugin to classic assumptions.
- Separate workers improve isolation, performance analysis, and plugin credibility.

Each plugin worker owns:

- accepted frontend client sockets assigned to that worker
- backend X sockets for those sessions
- per-session parser state
- per-session auth state
- per-session rule context


## 6. Runtime Architecture

The plugin is internally divided into four subsystems.

### 6.1 Frontend service

Responsibilities:

- owns `mysqlx` listeners
- accepts client sockets
- performs TLS negotiation if ProxySQL-terminated TLS is enabled
- runs X handshake and auth exchange
- creates frontend session objects

### 6.2 Identity and policy binding

Responsibilities:

- resolve `mysql_users` plus `mysqlx_users`
- determine whether the account is X-enabled
- determine allowed auth methods and TLS requirements
- attach route profile
- attach policy profile
- attach backend identity mapping mode

### 6.3 Backend X service

Responsibilities:

- choose a backend destination using shared topology state
- establish outbound backend X sessions
- authenticate using resolved backend identity mode
- enforce pooling boundaries if pooling exists
- expose connection health and routing state

### 6.4 Policy engine

Responsibilities:

- parse X messages after session establishment
- classify SQL vs CRUD vs document-store operations
- evaluate rules
- perform allow, deny, reroute, or future rewrite decisions
- produce observability events

For slices 1-2, this subsystem only needs architectural hooks and minimal scaffolding, not full implementation.


## 7. Identity Model

### 7.1 Canonical and override tables

`mysql_users` remains canonical for shared account identity.

`mysqlx_users` adds protocol-specific overrides.

Recommended shape for `mysqlx_users`:

```sql
CREATE TABLE mysqlx_users (
  username VARCHAR NOT NULL PRIMARY KEY,
  active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
  require_tls INT CHECK (require_tls IN (0,1)) NOT NULL DEFAULT 0,
  allowed_auth_methods VARCHAR NOT NULL DEFAULT '',
  default_route VARCHAR,
  policy_profile VARCHAR,
  backend_auth_mode VARCHAR NOT NULL DEFAULT 'mapped',
  backend_username VARCHAR,
  backend_password VARCHAR,
  attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',
  comment VARCHAR NOT NULL DEFAULT ''
);
```

`runtime_mysqlx_users` should mirror it.

### 7.2 Resolution flow

Identity resolution is deterministic:

1. Look up `mysql_users.username`.
2. If no canonical user exists, deny authentication.
3. Look up `mysqlx_users.username`.
4. If no `mysqlx_users` row exists, the account is not X-enabled by default.
5. Merge canonical and X-specific fields into a resolved identity object.

The resolved identity object includes:

- canonical username
- canonical default hostgroup
- max connections
- X enabled flag
- allowed auth methods
- TLS requirements
- default route
- policy profile
- backend auth mode
- backend credential override if configured
- protocol-specific attributes

### 7.3 Backend identity modes

The resolved identity supports three backend modes:

- `pass_through`
  - backend X session authenticates using the same logical username and client-supplied secret semantics where supported
- `mapped`
  - backend X session uses explicit backend credentials from the resolved identity
- `service_account`
  - plugin authenticates the client itself and opens backend sessions using service credentials, with optional future impersonation metadata

Phase 1 should implement:

- `mapped`
- `service_account`

`pass_through` can be supported only if the auth semantics are safe and the plugin can avoid retaining client secrets inappropriately. If that cannot be made correct early, it should be documented as unsupported rather than approximated.
Until then, configuration validation should reject `pass_through` rather than silently downgrading it.


## 8. Frontend `mysqlx` Termination

### 8.1 Session establishment

On accept:

1. assign socket to a plugin worker
2. create session context
3. initialize transport state
4. begin X handshake
5. negotiate capability set
6. authenticate client
7. resolve identity and policy binding
8. select route target set
9. establish backend X session
10. transition to proxied active state

### 8.2 Authentication behavior

The plugin terminates frontend X authentication itself.

This is required for:

- deep integration
- dual-mode account enforcement
- future X-aware rules
- future session-aware routing and policy

The frontend auth design must support:

- account disabled behavior
- TLS-required behavior
- per-user allowed auth methods
- clear error mapping
- connection accounting before and after authentication

### 8.3 Session object

Each frontend session tracks:

- transport state
- TLS state
- X capability state
- authentication state
- resolved identity
- assigned route
- policy profile binding
- parser state
- backend session handle
- counters and timing


## 9. Backend X Connectivity

### 9.1 Backend transport model

The plugin manages backend X connections directly.

Do not build slice 2 on top of:

- `MySQL_Connection`
- `MYSQL *`
- MariaDB Connector-C classic protocol helpers

The backend side should be native to the plugin and X-aware from the start.

### 9.2 Route and destination model

Recommended route table:

```sql
CREATE TABLE mysqlx_routes (
  name VARCHAR NOT NULL PRIMARY KEY,
  bind VARCHAR NOT NULL,
  destination_hostgroup INT NOT NULL,
  fallback_hostgroup INT,
  strategy VARCHAR NOT NULL DEFAULT 'first_available',
  active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
  attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',
  comment VARCHAR NOT NULL DEFAULT ''
);
```

`runtime_mysqlx_routes` should mirror it.

Hostgroup semantics remain shared with core topology tables.

### 9.3 Destination selection

Slice 2 should support:

- `first_available`
- `round_robin`
- `round_robin_with_fallback`

Destination eligibility is derived from shared runtime topology state:

- `mysql_servers`
- replication hostgroup mappings
- Group Replication hostgroup mappings
- monitor health state

The core may provide hostgroup snapshots, but the plugin should own final route selection semantics.

### 9.4 Pooling and multiplexing boundaries

For initial implementation:

- no cross-user multiplexing
- no session reuse across incompatible policy bindings
- no reuse across differing backend auth modes
- no reuse across differing backend capability sets

Pooling may be introduced cautiously for:

- identical backend target
- identical backend auth identity
- identical capability and TLS requirements
- no session-local state that makes reuse unsafe

This means the first implementation should assume one live frontend session owns one backend X session.


## 10. Policy Engine Architecture

The eventual policy engine must understand X message types well enough to classify operations.

The design should reserve explicit hooks for:

- SQL statement execution
- CRUD operations
- document collection operations
- transaction state
- prepared or repeated execution forms if exposed by X

Recommended policy objects:

- `mysqlx_policy_profiles`
- `mysqlx_rules`

Where `policy_profile` on the resolved identity selects a ruleset.

Initial rule outcomes:

- allow
- deny
- reroute
- require primary
- require reader
- emit audit event

Rewrite should be a deferred capability unless message rewriting is proven safe for the targeted X operations.


## 11. Group Replication Notifications

This is Phase 2 of the broader `mysqlx` project, but not required for slices 1-2.

The plugin should still be architected so that a future GR notification subsystem can:

- maintain X connections to cluster members
- receive topology-change notifications
- trigger topology cache refresh
- reduce convergence time for route decisions

This subsystem should feed into shared routing state, not bypass it with a separate topology model.


## 12. Admin And Observability Surface

### 12.1 Config tables

Required:

- `mysqlx_users`
- `runtime_mysqlx_users`
- `mysqlx_routes`
- `runtime_mysqlx_routes`

Deferred but architected:

- `mysqlx_policy_profiles`
- `mysqlx_rules`

### 12.2 Stats tables

Recommended initial stats:

```sql
CREATE TABLE stats_mysqlx_routes (
  name VARCHAR NOT NULL,
  destination_hostgroup INT NOT NULL,
  ConnOK INT NOT NULL,
  ConnERR INT NOT NULL,
  ConnUsed INT NOT NULL,
  Bytes_data_sent BIGINT NOT NULL,
  Bytes_data_recv BIGINT NOT NULL
);
```

And per-connection/session stats exposed through admin commands or a runtime table with:

- username
- route
- worker id
- backend host and port
- auth mode
- connection state
- bytes in and out
- session age


## 13. Core Integration Points

The required core changes should be narrowly scoped.

### 13.1 Required generic hooks

- plugin loader and registry
- plugin lifecycle management
- listener conflict validation integration
- config snapshot export for shared tables
- runtime config change notifications
- stats namespace registration
- logging and diagnostics hooks

### 13.2 Avoided core entanglement

Do not modify classic code so that X logic is threaded through:

- MySQL classic handshake path
- classic prepared statement machinery
- MariaDB Connector-C connection lifecycle
- MySQL worker thread scheduling


## 14. Risks

### 14.1 Largest implementation risk

Frontend auth termination plus backend X session establishment in a plugin is materially larger than Router-style passthrough. That is intentional, but it raises schedule risk.

### 14.2 Design risk

If the plugin API is too small, the plugin will be forced into ugly duplication.

If the plugin API is too broad, ProxySQL core becomes an accidental protocol framework.

The extension API must stay narrow and intentionally generic.

### 14.3 Operational risk

Dual-mode accounts can become confusing if fallback rules are vague.

Mitigation:

- `mysqlx` disabled unless explicitly enabled in `mysqlx_users`
- deterministic merge rules
- admin diagnostics showing the resolved identity object


## 15. Testing Strategy

### 15.1 Slice 1 tests

- authenticate valid dual-mode account
- reject canonical user without `mysqlx_users` enablement
- enforce TLS-required accounts
- enforce allowed auth methods
- resolve merged identity correctly

### 15.2 Slice 2 tests

- connect backend X session with mapped identity
- connect backend X session with service-account mode
- select destination from route hostgroup
- fallback when primary hostgroup has no eligible destination
- reject invalid route configuration
- preserve one frontend to one backend ownership

### 15.3 Plugin integration tests

- startup with plugin enabled
- startup with plugin disabled
- config reload of `mysqlx_users`
- config reload of `mysqlx_routes`
- worker-thread isolation under concurrent sessions


## 16. Recommended Implementation Order

1. core plugin loader and minimal extension API
2. plugin-owned listeners and worker threads
3. `mysqlx_users` and `mysqlx_routes` config surfaces
4. resolved identity pipeline
5. frontend X handshake and auth termination
6. backend X session establishment
7. route selection and fallback
8. stats/admin diagnostics
9. parser and policy hooks
10. full rule engine
11. GR notifications


## 17. Final Recommendation

Build `mysqlx` as an in-process ProxySQL plugin with its own worker threads and a narrow core extension API.

Keep:

- shared topology and canonical user identity in core-managed tables
- X-specific overrides, routes, and future rules in plugin-specific tables

Implement first:

- frontend auth termination
- dual-mode account resolution
- backend X session management
- route selection over shared hostgroups

Design now, but defer implementation of:

- full X-aware rule engine
- X-based Group Replication notifications

This is the best match for:

- deep integration
- plugin separability
- future extensibility
- minimal contamination of ProxySQL classic protocol internals
