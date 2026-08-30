# Per-Interface MySQL Server Version Design

**Date:** 2026-08-30
**Replacement for:** PR #4784
**Feature tier:** `PROXYSQL31`

## Problem

ProxySQL currently advertises one frontend MySQL server version from
`mysql-server_version`. Operators that expose multiple MySQL listeners cannot
make different listeners identify as different MySQL versions without running
multiple ProxySQL instances.

PR #4784 attempted to solve this by attaching a server version to backend rows.
That couples a frontend-handshake property to backend routing and introduces
unsafe schema migrations, incomplete configuration paths, and inconsistent
lookup keys. The replacement must keep the setting entirely in frontend
listener configuration and must not change any `mysql_servers` schema.

## Goal

Add `mysql-server_version_by_interface`, a JSON object that optionally overrides
the advertised server version for individual entries from `mysql-interfaces`.
Keep `mysql-server_version` as the scalar fallback for every listener without a
matching override.

The relationship between the two interface variables is deliberately loose.
The override object is a catalog, not a mirror of the listeners active on the
current ProxySQL instance. It may contain hundreds or thousands of entries used
by other nodes or by future configurations.

## Configuration Contract

The existing scalar remains unchanged:

```sql
SET mysql-server_version = '8.0.11';
```

The new variable is a string containing a JSON object and defaults to `{}`:

```sql
SET mysql-server_version_by_interface = '{
  "0.0.0.0:6033": "8.0.30",
  "127.0.0.1:6034": "5.7.44",
  "[::]:6035": "8.4.0",
  "/tmp/proxysql.sock": "8.0.36"
}';
LOAD MYSQL VARIABLES TO RUNTIME;
```

Each JSON property name is an interface token in the same textual form used by
`mysql-interfaces`. Each property value is the server version to advertise on
that listener.

For a newly accepted connection:

1. Identify the exact `mysql-interfaces` token for the listening socket that
   accepted the connection.
2. Perform an exact, case-sensitive textual lookup in
   `mysql-server_version_by_interface`.
3. Use the mapped value when the key exists.
4. Otherwise use `mysql-server_version`.

The lookup is based on the bound listener, not the destination address reported
by the client connection. No address normalization, hostname resolution,
wildcard expansion, or port-only matching is performed. TCP, bracketed IPv6,
and Unix-socket tokens are all valid keys.

## Loose Correlation

Loading the override variable does not compare its keys with the current value
of `mysql-interfaces`. In particular:

- an override may be loaded before its listener exists;
- a shared catalog may contain entries for many ProxySQL nodes;
- removing a listener does not remove its override;
- an unmatched or misspelled entry remains stored and has no runtime effect;
- an empty catalog means every listener uses the scalar fallback.

This loose correlation also means `mysql-server_version_by_interface`
synchronizes through ProxySQL Cluster as an ordinary MySQL variable. Its
synchronization is independent of `cluster_sync_interfaces`; nodes use whichever
catalog entries match their own listeners.

## Validation and Atomicity

`LOAD MYSQL VARIABLES TO RUNTIME` accepts the new value only when:

- it parses as a JSON object;
- every key is a non-empty string without an embedded NUL byte;
- every value is a non-empty string without an embedded NUL byte; and
- an object does not contain duplicate keys.

The loader does not require a key to name a currently active listener. Arrays,
scalars, `null`, non-string values, empty strings, strings containing an
embedded NUL byte, malformed JSON, and duplicate keys are rejected.

Parsing and validation build a temporary catalog first. A failure leaves the
previous runtime string and parsed catalog intact and follows the existing MySQL
variable rejection/reporting path. A successful load publishes the complete new
catalog as one snapshot; readers never observe a partially replaced map.

The raw JSON string remains available through the normal variable getter so the
existing `SAVE MYSQL VARIABLES TO DISK`, restart loading, and cluster checksum
mechanisms continue to work.

## Listener Identity

The listener manager already associates an `iface_info` record with each
listening file descriptor. In a `PROXYSQL31` build it must also preserve the
original, complete interface token as a stable lookup identity before listener
parsing mutates or splits the input.

The accepted connection obtains this identity through the listening file
descriptor. This avoids reconstructing strings from `address` and `port`, which
would be ambiguous or fragile for IPv6, Unix sockets, and textual aliases.
`SO_REUSEPORT` may create multiple listening descriptors for one interface; all
of them retain the same interface identity and therefore select the same
override.

## Runtime Data Flow

The parsed override catalog follows the existing MySQL thread-variable refresh
mechanism. Each worker sees an immutable, internally owned snapshot suitable for
constant-time lookup. Configuration storage, parsed-map ownership, and session
ownership must use explicit value or RAII semantics; raw map entries must not be
shared as independently freed pointers.

When a worker accepts a frontend connection, it resolves the advertised version
from the listener identity and the worker's current configuration snapshot. The
resolved string is copied into session-owned state before the initial handshake
is generated.

The version is pinned for the lifetime of that frontend session. Later runtime
loads affect only connections accepted after publication of the new snapshot.
An existing connection cannot change the version it announced during its
handshake.

## Frontend Version Consistency

The session-pinned value replaces the global scalar wherever ProxySQL internally
uses its advertised frontend version:

- the server-version field in the initial MySQL handshake;
- internally generated `SELECT @@version` and `SELECT VERSION()` results;
- version-dependent handling of the MySQL client's `SELECT $$` capability
  probe.

`mysql-select_version_forwarding` keeps its existing routing behavior. The
pinned value is used in `never` mode and as the internal fallback in
`smart_fallback_internal`. `always` continues forwarding to a backend, and
`smart_fallback_proxy` continues forwarding when it cannot obtain a backend
version.

No per-interface version participates in backend selection, hostgroup matching,
health checks, or backend capability negotiation.

## Feature-Tier Boundary

The variable and all supporting state and behavior are compiled only when
`PROXYSQL31` is defined. `PROXYSQL40=1` inherits the feature through the existing
build hierarchy.

A default v3.0 build:

- does not list or recognize `mysql-server_version_by_interface`;
- retains the current scalar-only handshake and query behavior;
- does not carry the new parsed catalog or session state; and
- has no MySQL table or SQLite schema changes related to this feature.

The replacement must not modify `mysql-interfaces`, `mysql_servers`,
`mysql_servers_ssl_params`, or their historical schema signatures.

## Observability

Normal variable inspection exposes the configured JSON string through
`runtime_global_variables`. Invalid loads use the existing warning and rejected
variable feedback. Unmatched entries are intentionally silent because a large
catalog is expected to contain entries unused by a particular node.

No per-connection log is added. Logging every match would add avoidable noise on
the accept path.

## Testing

### Variable unit tests

In a `PROXYSQL31=1` build, extend the MySQL variable unit coverage to verify:

- the variable is registered with default `{}`;
- valid TCP, IPv6, Unix-socket, and large multi-node catalogs are accepted;
- unmatched mappings are retained;
- malformed JSON, non-object roots, non-string or empty values, empty keys,
  embedded NUL bytes, and duplicate keys are rejected;
- rejection preserves the previous runtime snapshot; and
- replacing the catalog, clearing it with `{}`, getter round-tripping, and
  persistence behave correctly.

In a default v3.0 build, verify that the variable is absent from the registry and
the existing scalar behavior is unchanged.

### Frontend integration tests

Start ProxySQL with multiple listeners and establish new connections to verify:

- mapped listeners advertise their exact configured versions;
- an unmapped listener advertises `mysql-server_version`;
- two addresses using the same numeric port can advertise different versions;
- IPv4, bracketed IPv6, and Unix-socket mappings resolve through their original
  listener tokens;
- internal version queries and the `SELECT $$` probe agree with the handshake;
- version-forwarding modes retain their existing backend behavior;
- a runtime catalog replacement affects new connections but not existing ones;
  and
- a catalog with many inactive mappings does not require those listeners to
  exist.

Cluster coverage verifies that the JSON catalog synchronizes as a normal MySQL
variable even when `cluster_sync_interfaces=false`, and that each node applies
only the entries matching its local listeners.

## Rollout

Open a replacement PR based on the v3.0 branch with `PROXYSQL31=1` coverage in
CI. Close PR #4784 with a concise explanation that the replacement models the
requirement as a frontend listener override, avoids backend schema migrations,
and links to the new PR.

## Non-Goals

- Changing the grammar or runtime mutability of `mysql-interfaces`.
- Requiring the override catalog and active listener list to match.
- Defining port-only, address-normalized, wildcard, CIDR, or hostname-equivalent
  matching.
- Changing the meaning or default of `mysql-server_version`.
- Advertising different versions based on backend destination or hostgroup.
- Adding columns to any server, SSL-parameter, or runtime table.
