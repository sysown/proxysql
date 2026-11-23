# GTID reader wire contract

ProxySQL routes causal reads by asking which servers already hold a GTID. It
learns that from a plain-text stream on each server's `gtid_port`. The usual
sender is `proxysql_binlog_reader`, but any program that follows this contract
can report progress for a read target.

This page describes the behavior of `GTID_Server_Data` in
`lib/GTID_Server_Data.cpp`.

## Connection

- ProxySQL is the TCP client. It connects to `mysql_servers.hostname` on
  `mysql_servers.gtid_port`.
- The stream is push-only. ProxySQL sends nothing and there is no handshake or
  authentication, so the port must only be reachable from trusted hosts.
- One port reports one backend.
- ProxySQL retries a lost connection every
  `mysql-binlog_reader_connect_retry_msec` milliseconds (default 3000).

## Messages

Each message is one line ending in `\n`.

| Message | Meaning |
|---|---|
| `ST=<id>:<interval>[,<id>:<interval>...]` | Bootstrap: the full set the target holds |
| `I1=<id>:<trxid>` | One transaction |
| `I2=<trxid>` | One transaction, same id as the last `ST`, `I1` or `I3` |
| `I3=<id>:<start>-<end>` | A range of transactions |
| `I4=<start>-<end>` | A range, same id as the last `ST`, `I1` or `I3` |

Send `ST=` first on every connection. `I2=` and `I4=` are invalid until a
message has established an id.

### Identifiers

The id is a MySQL server UUID or a MariaDB domain id (canonical decimal). One
connection uses one kind only. Mixing them is a protocol error.

- In `ST=`, a UUID may keep its dashes. ProxySQL removes them.
- In `I1=` and `I3=`, send the UUID as 32 lowercase hexadecimal digits with **no
  dashes**. ProxySQL stores these ids as received, and tracked GTIDs are compared
  in the dash-free form, so a dashed id here never matches a query.

### Bootstrap format

Each `ST=` item holds exactly one interval. MySQL's compact form with several
intervals for one UUID is rejected, so repeat the UUID instead:

```text
# gtid_executed: 3e11fa47-71ca-11e1-9e33-c80aa9429562:1-5:7-9
ST=3e11fa47-71ca-11e1-9e33-c80aa9429562:1-5,3e11fa47-71ca-11e1-9e33-c80aa9429562:7-9
```

An empty `ST=` is valid and means the target holds nothing yet.

### Limits and errors

- An `I` message must be shorter than 80 bytes, not counting the newline.
- ProxySQL disconnects on an invalid `ST=`, an oversized message, an unknown
  `I` type, a malformed `I1=` or `I3=` id, an invalid range, or a change of id
  kind. It then retries.
- Tagged GTIDs are not supported for routing.
- Other lines are currently ignored. Do not rely on this: a future version may
  give them a meaning.

## What an advertised GTID promises

Reporting a GTID means: **a read served by this target now reflects that
transaction, for every table the target can serve.**

If some tables lag behind others, report only what holds for all of them.
Reporting more makes ProxySQL serve stale data as if it were consistent.

ProxySQL only adds to the set during a connection. To withdraw a claim, close
the connection and send a smaller `ST=` on the next one. ProxySQL clears the set
when a new connection is established.

ProxySQL also adds the GTIDs that a backend returns in its OK packets to that
backend's set. A target should only return a GTID there under the same promise.

## Disconnects and stale streams

| Situation | Behavior |
|---|---|
| Connection lost | The last known set stays in use until a reconnect succeeds. It can be behind, but it stays valid while the target keeps its data. |
| Reconnected | The set is cleared. GTID-routed reads skip this server until `ST=` arrives. |
| Silent network failure | Not detected: the set stops advancing and the target looks behind. |
| Target restored or data lost | The target must drop its connection and report its real set. A connection that stays open keeps the old claim. |

## When no target has the GTID

ProxySQL does not fall back automatically. The query waits under the normal
backend acquisition limits and the log reports `Waiting for replication`.

The exception is a tracked value that cannot be used for routing, such as a
multi-UUID set or a tagged GTID. With `gtid_from_hostgroup`, that query is sent
to the source hostgroup.

To keep reads available while a target catches up, include a server that always
has the data, usually the writer, in the reader hostgroup with a low weight.
