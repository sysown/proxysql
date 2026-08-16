# Backend `CLIENT_DEPRECATE_EOF` Negotiation Design

**Date:** 2026-08-15
**Status:** Approved for implementation planning
**Related:** PR #6076; MariaDB Connector/C capability patch

## Context

ProxySQL currently enables `CLIENT_DEPRECATE_EOF` for an outbound backend connection by changing `MYSQL::options.client_flag` before `mysql_real_connect_start()`.  The bundled MariaDB Connector/C patch subsequently uses that configuration field to decide whether to retain the bit advertised by the server greeting.

That creates an API inconsistency: the same capability passed through the `client_flag` argument to `mysql_real_connect()` is sent during the handshake, but Connector/C discards the server-advertised bit while parsing result packets.  A valid deprecated-EOF result can then be parsed as legacy EOF.

## Decision

ProxySQL will express its outbound preference only through the local `client_flags` argument passed to `mysql_real_connect_start()`.  It will no longer mutate Connector/C's persistent `MYSQL::options.client_flag` for this capability.

The Connector/C patch will use its already-merged effective `client_flag` value when deciding whether to retain the bit from the server greeting.  It must never add the bit to `mysql->server_capabilities`; a backend which does not advertise it remains a legacy-EOF backend even when ProxySQL requests it.

Fast-forward connections retain their stricter policy: request the bit only when the frontend both negotiated it and was offered it by ProxySQL.

## Test design

Use ProxySQL's SQLite3 listener (port 6030) as a backend of the same ProxySQL instance.  `mysql-enable_client_deprecate_eof` controls its greeting, while `mysql-enable_server_deprecate_eof` controls ProxySQL's outbound request.

The regression coverage must prove both rows are parsed correctly:

| SQLite3 listener advertises the capability | ProxySQL requests it | Expected backend state |
| --- | --- | --- |
| yes | yes | `server_capabilities` retains the bit; deprecated EOF is parsed |
| no | yes | `server_capabilities` lacks the bit; legacy EOF is parsed |

The direct SQLite3 special-query test covers Connector/C's public `mysql_real_connect(..., client_flags)` API path.  The existing self-loop capability-matching test covers ProxySQL's outbound connection setup.  Both tests restore the global configuration after completion.

## Non-goals

- Do not make `CLIENT_DEPRECATE_EOF` unconditional for backends.
- Do not infer support from a requested client flag.
- Do not introduce another test service or duplicate the existing self-loop setup.
