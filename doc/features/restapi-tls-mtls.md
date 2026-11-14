# REST API TLS, mTLS and configurable listen address

The REST API / Prometheus endpoint (`admin-restapi_port`, default `6070`)
supports HTTPS, optional client-certificate authentication (mTLS), and a
configurable bind address. Defaults preserve the historical plain-HTTP,
all-interfaces behavior.

## Admin variables

| Variable | Default | Description |
|----------|---------|-------------|
| `admin-restapi_use_ssl` | `false` | `true` serves HTTPS on `admin-restapi_port` using ProxySQL's existing TLS key/certificate. |
| `admin-restapi_ssl_verify_client` | `false` | `true` requires a client certificate signed by the configured CA. Requires `admin-restapi_use_ssl=true`. |
| `admin-restapi_interface` | `""` | Empty/`0.0.0.0` binds all IPv4 interfaces. `::` binds all IPv6 interfaces and, on platforms with IPv6-only sockets, does not accept IPv4 connections. A numeric IPv4 or IPv6 address binds only that address. A path starting with `/`, or prefixed with `unix:` followed by an absolute path, creates a Unix-domain socket. |
| `admin-restapi_ssl_ca` | `""` | CA certificate PEM used to validate client certificates. Empty reads ProxySQL's configured CA file (normally `datadir/proxysql-ca.pem`). Relative paths resolve against the ProxySQL datadir. |

All variables are available through `SET`/`SHOW`, `global_variables`,
`runtime_global_variables`, `LOAD/SAVE ADMIN VARIABLES`, and the
`admin_variables` section of the configuration file.

## Enabling HTTPS

```sql
SET admin-restapi_enabled='true';
SET admin-restapi_use_ssl='true';
LOAD ADMIN VARIABLES TO RUNTIME;
```

The listener restarts asynchronously and serves the certificate loaded by
the standard ProxySQL TLS subsystem. Existing PEM files are
`proxysql-key.pem` and `proxysql-cert.pem` in the datadir; they may be
replaced and re-read with:

```sql
PROXYSQL RELOAD TLS;
```

Certificate reload is issued without restarting ProxySQL and applies to the
REST listener, including when the reload is requested from a `/sync` script.
The REST listener restarts asynchronously, so existing REST connections may
close during reconfiguration. A `/sync` script can finish while its HTTP
response is interrupted.

## Enabling mutual TLS

1. Leave `proxysql-ca.pem` unchanged. Set `admin-restapi_ssl_ca` to the PEM
   of the CA that signs your client certificates (a path relative to the
   datadir, or absolute). This keeps ProxySQL's global CA available for the
   server certificate and other TLS verification.
2. If replacing ProxySQL's server identity, load it with `PROXYSQL RELOAD TLS`.
3. Enable verification:

```sql
SET admin-restapi_use_ssl='true';
SET admin-restapi_ssl_verify_client='true';
SET admin-restapi_ssl_ca='client-ca.pem';   -- explicit client CA path
LOAD ADMIN VARIABLES TO RUNTIME;
```

An explicit `admin-restapi_ssl_ca` path is read when the listener
configuration is applied, including `LOAD ADMIN VARIABLES TO RUNTIME`.
`PROXYSQL RELOAD TLS` rereads ProxySQL's global server identity and forces an
HTTPS REST listener restart, which reapplies the listener configuration and
rereads the client CA.

Leaving `admin-restapi_ssl_ca` empty continues to use ProxySQL's own CA
(`datadir/proxysql-ca.pem`) for client verification; an explicit path avoids
overloading the CA that also issues ProxySQL's server certificate.

When verification is enabled, every request must present a client
certificate whose chain is trusted by the configured CA, whose validity
period is current, and which is valid for TLS client authentication. Missing,
untrusted, expired, or wrong-purpose certificates are rejected with HTTP
`403` before any resource handler runs. This applies uniformly to
`/metrics`, `/sync`, the TSDB endpoints, and any future resource.

Ordinary HTTPS listeners (`ssl_verify_client=false`) do not request client
certificates and do not install a client trust store.

## Interface binding

```sql
-- IPv4
SET admin-restapi_interface='127.0.0.1';

-- IPv6
SET admin-restapi_interface='::1';

-- Unix socket
SET admin-restapi_interface='/var/run/proxysql/restapi.sock';
-- or
SET admin-restapi_interface='unix:/var/run/proxysql/restapi.sock';
```

An invalid address, an overlong Unix path, or an existing Unix path is an
error: the listener stays down rather than falling back to all interfaces.
The server never removes a pre-existing Unix path (including stale sockets
and regular files); choose a path that does not exist. The socket this
server creates is removed when the listener is reconfigured or ProxySQL
shuts down.

The socket's immediate parent directory must be owned by root or the ProxySQL
user. If it permits group or other writes, it must have the sticky bit set.

On Linux the listener binds through the already-pinned parent file descriptor,
so socket creation cannot be redirected by renaming an ancestor. This requires
`/proc/self/fd` to be available; otherwise listener startup fails. On other
platforms it binds the canonical pathname and relies on post-bind ownership
verification; a renamed ancestor may still redirect creation there.

## Fail-closed behavior

- `admin-restapi_ssl_verify_client=true` with
  `admin-restapi_use_ssl=false`: the listener does not start (no silent
  HTTP downgrade).
- HTTPS requested but ProxySQL key/cert unavailable: the listener does not
  start (no silent HTTP downgrade).
- Client verification requested but no CA PEM available: the listener does
  not start.
- Bind failures are reported in the ProxySQL error log; the listener is not
  started on a different address.

`LOAD ADMIN VARIABLES TO RUNTIME` itself still succeeds; listener startup
failures are reported in the error log, matching the existing behavior for
an unavailable REST port.
