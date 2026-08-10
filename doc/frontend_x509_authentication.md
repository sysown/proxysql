# Frontend X.509 authentication

`require_x509` is available in v3.1.x Innovative-tier and v4.x builds. v3.0.x does not recognize or read the key; it does not look up, validate, log, or enforce `require_x509`.

## Configure a frontend account

Set the policy in the existing `mysql_users.attributes` JSON object:

```sql
UPDATE mysql_users
   SET attributes='{"require_x509":true}'
 WHERE username='application_user';
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;
```

`require_x509` accepts only a JSON boolean (`true` or `false`). A malformed value is retained in the runtime record, diagnosed when users are loaded, and denied at authentication until it is corrected. ProxySQL does not coerce malformed strings or numbers into a boolean.

## What the policy proves

The frontend TLS context validates client certificates against ProxySQL's frontend `proxysql-ca.pem`. With `require_x509=true`, the configured password or authentication plugin must succeed **and** the physical frontend TLS connection must have presented a certificate whose verification result is `X509_V_OK`. A trusted client certificate without a URI SAN is sufficient.

`use_ssl` requires an encrypted transport. `require_x509` additionally requires a verified client certificate.

`spiffe_id` binds a username to a URI SAN identity and remains the authoritative identity check after the configured frontend password step. `require_x509` proves membership in the trusted PKI and remains additive to password authentication. If both attributes are present, both policies must pass.

## Connection changes and pass-through authentication

`COM_CHANGE_USER` does not renegotiate TLS. The target account reuses immutable certificate evidence from the original physical connection; absent or invalid evidence rejects a `require_x509` target and requires a fresh connection. Any SPIFFE-authenticated source and every SPIFFE target are rejected, also requiring a fresh connection.

For row-backed pass-through authentication, ProxySQL enforces this policy before the username allowlist, cache lookup, cleartext request, and backend probe. Backend verification still supplies the password verdict. SPIFFE rows are excluded from pass-through. Unknown-user pass-through has no row attribute, so it remains governed by its existing TLS transport gate. `COM_CHANGE_USER` rejects pass-through targets, while a pass-through-authenticated source may change to an ordinary password-backed row.

The frontend client certificate is never forwarded to a backend. Backend client certificates and keys are configured independently through backend SSL settings.

## Failures

Authentication-policy denials return the generic MySQL error 1045; configuration and certificate details remain in ProxySQL logs. The existing earlier TLS-handshake failure for an untrusted certificate that carries a SPIFFE URI SAN is preserved.
