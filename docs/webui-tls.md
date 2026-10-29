# Securing the ProxySQL WebUI with a trusted certificate

The ProxySQL WebUI is served over HTTPS. On a new installation, ProxySQL
creates a local CA, server certificate, and private key in its data directory.
That certificate is self-signed and is intentionally not trusted by web
browsers. A browser warning such as `net::ERR_CERT_AUTHORITY_INVALID` is the
expected result until an operator installs a trusted certificate.

Do not train users to bypass the warning. Use a certificate whose identity
matches the hostname used to open the WebUI and whose issuer is trusted by the
user's browser.

## Current certificate files

ProxySQL currently loads these three files from `datadir`:

| File | Purpose |
| --- | --- |
| `proxysql-key.pem` | WebUI private key |
| `proxysql-cert.pem` | WebUI server certificate |
| `proxysql-ca.pem` | CA certificate used by ProxySQL's TLS context |

All three files must be present. On first startup, when none are present,
ProxySQL generates all three. A partial set is rejected.

This fixed-name convention is supported by the current implementation but is
not yet an operator-configurable certificate interface. See
[Product direction](#product-direction) for the intended permanent solution.

## Production deployment

1. Choose a stable DNS name for the WebUI, for example
   `proxysql-admin.example.internal`.
2. Obtain a certificate for that exact DNS name from the organization's PKI or
   a public CA. The certificate must contain the name in a Subject Alternative
   Name (SAN); a Common Name alone is not sufficient for current browsers.
3. Stop ProxySQL, then back up the existing three PEM files from its data
   directory. Keep the private-key backup protected.
4. Install the CA certificate, server certificate (including any intermediate
   chain required by the TLS listener), and matching unencrypted private key
   under the filenames above. Ensure the ProxySQL service account can read
   them and that other users cannot read `proxysql-key.pem`.
5. Start ProxySQL and open the WebUI using the same DNS name in the
   certificate. Do not use an IP address unless that IP address is also a SAN.

Verify the files before and after installation:

```sh
openssl x509 -in /path/to/datadir/proxysql-cert.pem -noout -subject -issuer -dates
openssl x509 -in /path/to/datadir/proxysql-cert.pem -noout -text | grep -A1 'Subject Alternative Name'
openssl x509 -in /path/to/datadir/proxysql-cert.pem -checkend 2592000 -noout
```

The final command exits non-zero when the certificate expires within 30 days.

### Renewing without a restart

Write a complete replacement set of the three files using an atomic
file-replacement procedure appropriate for the operating system. Do not leave
a moment where only one or two files exist. Then, using an authenticated
ProxySQL Admin connection, run:

```sql
PROXYSQL RELOAD TLS;
```

ProxySQL validates the new key/certificate pair before swapping the TLS
context. If validation fails, investigate the error and retain the currently
working files rather than accepting a browser warning.

## Reverse proxy deployments

An organization may terminate public TLS at an existing reverse proxy or load
balancer. In that model:

- the external listener presents the organization-managed, browser-trusted
  certificate;
- the proxy restricts access to the WebUI and forwards only to ProxySQL;
- the proxy-to-ProxySQL hop remains HTTPS and must validate ProxySQL's
  certificate against the local or organizational CA; and
- direct access to ProxySQL's WebUI port is firewalled or bound only where the
  reverse proxy can reach it.

TLS termination does not make it safe to expose the Admin interface broadly.
Use network restrictions, strong Admin credentials, and the organization's
normal identity/access controls.

## Local development

For a developer machine, use a locally trusted development CA and generate a
certificate containing `localhost` and any local IP address used in the
browser. Installing that CA in the developer's trust store is a local
development action; it must not be shipped as a production trust anchor.

The ProxySQL-generated certificate is suitable only for bootstrap and test
environments. `curl -k` and a browser interstitial may help diagnose a local
test instance, but neither is a deployment solution.

## Troubleshooting

| Browser or server result | Likely cause | Resolution |
| --- | --- | --- |
| `net::ERR_CERT_AUTHORITY_INVALID` | Self-signed or untrusted issuing CA | Install a certificate from a CA trusted by the browser, or configure the reverse proxy with one. |
| `net::ERR_CERT_COMMON_NAME_INVALID` | URL hostname/IP is absent from SAN | Use the certificate's DNS name, or issue a certificate with the required DNS/IP SAN. |
| `PROXYSQL RELOAD TLS` fails | Missing PEM file, unreadable key, malformed PEM, or key/certificate mismatch | Restore a complete valid set, check ownership/permissions, then reload again. |
| Works in `curl -k` but not in a browser | Certificate validation is being bypassed by curl | Fix issuer trust and hostname/SAN; do not use `-k` for normal verification. |

## Product direction

The fixed filenames above solve immediate deployment needs but are not a
sufficient long-term user experience. The proposed core enhancement is to add
an explicit WebUI TLS configuration surface with:

- certificate, key, and CA-chain file paths owned by the operator;
- startup and reload validation with atomic retention of the previous working
  TLS context;
- certificate health in diagnostics: active paths, issuer, SANs, expiry, last
  successful reload, and last error; and
- an explicit development/bootstrap self-signed mode, clearly marked as
  untrusted rather than presented as a production default.

This change belongs in ProxySQL core because the core process owns the TLS
context used by both the builtin HTTP server and the Web Interface plugin.
