# RSA key exchange for `caching_sha2_password`

ProxySQL 3.1 can authenticate MySQL clients that use
`caching_sha2_password` over a non-TLS frontend connection. When full
authentication is required, the client can request ProxySQL's RSA public key,
encrypt its password, and send the ciphertext back to ProxySQL.

TLS remains the recommended configuration. Requesting a public key over an
unauthenticated connection encrypts the password on the wire, but it does not
authenticate the ProxySQL server and is vulnerable to public-key substitution
by an active network attacker. Use TLS when server identity and transport
integrity are required.

## Configuration

The following MySQL variables are available in ProxySQL 3.1 and later:

| Variable | Default | Description |
| --- | --- | --- |
| `mysql-caching_sha2_password_auto_generate_rsa_keys` | `true` | Generate a 2048-bit RSA pair when both configured files are absent. |
| `mysql-caching_sha2_password_private_key_path` | `proxysql-caching-sha2-private-key.pem` | Private-key path. A relative path is resolved below ProxySQL's data directory. |
| `mysql-caching_sha2_password_public_key_path` | `proxysql-caching-sha2-public-key.pem` | Public-key path. A relative path is resolved below ProxySQL's data directory. |

Apply changes with:

```sql
LOAD MYSQL VARIABLES TO RUNTIME;
```

The three variables form one configuration unit. ProxySQL validates or
generates the complete pair before publishing it to frontend sessions. If a
reload fails, all three runtime values and the previously loaded key snapshot
remain unchanged.

Relative paths must stay beneath ProxySQL's data directory. Empty, `.` and
`..` components are rejected, and every parent directory is opened without
following symbolic links. Absolute paths are allowed when keys are managed in
another operator-controlled directory.

## Key formats and permissions

The private key must be an unencrypted PKCS#8 PEM RSA private key (the PEM
header is `BEGIN PRIVATE KEY`). Traditional PKCS#1 (`BEGIN RSA PRIVATE KEY`)
and encrypted private keys are rejected. The public key must be a PEM
SubjectPublicKeyInfo public key. The two files must contain a structurally
valid matching RSA pair of at least 2048 bits.

The private file must be a regular file and must not grant any group or other
permissions. Generated files use these modes:

- private key: `0600`
- public key: `0644`

Encrypted private keys are not supported because ProxySQL has no runtime
passphrase input for this feature.

If the compiled default pair is unusable during initial runtime loading and
cannot be regenerated safely, ProxySQL records an explicit TLS-only state
(automatic generation off and both paths empty). TLS authentication remains
available, while RSA public-key authentication stays disabled until a valid
pair is loaded.

Automatic generation occurs only when both paths are absent. If exactly one
file exists, ProxySQL reports a configuration error and does not overwrite or
replace either path. Generation uses temporary files and no-overwrite
publication so concurrent ProxySQL processes cannot publish a mixed pair.

## Reload and cluster behavior

Each authentication exchange retains the same immutable key snapshot from the
public-key response through RSA decryption. A concurrent
`LOAD MYSQL VARIABLES TO RUNTIME` can therefore rotate keys without breaking
an exchange already in progress.

Cluster synchronization transfers the variable values, not private-key
contents. Every ProxySQL node must be able to read its configured local pair,
or generate its own pair when automatic generation is enabled. Do not store
private-key contents in the ProxySQL configuration database.

## Client behavior and failures

The client must use `caching_sha2_password`, disable TLS only when intended,
and enable its server-public-key request option. For Oracle's MySQL CLI:

```bash
mysql --default-auth=caching_sha2_password \
  --ssl-mode=DISABLED --get-server-public-key \
  --host=127.0.0.1 --port=6033 --user=app --password
```

ProxySQL implements the MySQL protocol's RSA OAEP exchange, including the
protocol-defined SHA-1 OAEP and MGF1 digests and password/scramble XOR step.
Malformed ciphertext, malformed plaintext, and an incorrect password all
produce the normal `1045` / `28000` access-denied response. If no valid RSA key
pair is available, the same error code and SQLSTATE are returned with a message
that identifies the unavailable RSA key exchange and suggests TLS or key
configuration.
