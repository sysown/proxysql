# RSA key exchange for `caching_sha2_password`

ProxySQL 3.1 and 4.0 can authenticate MySQL clients that use
`caching_sha2_password` over a non-TLS frontend connection. When full
authentication is required, the client can either request ProxySQL's RSA
public key or use a trusted copy provisioned locally, encrypt its password, and
send the ciphertext back to ProxySQL. This feature is not available in
ProxySQL 3.0.

TLS remains the recommended configuration. Requesting a public key over an
unauthenticated connection encrypts the password on the wire, but it does not
authenticate the ProxySQL server and is vulnerable to public-key substitution
by an active network attacker. Use TLS when server identity and transport
integrity are required.

## Configuration

The following MySQL variables are available in ProxySQL 3.1 and 4.0:

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
full-authentication challenge through RSA decryption. This applies whether the
client requests the public key or already has a pinned copy. A concurrent
`LOAD MYSQL VARIABLES TO RUNTIME` can therefore rotate keys without breaking
an exchange already in progress.

Clients that use a pinned public key must be updated when the ProxySQL key pair
is rotated. Coordinate publication of the new public key, client configuration
changes, and the ProxySQL runtime reload: a client using a key that does not
match the key snapshot selected by ProxySQL cannot authenticate. ProxySQL does
not provide a grace period in which new connections can use both the old and
new private keys.

Cluster synchronization transfers the variable values, not private-key
contents. Every ProxySQL node must be able to read its configured local pair,
or generate its own pair when automatic generation is enabled. Do not store
private-key contents in the ProxySQL configuration database.

## Client modes

The client must use `caching_sha2_password` and disable TLS only when intended.
Oracle's MySQL CLI supports two RSA modes.

### Request ProxySQL's public key

With `--get-server-public-key`, the client asks ProxySQL for its current public
key during authentication:

```bash
mysql --default-auth=caching_sha2_password \
  --ssl-mode=DISABLED --get-server-public-key \
  --host=127.0.0.1 --port=6033 --user=app --password
```

After ProxySQL sends the full-authentication challenge (`0x04`), the client
requests the key (`0x02`). ProxySQL returns the public key and decrypts the
client's following RSA ciphertext with the same retained key snapshot.

This mode prevents passive observers from learning the password, but it does
not authenticate ProxySQL. An active attacker can substitute another public
key. Prefer TLS or the pinned-key mode when server identity matters.

### Use a provisioned public key

With `--server-public-key-path`, the client reads a trusted public key from a
local file:

```bash
mysql --default-auth=caching_sha2_password \
  --ssl-mode=DISABLED \
  --server-public-key-path=/etc/proxysql/proxysql-caching-sha2-public-key.pem \
  --host=127.0.0.1 --port=6033 --user=app --password
```

After the `0x04` challenge, the client encrypts the password immediately and
sends the RSA ciphertext without first requesting a key with `0x02`. ProxySQL
decrypts it with the key snapshot retained when it emitted the challenge.

Provision the public-key file through a trusted channel and protect its
integrity. This mode verifies that the endpoint possesses the corresponding
private key and avoids unauthenticated in-band key substitution. RSA protects
only the password exchange; subsequent queries, results, and other session
traffic remain unencrypted and unauthenticated. Use TLS when the complete
connection needs confidentiality and integrity.

## Failures

ProxySQL implements the MySQL protocol's RSA OAEP exchange, including the
protocol-defined SHA-1 OAEP and MGF1 digests and password/scramble XOR step.
Malformed ciphertext, malformed plaintext, and an incorrect password all
produce the normal `1045` / `28000` access-denied response. If no valid RSA key
pair is available, the same error code and SQLSTATE are returned with a message
that identifies the unavailable RSA key exchange and suggests TLS or key
configuration.
