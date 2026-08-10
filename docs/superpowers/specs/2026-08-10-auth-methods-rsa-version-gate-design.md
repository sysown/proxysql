# Auth Methods RSA Version Gate Design

## Goal

Make `test_auth_methods-t` expect non-TLS `caching_sha2_password` RSA full authentication to succeed only when the ProxySQL instance under test is version 3.1 or newer. ProxySQL versions older than 3.1 must retain the existing expected-failure behavior.

## Runtime capability detection

The test will query `SELECT @@version` through the already-established ProxySQL Admin connection. It will parse the leading major and minor numeric components and derive one capability flag:

- `false` for versions below 3.1;
- `true` for versions 3.1 and newer.

The runtime version is authoritative. Compile-time flags are unsuitable because the TAP executable may be used against a separately built ProxySQL binary. Failure to query or parse the ProxySQL version will terminate the test with a diagnostic instead of silently selecting the wrong expectations.

## Authentication expectations

The existing exceptional-failure rule for non-TLS, hashed `caching_sha2_password` credentials will apply only when RSA full authentication is unavailable. On ProxySQL 3.1 and newer, valid credentials will follow the normal success path on their first attempt.

RSA full authentication adds one server packet for the public-key response. The session-packet classifier will recognize that exchange for RSA-capable ProxySQL versions so the existing full-auth assertions continue to describe the actual protocol rather than merely accepting the connection.

All unrelated authentication limitations and expectations remain unchanged.

## Verification

The TAP test will contain literal boundary checks covering pre-3.1, 3.1, later, suffixed, and malformed version strings. After the red/green cycle, the focused test binary will be built and run against the local ProxySQL test environment. The verified change will be pushed only after explicit user approval.
