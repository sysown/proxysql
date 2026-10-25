# TLS assurance follow-up

The fifty-client comparison measured ProxySQL ahead of PgBouncer with TLS on both hops. The previous build was already ahead: approximately 15.27% for SELECT 1 and 8.07% for 4KB. The latest build measured 13.79% and 12.20% ahead respectively. Thus the cross-product lead was present before the latest COPY, completed-session and DataRow changes. These remain workload-specific single-run observations, with fifty clients and ten retained backends.

## Encryption evidence and code inspection

Every saved benchmark transport probe negotiated TLSv1.3 / TLS_AES_256_GCM_SHA384 on the frontend and reported the same protocol and cipher in PostgreSQL pg_stat_ssl for the backend. Both PgBouncer server snapshots additionally show that protocol/cipher on all ten retained backend connections. Workload clients required TLS; administrative monitoring alone was plaintext.

The latest product diff does not remove SSL_read or SSL_write, change negotiated ciphers, bypass a handshake, or change backend SSL policy. Native DataRows are framed only after OpenSSL returns decrypted data. The bulk-copy path retains complete-frame length/cap checks, leaves malformed/incomplete frames to existing error handling, and preserves the suspension fallback and non-row side effects. Source review found no correctness blocker, but this is not a proof for every protocol input.

The earlier frontend TLS handshake cache is also present in both benchmarked ProxySQL builds. Its flag starts false, is set only after SSL_do_handshake returns success and the existing peer-certificate checks complete, and applies only to owned frontend TLSv1.3 connections. New SSL objects and backend ownership transitions reset the flag; other cases retain the OpenSSL state predicate. The flag avoids repeated state queries, while encrypted I/O and ciphertext draining continue through OpenSSL.

OpenSSL documents that successful reads process complete records, including decryption and integrity checks: [SSL_read documentation](https://docs.openssl.org/3.5/man3/SSL_read/). Its I/O functions can process handshake-related work as well: [SSL_get_error documentation](https://docs.openssl.org/3.5/man3/SSL_get_error/). The code review does not substitute for dedicated post-handshake/key-update coverage.

## Fresh fail-closed checks

Ran the immutable latest binary, source 754dc4af4792b22c825d9663c4a86739bc0cbaff, SHA256 7fd4064c6551cf63899dff09f5ca658974e5eb896157eac76889dc14125aaa55, in a new isolated instance. These checks were outside all performance windows; their intentional connection/authentication failures do not contaminate benchmark results.

| Check | Observation |
|---|---|
| Valid TLS connection and SELECT 1 | Successful; returned the expected result |
| Plaintext connection to the TLS-required user | Rejected with SSL-required authentication error |
| Incorrect frontend password over TLS | Rejected with access-denied error |
| Completed TLSv1.3 handshake followed by a damaged encrypted application record | Rejected by closure/TLS error; no PostgreSQL application response was received |
| Backend replies N to PostgreSQL SSLRequest | Query failed with SSL-required error; proxy closed the backend connection without sending a plaintext StartupMessage |

The fake backend received exactly the PostgreSQL SSLRequest and no bytes after refusing TLS. The proxy stayed running through the checks and the isolated instance was stopped afterward. The machine-readable evidence is [assurance.json](assurance.json), with transport proof, binary identity, runtime settings and [cleanup.json](cleanup.json) alongside it. The standalone checker is preserved; no product code or repository tests were modified.

## Limits and benchmark policy

The benchmark requires encryption but does not exercise strict CA plus hostname verification. PGSSLMODE=require does not provide verify-full hostname matching; with a root CA present libpq may additionally validate the chain, but that remains different from verify-full. See [PostgreSQL SSL modes](https://www.postgresql.org/docs/15/libpq-ssl.html). Native backend REQUIRE can use SSL_VERIFY_NONE, as documented in the existing connection code; the latest optimizations do not introduce or change that policy.

SQL parsing, query digests and command statistics remain disabled at the user's earlier request. The throughput workloads are SELECT 1 and a generated row result. They do not qualify general SQL session-state, temporary-table, multiplexing, extended-protocol or certificate-policy behavior for production.

ProxySQL and PgBouncer use different existing OpenSSL builds in this comparison: ProxySQL reports OpenSSL 3.5.7, while PgBouncer reports OpenSSL 3.0.22. The cross-product result does not isolate TLS-library costs, and it is not evidence that cryptographic work was skipped.

No encryption or authentication bypass was found in this inspection or these negative checks. That is a bounded finding, not a blanket production-safety guarantee; wider protocol, malformed-input, certificate-policy and TLS post-handshake coverage remains outside these checks.
