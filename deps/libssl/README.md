# Vendored OpenSSL

ProxySQL vendors OpenSSL 3.5.7 from the official release asset:

<https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz>

The published SHA-256 is:

```text
a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8
```

The source archive is stored with Git LFS. A source checkout must hydrate it
before building:

```bash
git lfs install
git lfs pull --include=deps/libssl/openssl-3.5.7.tar.gz
deps/libssl/verify-source.bash
```

The verifier rejects missing files, unhydrated LFS pointers, checksum
mismatches, invalid gzip data, unsafe archive paths, and unexpected archive
layouts before extraction.

OpenSSL updates stay on the 3.5 LTS series through 8 April 2030. Selecting a
successor requires a separately reviewed design. Follow the authoritative
[vendored OpenSSL maintenance guide](../../doc/vendored_openssl.md) to verify
official signatures and digests, update every version-coupled file atomically,
and run the upstream and ProxySQL acceptance matrices for issue #6115.

Static vendoring is not a FIPS claim. Building and operating an exactly
qualified FIPS provider/core combination is separate future work tracked by
[GitHub issue #6116](https://github.com/sysown/proxysql/issues/6116).
