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

OpenSSL updates stay on the 3.5 LTS series until a separately reviewed design
selects a successor. An update must replace the LFS object, digest, versioned
symlink, and build pin together, then run the upstream OpenSSL tests and the
complete ProxySQL TLS and platform matrix.

Static vendoring is not a FIPS claim. Building and operating a matching FIPS
provider is separate future work tracked by GitHub issue #6116.
