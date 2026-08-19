# Vendored OpenSSL maintenance

ProxySQL builds against a mandatory vendored OpenSSL 3.5 LTS source archive.
The current pin is OpenSSL 3.5.7. OpenSSL 3.5 is supported upstream through
8 April 2030; moving to another release series requires a separately reviewed
design rather than an incidental dependency update.

This document is the supported maintenance procedure for
[issue #6115](https://github.com/sysown/proxysql/issues/6115).

## Hydrate and verify a checkout

Install Git LFS before cloning, or install it and hydrate an existing checkout:

```bash
git lfs install
git lfs pull --include=deps/libssl/openssl-3.5.7.tar.gz
deps/libssl/verify-source.bash
```

`verify-source.bash` rejects an unhydrated LFS pointer, a checksum mismatch,
invalid gzip data, unsafe paths, and an unexpected archive layout before the
build extracts anything. If a generated GitHub source archive is used instead
of a Git checkout, it must also contain the hydrated OpenSSL archive; repository
archives must have **Include Git LFS objects in archives** enabled.

The source archive is the official OpenSSL release asset. Its expected SHA-256
is recorded in `deps/libssl/openssl-3.5.7.tar.gz.sha256`. Verify the checked-in
object and LFS metadata with:

```bash
deps/libssl/verify-source.bash
git lfs ls-files --name-only | grep -Fx deps/libssl/openssl-3.5.7.tar.gz
git check-attr filter diff merge text -- deps/libssl/openssl-3.5.7.tar.gz
```

The attributes must report `filter=lfs`, `diff=lfs`, `merge=lfs`, and
`text=unset`.

## Authenticate a proposed patch release

Start in a new temporary directory. Replace `3.5.x` only after selecting a
published 3.5 LTS patch release from the
[official OpenSSL downloads page](https://www.openssl.org/source/).

```bash
openssl_update_dir=$(mktemp -d)
cd "$openssl_update_dir"
new_version=3.5.x
release_base="https://github.com/openssl/openssl/releases/download/openssl-${new_version}"

curl -fLO "${release_base}/openssl-${new_version}.tar.gz"
curl -fLO "${release_base}/openssl-${new_version}.tar.gz.asc"
curl -fLO "${release_base}/openssl-${new_version}.tar.gz.sha256"
curl -fL https://mirror.openssl-library.org/source/pubkeys.asc \
  -o openssl-pubkeys.asc

gpg --import openssl-pubkeys.asc
gpg --fingerprint B146647E45A7B33947AB226B2A2C87D161692D40
gpg --verify "openssl-${new_version}.tar.gz.asc" \
  "openssl-${new_version}.tar.gz"
sha256sum -c "openssl-${new_version}.tar.gz.sha256"
```

On macOS, use `shasum -a 256 -c` if `sha256sum` is unavailable. Before trusting
the downloaded key, manually compare its full fingerprint with the current
[OpenSSL artifact-signing policy](https://openssl-library.org/policies/general/artifact-signing-policy/).
The fingerprint above is the current primary release-signing fingerprint; a
future signing-policy change must be reviewed, not silently copied from the
downloaded key bundle.

Run the upstream tests in this separate temporary source tree before accepting
the release:

```bash
tar -xzf "openssl-${new_version}.tar.gz"
cd "openssl-${new_version}"
./Configure
make -j4
make test
```

Do not reuse ProxySQL's extracted dependency tree for this test. The production
dependency is configured with `no-shared no-tests -fPIC`, so a separate build is
required to exercise the upstream test suite.

## Update the repository atomically

Make all version-dependent changes in one commit:

1. Replace `deps/libssl/openssl-<old>.tar.gz` with the authenticated archive and
   ensure the new archive is stored by Git LFS.
2. Replace the checksum file with `openssl-<new>.tar.gz.sha256`; retain the
   official digest and archive basename.
3. Change `deps/libssl/openssl` to point to the new versioned directory.
4. Change `OPENSSL_VERSION` in `common_mk/openssl_flags.mk`.
5. Replace the exact old archive rule in `.gitattributes` with the exact new
   path. Do not add a wildcard rule or retain the old path.
6. Update the version, archive path, expected archive root, and recovery command
   in `deps/libssl/verify-source.bash`.
7. Update version-specific expectations and fixtures in
   `test/infra/control/test-vendored-openssl-source.bash`,
   `test/infra/control/test-vendored-openssl-build-contract.bash`, and
   `test/tap/tests/unit/vendored_openssl_version_unit-t.cpp`.
8. Update the current version and digest in this guide,
   `deps/libssl/README.md`, and the top-level `README.md`.

Search for stale references before committing:

```bash
old_version=3.5.7
rg -n "$old_version|openssl-$old_version" \
  .gitattributes README.md common_mk deps doc test
git lfs ls-files
git check-attr filter diff merge text -- \
  "deps/libssl/openssl-${new_version}.tar.gz"
deps/libssl/verify-source.bash
```

Review `git diff --cached` and commit the archive pointer, digest, pin, symlink,
verifier, tests, LFS rule, and documentation together. Never merge a version
update whose source object can only be found in one maintainer's local LFS
store.

## ProxySQL acceptance checks

Run every static contract check:

```bash
test/infra/control/test-vendored-openssl-source.bash
test/infra/control/test-vendored-openssl-build-contract.bash
test/infra/control/test-vendored-openssl-consumers.bash
test/infra/control/test-openssl-linkage-check.bash
test/infra/control/test-no-system-openssl-links.bash
test/infra/control/test-openssl-package-contract.bash
test/infra/control/validate-openssl-lfs-workflows.bash
```

Then perform clean Stable 3.0, Innovative 3.1, and Chassis 4.0 builds. Check the
executable and, for 4.0, both shared plugins:

```bash
test/infra/control/check-openssl-linkage.bash \
  src/proxysql \
  plugins/mysqlx/ProxySQL_MySQLX_Plugin.so \
  plugins/genai/ProxySQL_GenAI_Plugin.so
src/proxysql --version
```

The executable must report the new embedded OpenSSL version and must not depend
on a host `libssl` or `libcrypto`. Plugins must import the executable-owned
OpenSSL core; they must not embed or dynamically link another core.

Run the focused OpenSSL version, RSA authentication, MySQLX TLS, and plugin-load
unit tests. Also run the existing MySQL and PostgreSQL TLS, SCRAM, certificate,
and OpenSSL error-queue TAP groups. The release matrix must cover:

- Linux amd64 with GCC and Clang, and Linux arm64;
- Debian packages, RHEL-family and SUSE RPMs, and the generic tarball;
- macOS Intel and Apple Silicon, and FreeBSD;
- release, debug, ASAN, TSAN, coverage, and cluster-simulator jobs; and
- Stable 3.0, Innovative 3.1, and Chassis 4.0.

Inspect each produced executable and plugin with the linkage checker or the
platform-equivalent `readelf`, `ldd`, or `otool` evidence. Install packages in
clean representative containers and verify that they run without a system
OpenSSL runtime. Finally run `git lfs fsck` and verify a GitHub-generated source
archive for the candidate commit with `deps/libssl/verify-source.bash`.

## FIPS boundary

Static OpenSSL vendoring is not a FIPS claim and this dependency must not ship,
configure, or load `fips.so`. Future FIPS module work is tracked separately by
[issue #6116](https://github.com/sysown/proxysql/issues/6116).

OpenSSL's same-major provider compatibility is a technical interface promise;
it is not ProxySQL's support policy and does not establish FIPS compliance. A
future supported FIPS configuration must qualify an exact combination of the
validated provider source or artifact, OpenSSL core, target platform, build
recipe, configuration, and per-machine `fipsinstall` output required by that
module's security policy. Loading whatever `fips.so` happens to be installed on
the host is therefore outside the supported design.

Review the current [OpenSSL release strategy](https://www.openssl-library.org/policies/releasestrat/)
and the validated module's security policy whenever #6116 is implemented or
the vendored release series changes.
