# Mandatory Vendored OpenSSL Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete GitHub issue #6115 by making OpenSSL 3.5.7 a mandatory, integrity-checked Git LFS dependency and by proving that every supported ProxySQL build and package uses one executable-owned statically linked OpenSSL core.

**Architecture:** A checked-in LFS source archive and SHA-256 preflight feed one position-independent, static OpenSSL build beneath `deps/libssl/openssl`. Canonical Make variables route ProxySQL, bundled libraries, tools, and tests to that tree. The executable force-loads and exports the OpenSSL core; shared plugins keep unresolved OpenSSL references and therefore cannot embed a second core. Linkage, packaging, and CI contract checks prevent regressions.

**Tech Stack:** OpenSSL 3.5.7 LTS, Git LFS, GNU Make, Bash, CMake/Autoconf dependency builds, ELF `readelf`/`nm`, Mach-O `otool`/`nm`, GitHub Actions, Debian/RPM/tarball packaging, ProxySQL TAP tests.

**Spec:** `docs/superpowers/specs/2026-08-19-vendored-openssl-design.md`

## Global Constraints

- Implement only #6115. Do not build, package, configure, or load `fips.so`, and do not make a FIPS claim.
- Pin OpenSSL 3.5.7 and this published SHA-256: `a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8`.
- Linux, macOS, and FreeBSD builds must always use the vendored source. Remove `CUSTOM_OPENSSL_PATH`, `OPENSSL_ROOT_DIR`, `pkg-config`, and distro-specific OpenSSL selection as build choices.
- Configure OpenSSL with `no-shared no-tests -fPIC`. Do not use `no-module` or `no-dso`; later #6116 requires provider and DSO support.
- The ProxySQL executable owns the sole OpenSSL core in its process. No shared plugin may link or embed `libssl` or `libcrypto`.
- Reference OpenSSL archives by exact path in final links. Do not rely on `-lssl`, `-lcrypto`, or a host library search path.
- Keep system GnuTLS and the current libmicrohttpd backend unchanged. The OpenSSL-backed libmicrohttpd investigation belongs only to #6116.
- Preserve the public-API BIO cleanup from commit `2e46f53bafa73dba431065cf6d5c2770dd0c152f`; do not restore old OpenSSL internal-structure patches or checks.
- Use bounded parallelism for local builds. Clean before switching Stable, Innovative, and Chassis tiers.
- Keep every task reviewable and commit it only after its stated checks pass.

---

### Task 1: Establish the Git LFS source and fail-fast integrity contract

**Files:**

- Create: `.gitattributes`
- Create: `deps/libssl/openssl-3.5.7.tar.gz` (Git LFS object)
- Create: `deps/libssl/openssl-3.5.7.tar.gz.sha256`
- Create: `deps/libssl/openssl` (symlink to `openssl-3.5.7`)
- Create: `deps/libssl/verify-source.bash`
- Create: `test/infra/control/test-vendored-openssl-source.bash`
- Modify: `deps/libssl/README.md`

**Interfaces:**

- `deps/libssl/verify-source.bash [ARCHIVE [CHECKSUM_FILE]]` verifies existence, LFS hydration, the exact checksum-file basename, SHA-256, gzip integrity, a single `openssl-3.5.7/` archive root, safe member paths, and the presence of `openssl-3.5.7/Configure`.
- With no arguments, the verifier checks the production archive and digest.
- The exact LFS rule is `deps/libssl/openssl-3.5.7.tar.gz filter=lfs diff=lfs merge=lfs -text`.

- [x] **Step 1: Write the source-verifier regression tests first.**

  Make the test script create temporary archives and checksum files and cover:

  1. missing archive;
  2. a three-line Git LFS pointer in place of the archive;
  3. corrupt archive content with the published filename;
  4. checksum filename mismatch;
  5. an archive containing `../escape` or an absolute path;
  6. an archive with the wrong top-level directory;
  7. a valid fixture archive;
  8. the real checked-in OpenSSL archive.

- [x] **Step 2: Run the test and prove RED.**

  Run:

  ```bash
  test/infra/control/test-vendored-openssl-source.bash
  ```

  Expected: FAIL because `deps/libssl/verify-source.bash` and the production archive do not exist yet.

- [x] **Step 3: Implement the portable verifier.**

  Select SHA-256 tooling in this order so the same script works on all supported builders:

  ```bash
  if command -v sha256sum >/dev/null 2>&1; then
      actual=$(sha256sum "$archive" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
      actual=$(shasum -a 256 "$archive" | awk '{print $1}')
  else
      actual=$(sha256 -q "$archive")
  fi
  ```

  The unhydrated-pointer diagnostic must name the file and print this recovery command:

  ```text
  git lfs pull --include=deps/libssl/openssl-3.5.7.tar.gz
  ```

- [x] **Step 4: Add and hydrate the official release asset through Git LFS.**

  Run:

  ```bash
  git lfs install --local
  git lfs track deps/libssl/openssl-3.5.7.tar.gz
  curl -fL --retry 5 \
    -o deps/libssl/openssl-3.5.7.tar.gz \
    https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz
  printf '%s  %s\n' \
    a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8 \
    openssl-3.5.7.tar.gz \
    > deps/libssl/openssl-3.5.7.tar.gz.sha256
  ln -s openssl-3.5.7 deps/libssl/openssl
  git add .gitattributes deps/libssl
  ```

  Confirm that `.gitattributes` contains only the exact-path OpenSSL rule unless another independent LFS rule already exists.

- [x] **Step 5: Verify the production object and LFS index.**

  Run:

  ```bash
  test/infra/control/test-vendored-openssl-source.bash
  deps/libssl/verify-source.bash
  git lfs ls-files --name-only | grep -Fx deps/libssl/openssl-3.5.7.tar.gz
  git check-attr filter diff merge text -- deps/libssl/openssl-3.5.7.tar.gz
  ```

  Expected: all fixture cases pass, the production digest matches, the LFS file is listed, and attributes report `filter=lfs`, `diff=lfs`, `merge=lfs`, `text=unset`.

- [x] **Step 6: Document source ownership and recovery.**

  Replace the obsolete BIO warning in `deps/libssl/README.md` with the pin, official URL, checksum, LFS hydration command, verifier command, update policy, and an explicit statement that vendoring is not a FIPS claim.

- [x] **Step 7: Commit the source contract.**

  ```bash
  git commit -m "deps: vendor OpenSSL 3.5.7 source via LFS"
  ```

---

### Task 2: Build one canonical static OpenSSL dependency

**Files:**

- Modify: `common_mk/openssl_flags.mk`
- Delete: `common_mk/openssl_version_check.mk`
- Modify: `deps/Makefile`
- Create: `test/infra/control/test-vendored-openssl-build-contract.bash`

**Interfaces:**

- `common_mk/openssl_flags.mk` produces:

  ```make
  OPENSSL_VERSION := 3.5.7
  DEPS_PATH ?= $(PROXYSQL_PATH)/deps
  SSL_PATH := $(DEPS_PATH)/libssl/openssl
  SSL_IDIR := $(SSL_PATH)/include
  SSL_LDIR := $(SSL_PATH)
  LIB_SSL_PATH := $(SSL_LDIR)/libssl.a
  LIB_CRYPTO_PATH := $(SSL_LDIR)/libcrypto.a
  OPENSSL_STATIC_LIBS := $(LIB_SSL_PATH) $(LIB_CRYPTO_PATH)
  ```

- `make -C deps libssl` verifies, extracts, configures, and builds the two archives.
- `libssl/openssl/.proxysql-build-complete` is the single build stamp; both archives depend on it, preventing duplicate recipes under parallel Make.

- [x] **Step 1: Write the Make-contract test first.**

  Assert that a dry run:

  - invokes `verify-source.bash` before `tar`;
  - extracts only the exact 3.5.7 archive;
  - invokes `./config no-shared no-tests -fPIC`;
  - never invokes `pkg-config`, `CUSTOM_OPENSSL_PATH`, `OPENSSL_ROOT_DIR`, `no-module`, or `no-dso`;
  - tests both `libssl.a` and `libcrypto.a` before touching the completion stamp.

- [x] **Step 2: Run the contract test and prove RED.**

  ```bash
  test/infra/control/test-vendored-openssl-build-contract.bash
  ```

  Expected: FAIL because the current Makefiles discover and version-check system OpenSSL.

- [x] **Step 3: Replace discovery with canonical vendored paths.**

  Reduce `common_mk/openssl_flags.mk` to the assignments above. Delete `common_mk/openssl_version_check.mk` and remove its include and `check_openssl_version` target from `deps/Makefile`.

- [x] **Step 4: Add the verified OpenSSL build rule before every consumer.**

  Use a stamp recipe with this ordering:

  ```make
  OPENSSL_BUILD_STAMP := libssl/openssl/.proxysql-build-complete

  $(OPENSSL_BUILD_STAMP): libssl/openssl-$(OPENSSL_VERSION).tar.gz \
                         libssl/openssl-$(OPENSSL_VERSION).tar.gz.sha256 \
                         libssl/verify-source.bash deps/Makefile
	cd libssl && ./verify-source.bash
	rm -rf libssl/openssl-$(OPENSSL_VERSION)
	cd libssl && tar --no-same-owner -zxf openssl-$(OPENSSL_VERSION).tar.gz
	cd libssl/openssl && CC=$(CC) CXX=$(CXX) ./config no-shared no-tests -fPIC
	cd libssl/openssl && $(MAKE)
	test -f $(LIB_SSL_PATH)
	test -f $(LIB_CRYPTO_PATH)
	touch $@

  $(LIB_SSL_PATH) $(LIB_CRYPTO_PATH): $(OPENSSL_BUILD_STAMP)
	@test -f $@

  .PHONY: libssl
  libssl: $(LIB_SSL_PATH) $(LIB_CRYPTO_PATH)
  ```

  Put `libssl` first in `targets` so a normal dependency build establishes the canonical core before consumers start.

- [x] **Step 5: Run the contract and build OpenSSL.**

  ```bash
  test/infra/control/test-vendored-openssl-build-contract.bash
  make -C deps -j4 libssl
  deps/libssl/openssl/apps/openssl version -a
  ```

  Expected: PASS; the CLI reports `OpenSSL 3.5.7`, both `.a` files exist, and the reported source/build directory is the vendored tree.

- [x] **Step 6: Prove provider/DSO capability was retained.**

  Run:

  ```bash
  ! grep -Eq 'OPENSSL_NO_(MODULE|DSO)' deps/libssl/openssl/include/openssl/configuration.h
  test -f deps/libssl/openssl/providers/legacy.so || \
    test -f deps/libssl/openssl/providers/legacy.dylib || \
    grep -q 'legacy' deps/libssl/openssl/providers/build.info
  ```

  Expected: neither `OPENSSL_NO_MODULE` nor `OPENSSL_NO_DSO` is defined and provider build metadata is present. The normal `no-shared` build is allowed to compile the default/base providers into `libcrypto`; #6116 will build the validated FIPS module separately.

- [x] **Step 7: Commit the canonical build.**

  ```bash
  git commit -am "build: compile mandatory vendored OpenSSL"
  ```

---

### Task 3: Route every bundled dependency to the vendored core

**Files:**

- Modify: `deps/Makefile`
- Modify: `test/deps/Makefile`
- Create: `test/infra/control/test-vendored-openssl-consumers.bash`

**Interfaces:**

- OpenSSL-consuming dependency targets depend on `$(OPENSSL_BUILD_STAMP)` or on a phony bridge that runs `$(MAKE) -C $(DEPS_PATH) libssl`.
- CMake consumers receive `OPENSSL_ROOT_DIR=$(SSL_PATH)`, `OPENSSL_INCLUDE_DIR=$(SSL_IDIR)`, and exact archive filenames.
- Autoconf consumers receive only `$(SSL_IDIR)`, `$(SSL_LDIR)`, and exact archive paths; host `pkg-config` output is excluded.

- [x] **Step 1: Write a source-level consumer audit and prove RED.**

  The audit must reject system discovery and bare OpenSSL link flags in active ProxySQL Makefiles:

  ```bash
  rg -n 'CUSTOM_OPENSSL_PATH|pkg-config.*openssl|brew --prefix openssl|OPENSSL_ROOT_DIR.*SSL_IDIR' \
    common_mk deps/Makefile test/deps/Makefile
  rg -n -- '-lssl|-lcrypto' deps/Makefile test/deps/Makefile
  ```

  It must also assert OpenSSL prerequisites on the curl, MariaDB Connector/C, PostgreSQL/libpq, libusual, libscram, and test connector targets.

- [x] **Step 2: Fix bundled dependency prerequisites and configuration.**

  Apply these exact contracts:

  - curl: add the OpenSSL stamp prerequisite; use `CPPFLAGS=-I$(SSL_IDIR)`, `LDFLAGS=-L$(SSL_LDIR)`, `LIBS=$(OPENSSL_STATIC_LIBS)`, `--with-openssl=$(SSL_PATH)`, `--disable-shared`, and `--enable-static`;
  - MariaDB Connector/C: use `-DOPENSSL_ROOT_DIR=$(SSL_PATH)`, `-DOPENSSL_INCLUDE_DIR=$(SSL_IDIR)`, `-DOPENSSL_SSL_LIBRARY=$(LIB_SSL_PATH)`, and `-DOPENSSL_CRYPTO_LIBRARY=$(LIB_CRYPTO_PATH)`;
  - PostgreSQL/libpq: use the vendored include/library directories and place `$(OPENSSL_STATIC_LIBS)` in the link-test `LIBS` value;
  - libusual: use `--with-openssl=$(SSL_PATH)` plus the exact static libraries;
  - libscram: change `LIBOPENSSL_DIR` from the include directory to `$(SSL_PATH)` and pass the exact archives if its Makefile exposes library variables;
  - `test/deps/Makefile`: add a `vendored_openssl` bridge target and pass the same root/include/archive variables to every MariaDB/MySQL test connector that enables OpenSSL.

- [x] **Step 3: Run the audit and dependency builds.**

  ```bash
  test/infra/control/test-vendored-openssl-consumers.bash
  make -C deps -j4 curl mariadb_client postgresql libusual libscram
  make -C test/deps -j4 mariadb_client
  ```

  Expected: PASS; configuration logs name only `deps/libssl/openssl`, curl produces `libcurl.a` and no `libcurl.so`/`libcurl.dylib`, and all requested archives build.

- [x] **Step 4: Prove the static consumers did not capture host OpenSSL paths.**

  ```bash
  rg -n '/usr/(local/)?(include|lib).*(ssl|crypto)|opt/homebrew/opt/openssl' \
    deps/curl/curl/config.log \
    deps/mariadb-client-library/mariadb_client/CMakeCache.txt \
    deps/postgresql/postgresql/config.log
  ```

  Expected: no match. A plain platform path unrelated to OpenSSL is acceptable; an OpenSSL header or library path outside `deps/libssl/openssl` is not.

- [x] **Step 5: Commit dependency routing.**

  ```bash
  git commit -am "build: route bundled dependencies to vendored OpenSSL"
  ```

---

### Task 4: Make the executable the sole OpenSSL owner for shared plugins

**Files:**

- Modify: `common_mk/openssl_flags.mk`
- Modify: `src/Makefile`
- Modify: `plugins/mysqlx/Makefile`
- Create: `test/infra/control/check-openssl-linkage.bash`
- Create: `test/infra/control/test-openssl-linkage-check.bash`

**Interfaces:**

- `OPENSSL_EXPORT_LIBS` force-loads both archives into an executable:

  ```make
  ifeq ($(UNAME_S),Darwin)
  OPENSSL_EXPORT_LIBS := -Wl,-force_load,$(LIB_SSL_PATH) \
                         -Wl,-force_load,$(LIB_CRYPTO_PATH)
  else
  OPENSSL_EXPORT_LIBS := -Wl,--whole-archive $(OPENSSL_STATIC_LIBS) \
                         -Wl,--no-whole-archive
  endif
  ```

- `check-openssl-linkage.bash EXECUTABLE [PLUGIN ...]` rejects dynamic OpenSSL dependencies everywhere, rejects plugin-defined OpenSSL sentinel symbols, and proves each plugin's undefined OpenSSL symbols are exported by the executable.

- [x] **Step 1: Test the linkage checker with tiny fixtures and prove RED.**

  Compile fixtures for these cases:

  1. executable with dynamic `libssl` — reject;
  2. plugin linked with dynamic `libssl` — reject;
  3. plugin containing a static implementation of `OpenSSL_version` — reject;
  4. plugin with an unresolved `SSL_CTX_new` absent from the executable export table — reject;
  5. executable exporting `SSL_CTX_new` plus a plugin that imports it — accept.

  Use `cc -shared -fPIC` on ELF and `cc -dynamiclib -undefined dynamic_lookup` on macOS.

- [x] **Step 2: Implement the cross-platform checker.**

  On ELF, inspect `readelf -d`, `nm -D --defined-only`, and `nm -D --undefined-only`. On macOS, inspect `otool -L`, `nm -gU`, and `nm -g`. Treat `libssl.so`, `libcrypto.so`, `libssl.dylib`, and `libcrypto.dylib` as forbidden. Use `OpenSSL_version`, `SSL_CTX_new`, `EVP_MD_fetch`, and `OSSL_PROVIDER_load` as embedded-core sentinels.

- [x] **Step 3: Link ProxySQL with the force-loaded core.**

  In `src/Makefile`:

  - remove the normal, AlmaLinux 8, and Darwin `-lssl -lcrypto` variants;
  - place `$(OPENSSL_EXPORT_LIBS)` after the static ProxySQL/dependency archives and before dynamic platform libraries;
  - retain `-Wl,--export-dynamic` on ELF;
  - retain the macOS `-force_load` behavior for `libproxysql.a` and add the OpenSSL force-load flags;
  - add `$(LIB_SSL_PATH) $(LIB_CRYPTO_PATH)` as explicit prerequisites of `src/proxysql`.

- [x] **Step 4: Stop MySQLX from owning OpenSSL.**

  Keep `-I$(SSL_IDIR)` in `plugins/mysqlx/Makefile`, but remove `-L$(SSL_LDIR) -lssl -lcrypto` and do not add `$(OPENSSL_STATIC_LIBS)`. ELF leaves the plugin's OpenSSL API references undefined for the loader; macOS continues to use `-undefined dynamic_lookup`.

- [x] **Step 5: Build Chassis and prove the process boundary.**

  ```bash
  make clean
  PROXYSQL40=1 make -j4 build_src
  PROXYSQL40=1 make -C plugins/mysqlx -j4
  test/infra/control/check-openssl-linkage.bash \
    src/proxysql \
    plugins/mysqlx/ProxySQL_MySQLX_Plugin.so \
    plugins/genai/ProxySQL_GenAI_Plugin.so
  ```

  Expected: PASS; ProxySQL and plugins have no dynamic OpenSSL dependency, plugins define none of the sentinels, and all plugin OpenSSL imports are present in the executable's export table.

- [x] **Step 6: Run the real plugin load and TLS unit tests.**

  ```bash
  PROXYSQL40=1 make -C test/tap/tests/unit -j4 \
    test_mysqlx_plugin_load-t mysqlx_tls_unit-t genai_plugin_load_unit-t
  test/tap/tests/unit/test_mysqlx_plugin_load-t
  test/tap/tests/unit/mysqlx_tls_unit-t
  test/tap/tests/unit/genai_plugin_load_unit-t
  ```

  Expected: all TAP assertions pass and the real MySQLX plugin is loaded by a host that owns the only OpenSSL core.

- [x] **Step 7: Commit the single-runtime link.**

  ```bash
  git commit -am "build: make proxysql own the OpenSSL runtime"
  ```

---

### Task 5: Move all tests and helper binaries off system OpenSSL

**Files:**

- Modify: `test/tap/tap/Makefile`
- Modify: `test/tap/tests/Makefile`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/tests_with_deps/deprecate_eof_support/Makefile`
- Modify: `test/deps/cluster_simulator/Makefile`
- Modify: `test/PrepStmt/Makefile`
- Modify: `RAG_POC/Makefile`
- Modify: `test/rag/Makefile`
- Modify: any additional active Makefile identified by the audit below
- Create: `test/infra/control/test-no-system-openssl-links.bash`

**Interfaces:**

- Every executable test link uses `$(OPENSSL_STATIC_LIBS)` or `$(OPENSSL_EXPORT_LIBS)`.
- Plugin-loading unit binaries use `$(OPENSSL_EXPORT_LIBS)` so plugin-only APIs remain exported.
- TAP stops copying or depending on shared libcurl and links `$(CURL_LDIR)/libcurl.a` instead.

- [x] **Step 1: Add the repository-wide active-link audit and prove RED.**

  Search Makefiles and shell build scripts while excluding docs, extracted dependency trees, and generated configure files. Fail on bare `-lssl`, bare `-lcrypto`, `brew --prefix openssl`, or a system OpenSSL root. Permit only canonical variables from `common_mk/openssl_flags.mk` and the intentional negative fixtures in `test-openssl-linkage-check.bash`.

- [x] **Step 2: Convert TAP and unit-test links.**

  - replace every `-lssl -lcrypto` pair with the exact canonical archives;
  - place those archives after `libcurl.a`, `libpq.a`, and other consumers so static symbol resolution is correct;
  - use `OPENSSL_EXPORT_LIBS` for unit executables that load MySQLX;
  - remove `libcurl$(SHLIB_EXT)` from `test/tap/tap/Makefile` targets and prerequisites;
  - link or leave unresolved `libpq.a` references without introducing a shared `libpq`-owned OpenSSL core.

- [x] **Step 3: Convert standalone helpers and simulation builds.**

  Apply the same exact archive variables to the cluster simulator, PrepStmt, deprecate-EOF test, RAG proof of concept, and RAG test. Add the repository root/path includes where the small Makefiles do not currently include `makefiles_paths.mk`.

- [x] **Step 4: Run the audit and focused crypto regressions.**

  ```bash
  test/infra/control/test-no-system-openssl-links.bash
  PROXYSQL40=1 make -C test/tap/tests/unit -j4 \
    caching_sha2_rsa_unit-t mysqlx_tls_unit-t test_mysqlx_plugin_load-t
  test/tap/tests/unit/caching_sha2_rsa_unit-t
  test/tap/tests/unit/mysqlx_tls_unit-t
  test/tap/tests/unit/test_mysqlx_plugin_load-t
  ```

  Expected: the audit passes and all focused TAP binaries pass.

- [x] **Step 5: Build the ordinary TAP and simulator link surfaces.**

  ```bash
  make -C test/tap/tap -j4
  make -C test/tap/tests -j4 tests_no_infra
  make -C test/deps/cluster_simulator -j4
  ```

  Expected: all links succeed without a host OpenSSL development package or shared libcurl from the vendored tree.

- [x] **Step 6: Commit the test/tool migration.**

  ```bash
  git commit -am "test: use the vendored OpenSSL runtime"
  ```

---

### Task 6: Expose and test the embedded version

**Files:**

- Modify: `lib/ProxySQL_Admin_Stats.cpp`
- Modify: `test/tap/tests/test_cacert_load_and_verify_duration-t.cpp`
- Create: `test/tap/tests/unit/vendored_openssl_version_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`

**Interfaces:**

- `stats.stats_mysql_global` keeps `OpenSSL_Version_Num` and adds `OpenSSL_Version`, populated with `OpenSSL_version(OPENSSL_VERSION)`.
- The unit-test rule passes `-DPROXYSQL_VENDORED_OPENSSL_VERSION=\"$(OPENSSL_VERSION)\"`; the test compares that build pin with `OPENSSL_VERSION_STR` and `OpenSSL_version(OPENSSL_VERSION)`.

- [x] **Step 1: Add the failing compile-time/runtime version unit test.**

  The test must assert that the header and runtime strings both begin with `OpenSSL 3.5.7` and that `OpenSSL_version_num()` has major/minor/patch `3/5/7`.

- [x] **Step 2: Register, build, and run it.**

  ```bash
  make -C test/tap/tests/unit vendored_openssl_version_unit-t
  test/tap/tests/unit/vendored_openssl_version_unit-t
  ```

  Expected before the change: FAIL on any host library/version mismatch. Expected after canonical linkage: all assertions pass.

- [x] **Step 3: Add the human-readable statistics row.**

  Immediately beside `OpenSSL_Version_Num`, add:

  ```cpp
  sqlite3_global_stats_row_step_str(
      statsdb, row_stmt, "OpenSSL_Version", OpenSSL_version(OPENSSL_VERSION));
  ```

  Update `test_cacert_load_and_verify_duration-t.cpp` to read both rows and require the string prefix `OpenSSL 3.5.7` before applying its existing numeric performance-regression logic.

- [x] **Step 4: Run the focused unit and TAP compile.**

  ```bash
  make -C test/tap/tests/unit vendored_openssl_version_unit-t
  test/tap/tests/unit/vendored_openssl_version_unit-t
  make -C test/tap/tests test_cacert_load_and_verify_duration-t
  ```

  Expected: unit TAP passes and the integration TAP compiles against the vendored headers and archives.

- [x] **Step 5: Commit version inventory support.**

  ```bash
  git commit -am "stats: expose embedded OpenSSL version"
  ```

---

### Task 7: Remove shared OpenSSL from package metadata and tarballs

**Files:**

- Modify: `docker/images/proxysql/deb-compliant/ctl/proxysql.ctl`
- Modify: `docker/images/proxysql/rhel-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec`
- Modify: `docker/images/proxysql/suse-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec`
- Modify: `docker/images/proxysql/tarball-compliant/entrypoint/entrypoint.bash`
- Modify: `tools/test-tarball-runtime.sh`
- Create: `test/infra/control/test-openssl-package-contract.bash`
- Modify: `README.md`

**Interfaces:**

- Debian/RPM metadata retains GnuTLS but no longer declares OpenSSL for ProxySQL.
- The generic Linux tarball contains no copied `libssl.so.3` or `libcrypto.so.3`.
- The tarball smoke test rejects those dynamic dependencies in the binary and all packaged plugins.

- [x] **Step 1: Write the package contract test and prove RED.**

  The test must fail if:

  - `proxysql.ctl` contains `libssl`;
  - either RPM spec has an OpenSSL `Requires:`;
  - the tarball entrypoint calls `bundle_runtime_library` for `libssl` or `libcrypto`;
  - the tarball test expects OpenSSL to resolve from `lib/` rather than forbidding it.

- [x] **Step 2: Remove obsolete runtime metadata and bundling.**

  Keep GnuTLS requirements intact. Remove only OpenSSL requirements. Remove the bundling function entirely if OpenSSL is its only caller; otherwise remove only its two OpenSSL invocations.

- [x] **Step 3: Invert the runtime smoke test.**

  For the main binary and every `lib/proxysql/*.so`, collect `ldd` output and fail on:

  ```text
  libssl.so
  libcrypto.so
  not found
  ```

  Preserve `--version` execution in the three clean runtime images.

- [x] **Step 4: Update user-facing tarball documentation.**

  Remove the README statement that generic tarballs require host OpenSSL 3. State that ProxySQL embeds pinned OpenSSL 3.5.7, still dynamically requires GnuTLS, and that this is not a FIPS claim.

- [x] **Step 5: Run package checks.**

  ```bash
  test/infra/control/test-openssl-package-contract.bash
  test/infra/control/check-openssl-linkage.bash \
    src/proxysql \
    plugins/mysqlx/ProxySQL_MySQLX_Plugin.so \
    plugins/genai/ProxySQL_GenAI_Plugin.so
  ```

  Expected: PASS with no declared, bundled, or dynamic OpenSSL runtime.

- [x] **Step 6: Build and test an amd64 tarball.**

  ```bash
  make clean
  make -j4 tarball
  tools/test-tarball-runtime.sh
  ```

  Expected: the tarball works on AlmaLinux 9, Debian 12, and Ubuntu 22.04, and none of those clean images supplies OpenSSL to ProxySQL.

- [x] **Step 7: Commit packaging changes.**

  ```bash
  git commit -am "packaging: drop shared OpenSSL runtime"
  ```

---

### Task 8: Hydrate the LFS source in every build workflow

**Files:**

- Modify: `.github/workflows/CI-package-amd64-*.yml` (127 build-job checkouts)
- Modify: `.github/workflows/CI-package-arm64-*.yml` (43 build-job checkouts)
- Modify: `.github/workflows/CI-build-macos-*.yml` (6 build-job checkouts)
- Modify: `.github/workflows/CI-cluster-simulator.yml` (build job only)
- Modify: other direct build/test workflows identified by the validator
- Modify: `.github/workflows/CI-build-macos-*.yml` (remove build-time Homebrew OpenSSL environment and install)
- Create: `test/infra/control/validate-openssl-lfs-workflows.bash`

**Interfaces:**

- A checkout in a job that compiles ProxySQL or an OpenSSL-dependent test has `lfs: true`.
- Metadata-only `init_release` and fan-out runtime-test checkouts do not hydrate LFS.
- The validator maps each checkout step to its YAML job and checks only build jobs, preventing unnecessary LFS bandwidth consumption.

- [x] **Step 1: Write and run the workflow validator before changing YAML.**

  The validator must enumerate direct workflows, identify jobs containing a ProxySQL `make`/build-control invocation, and require `lfs: true` on that job's checkout. It must explicitly check package `build`, macOS `build`, cluster-simulator `build`, unit/sanitizer build jobs, and tarball jobs. It must reject `lfs: true` in package/macOS `init_release` jobs.

  Expected: FAIL for the 176 package/macOS build jobs and the cluster simulator; existing ASAN/TSAN hydration remains accepted.

- [x] **Step 2: Add targeted LFS hydration mechanically.**

  In each affected build-job checkout, add:

  ```yaml
      with:
        repository: ${{ github.repository }}
        ref: ${{ github.sha }}
        fetch-depth: 0
        lfs: true
  ```

  Preserve existing checkout settings and add only `lfs: true` when the other keys already exist.

- [x] **Step 3: Remove system OpenSSL from macOS build selection.**

  Delete `PKG_CONFIG_PATH` and `OPENSSL_ROOT_DIR` from all six macOS build jobs and remove `openssl@3` from their Homebrew install lists. Leave an OpenSSL CLI package only if a workflow step demonstrably invokes the CLI; it must not expose headers or libraries to Make.

- [x] **Step 4: Validate the full workflow set and YAML diffs.**

  ```bash
  test/infra/control/validate-openssl-lfs-workflows.bash
  git diff --check
  git diff --stat -- .github/workflows
  ```

  Expected: PASS; only build jobs hydrate LFS and all 176 generated package/macOS changes have the same shape.

- [x] **Step 5: Coordinate the reusable primary build workflow.**

  `.github/workflows/CI-builds.yml` delegates to `sysown/proxysql/.github/workflows/ci-builds.yml@GH-Actions`; its checkout is not present on `v3.0`. Make the corresponding `lfs: true` change on the `GH-Actions` branch in the same delivery window, then dispatch `CI-builds` against the implementation commit. Record that companion commit in issue #6115. Do not mark #6115 complete while the reusable workflow can still produce an unhydrated checkout.

- [ ] **Step 6: Enable LFS content in GitHub source archives.**

  In repository Settings → Archives, enable **Include Git LFS objects in archives**. Download a generated source archive for the implementation commit and verify:

  ```bash
  file deps/libssl/openssl-3.5.7.tar.gz
  deps/libssl/verify-source.bash
  ```

  Expected: the file is a gzip archive, not an LFS pointer, and verification passes. Record this operational evidence in #6115.

- [x] **Step 7: Commit workflow hydration.**

  ```bash
  git commit -am "ci: hydrate vendored OpenSSL source in build jobs"
  ```

---

### Task 9: Add the supported OpenSSL patch-update procedure

**Files:**

- Create: `doc/vendored_openssl.md`
- Modify: `README.md`
- Modify: `deps/libssl/README.md`

**Interfaces:**

- The update guide is the authoritative process for staying on OpenSSL 3.5 LTS through 8 April 2030.
- The guide distinguishes normal vendoring from the future FIPS project #6116.

- [x] **Step 1: Document the build and update workflow.**

  Include exact sections for:

  - required Git LFS installation and hydration;
  - source/digest verification;
  - changing `OPENSSL_VERSION`, the archive, symlink, digest, and LFS rule in one commit;
  - checking the official release signature/digest;
  - running upstream tests with a separate temporary OpenSSL build before accepting an update;
  - running all ProxySQL linkage, TLS, package, and platform checks;
  - the 3.5 LTS support end date and the requirement for a reviewed successor design;
  - why static vendoring alone is not FIPS compliance;
  - why a FIPS provider must match the exact core build and configuration from #6116.

- [x] **Step 2: Link the guide from README and dependency README.**

  Add a concise source-build prerequisite to `README.md` and keep detailed recovery/update instructions in `doc/vendored_openssl.md`.

- [x] **Step 3: Validate commands and links.**

  ```bash
  git lfs pull --include=deps/libssl/openssl-3.5.7.tar.gz
  deps/libssl/verify-source.bash
  test -f doc/vendored_openssl.md
  rg -n '6115|6116|8 April 2030|not a FIPS claim' \
    README.md deps/libssl/README.md doc/vendored_openssl.md
  ```

  Expected: every documented command succeeds and the project boundary is explicit.

- [x] **Step 4: Commit documentation.**

  ```bash
  git commit -am "docs: document vendored OpenSSL maintenance"
  ```

---

### Task 10: Run the complete cross-tier and release verification matrix

**Files:**

- Modify only if a verification failure exposes an in-scope defect; add a focused regression before fixing it.
- Update: `docs/superpowers/plans/2026-08-19-vendored-openssl.md` (check completed boxes as evidence is collected)

**Interfaces:**

- Produces the evidence required to close #6115; it does not produce FIPS artifacts.

- [x] **Step 1: Run all static contract checks from a clean worktree.**

  ```bash
  test/infra/control/test-vendored-openssl-source.bash
  test/infra/control/test-vendored-openssl-build-contract.bash
  test/infra/control/test-vendored-openssl-consumers.bash
  test/infra/control/test-openssl-linkage-check.bash
  test/infra/control/test-no-system-openssl-links.bash
  test/infra/control/test-openssl-package-contract.bash
  test/infra/control/validate-openssl-lfs-workflows.bash
  ```

  Expected: all checks pass.

- [x] **Step 2: Build and inspect Stable 3.0.**

  ```bash
  make clean
  make -j4 build_src_debug
  test/infra/control/check-openssl-linkage.bash src/proxysql
  src/proxysql --version
  ```

  Expected: a 3.0 DEBUG binary, embedded OpenSSL 3.5.7, and no dynamic OpenSSL dependency.

- [x] **Step 3: Build and inspect Innovative 3.1.**

  ```bash
  make clean
  PROXYSQL31=1 make -j4 build_src_debug
  test/infra/control/check-openssl-linkage.bash src/proxysql
  src/proxysql --version
  ```

  Expected: a 3.1 DEBUG binary with the same OpenSSL core and linkage result.

- [x] **Step 4: Build and inspect Chassis 4.0 plus plugins.**

  ```bash
  make clean
  PROXYSQL40=1 make -j4 build_src_debug
  PROXYSQL40=1 make -C plugins/mysqlx -j4
  PROXYSQL40=1 make -C plugins/genai -j4
  test/infra/control/check-openssl-linkage.bash \
    src/proxysql \
    plugins/mysqlx/ProxySQL_MySQLX_Plugin.so \
    plugins/genai/ProxySQL_GenAI_Plugin.so
  ```

  Expected: a 4.0 DEBUG binary; both plugins import the executable's OpenSSL and embed none.

- [ ] **Step 5: Run focused crypto and TLS regressions.**

  Build and run at minimum:

  ```bash
  PROXYSQL40=1 make -C test/tap/tests/unit -j4 \
    vendored_openssl_version_unit-t \
    caching_sha2_rsa_unit-t \
    mysqlx_tls_unit-t \
    test_mysqlx_plugin_load-t \
    genai_plugin_load_unit-t
  test/tap/tests/unit/vendored_openssl_version_unit-t
  test/tap/tests/unit/caching_sha2_rsa_unit-t
  test/tap/tests/unit/mysqlx_tls_unit-t
  test/tap/tests/unit/test_mysqlx_plugin_load-t
  test/tap/tests/unit/genai_plugin_load_unit-t
  ```

  Then run the existing MySQL/PostgreSQL TLS, SCRAM, certificate, and error-queue TAP groups through `test/infra/control/run-tests-isolated.bash`, including `reg_test_4556-ssl_error_queue-t`, `reg_test_3765_ssl_pollout-t`, and `test_cacert_load_and_verify_duration-t`.

  Expected: all selected TAP tests pass.

- [ ] **Step 6: Run package CI across representative architectures and distributions.**

  Required green jobs:

  - Linux amd64 GCC and Clang;
  - Linux arm64;
  - Debian package, RHEL-family RPM, SUSE RPM, and generic tarball;
  - macOS 13 Intel and macOS 14 Apple Silicon;
  - FreeBSD build;
  - ASAN, TSAN, coverage, cluster simulator;
  - Stable, Innovative, and Chassis tiers.

  In each built artifact, run the linkage checker or the platform-equivalent `ldd`/`readelf`/`otool` evidence.

- [x] **Step 7: Verify the failure modes manually once.**

  In a temporary checkout, replace the archive with an LFS pointer and then with corrupt bytes. Run `make -C deps libssl` for each case.

  Expected: both fail before extraction; the pointer case prints the exact `git lfs pull --include=...` recovery command and the corruption case prints expected and actual SHA-256 values.

  Local evidence collected on 2026-08-19:

  - the seven clean static contract checks pass, including 13 source-verifier cases and 179 workflow build jobs;
  - Stable 3.0, Innovative 3.1, and Chassis 4.0 debug builds report embedded OpenSSL 3.5.7 and no dynamic OpenSSL dependency;
  - the Chassis executable and both shared plugins pass the ownership checker, and both plugins retain unresolved EVP imports for the executable-owned core;
  - the five focused unit/plugin tests pass (150 assertions total), as do `reg_test_3765_ssl_pollout-t`, `reg_test_4556-ssl_error_queue-t`, and `test_cacert_load_and_verify_duration-t` in an isolated MySQL 8.4 environment;
  - MySQL 5.7 and 8.4 test-client builds were inspected and corrected so every generated OpenSSL link resolves to the vendored archives;
  - the amd64 tarball contract passes on AlmaLinux 9, Debian 12, and Ubuntu 22.04, with embedded OpenSSL 3.5.7 and no bundled or dynamic `libssl`/`libcrypto`;
  - disposable-checkout pointer and checksum-mismatch failures occur before extraction with the required diagnostics.

  The full platform/package CI matrix, the PostgreSQL/SCRAM group sweep, and GitHub-generated source-archive hydration remain publication-time gates below.

- [x] **Step 8: Perform final repository checks.**

  ```bash
  git diff --check origin/v3.0...HEAD
  git status --short
  git log --oneline origin/v3.0..HEAD
  git lfs fsck
  ```

  Expected: no whitespace errors, no generated build artifacts, an intentional commit series, and a healthy LFS object.

- [ ] **Step 9: Update issue #6115 with evidence.**

  Post the implementation commits/PR, the exact OpenSSL digest, platform/tier results, binary/plugin linkage output, package results, the `GH-Actions` companion commit, and confirmation that GitHub source archives include the LFS object. State explicitly that #6116 remains separate future FIPS work.

- [x] **Step 10: Commit plan progress if checkbox evidence changed.**

  ```bash
  git add docs/superpowers/plans/2026-08-19-vendored-openssl.md
  git commit -m "docs: record vendored OpenSSL verification"
  ```
