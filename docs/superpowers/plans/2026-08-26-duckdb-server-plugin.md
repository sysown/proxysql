# DuckDB Server Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose an embedded DuckDB instance over the MySQL and PostgreSQL wire protocols as a loadable ProxySQL 4.0 plugin.

**Architecture:** The plugin `dlopen`s into a proxysql binary that exports its symbols, so it reuses core's `MySQL_Session` / `PgSQL_Session`, authentication, and result serializers instead of implementing a wire protocol. Each accepted socket gets a thread that builds a core session with `session_type = PROXYSQL_SESSION_SQLITE` and a plugin-supplied `handler_function`; that handler runs DuckDB SQL and converts `duckdb_result` into a `SQLite3_result`, which core serializes. No file outside `plugins/duckdb/`, `deps/duckdb/`, build glue, and tests is modified.

**Tech Stack:** C++17, DuckDB C API (`duckdb.h`), GNU Make, git LFS, TAP tests.

**Spec:** `docs/superpowers/specs/2026-08-26-duckdb-server-plugin-design.md`

## Global Constraints

- **Tier:** v4.0 only. Every source file and Makefile stanza is gated on `PROXYSQL40=1`. `PROXYSQL40=1` implies `PROXYSQL31=1` implies `PROXYSQLFFTO=1` + `PROXYSQLTSDB=1`.
- **Build the tier consistently.** Pass `PROXYSQL40=1` on *every* `make` in a session. Switching tiers without `make clean` produces `undefined reference to 'mysql_thread___ffto_max_buffer_size'` — a stale-object tier mismatch, never a real breakage. Do not "fix" it by dropping the flag.
- **Debug build required for TAP.** The isolated harness issues debug-only admin commands. Build with `PROXYSQL40=1 make debug` and `PROXYSQL40=1 make build_tap_test_debug`.
- **Zero core changes.** No edits to `lib/`, `src/` (except none), or `include/` core headers. The only non-plugin, non-deps, non-test edits permitted are: `.gitattributes`, `deps/Makefile`, `include/makefiles_paths.mk`, the top-level `Makefile`, `test/tap/groups/groups.json`, `test/tap/tests/unit/Makefile`, and `.github/workflows/*.yml`.
- **Plugin visibility:** compile with `-fvisibility=hidden -fvisibility-inlines-hidden`; only `proxysql_plugin_descriptor_v1` is exported, via `extern "C" __attribute__((visibility("default")))`.
- **ABI:** set `abi_version = PROXYSQL_PLUGIN_ABI_VERSION` (currently 5) on the descriptor.
- **Session type:** always `PROXYSQL_SESSION_SQLITE`; always leave `thread->gen_args = nullptr`.
- **Naming:** C++ classes `PascalCase` with a `DuckDB` prefix; members `snake_case`; macros `UPPER_SNAKE_CASE`. Files `duckdb_<unit>.{h,cpp}`.
- **Never report a failing test as flaky or pre-existing.** Read the log, state the root cause.

## File Structure

| File | Responsibility |
|---|---|
| `.gitattributes` | LFS filter for the DuckDB source archive |
| `deps/duckdb/duckdb-<version>.tar.gz` | Vendored source (LFS) |
| `deps/duckdb/duckdb-<version>.tar.gz.sha256` | Checksum sidecar |
| `deps/duckdb/verify-source.bash` | Pointer-file detection, checksum + root verification |
| `deps/duckdb/README.md` | Version-bump and LFS maintenance |
| `deps/Makefile` | `duckdb` target; added to `$(targets)` under `PROXYSQL40` |
| `include/makefiles_paths.mk` | `DUCKDB_PATH` / `DUCKDB_IDIR` / `DUCKDB_LDIR` |
| `plugins/duckdb/Makefile` | Plugin build |
| `plugins/duckdb/include/duckdb_plugin.h` | `DuckDBPluginContext`, accessor |
| `plugins/duckdb/src/duckdb_plugin.cpp` | Descriptor + four lifecycle callbacks |
| `plugins/duckdb/include/duckdb_config.h` | `DuckDBConfigStore` |
| `plugins/duckdb/src/duckdb_config.cpp` | Variable storage, validation, iface parsing |
| `plugins/duckdb/include/duckdb_engine.h` | `DuckDBEngine` |
| `plugins/duckdb/src/duckdb_engine.cpp` | Owns `duckdb_database`; opens with config; hands out connections |
| `plugins/duckdb/include/duckdb_result.h` | Conversion entry point |
| `plugins/duckdb/src/duckdb_result.cpp` | `duckdb_result` → `SQLite3_result` |
| `plugins/duckdb/include/duckdb_session.h` | `DuckDBSessionState`, handler template, error emitters |
| `plugins/duckdb/src/duckdb_session.cpp` | Handler, compatibility intercepts, PG error emitter |
| `plugins/duckdb/include/duckdb_listener.h` | `DuckDBListener` |
| `plugins/duckdb/src/duckdb_listener.cpp` | Accept loop, connection threads, join-on-stop |
| `plugins/duckdb/include/duckdb_admin_schema.h` | Schema registration entry point |
| `plugins/duckdb/src/duckdb_admin_schema.cpp` | Table def, runtime view, LOAD/SAVE commands |
| `plugins/duckdb/README.md` | Build, load, configure, connect, limitations |

Tests: `test/tap/tests/unit/duckdb_{config,engine,result,admin_schema,session}_unit-t.cpp`, `test/tap/tests/test_duckdb_plugin_load-t.cpp`, `test/tap/tests/test_duckdb_e2e_{mysql,pgsql}-t.cpp`, `test/tap/tests/test_duckdb_admin_tables-t.cpp`.

---

### Task 1: Vendor DuckDB and build it from source

**Files:**
- Create: `deps/duckdb/verify-source.bash`, `deps/duckdb/README.md`, `deps/duckdb/duckdb-<version>.tar.gz` (LFS), `deps/duckdb/duckdb-<version>.tar.gz.sha256`
- Create: `test/infra/control/test-vendored-duckdb-source.bash`
- Modify: `.gitattributes` (create if `feature/issue-6115-vendored-openssl` has not landed), `deps/Makefile`, `include/makefiles_paths.mk`, all `.github/workflows/*.yml` that reference `PROXYSQL40`

**Interfaces:**
- Consumes: nothing.
- Produces: `$(DUCKDB_IDIR)/duckdb.h`; `$(DUCKDB_LDIR)/libduckdb_static.a`; make target `duckdb` in `deps/Makefile`; `deps/duckdb/verify-source.bash` exiting 0 on a healthy tree.

- [ ] **Step 1: Pin the version and record it**

Choose the newest stable DuckDB release that builds with the oldest toolchain in the package matrix (AlmaLinux 8 is the floor — check `.github/workflows/CI-package-*almalinux8*.yml`). Download the source archive from `https://github.com/duckdb/duckdb/releases`, then:

```bash
cd deps && mkdir -p duckdb && cd duckdb
# <version> is the pinned release, e.g. 1.1.3
sha256sum duckdb-<version>.tar.gz | awk '{print $1"  duckdb-<version>.tar.gz"}' \
  > duckdb-<version>.tar.gz.sha256
tar -tzf duckdb-<version>.tar.gz | head -1   # record the archive root, e.g. duckdb-<version>/
```

Record the version, the SHA-256, and the archive root; every later step substitutes them.

- [ ] **Step 2: Write the failing verifier test**

Create `test/infra/control/test-vendored-duckdb-source.bash`, modelled on `test/infra/control/test-vendored-openssl-source.bash`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
verifier="${repo_root}/deps/duckdb/verify-source.bash"
tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT

fail=0
check() {
	local desc=$1; shift
	if "$@" >/dev/null 2>&1; then
		echo "ok - ${desc}"
	else
		echo "not ok - ${desc}"; fail=1
	fi
}
check_fails() {
	local desc=$1; shift
	if "$@" >/dev/null 2>&1; then
		echo "not ok - ${desc} (expected non-zero exit)"; fail=1
	else
		echo "ok - ${desc}"
	fi
}

# 1. The committed archive verifies.
check "committed archive passes verification" bash "${verifier}"

# 2. An unfetched LFS pointer is detected as such, not as a corrupt archive.
printf 'version https://git-lfs.github.com/spec/v1\noid sha256:deadbeef\nsize 1\n' \
	> "${tmp}/pointer.tar.gz"
echo "0000000000000000000000000000000000000000000000000000000000000000  pointer.tar.gz" \
	> "${tmp}/pointer.tar.gz.sha256"
check_fails "LFS pointer file is rejected" bash "${verifier}" "${tmp}/pointer.tar.gz"
bash "${verifier}" "${tmp}/pointer.tar.gz" 2>&1 | grep -qi "git lfs" \
	&& echo "ok - pointer rejection mentions git lfs" \
	|| { echo "not ok - pointer rejection must name git lfs"; fail=1; }

# 3. A checksum mismatch is rejected.
head -c 1024 /dev/urandom > "${tmp}/bad.tar.gz"
echo "0000000000000000000000000000000000000000000000000000000000000000  bad.tar.gz" \
	> "${tmp}/bad.tar.gz.sha256"
check_fails "checksum mismatch is rejected" bash "${verifier}" "${tmp}/bad.tar.gz"

exit "${fail}"
```

- [ ] **Step 3: Run it to make sure it fails**

Run: `bash test/infra/control/test-vendored-duckdb-source.bash`
Expected: FAIL — `deps/duckdb/verify-source.bash` does not exist yet.

- [ ] **Step 4: Write the verifier**

Create `deps/duckdb/verify-source.bash` (adapted from `deps/libssl/verify-source.bash`; substitute the pinned version and archive root):

```bash
#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
archive=${1:-"${script_dir}/duckdb-<version>.tar.gz"}
checksum_file=${2:-"${archive}.sha256"}
required_root=duckdb-<version>
lfs_path=deps/duckdb/duckdb-<version>.tar.gz

fail() { echo "ERROR: $*" >&2; exit 1; }

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	elif command -v shasum   >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
	elif command -v sha256   >/dev/null 2>&1; then sha256 -q "$1"
	else fail "no SHA-256 tool found; install sha256sum, shasum, or sha256"; fi
}

[[ -f "${archive}" ]] || fail "DuckDB source archive is missing: ${archive}"

first_line=
IFS= read -r first_line < "${archive}" || true
if [[ "${first_line}" == 'version https://git-lfs.github.com/spec/v1' ]]; then
	cat >&2 <<EOF
ERROR: ${archive} is an unfetched git LFS pointer, not the source archive.

This tree stores the DuckDB source via git LFS. Install git-lfs and fetch it:

    git lfs install
    git lfs pull --include "${lfs_path}"

In CI, add 'lfs: true' to the actions/checkout step of the workflow.
EOF
	exit 1
fi

[[ -f "${checksum_file}" ]] || fail "checksum file is missing: ${checksum_file}"
expected=$(awk '{print $1; exit}' "${checksum_file}")
actual=$(sha256_file "${archive}")
[[ "${expected}" == "${actual}" ]] || \
	fail "SHA-256 mismatch for ${archive}: expected ${expected}, got ${actual}"

root=$(tar -tzf "${archive}" | head -1 | cut -d/ -f1)
[[ "${root}" == "${required_root}" ]] || \
	fail "unexpected archive root '${root}', expected '${required_root}'"

echo "OK: ${archive} verified (sha256 ${actual}, root ${root}/)"
```

Then `chmod +x deps/duckdb/verify-source.bash test/infra/control/test-vendored-duckdb-source.bash`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `bash test/infra/control/test-vendored-duckdb-source.bash`
Expected: all `ok -` lines, exit 0.

- [ ] **Step 6: Put the archive under LFS**

If `.gitattributes` does not exist, create it; otherwise append:

```
deps/duckdb/duckdb-<version>.tar.gz filter=lfs diff=lfs merge=lfs -text
```

Then:

```bash
git lfs install
git add .gitattributes
git add deps/duckdb/duckdb-<version>.tar.gz
git lfs ls-files | grep duckdb   # must list the archive
```

Expected: `git lfs ls-files` prints the archive. If it does not, the `.gitattributes` entry was added after `git add` — run `git rm --cached deps/duckdb/duckdb-<version>.tar.gz` and re-add.

- [ ] **Step 7: Add the deps build target**

In `include/makefiles_paths.mk`, next to the `CLICKHOUSE_CPP_*` block (around line 62):

```make
DUCKDB_PATH := $(DEPS_PATH)/duckdb/duckdb
DUCKDB_IDIR := $(DUCKDB_PATH)/src/include
DUCKDB_LDIR := $(DUCKDB_PATH)/build/release/src
```

In `deps/Makefile`, add the target (modelled on the `clickhouse-cpp` recipe at lines 218-224):

```make
duckdb/duckdb/build/release/src/libduckdb_static.a:
	cd duckdb && ./verify-source.bash
	cd duckdb && rm -rf duckdb-*/ duckdb || true
	cd duckdb && tar -zxf duckdb-*.tar.gz && mv duckdb-*/ duckdb
	cd duckdb/duckdb && cmake -S . -B build/release \
		-DCMAKE_BUILD_TYPE=Release \
		-DBUILD_UNITTESTS=OFF \
		-DBUILD_SHELL=OFF \
		-DENABLE_SANITIZER=OFF \
		-DBUILD_EXTENSIONS=""
	cd duckdb/duckdb && CC=${CC} CXX=${CXX} cmake --build build/release -j$(shell nproc 2>/dev/null || echo 4)
	@test -f $@ || { echo "ERROR: duckdb build did not produce $@" >&2; exit 1; }

duckdb: duckdb/duckdb/build/release/src/libduckdb_static.a
```

And register it with the other `PROXYSQL40` deps (near line 65):

```make
ifeq ($(PROXYSQL40),1)
	targets += protobuf
	targets += duckdb
endif
```

Add to the `cleanall` recipe: `cd duckdb && rm -rf duckdb-*/ duckdb || true`.

- [ ] **Step 8: Build the dep and confirm the C API shape**

Run: `make -C deps PROXYSQL40=1 duckdb`
Expected: `deps/duckdb/duckdb/build/release/src/libduckdb_static.a` exists.

Then confirm which result API the pinned version exposes:

```bash
grep -c "duckdb_value_varchar\|duckdb_row_count\|duckdb_value_is_null" \
  deps/duckdb/duckdb/src/include/duckdb.h
```

Expected: 3 or more. **If the count is 0**, the pinned version removed the deprecated value accessors; in that case Task 5 must be implemented with `duckdb_fetch_chunk` + `duckdb_vector_get_data` + `duckdb_validity_row_is_valid` instead, and this step's finding must be recorded in `deps/duckdb/README.md` before proceeding.

- [ ] **Step 9: Enable LFS in CI**

Every workflow that references `PROXYSQL40` needs `lfs: true` on its `actions/checkout` step, or the tarball arrives as a pointer and `verify-source.bash` fails the build with the message from Step 4.

```bash
for f in $(grep -rl "PROXYSQL40" .github/workflows/*.yml); do
  grep -q "lfs: true" "$f" || \
    perl -0pi -e 's/(uses: actions\/checkout\@[^\n]*\n(\s+)with:\n)/$1$2  lfs: true\n/' "$f"
done
grep -rl "PROXYSQL40" .github/workflows/*.yml | xargs grep -L "lfs: true"
```

Expected: the last command prints nothing. Inspect the diff of two or three files by hand — a `with:` block that was absent needs adding rather than patching.

- [ ] **Step 10: Write the deps README**

Create `deps/duckdb/README.md` covering: the pinned version and its upstream URL; the SHA-256; that the archive is stored via git LFS and how to fetch it; the exact commands to bump the version (download, regenerate `.sha256`, update `required_root` and `archive` in `verify-source.bash`, update the `deps/Makefile` glob if the root changed, re-run the verifier test); the result-API finding from Step 8; and that `lfs: true` is required in any new `PROXYSQL40` workflow.

- [ ] **Step 11: Commit**

```bash
git add .gitattributes deps/duckdb include/makefiles_paths.mk deps/Makefile \
        test/infra/control/test-vendored-duckdb-source.bash .github/workflows
git commit -m "deps: vendor DuckDB <version> source via LFS

Builds libduckdb_static.a from source under PROXYSQL40, following the
deps/libssl vendoring pattern: LFS-stored archive, SHA-256 sidecar, and a
verify-source.bash that detects an unfetched LFS pointer instead of
failing later with a confusing tar error."
```

---

### Task 2: Plugin skeleton that loads, registers nothing, and unloads

**Files:**
- Create: `plugins/duckdb/Makefile`, `plugins/duckdb/include/duckdb_plugin.h`, `plugins/duckdb/src/duckdb_plugin.cpp`
- Create: `test/tap/tests/test_duckdb_plugin_load-t.cpp`
- Modify: `Makefile` (top level), `test/tap/tests/unit/Makefile`, `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: `$(DUCKDB_IDIR)`, `$(DUCKDB_LDIR)` from Task 1.
- Produces: `plugins/duckdb/ProxySQL_DuckDB_Plugin.so` exporting `proxysql_plugin_descriptor_v1`; `DuckDBPluginContext& duckdb_context()` declared in `duckdb_plugin.h`, with fields `ProxySQL_PluginServices* services`, `std::unique_ptr<DuckDBConfigStore> config_store`, `std::unique_ptr<DuckDBEngine> engine`, `std::unique_ptr<DuckDBListener> listener`, `bool started`.

- [ ] **Step 1: Write the failing test**

Create `test/tap/tests/test_duckdb_plugin_load-t.cpp`:

```cpp
#include "ProxySQL_PluginManager.h"
#include "tap.h"

#include <cstring>
#include <string>

#ifndef PROXYSQL_DUCKDB_PLUGIN_PATH
#define PROXYSQL_DUCKDB_PLUGIN_PATH "../../../plugins/duckdb/ProxySQL_DuckDB_Plugin.so"
#endif

int main() {
	plan(5);

	ProxySQL_PluginManager mgr;
	std::string err {};

	const bool loaded = mgr.load(PROXYSQL_DUCKDB_PLUGIN_PATH, err);
	ok(loaded, "load duckdb plugin succeeds");
	if (!loaded) {
		diag("load error: %s", err.c_str());
		BAIL_OUT("duckdb plugin must load before further assertions");
	}

	const bool schemas_ok = mgr.invoke_register_schemas_phase(err);
	ok(schemas_ok, "register_schemas phase succeeds");
	if (!schemas_ok) diag("register_schemas error: %s", err.c_str());

	const bool init_ok = mgr.init_all(err);
	ok(init_ok, "init_all succeeds");
	if (!init_ok) diag("init error: %s", err.c_str());

	const bool stop_ok = mgr.stop_all();
	ok(stop_ok, "stop_all succeeds without start_all");

	// Reloading the same path must be refused, proving the manager tracked it.
	std::string dup_err {};
	const bool dup = mgr.load(PROXYSQL_DUCKDB_PLUGIN_PATH, dup_err);
	ok(dup == false, "loading the same plugin path twice is refused");

	return exit_status();
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run:
```bash
cd test/tap/tests/unit && PROXYSQL40=1 make test_duckdb_plugin_load-t
```
Expected: FAIL — no rule to make target / the `.so` does not exist.

- [ ] **Step 3: Write the plugin context header**

Create `plugins/duckdb/include/duckdb_plugin.h`:

```cpp
#ifndef __DUCKDB_PLUGIN_H
#define __DUCKDB_PLUGIN_H

#include "ProxySQL_Plugin.h"

#include <memory>

class DuckDBConfigStore;
class DuckDBEngine;
class DuckDBListener;

// Process-wide plugin state. The chassis gives callbacks no context
// pointer, so the plugin reaches its own state through this accessor.
// Not thread-safe to mutate; every field is written only during the
// single-threaded lifecycle phases (init / start / stop) and read
// afterwards.
struct DuckDBPluginContext {
	ProxySQL_PluginServices* services { nullptr };
	std::unique_ptr<DuckDBConfigStore> config_store;
	std::unique_ptr<DuckDBEngine> engine;
	std::unique_ptr<DuckDBListener> listener;
	bool started { false };
};

DuckDBPluginContext& duckdb_context();

#endif // __DUCKDB_PLUGIN_H
```

- [ ] **Step 4: Write the descriptor with no-op lifecycle callbacks**

Create `plugins/duckdb/src/duckdb_plugin.cpp`:

```cpp
#include "duckdb_plugin.h"

namespace {

bool duckdb_register_schemas(ProxySQL_PluginServices* services) {
	if (services == nullptr) return false;
	return true;   // Task 6 registers the schema here.
}

bool duckdb_init(ProxySQL_PluginServices* services) {
	if (services == nullptr) return false;
	DuckDBPluginContext& ctx = duckdb_context();
	ctx.services = services;
	ctx.started = false;
	return true;
}

bool duckdb_start() {
	duckdb_context().started = true;
	return true;   // Task 8 opens the engine and binds listeners here.
}

// Pairs with init(), not start(): the chassis guarantees stop() runs for
// any plugin whose init() returned true, even if start() failed or never
// ran. Every teardown below must tolerate a null / never-started member.
bool duckdb_stop() {
	DuckDBPluginContext& ctx = duckdb_context();
	ctx.started = false;
	return true;
}

const char* duckdb_status_json() {
	return duckdb_context().started
		? "{\"name\":\"duckdb\",\"state\":\"running\"}"
		: "{\"name\":\"duckdb\",\"state\":\"stopped\"}";
}

const ProxySQL_PluginDescriptor duckdb_descriptor = {
	"duckdb",
	PROXYSQL_PLUGIN_ABI_VERSION,
	&duckdb_init,
	&duckdb_start,
	&duckdb_stop,
	&duckdb_status_json,
	&duckdb_register_schemas,
};

} // namespace

DuckDBPluginContext& duckdb_context() {
	static DuckDBPluginContext ctx {};
	return ctx;
}

// Default visibility is required: the .so is built with
// -fvisibility=hidden, and without this the loader fails with
// "undefined symbol: proxysql_plugin_descriptor_v1".
extern "C" __attribute__((visibility("default")))
const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1() {
	return &duckdb_descriptor;
}
```

- [ ] **Step 5: Write the plugin Makefile**

Create `plugins/duckdb/Makefile`, copying `plugins/mysqlx/Makefile` and making these changes: drop every protobuf and proto-generated stanza and the `.NOTPARALLEL:` line; set `PLUGIN_DIR := $(PROXYSQL_PATH)/plugins/duckdb` and `PLUGIN_SO := $(PLUGIN_DIR)/ProxySQL_DuckDB_Plugin.so`. Keep the repo-root discovery block, the tier-flag cascade block, and the hardening flags verbatim. Then:

```make
IDIRS := -I$(PROXYSQL_IDIR) -I$(PLUGIN_DIR)/include -I$(SQLITE3_IDIR) \
	-I$(DUCKDB_IDIR) -I$(SSL_IDIR) -I$(PROMETHEUS_IDIR) -I$(LIBCONFIG_IDIR) \
	-I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) -I$(RE2_IDIR) -I$(ZSTD_IDIR) \
	-I$(POSTGRESQL_IDIR) -I$(LIBUSUAL_IDIR) \
	-I$(PROXYSQL_PATH)/deps/lz4/lz4/lib

DUCKDB_AR := $(DUCKDB_LDIR)/libduckdb_static.a

SRCS := $(PLUGIN_DIR)/src/duckdb_plugin.cpp
HEADERS := $(wildcard $(PLUGIN_DIR)/include/*.h) $(PROXYSQL_PATH)/include/ProxySQL_Plugin.h
OBJS := $(patsubst $(PLUGIN_DIR)/src/%.cpp,$(ODIR)/%.o,$(SRCS))

$(DUCKDB_AR):
	$(MAKE) -C $(PROXYSQL_PATH)/deps PROXYSQL40=1 duckdb
	@test -f $@ || { echo "ERROR: deps duckdb build did not produce $@" >&2; exit 1; }

$(ODIR)/%.o: $(PLUGIN_DIR)/src/%.cpp $(HEADERS) $(DUCKDB_AR) | $(ODIR)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(IDIRS)

$(PLUGIN_SO): $(OBJS) $(DUCKDB_AR)
	$(CXX) -shared -o $@ $(OBJS) $(CXXFLAGS) -pthread \
		-Wl,--whole-archive $(DUCKDB_AR) -Wl,--no-whole-archive \
		-L$(SSL_LDIR) -lssl -lcrypto $(PLUGIN_LDFLAGS)
```

As each later task adds a `.cpp`, append it to `SRCS`.

- [ ] **Step 6: Wire the plugin into the top-level build**

In the top-level `Makefile`, beside every `plugins/mysqlx` line (280, 294, 427, 433, 539, 549, 556, 569, 581), add the matching `plugins/duckdb` line with the same flags and `OPTZ`. For example, at line 280:

```make
	$(if $(filter 1,$(PROXYSQL40)),cd plugins/duckdb && OPTZ="${O2} -ggdb" PROXYSQL40=$(PROXYSQL40) PROXYSQL31=$(PROXYSQL31) PROXYSQLFFTO=$(PROXYSQLFFTO) PROXYSQLTSDB=$(PROXYSQLTSDB) CC=${CC} CXX=${CXX} ${MAKE},@echo "[skip] duckdb plugin (PROXYSQL40 not set)")
```

At line 593 (install) and 639 (uninstall), mirror the mysqlx stanzas:

```make
	if [ -f plugins/duckdb/ProxySQL_DuckDB_Plugin.so ]; then \
		install -m 0755 plugins/duckdb/ProxySQL_DuckDB_Plugin.so /usr/lib/proxysql/plugins/ ; \
	fi
```

- [ ] **Step 7: Add the test build rule and register the test**

In `test/tap/tests/unit/Makefile`, add `test_duckdb_plugin_load-t` to the `PROXYSQL40`-only test list (beside `test_mysqlx_plugin_load-t` at line 496), a `duckdb_plugin_build` phony target mirroring `mysqlx_plugin_build` (line 368), and the rule:

```make
DUCKDB_PLUGIN_SO := $(PROXYSQL_PATH)/plugins/duckdb/ProxySQL_DuckDB_Plugin.so

.PHONY: duckdb_plugin_build
duckdb_plugin_build:
	$(MAKE) -C $(PROXYSQL_PATH)/plugins/duckdb all \
		PROXYSQL40=1 CC=$(CC) CXX=$(CXX)

test_duckdb_plugin_load-t: test_duckdb_plugin_load-t.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR) duckdb_plugin_build
	$(CXX) $< $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-DPROXYSQL_DUCKDB_PLUGIN_PATH='"$(DUCKDB_PLUGIN_SO)"' \
		-I$(PROXYSQL_PATH)/plugins/duckdb/include \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) $(ALLOW_MULTI_DEF) -o $@
```

In `test/tap/groups/groups.json`, add:

```json
  "test_duckdb_plugin_load-t" : [ "unit-tests-g1","@proxysql_min_version:4.0" ],
```

- [ ] **Step 8: Run the test to verify it passes**

Run:
```bash
PROXYSQL40=1 make -j$(nproc) && \
cd test/tap/tests/unit && PROXYSQL40=1 make test_duckdb_plugin_load-t && ./test_duckdb_plugin_load-t
```
Expected: `1..5` with five `ok` lines.

- [ ] **Step 9: Commit**

```bash
git add plugins/duckdb Makefile test/tap/tests/test_duckdb_plugin_load-t.cpp \
        test/tap/tests/unit/Makefile test/tap/groups/groups.json
git commit -m "feat(duckdb): add plugin skeleton with four-phase descriptor

The .so loads, runs register_schemas/init/stop, and unloads cleanly.
Lifecycle callbacks are intentionally empty; later tasks fill them in."
```

---

### Task 3: DuckDBConfigStore — typed variables, validation, iface parsing

**Files:**
- Create: `plugins/duckdb/include/duckdb_config.h`, `plugins/duckdb/src/duckdb_config.cpp`
- Create: `test/tap/tests/unit/duckdb_config_unit-t.cpp`
- Modify: `plugins/duckdb/Makefile` (`SRCS`), `test/tap/tests/unit/Makefile`, `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `struct DuckDBIface { std::string addr; uint16_t port; }`
  - `class DuckDBConfigStore` with `bool set(const std::string& name, const std::string& value, std::string& err)`, `std::string get(const std::string& name) const`, `std::vector<std::string> variable_names() const`, `bool validate(std::string& err) const`, and typed getters `std::string database_path() const`, `std::string memory_limit() const`, `int threads() const`, `int max_connections() const`, `bool read_only() const`, `std::vector<DuckDBIface> mysql_ifaces() const`, `std::vector<DuckDBIface> pgsql_ifaces() const`.
  - Free function `bool duckdb_parse_ifaces(const std::string& spec, std::vector<DuckDBIface>& out, std::string& err)`.

- [ ] **Step 1: Write the failing test**

Create `test/tap/tests/unit/duckdb_config_unit-t.cpp`:

```cpp
#include "duckdb_config.h"
#include "tap.h"

#include <string>
#include <vector>

int main() {
	plan(14);

	// --- iface parsing -------------------------------------------------
	std::vector<DuckDBIface> ifaces;
	std::string err;

	ok(duckdb_parse_ifaces("127.0.0.1:6031", ifaces, err) && ifaces.size() == 1,
	   "single iface parses");
	ok(ifaces.size() == 1 && ifaces[0].addr == "127.0.0.1" && ifaces[0].port == 6031,
	   "single iface has the right addr and port");

	ifaces.clear(); err.clear();
	ok(duckdb_parse_ifaces("0.0.0.0:6031;127.0.0.1:6032", ifaces, err) && ifaces.size() == 2,
	   "semicolon-separated ifaces parse");

	ifaces.clear(); err.clear();
	ok(duckdb_parse_ifaces("[::1]:6031", ifaces, err) && ifaces.size() == 1 &&
	   ifaces[0].addr == "::1" && ifaces[0].port == 6031,
	   "bracketed IPv6 iface parses");

	ifaces.clear(); err.clear();
	ok(duckdb_parse_ifaces("", ifaces, err) && ifaces.empty(),
	   "empty iface spec yields no listeners and is not an error");

	ifaces.clear(); err.clear();
	ok(duckdb_parse_ifaces("127.0.0.1", ifaces, err) == false && !err.empty(),
	   "iface without a port is rejected with a message");

	ifaces.clear(); err.clear();
	ok(duckdb_parse_ifaces("127.0.0.1:0", ifaces, err) == false,
	   "port 0 is rejected");

	ifaces.clear(); err.clear();
	ok(duckdb_parse_ifaces("127.0.0.1:70000", ifaces, err) == false,
	   "port above 65535 is rejected");

	// --- defaults ------------------------------------------------------
	DuckDBConfigStore cfg;
	ok(cfg.database_path() == ":memory:", "database_path defaults to :memory:");
	ok(cfg.read_only() == false, "read_only defaults to false");
	ok(cfg.max_connections() > 0, "max_connections has a positive default");

	// --- set / get -----------------------------------------------------
	err.clear();
	ok(cfg.set("threads", "4", err) && cfg.threads() == 4, "threads round-trips");

	err.clear();
	ok(cfg.set("threads", "not-a-number", err) == false && !err.empty(),
	   "non-numeric threads is rejected with a message");

	// --- cross-field validation ----------------------------------------
	// READ_ONLY is meaningless for an in-memory database and DuckDB rejects
	// the combination at open time; catch it at config time with a clear
	// message instead.
	err.clear();
	cfg.set("database_path", ":memory:", err);
	cfg.set("read_only", "true", err);
	ok(cfg.validate(err) == false && err.find("read_only") != std::string::npos,
	   "read_only with :memory: fails validation and names the variable");

	return exit_status();
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd test/tap/tests/unit && PROXYSQL40=1 make duckdb_config_unit-t`
Expected: FAIL — `duckdb_config.h` not found.

- [ ] **Step 3: Write the header**

Create `plugins/duckdb/include/duckdb_config.h`:

```cpp
#ifndef __DUCKDB_CONFIG_H
#define __DUCKDB_CONFIG_H

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

struct DuckDBIface {
	std::string addr;
	uint16_t port { 0 };
};

// Parses "addr:port" entries separated by ';'. IPv6 literals must be
// bracketed: "[::1]:6031". An empty spec is valid and yields no ifaces.
// Returns false and fills `err` on the first malformed entry.
bool duckdb_parse_ifaces(const std::string& spec,
                         std::vector<DuckDBIface>& out,
                         std::string& err);

// Holds the plugin's variables. All access is under one mutex; the store
// is read from connection threads and written only during the lifecycle
// phases and LOAD ... TO RUNTIME.
class DuckDBConfigStore {
public:
	DuckDBConfigStore();

	bool set(const std::string& name, const std::string& value, std::string& err);
	std::string get(const std::string& name) const;
	std::vector<std::string> variable_names() const;

	// Cross-field checks that a per-variable set() cannot make.
	bool validate(std::string& err) const;

	std::string database_path() const;
	std::string memory_limit() const;
	int threads() const;
	int max_connections() const;
	bool read_only() const;
	std::vector<DuckDBIface> mysql_ifaces() const;
	std::vector<DuckDBIface> pgsql_ifaces() const;

private:
	mutable std::mutex mutex_;
	std::map<std::string, std::string> values_;

	std::string get_locked(const std::string& name) const;
};

#endif // __DUCKDB_CONFIG_H
```

- [ ] **Step 4: Write the implementation**

Create `plugins/duckdb/src/duckdb_config.cpp`. Defaults, per the spec:

```cpp
#include "duckdb_config.h"

#include <cstdlib>
#include <sstream>

namespace {

bool parse_int(const std::string& s, long& out) {
	if (s.empty()) return false;
	char* end = nullptr;
	const long v = std::strtol(s.c_str(), &end, 10);
	if (end == nullptr || *end != '\0') return false;
	out = v;
	return true;
}

bool parse_bool(const std::string& s, bool& out) {
	if (s == "true" || s == "1" || s == "on")   { out = true;  return true; }
	if (s == "false" || s == "0" || s == "off") { out = false; return true; }
	return false;
}

bool parse_one_iface(const std::string& entry, DuckDBIface& out, std::string& err) {
	std::string addr;
	std::string port_str;
	if (!entry.empty() && entry[0] == '[') {
		const auto close = entry.find(']');
		if (close == std::string::npos || close + 1 >= entry.size() || entry[close + 1] != ':') {
			err = "malformed bracketed iface '" + entry + "'; expected [addr]:port";
			return false;
		}
		addr = entry.substr(1, close - 1);
		port_str = entry.substr(close + 2);
	} else {
		const auto colon = entry.rfind(':');
		if (colon == std::string::npos || colon == 0 || colon + 1 >= entry.size()) {
			err = "malformed iface '" + entry + "'; expected addr:port";
			return false;
		}
		addr = entry.substr(0, colon);
		port_str = entry.substr(colon + 1);
	}
	long port = 0;
	if (!parse_int(port_str, port) || port < 1 || port > 65535) {
		err = "invalid port in iface '" + entry + "'; expected 1-65535";
		return false;
	}
	out.addr = addr;
	out.port = static_cast<uint16_t>(port);
	return true;
}

} // namespace

bool duckdb_parse_ifaces(const std::string& spec,
                         std::vector<DuckDBIface>& out,
                         std::string& err) {
	out.clear();
	std::istringstream ss(spec);
	std::string entry;
	while (std::getline(ss, entry, ';')) {
		if (entry.empty()) continue;
		DuckDBIface iface;
		if (!parse_one_iface(entry, iface, err)) return false;
		out.push_back(iface);
	}
	return true;
}

DuckDBConfigStore::DuckDBConfigStore() {
	values_ = {
		{ "mysql_ifaces",    "0.0.0.0:6031" },
		{ "pgsql_ifaces",    "0.0.0.0:6032" },
		{ "database_path",   ":memory:"     },
		{ "memory_limit",    "1GB"          },
		{ "threads",         "2"            },
		{ "max_connections", "100"          },
		{ "read_only",       "false"        },
	};
}
```

`set()` takes the lock, rejects an unknown `name` with `err = "unknown duckdb variable '" + name + "'"`, then validates by name: `threads` and `max_connections` must parse as integers `>= 1`; `read_only` must parse as a bool; `mysql_ifaces` and `pgsql_ifaces` must satisfy `duckdb_parse_ifaces`; `database_path` and `memory_limit` are accepted as-is. On success it stores the value.

`validate()` takes the lock and returns false with
`err = "read_only=true requires a file-backed database_path; ':memory:' cannot be opened read-only"`
when `read_only` is true and `database_path` is `:memory:`.

The typed getters take the lock, read the string, and parse it with the helpers above, falling back to the constructor default if parsing somehow fails. `get()` returns an empty string for an unknown name. `variable_names()` returns the keys in map order.

- [ ] **Step 5: Add the build rules**

Append `$(PLUGIN_DIR)/src/duckdb_config.cpp` to `SRCS` in `plugins/duckdb/Makefile`.

In `test/tap/tests/unit/Makefile`, add `duckdb_config_unit-t` to the `PROXYSQL40` test list and:

```make
duckdb_config_unit-t: duckdb_config_unit-t.cpp $(PROXYSQL_PATH)/plugins/duckdb/src/duckdb_config.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/duckdb/src/duckdb_config.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/duckdb/include \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) $(ALLOW_MULTI_DEF) -o $@
```

In `groups.json`: `"duckdb_config_unit-t" : [ "unit-tests-g1","@proxysql_min_version:4.0" ],`

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd test/tap/tests/unit && PROXYSQL40=1 make duckdb_config_unit-t && ./duckdb_config_unit-t`
Expected: `1..14`, all `ok`.

- [ ] **Step 7: Commit**

```bash
git add plugins/duckdb test/tap/tests/unit/duckdb_config_unit-t.cpp \
        test/tap/tests/unit/Makefile test/tap/groups/groups.json
git commit -m "feat(duckdb): add config store with iface parsing and validation

Rejects read_only=true against a :memory: database at config time rather
than letting duckdb_open_ext fail later with a less specific message."
```

---

### Task 4: DuckDBEngine — open, configure, hand out connections, close

**Files:**
- Create: `plugins/duckdb/include/duckdb_engine.h`, `plugins/duckdb/src/duckdb_engine.cpp`
- Create: `test/tap/tests/unit/duckdb_engine_unit-t.cpp`
- Modify: `plugins/duckdb/Makefile`, `test/tap/tests/unit/Makefile`, `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: `DuckDBConfigStore` (Task 3).
- Produces: `class DuckDBEngine` with `bool open(const DuckDBConfigStore& cfg, std::string& err)`, `void close()`, `bool is_open() const`, `bool connect(duckdb_connection* out, std::string& err)`, `void disconnect(duckdb_connection* conn)`, `size_t open_connections() const`, `bool try_reserve_connection()`, `void release_connection()`.

- [ ] **Step 1: Write the failing test**

Create `test/tap/tests/unit/duckdb_engine_unit-t.cpp`:

```cpp
#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "tap.h"

#include <string>

int main() {
	plan(10);

	DuckDBConfigStore cfg;
	std::string err;

	DuckDBEngine engine;
	ok(engine.is_open() == false, "engine starts closed");

	ok(engine.open(cfg, err), "open with defaults (:memory:) succeeds");
	if (!engine.is_open()) {
		diag("open error: %s", err.c_str());
		BAIL_OUT("engine must open before connection assertions");
	}
	ok(engine.is_open(), "is_open reports true after open");

	duckdb_connection conn = nullptr;
	err.clear();
	ok(engine.connect(&conn, err) && conn != nullptr, "connect yields a connection");
	ok(engine.open_connections() == 1, "open_connections counts the connection");

	// A query must actually run, otherwise "open" proves nothing.
	duckdb_result res;
	const bool q_ok = (duckdb_query(conn, "SELECT 42 AS answer", &res) == DuckDBSuccess);
	ok(q_ok, "a trivial query executes on the connection");
	if (q_ok) duckdb_destroy_result(&res);

	engine.disconnect(&conn);
	ok(conn == nullptr, "disconnect nulls the caller's handle");
	ok(engine.open_connections() == 0, "open_connections drops back to zero");

	engine.close();
	ok(engine.is_open() == false, "close makes the engine closed");

	// close() must be idempotent: stop() can run without start().
	engine.close();
	ok(engine.is_open() == false, "close is idempotent");

	return exit_status();
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd test/tap/tests/unit && PROXYSQL40=1 make duckdb_engine_unit-t`
Expected: FAIL — `duckdb_engine.h` not found.

- [ ] **Step 3: Write the header**

Create `plugins/duckdb/include/duckdb_engine.h`:

```cpp
#ifndef __DUCKDB_ENGINE_H
#define __DUCKDB_ENGINE_H

#include "duckdb.h"

#include <atomic>
#include <cstddef>
#include <mutex>
#include <string>

class DuckDBConfigStore;

// Owns the single process-wide duckdb_database. Connections are created
// per session; DuckDB's own concurrency control serialises them, so no
// external pool is needed.
class DuckDBEngine {
public:
	DuckDBEngine() = default;
	~DuckDBEngine();

	DuckDBEngine(const DuckDBEngine&) = delete;
	DuckDBEngine& operator=(const DuckDBEngine&) = delete;

	// Applies memory_limit, threads and access_mode from `cfg`, then opens
	// cfg.database_path(). Returns false with `err` set on failure; the
	// engine is left closed.
	bool open(const DuckDBConfigStore& cfg, std::string& err);

	// Safe to call when never opened, and safe to call twice.
	void close();
	bool is_open() const;

	bool connect(duckdb_connection* out, std::string& err);
	void disconnect(duckdb_connection* conn);

	size_t open_connections() const;

	// max_connections admission control, used by the accept loop before a
	// session object is built. Reserve on accept, release on thread exit.
	bool try_reserve_connection();
	void release_connection();

	void set_max_connections(size_t n);

private:
	mutable std::mutex mutex_;
	duckdb_database database_ { nullptr };
	std::atomic<size_t> open_connections_ { 0 };
	std::atomic<size_t> reserved_ { 0 };
	std::atomic<size_t> max_connections_ { 100 };
};

#endif // __DUCKDB_ENGINE_H
```

- [ ] **Step 4: Write the implementation**

Create `plugins/duckdb/src/duckdb_engine.cpp`:

```cpp
#include "duckdb_engine.h"
#include "duckdb_config.h"

#include <utility>

DuckDBEngine::~DuckDBEngine() {
	close();
}

bool DuckDBEngine::open(const DuckDBConfigStore& cfg, std::string& err) {
	err.clear();
	if (!cfg.validate(err)) return false;

	std::lock_guard<std::mutex> lock(mutex_);
	if (database_ != nullptr) {
		err = "duckdb engine is already open";
		return false;
	}

	duckdb_config config = nullptr;
	if (duckdb_create_config(&config) != DuckDBSuccess) {
		err = "duckdb_create_config failed";
		return false;
	}

	// set_config failures are reported rather than ignored: a silently
	// dropped memory_limit would let a runaway query take the process down.
	auto set_or_fail = [&](const char* k, const std::string& v) -> bool {
		if (duckdb_set_config(config, k, v.c_str()) != DuckDBSuccess) {
			err = std::string("duckdb_set_config failed for '") + k + "'='" + v + "'";
			return false;
		}
		return true;
	};

	bool ok = set_or_fail("memory_limit", cfg.memory_limit())
	       && set_or_fail("threads", std::to_string(cfg.threads()));
	if (ok && cfg.read_only()) ok = set_or_fail("access_mode", "READ_ONLY");
	if (!ok) { duckdb_destroy_config(&config); return false; }

	char* open_err = nullptr;
	const std::string path = cfg.database_path();
	const duckdb_state st = duckdb_open_ext(path.c_str(), &database_, config, &open_err);
	duckdb_destroy_config(&config);

	if (st != DuckDBSuccess) {
		err = "duckdb_open_ext failed for '" + path + "'";
		if (open_err != nullptr) { err += ": "; err += open_err; duckdb_free(open_err); }
		database_ = nullptr;
		return false;
	}
	if (open_err != nullptr) duckdb_free(open_err);

	max_connections_.store(static_cast<size_t>(cfg.max_connections()));
	return true;
}

void DuckDBEngine::close() {
	std::lock_guard<std::mutex> lock(mutex_);
	if (database_ == nullptr) return;
	duckdb_close(&database_);
	database_ = nullptr;
}

bool DuckDBEngine::is_open() const {
	std::lock_guard<std::mutex> lock(mutex_);
	return database_ != nullptr;
}

bool DuckDBEngine::connect(duckdb_connection* out, std::string& err) {
	if (out == nullptr) { err = "connect: null out parameter"; return false; }
	*out = nullptr;
	std::lock_guard<std::mutex> lock(mutex_);
	if (database_ == nullptr) { err = "duckdb engine is not open"; return false; }
	if (duckdb_connect(database_, out) != DuckDBSuccess) {
		*out = nullptr;
		err = "duckdb_connect failed";
		return false;
	}
	open_connections_.fetch_add(1);
	return true;
}

void DuckDBEngine::disconnect(duckdb_connection* conn) {
	if (conn == nullptr || *conn == nullptr) return;
	duckdb_disconnect(conn);
	*conn = nullptr;
	open_connections_.fetch_sub(1);
}

size_t DuckDBEngine::open_connections() const { return open_connections_.load(); }

void DuckDBEngine::set_max_connections(size_t n) { max_connections_.store(n); }

bool DuckDBEngine::try_reserve_connection() {
	const size_t cap = max_connections_.load();
	size_t cur = reserved_.load();
	while (cur < cap) {
		if (reserved_.compare_exchange_weak(cur, cur + 1)) return true;
	}
	return false;
}

void DuckDBEngine::release_connection() {
	size_t cur = reserved_.load();
	while (cur > 0) {
		if (reserved_.compare_exchange_weak(cur, cur - 1)) return;
	}
}
```

- [ ] **Step 5: Add the build rules**

Append `$(PLUGIN_DIR)/src/duckdb_engine.cpp` to `SRCS`. In `test/tap/tests/unit/Makefile`, add `duckdb_engine_unit-t` to the `PROXYSQL40` list and a rule that compiles both `duckdb_engine.cpp` and `duckdb_config.cpp`, adds `-I$(DUCKDB_IDIR)`, and links `$(DUCKDB_LDIR)/libduckdb_static.a`:

```make
DUCKDB_AR := $(DUCKDB_LDIR)/libduckdb_static.a

duckdb_engine_unit-t: duckdb_engine_unit-t.cpp $(PROXYSQL_PATH)/plugins/duckdb/src/duckdb_engine.cpp $(PROXYSQL_PATH)/plugins/duckdb/src/duckdb_config.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR) $(DUCKDB_AR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/duckdb/src/duckdb_engine.cpp $(PROXYSQL_PATH)/plugins/duckdb/src/duckdb_config.cpp $(TEST_HELPERS_OBJ) $(IDIRS) -I$(DUCKDB_IDIR) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/duckdb/include \
		$(WHOLE_LIBPROXYSQL) $(DUCKDB_AR) $(STATIC_LIBS) $(MYLIBS) $(ALLOW_MULTI_DEF) -o $@
```

In `groups.json`: `"duckdb_engine_unit-t" : [ "unit-tests-g1","@proxysql_min_version:4.0" ],`

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd test/tap/tests/unit && PROXYSQL40=1 make duckdb_engine_unit-t && ./duckdb_engine_unit-t`
Expected: `1..10`, all `ok`.

- [ ] **Step 7: Commit**

```bash
git add plugins/duckdb test/tap/tests/unit/duckdb_engine_unit-t.cpp \
        test/tap/tests/unit/Makefile test/tap/groups/groups.json
git commit -m "feat(duckdb): add engine owning the embedded database

open() applies memory_limit/threads/access_mode and reports set_config
failures rather than silently dropping them. close() is idempotent so
stop() can run without a matching start()."
```

---

### Task 5: Convert `duckdb_result` to `SQLite3_result`

**Files:**
- Create: `plugins/duckdb/include/duckdb_result.h`, `plugins/duckdb/src/duckdb_result.cpp`
- Create: `test/tap/tests/unit/duckdb_result_unit-t.cpp`
- Modify: `plugins/duckdb/Makefile`, `test/tap/tests/unit/Makefile`, `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: nothing from earlier tasks (takes a raw `duckdb_result*`).
- Produces: `SQLite3_result* duckdb_result_to_sqlite3(duckdb_result* res)` — caller owns and deletes the returned object; returns `nullptr` when `res` has zero columns.

- [ ] **Step 1: Write the failing test**

Create `test/tap/tests/unit/duckdb_result_unit-t.cpp`:

```cpp
#include "duckdb_result.h"
#include "duckdb.h"
#include "sqlite3db.h"
#include "tap.h"

#include <memory>
#include <string>

namespace {

// Runs `sql` on a fresh in-memory database and converts the result.
SQLite3_result* run(duckdb_connection conn, const char* sql) {
	duckdb_result res;
	if (duckdb_query(conn, sql, &res) != DuckDBSuccess) {
		duckdb_destroy_result(&res);
		return nullptr;
	}
	SQLite3_result* out = duckdb_result_to_sqlite3(&res);
	duckdb_destroy_result(&res);
	return out;
}

} // namespace

int main() {
	plan(11);

	duckdb_database db = nullptr;
	duckdb_connection conn = nullptr;
	if (duckdb_open(":memory:", &db) != DuckDBSuccess ||
	    duckdb_connect(db, &conn) != DuckDBSuccess) {
		BAIL_OUT("could not open an in-memory duckdb");
	}

	{
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT 42 AS answer"));
		ok(r != nullptr, "integer select converts");
		ok(r && r->columns == 1, "one column");
		ok(r && r->rows_count == 1, "one row");
		ok(r && std::string(r->column_definition[0]->name) == "answer",
		   "column name is preserved");
		ok(r && std::string(r->rows[0]->fields[0]) == "42",
		   "integer value renders as text");
	}

	{
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT NULL AS n, 1 AS m"));
		ok(r && r->rows[0]->fields[0] == nullptr, "SQL NULL becomes a null field");
		ok(r && r->rows[0]->sizes[0] == 0, "null field has zero size");
		ok(r && r->rows[0]->fields[1] != nullptr, "the non-null neighbour survives");
	}

	{
		// Nested types must round-trip through duckdb's own rendering.
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT [1,2,3] AS l"));
		ok(r && r->rows_count == 1 && r->rows[0]->fields[0] != nullptr,
		   "LIST renders without crashing");
	}

	{
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT 1 WHERE false"));
		ok(r && r->columns == 1 && r->rows_count == 0,
		   "empty resultset keeps its column definitions");
	}

	{
		// A statement with no columns must convert to nullptr so the caller
		// takes the affected-rows path instead of sending an empty set.
		duckdb_result res;
		duckdb_query(conn, "CREATE TABLE t(a INTEGER)", &res);
		SQLite3_result* r = duckdb_result_to_sqlite3(&res);
		ok(r == nullptr, "a zero-column result converts to nullptr");
		delete r;
		duckdb_destroy_result(&res);
	}

	duckdb_disconnect(&conn);
	duckdb_close(&db);
	return exit_status();
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd test/tap/tests/unit && PROXYSQL40=1 make duckdb_result_unit-t`
Expected: FAIL — `duckdb_result.h` not found.

- [ ] **Step 3: Write the header**

Create `plugins/duckdb/include/duckdb_result.h`:

```cpp
#ifndef __DUCKDB_RESULT_H
#define __DUCKDB_RESULT_H

#include "duckdb.h"

class SQLite3_result;

// Converts a materialised duckdb_result into the SQLite3_result that
// core's MySQL and PostgreSQL serialisers both consume.
//
// Every value is rendered with duckdb_value_varchar(), which is correct
// on the wire because both text protocols transmit values as strings and
// both serialisers label every column as text anyway (MYSQL_TYPE_VAR_STRING
// / TEXTOID). SQL NULL becomes a null field pointer, which SQLite3_row
// stores with size 0 and SQLite3_to_Postgres emits as a -1 length.
//
// Returns nullptr when the result has no columns (DDL/DML): the caller
// must then take the affected-rows path.
//
// The caller owns the returned object and must `delete` it.
SQLite3_result* duckdb_result_to_sqlite3(duckdb_result* res);

#endif // __DUCKDB_RESULT_H
```

- [ ] **Step 4: Write the implementation**

Create `plugins/duckdb/src/duckdb_result.cpp`:

```cpp
#include "duckdb_result.h"
#include "sqlite3db.h"

#include <vector>

SQLite3_result* duckdb_result_to_sqlite3(duckdb_result* res) {
	if (res == nullptr) return nullptr;

	const idx_t ncols = duckdb_column_count(res);
	if (ncols == 0) return nullptr;

	SQLite3_result* out = new SQLite3_result(static_cast<int>(ncols));
	for (idx_t c = 0; c < ncols; c++) {
		const char* name = duckdb_column_name(res, c);
		out->add_column_definition(SQLITE_TEXT, name != nullptr ? name : "");
	}

	const idx_t nrows = duckdb_row_count(res);
	std::vector<char*> fields(static_cast<size_t>(ncols), nullptr);

	for (idx_t r = 0; r < nrows; r++) {
		for (idx_t c = 0; c < ncols; c++) {
			// duckdb_value_varchar returns nullptr for NULL, which is
			// exactly the representation SQLite3_row::add_fields wants.
			fields[c] = duckdb_value_is_null(res, c, r)
				? nullptr
				: duckdb_value_varchar(res, c, r);
		}
		out->add_row(fields.data());
		for (idx_t c = 0; c < ncols; c++) {
			if (fields[c] != nullptr) { duckdb_free(fields[c]); fields[c] = nullptr; }
		}
	}
	return out;
}
```

**If Task 1 Step 8 found the deprecated accessors absent**, replace the row loop with a `duckdb_fetch_chunk` loop: for each chunk, `duckdb_data_chunk_get_size()` gives the row count and `duckdb_data_chunk_get_vector()` + `duckdb_vector_get_validity()` + `duckdb_validity_row_is_valid()` give per-value validity; render each value by casting the chunk to VARCHAR with a `CAST(col AS VARCHAR)` projection wrapped around the user's query. Keep the same signature and the same null-field contract so no caller changes.

- [ ] **Step 5: Add the build rules**

Append `$(PLUGIN_DIR)/src/duckdb_result.cpp` to `SRCS`. In `test/tap/tests/unit/Makefile`, add `duckdb_result_unit-t` to the `PROXYSQL40` list with a rule matching Task 4's shape (compile `duckdb_result.cpp`, add `-I$(DUCKDB_IDIR)`, link `$(DUCKDB_AR)`).

In `groups.json`: `"duckdb_result_unit-t" : [ "unit-tests-g1","@proxysql_min_version:4.0" ],`

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd test/tap/tests/unit && PROXYSQL40=1 make duckdb_result_unit-t && ./duckdb_result_unit-t`
Expected: `1..11`, all `ok`.

- [ ] **Step 7: Run it under ASAN to prove the allocations balance**

`duckdb_value_varchar` allocates per value; a missed `duckdb_free` would leak once per cell.

```bash
cd test/tap/tests/unit && NOJEMALLOC=1 WITHASAN=1 PROXYSQL40=1 make duckdb_result_unit-t && \
  ASAN_OPTIONS=detect_leaks=1 ./duckdb_result_unit-t
```
Expected: tests pass and ASAN reports no leaks. If it reports leaks originating in `duckdb_result_to_sqlite3`, the `duckdb_free` loop is wrong — fix it before committing.

- [ ] **Step 8: Commit**

```bash
git add plugins/duckdb test/tap/tests/unit/duckdb_result_unit-t.cpp \
        test/tap/tests/unit/Makefile test/tap/groups/groups.json
git commit -m "feat(duckdb): convert duckdb_result to SQLite3_result

Renders every value through duckdb_value_varchar so nested types work,
and maps SQL NULL to a null field pointer, which both core serialisers
already handle. Zero-column results convert to nullptr so callers take
the affected-rows path."
```

---

### Task 6: Admin schema — `duckdb_variables`, runtime view, LOAD/SAVE

**Files:**
- Create: `plugins/duckdb/include/duckdb_admin_schema.h`, `plugins/duckdb/src/duckdb_admin_schema.cpp`
- Create: `test/tap/tests/unit/duckdb_admin_schema_unit-t.cpp`
- Modify: `plugins/duckdb/src/duckdb_plugin.cpp`, `plugins/duckdb/Makefile`, `test/tap/tests/unit/Makefile`, `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: `DuckDBConfigStore` (Task 3), `duckdb_context()` (Task 2).
- Produces:
  - `bool duckdb_register_admin_schema(ProxySQL_PluginServices& services)`
  - `bool duckdb_install_variables_from_admin(SQLite3DB& admindb, DuckDBConfigStore& store, std::string& err)`
  - `bool duckdb_save_variables_to_admin(SQLite3DB& admindb, const DuckDBConfigStore& store, std::string& err)`
  - `void duckdb_refresh_runtime_variables(SQLite3DB* db, void* opaque)`
  - `bool duckdb_sync_variables_disk_to_memory(SQLite3DB& admindb, std::string& err)`
  - `extern const char kDuckDBVariablesTableDef[];` and `extern const char kRuntimeDuckDBVariablesTableDef[];`

- [ ] **Step 1: Write the failing test**

Create `test/tap/tests/unit/duckdb_admin_schema_unit-t.cpp`:

```cpp
#include "duckdb_admin_schema.h"
#include "duckdb_config.h"
#include "sqlite3db.h"
#include "tap.h"

#include <memory>
#include <string>

int main() {
	plan(9);

	SQLite3DB db;
	db.open((char*)":memory:", 0);
	ok(db.execute(kDuckDBVariablesTableDef), "duckdb_variables DDL is valid SQLite");
	ok(db.execute(kRuntimeDuckDBVariablesTableDef),
	   "runtime_duckdb_variables DDL is valid SQLite");

	// --- admin table -> module ----------------------------------------
	db.execute("INSERT OR REPLACE INTO duckdb_variables VALUES ('threads','8')");
	db.execute("INSERT OR REPLACE INTO duckdb_variables VALUES ('database_path','/tmp/x.db')");

	DuckDBConfigStore store;
	std::string err;
	ok(duckdb_install_variables_from_admin(db, store, err), "install from admin succeeds");
	ok(store.threads() == 8, "threads was installed into the module");
	ok(store.database_path() == "/tmp/x.db", "database_path was installed into the module");

	// An unknown row must not abort the whole load, but must be reported.
	db.execute("INSERT OR REPLACE INTO duckdb_variables VALUES ('nonsense','1')");
	err.clear();
	ok(duckdb_install_variables_from_admin(db, store, err) && !err.empty(),
	   "an unknown variable is skipped and reported, not fatal");

	// --- module -> admin table ----------------------------------------
	DuckDBConfigStore other;
	err.clear();
	ok(duckdb_save_variables_to_admin(db, other, err), "save to admin succeeds");
	{
		char* serr = nullptr;
		std::unique_ptr<SQLite3_result> r(
			db.execute_statement("SELECT variable_value FROM duckdb_variables "
			                     "WHERE variable_name='threads'", &serr));
		ok(r && r->rows_count == 1 && std::string(r->rows[0]->fields[0]) == "2",
		   "save overwrote the admin row with the module default");
	}

	// --- runtime view projection --------------------------------------
	db.execute("INSERT INTO runtime_duckdb_variables VALUES ('stale','stale')");
	duckdb_refresh_runtime_variables(&db, &other);
	{
		char* serr = nullptr;
		std::unique_ptr<SQLite3_result> r(
			db.execute_statement("SELECT COUNT(*) FROM runtime_duckdb_variables "
			                     "WHERE variable_name='stale'", &serr));
		ok(r && r->rows_count == 1 && std::string(r->rows[0]->fields[0]) == "0",
		   "refresh wipes stale rows before re-projecting");
	}

	return exit_status();
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd test/tap/tests/unit && PROXYSQL40=1 make duckdb_admin_schema_unit-t`
Expected: FAIL — `duckdb_admin_schema.h` not found.

- [ ] **Step 3: Write the header**

Create `plugins/duckdb/include/duckdb_admin_schema.h`:

```cpp
#ifndef __DUCKDB_ADMIN_SCHEMA_H
#define __DUCKDB_ADMIN_SCHEMA_H

#include "ProxySQL_Plugin.h"

#include <string>

class SQLite3DB;
class DuckDBConfigStore;

extern const char kDuckDBVariablesTableDef[];
extern const char kRuntimeDuckDBVariablesTableDef[];

// Phase B entry point: registers tables, the runtime view, and the
// LOAD/SAVE commands. Must not touch DB handles — they are null here.
bool duckdb_register_admin_schema(ProxySQL_PluginServices& services);

// LOAD DUCKDB VARIABLES TO RUNTIME: read the editable admin table and
// install every recognised row into the module. Unknown or invalid rows
// are skipped and appended to `err`; the call still returns true so one
// bad row cannot block the whole load.
bool duckdb_install_variables_from_admin(SQLite3DB& admindb,
                                        DuckDBConfigStore& store,
                                        std::string& err);

// SAVE DUCKDB VARIABLES: dump the module into the editable admin table.
bool duckdb_save_variables_to_admin(SQLite3DB& admindb,
                                   const DuckDBConfigStore& store,
                                   std::string& err);

// register_runtime_view refresh callback. `opaque` is a DuckDBConfigStore*.
void duckdb_refresh_runtime_variables(SQLite3DB* db, void* opaque);

// Startup disk -> memory refresh of the editable table, matching what
// proxysql_admin does for mysql_users et al. Pure admin-tier persistence:
// no module involvement, no runtime view.
bool duckdb_sync_variables_disk_to_memory(SQLite3DB& admindb, std::string& err);

#endif // __DUCKDB_ADMIN_SCHEMA_H
```

- [ ] **Step 4: Write the implementation**

Create `plugins/duckdb/src/duckdb_admin_schema.cpp`. The table definitions:

```cpp
const char kDuckDBVariablesTableDef[] =
	"CREATE TABLE duckdb_variables ("
	" variable_name VARCHAR NOT NULL PRIMARY KEY,"
	" variable_value VARCHAR NOT NULL DEFAULT ''"
	" )";

const char kRuntimeDuckDBVariablesTableDef[] =
	"CREATE TABLE runtime_duckdb_variables ("
	" variable_name VARCHAR NOT NULL PRIMARY KEY,"
	" variable_value VARCHAR NOT NULL DEFAULT ''"
	" )";
```

`duckdb_register_admin_schema` registers both tables against `admin_db` via `services.register_table`, registers the runtime view, and registers the two commands plus their aliases:

```cpp
bool duckdb_register_admin_schema(ProxySQL_PluginServices& services) {
	if (services.register_table == nullptr) return false;

	const ProxySQL_PluginTableDef tables[] = {
		{ ProxySQL_PluginDBKind::admin_db,  "duckdb_variables",         kDuckDBVariablesTableDef },
		{ ProxySQL_PluginDBKind::config_db, "duckdb_variables",         kDuckDBVariablesTableDef },
		{ ProxySQL_PluginDBKind::admin_db,  "runtime_duckdb_variables", kRuntimeDuckDBVariablesTableDef },
	};
	for (const auto& t : tables) services.register_table(t);

	if (services.register_runtime_view != nullptr) {
		ProxySQL_PluginRuntimeView view {};
		view.table_name = "runtime_duckdb_variables";
		view.refresh    = &duckdb_refresh_runtime_variables;
		view.opaque     = duckdb_context().config_store.get();
		view.db_kind    = ProxySQL_PluginDBKind::admin_db;
		services.register_runtime_view(view);
	}

	if (services.register_command != nullptr) {
		services.register_command("LOAD DUCKDB VARIABLES TO RUNTIME", &cmd_load_variables);
		services.register_command("SAVE DUCKDB VARIABLES TO DISK",    &cmd_save_variables_to_disk);
		services.register_command("SAVE DUCKDB VARIABLES TO MEMORY",  &cmd_save_variables_to_memory);
		if (services.register_command_alias != nullptr) {
			services.register_command_alias("LOAD DUCKDB VARIABLES TO RUNTIME",
			                                "LOAD DUCKDB VARIABLES FROM MEMORY");
			services.register_command_alias("SAVE DUCKDB VARIABLES TO MEMORY",
			                                "SAVE DUCKDB VARIABLES FROM RUNTIME TO MEMORY");
		}
	}
	return true;
}
```

**Note on `view.opaque`:** `register_schemas` runs before `init()`, so `config_store` is still null at registration time. Move the `config_store` construction from `init()` into `duckdb_context()`'s first use — i.e. construct it in the `DuckDBPluginContext` accessor's `static` initialiser — so the pointer is stable and non-null in both phases. Update Task 2's `duckdb_init` accordingly: it sets `ctx.services` only.

`duckdb_install_variables_from_admin` runs
`SELECT variable_name, variable_value FROM duckdb_variables` via
`admindb.execute_statement()`, calls `store.set(name, value, one_err)` for each row, and on a failed `set` appends `one_err` to `err` and continues.

`duckdb_save_variables_to_admin` wraps `BEGIN` / `DELETE FROM duckdb_variables` / one `INSERT` per `store.variable_names()` / `COMMIT` in a transaction, checking every `execute()` return and issuing `ROLLBACK` on any failure — the pattern from `plugins/mysqlx/src/mysqlx_plugin.cpp:replace_table_atomically`. Single-quote-escape each value by doubling `'`.

`duckdb_refresh_runtime_variables` does the same transactional wipe-and-refill against `runtime_duckdb_variables`, reading from the `DuckDBConfigStore*` in `opaque`, and returns early if `db` or `opaque` is null.

`duckdb_sync_variables_disk_to_memory` copies `disk.duckdb_variables` into `main.duckdb_variables` with a single `BEGIN` / `DELETE FROM main.duckdb_variables` / `INSERT INTO main.duckdb_variables SELECT * FROM disk.duckdb_variables` / `COMMIT`, checking every `execute()` return and rolling back on any failure. The DELETE runs unconditionally so an empty source still clears the destination (see PR #5643).

The three command callbacks have signature
`ProxySQL_PluginCommandResult (*)(const ProxySQL_PluginCommandContext&, const char*)`.
`cmd_load_variables` calls `duckdb_install_variables_from_admin(*ctx.admindb, *duckdb_context().config_store, err)`; `cmd_save_variables_to_memory` calls `duckdb_save_variables_to_admin`; `cmd_save_variables_to_disk` copies `main.duckdb_variables` into `disk.duckdb_variables` with the same transactional DELETE+INSERT. Each returns `{0, rows, ""}` on success and `{1, 0, err}` on failure.

- [ ] **Step 5: Wire Phase B into the descriptor**

In `plugins/duckdb/src/duckdb_plugin.cpp`, include `duckdb_admin_schema.h` and `duckdb_config.h`, replace the stub body:

```cpp
bool duckdb_register_schemas(ProxySQL_PluginServices* services) {
	if (services == nullptr) return false;
	return duckdb_register_admin_schema(*services);
}
```

and change `duckdb_context()` so the config store exists before Phase B:

```cpp
DuckDBPluginContext& duckdb_context() {
	static DuckDBPluginContext ctx = [] {
		DuckDBPluginContext c {};
		c.config_store = std::make_unique<DuckDBConfigStore>();
		return c;
	}();
	return ctx;
}
```

- [ ] **Step 6: Add the build rules**

Append `$(PLUGIN_DIR)/src/duckdb_admin_schema.cpp` to `SRCS`. Add `duckdb_admin_schema_unit-t` to the unit `Makefile` list with a rule compiling `duckdb_admin_schema.cpp` + `duckdb_config.cpp` + `duckdb_plugin.cpp` (for `duckdb_context()`), and register it in `groups.json` as `[ "unit-tests-g1","@proxysql_min_version:4.0" ]`.

- [ ] **Step 7: Run both tests to verify they pass**

Run:
```bash
cd test/tap/tests/unit && PROXYSQL40=1 make duckdb_admin_schema_unit-t test_duckdb_plugin_load-t && \
  ./duckdb_admin_schema_unit-t && ./test_duckdb_plugin_load-t
```
Expected: `1..9` all `ok`, then `1..5` all `ok`. The plugin-load test must still pass — Phase B now does real work and a bad table def would surface there.

- [ ] **Step 8: Commit**

```bash
git add plugins/duckdb test/tap/tests/unit/duckdb_admin_schema_unit-t.cpp \
        test/tap/tests/unit/Makefile test/tap/groups/groups.json
git commit -m "feat(duckdb): register duckdb_variables and LOAD/SAVE commands

Follows the chassis separation of duties: LOAD reads the editable table
and installs into the module, SAVE dumps the module back, and
runtime_duckdb_variables is projected on demand by a refresh callback."
```

---

### Task 7: Session handler — SQL extraction, intercepts, execution

**Files:**
- Create: `plugins/duckdb/include/duckdb_session.h`, `plugins/duckdb/src/duckdb_session.cpp`
- Create: `test/tap/tests/unit/duckdb_session_unit-t.cpp`
- Modify: `plugins/duckdb/Makefile`, `test/tap/tests/unit/Makefile`, `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: `DuckDBEngine` (Task 4), `duckdb_result_to_sqlite3` (Task 5), `duckdb_context()` (Task 2).
- Produces:
  - `enum class DuckDBIntercept { none, version, database, show_tables, show_databases, ok_noop };`
  - `DuckDBIntercept duckdb_classify_query(const char* sql, size_t len);`
  - `SQLite3_result* duckdb_build_intercept_result(DuckDBIntercept kind);`
  - `struct DuckDBSessionState { duckdb_connection conn; }` and `DuckDBSessionState& duckdb_session_state();`
  - `template <typename S> void duckdb_session_handler(S* sess, void* pa, PtrSize_t* pkt);` explicitly instantiated for `MySQL_Session` and `PgSQL_Session`.
  - `void duckdb_send_mysql_error(MySQL_Session* sess, uint16_t code, const char* sqlstate, const char* msg);`
  - `void duckdb_send_pgsql_error(PgSQL_Session* sess, const char* sqlstate, const char* msg);`

- [ ] **Step 1: Write the failing test**

Create `test/tap/tests/unit/duckdb_session_unit-t.cpp`. It covers the two pure functions; the socket-bound handler is covered end-to-end in Tasks 8 and 9.

```cpp
#include "duckdb_session.h"
#include "sqlite3db.h"
#include "tap.h"

#include <cstring>
#include <memory>
#include <string>

namespace {
DuckDBIntercept classify(const char* s) {
	return duckdb_classify_query(s, std::strlen(s));
}
} // namespace

int main() {
	plan(12);

	ok(classify("SELECT @@version") == DuckDBIntercept::version,
	   "SELECT @@version is intercepted");
	ok(classify("select @@VERSION") == DuckDBIntercept::version,
	   "intercept matching is case-insensitive");
	ok(classify("  SELECT   @@version  ") == DuckDBIntercept::version,
	   "leading, trailing and inner whitespace are tolerated");
	ok(classify("SELECT version()") == DuckDBIntercept::version,
	   "SELECT version() is intercepted");
	ok(classify("SELECT DATABASE()") == DuckDBIntercept::database,
	   "SELECT DATABASE() is intercepted");
	ok(classify("SHOW TABLES") == DuckDBIntercept::show_tables,
	   "SHOW TABLES is intercepted");
	ok(classify("SHOW DATABASES") == DuckDBIntercept::show_databases,
	   "SHOW DATABASES is intercepted");
	ok(classify("SET autocommit=1") == DuckDBIntercept::ok_noop,
	   "SET is accepted as a no-op");
	ok(classify("SELECT * FROM t") == DuckDBIntercept::none,
	   "an ordinary query is not intercepted");
	ok(classify("") == DuckDBIntercept::none,
	   "an empty query is not intercepted");

	// A prefix must not match: "SELECT @@version_comment" is a real query.
	ok(classify("SELECT @@version_comment") == DuckDBIntercept::none,
	   "a longer variable name is not mistaken for @@version");

	{
		std::unique_ptr<SQLite3_result> r(
			duckdb_build_intercept_result(DuckDBIntercept::version));
		ok(r && r->columns == 1 && r->rows_count == 1 &&
		   r->rows[0]->fields[0] != nullptr,
		   "the version intercept builds a one-cell resultset");
	}

	return exit_status();
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd test/tap/tests/unit && PROXYSQL40=1 make duckdb_session_unit-t`
Expected: FAIL — `duckdb_session.h` not found.

- [ ] **Step 3: Write the header**

Create `plugins/duckdb/include/duckdb_session.h`:

```cpp
#ifndef __DUCKDB_SESSION_H
#define __DUCKDB_SESSION_H

#include "duckdb.h"

#include <cstddef>
#include <cstdint>

class SQLite3_result;
class MySQL_Session;
class PgSQL_Session;
struct PtrSize_t;

enum class DuckDBIntercept {
	none,             // hand to DuckDB
	version,
	database,
	show_tables,
	show_databases,
	ok_noop           // answer with a bare OK
};

// Recognises the handful of statements drivers send that DuckDB either
// does not understand or answers differently from what a MySQL/PG client
// expects. Matching ignores case and collapses whitespace, and requires a
// full match so "SELECT @@version_comment" is not taken for "@@version".
DuckDBIntercept duckdb_classify_query(const char* sql, size_t len);

// Builds the canned resultset for an intercept. Returns nullptr for
// `none` and `ok_noop` (the caller sends an OK instead). Caller deletes.
SQLite3_result* duckdb_build_intercept_result(DuckDBIntercept kind);

// One DuckDB connection per connection thread. The listener creates the
// connection after accept and destroys it before the thread exits, so
// thread_local storage is exactly session-scoped here.
struct DuckDBSessionState {
	duckdb_connection conn { nullptr };
};
DuckDBSessionState& duckdb_session_state();

void duckdb_send_mysql_error(MySQL_Session* sess, uint16_t code,
                             const char* sqlstate, const char* msg);
void duckdb_send_pgsql_error(PgSQL_Session* sess, const char* sqlstate,
                             const char* msg);

// Registered as sess->handler_function. `pa` is core's hardcoded global
// (GloSQLite3Server) and is deliberately ignored: the plugin reaches its
// own state through duckdb_context() / duckdb_session_state().
template <typename S>
void duckdb_session_handler(S* sess, void* pa, PtrSize_t* pkt);

#endif // __DUCKDB_SESSION_H
```

- [ ] **Step 4: Write the classifier and intercept builder**

Create `plugins/duckdb/src/duckdb_session.cpp`. Normalise first, then compare against a table:

```cpp
#include "duckdb_session.h"
#include "duckdb_plugin.h"
#include "duckdb_engine.h"
#include "duckdb_result.h"
#include "sqlite3db.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>

namespace {

// Uppercases, trims, and collapses internal runs of whitespace to one
// space, so "  select   @@VERSION " becomes "SELECT @@VERSION".
std::string normalize(const char* sql, size_t len) {
	std::string out;
	out.reserve(len);
	bool in_space = true;   // true so leading whitespace is dropped
	for (size_t i = 0; i < len && sql[i] != '\0'; i++) {
		const unsigned char c = static_cast<unsigned char>(sql[i]);
		if (std::isspace(c)) {
			if (!in_space) { out.push_back(' '); in_space = true; }
		} else {
			out.push_back(static_cast<char>(std::toupper(c)));
			in_space = false;
		}
	}
	while (!out.empty() && out.back() == ' ') out.pop_back();
	return out;
}

} // namespace

DuckDBIntercept duckdb_classify_query(const char* sql, size_t len) {
	if (sql == nullptr || len == 0) return DuckDBIntercept::none;
	const std::string q = normalize(sql, len);
	if (q.empty()) return DuckDBIntercept::none;

	if (q == "SELECT @@VERSION" || q == "SELECT VERSION()")
		return DuckDBIntercept::version;
	if (q == "SELECT DATABASE()" || q == "SELECT CURRENT_DATABASE()")
		return DuckDBIntercept::database;
	if (q == "SHOW TABLES")     return DuckDBIntercept::show_tables;
	if (q == "SHOW DATABASES" || q == "SHOW SCHEMAS")
		return DuckDBIntercept::show_databases;
	// Session-state statements clients send unprompted. DuckDB has no
	// equivalent; accepting them silently is what SQLite3_Server does.
	if (q.rfind("SET ", 0) == 0)  return DuckDBIntercept::ok_noop;
	return DuckDBIntercept::none;
}

SQLite3_result* duckdb_build_intercept_result(DuckDBIntercept kind) {
	switch (kind) {
	case DuckDBIntercept::version: {
		SQLite3_result* r = new SQLite3_result(1);
		r->add_column_definition(SQLITE_TEXT, "version");
		const char* v = duckdb_library_version();
		const char* row[1] = { v != nullptr ? v : "duckdb" };
		r->add_row(row);
		return r;
	}
	case DuckDBIntercept::database: {
		SQLite3_result* r = new SQLite3_result(1);
		r->add_column_definition(SQLITE_TEXT, "DATABASE()");
		const char* row[1] = { "memory" };
		r->add_row(row);
		return r;
	}
	case DuckDBIntercept::show_tables:
	case DuckDBIntercept::show_databases:
		// Answered by rewriting to DuckDB SQL in the handler, not here.
		return nullptr;
	case DuckDBIntercept::none:
	case DuckDBIntercept::ok_noop:
	default:
		return nullptr;
	}
}

DuckDBSessionState& duckdb_session_state() {
	static thread_local DuckDBSessionState state {};
	return state;
}
```

`show_tables` and `show_databases` are handled in the handler by substituting DuckDB SQL — `SHOW TABLES` becomes `SELECT table_name FROM information_schema.tables WHERE table_schema='main'`, `SHOW DATABASES` becomes `SELECT DISTINCT table_schema AS Database FROM information_schema.tables` — so they return live data rather than a canned row.

- [ ] **Step 5: Write the handler template**

Still in `duckdb_session.cpp`, add the includes `MySQL_Session.h`, `PgSQL_Session.h`, `MySQL_Protocol.h`, `PgSQL_Protocol.h`, `proxysql.h`, then:

```cpp
template <typename S>
void duckdb_session_handler(S* sess, void* pa, PtrSize_t* pkt) {
	(void)pa;   // core passes GloSQLite3Server; the plugin ignores it.

	std::string sql;
	if constexpr (std::is_same_v<S, MySQL_Session>) {
		// Skip the 4-byte header and the 1-byte command.
		if (pkt->size <= sizeof(mysql_hdr) + 1) {
			duckdb_send_mysql_error(sess, 1064, "42000", "Malformed packet");
			return;
		}
		const size_t len = pkt->size - sizeof(mysql_hdr) - 1;
		sql.assign((const char*)pkt->ptr + sizeof(mysql_hdr) + 1, len);
	} else {
		pgsql_hdr hdr {};
		if (sess->client_myds->myprot.get_header((unsigned char*)pkt->ptr, pkt->size, &hdr) == false) {
			duckdb_send_pgsql_error(sess, "08P01", "Malformed packet");
			return;
		}
		switch (hdr.type) {
		case PG_PKT_STARTUP_V2:
		case PG_PKT_STARTUP:
		case PG_PKT_CANCEL:
		case PG_PKT_SSLREQ:
		case PG_PKT_GSSENCREQ:
			duckdb_send_pgsql_error(sess, "0A000", "Unsupported query type");
			return;
		default:
			break;
		}
		if (hdr.data.size < 2 || hdr.data.ptr == nullptr ||
		    ((const char*)hdr.data.ptr)[hdr.data.size - 1] != '\0') {
			duckdb_send_pgsql_error(sess, "08P01", "Malformed query packet");
			return;
		}
		sql.assign((const char*)hdr.data.ptr, hdr.data.size - 1);
	}

	const DuckDBIntercept kind = duckdb_classify_query(sql.c_str(), sql.size());
	std::string effective = sql;
	switch (kind) {
	case DuckDBIntercept::show_tables:
		effective = "SELECT table_name FROM information_schema.tables "
		            "WHERE table_schema='main'";
		break;
	case DuckDBIntercept::show_databases:
		effective = "SELECT DISTINCT table_schema AS \"Database\" "
		            "FROM information_schema.tables";
		break;
	case DuckDBIntercept::version:
	case DuckDBIntercept::database: {
		SQLite3_result* r = duckdb_build_intercept_result(kind);
		duckdb_send_result(sess, r, nullptr, 0, sql.c_str());
		delete r;
		return;
	}
	case DuckDBIntercept::ok_noop:
		duckdb_send_result(sess, nullptr, nullptr, 0, sql.c_str());
		return;
	case DuckDBIntercept::none:
	default:
		break;
	}

	DuckDBSessionState& st = duckdb_session_state();
	if (st.conn == nullptr) {
		if constexpr (std::is_same_v<S, MySQL_Session>)
			duckdb_send_mysql_error(sess, 1105, "HY000", "No DuckDB connection for this session");
		else
			duckdb_send_pgsql_error(sess, "08003", "No DuckDB connection for this session");
		return;
	}

	duckdb_result res;
	if (duckdb_query(st.conn, effective.c_str(), &res) != DuckDBSuccess) {
		const char* msg = duckdb_result_error(&res);
		std::string copy = msg != nullptr ? msg : "DuckDB query failed";
		duckdb_destroy_result(&res);
		if constexpr (std::is_same_v<S, MySQL_Session>)
			duckdb_send_mysql_error(sess, 1064, "42000", copy.c_str());
		else
			duckdb_send_pgsql_error(sess, "42601", copy.c_str());
		return;
	}

	SQLite3_result* out = duckdb_result_to_sqlite3(&res);
	const int affected = static_cast<int>(duckdb_rows_changed(&res));
	duckdb_destroy_result(&res);
	duckdb_send_result(sess, out, nullptr, affected, sql.c_str());
	delete out;
}

template void duckdb_session_handler<MySQL_Session>(MySQL_Session*, void*, PtrSize_t*);
template void duckdb_session_handler<PgSQL_Session>(PgSQL_Session*, void*, PtrSize_t*);
```

`duckdb_send_result` is a private overload pair. **Declare both overloads above `duckdb_session_handler`** — the template calls them, and with no dependent-name lookup to save you they must be visible at that point:

```cpp
void duckdb_send_result(MySQL_Session* sess, SQLite3_result* r, char* err,
                        int affected, const char* /*sql*/) {
	sess->SQLite3_to_MySQL(r, err, affected, &sess->client_myds->myprot);
}

void duckdb_send_result(PgSQL_Session* sess, SQLite3_result* r, char* err,
                        int affected, const char* sql) {
	// `sql` matters: SQLite3_to_Postgres derives the CommandComplete tag
	// from its first whitespace-delimited word.
	SQLite3_to_Postgres(&sess->client_myds->PSarrayOUT, r, err, affected, sql);
}
```

The error emitters:

```cpp
void duckdb_send_mysql_error(MySQL_Session* sess, uint16_t code,
                             const char* sqlstate, const char* msg) {
	MySQL_Protocol* myprot = &sess->client_myds->myprot;
	MySQL_Data_Stream* myds = myprot->get_myds();
	myds->DSS = STATE_QUERY_SENT_DS;
	myprot->generate_pkt_ERR(true, NULL, NULL, 1, code, sqlstate, msg);
	myds->DSS = STATE_SLEEP;
}

// Deliberately does NOT reuse SQLite3_to_Postgres's error branch: that
// path hardcodes SQLSTATE 28000 (invalid authorization), which is wrong
// for a syntax error. Keeping our own emitter avoids a core change.
void duckdb_send_pgsql_error(PgSQL_Session* sess, const char* sqlstate,
                             const char* msg) {
	PG_pkt pkt(64);
	pkt.write_generic('E', "cscscsc",
		'S', "ERROR",
		'C', sqlstate,
		'M', msg, 0);
	pkt.to_PtrSizeArray(&sess->client_myds->PSarrayOUT);
	pkt.write_ReadyForQuery('I');
	pkt.to_PtrSizeArray(&sess->client_myds->PSarrayOUT);
}
```

- [ ] **Step 6: Add the build rules**

Append `$(PLUGIN_DIR)/src/duckdb_session.cpp` to `SRCS`. Add `duckdb_session_unit-t` to the unit `Makefile` list — the rule compiles only `duckdb_session.cpp` plus `duckdb_result.cpp`, needs `-I$(DUCKDB_IDIR)` and `$(DUCKDB_AR)`, and links `$(WHOLE_LIBPROXYSQL)` for `SQLite3_result` and the session classes. Register in `groups.json` as `[ "unit-tests-g1","@proxysql_min_version:4.0" ]`.

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd test/tap/tests/unit && PROXYSQL40=1 make duckdb_session_unit-t && ./duckdb_session_unit-t`
Expected: `1..12`, all `ok`.

- [ ] **Step 8: Commit**

```bash
git add plugins/duckdb test/tap/tests/unit/duckdb_session_unit-t.cpp \
        test/tap/tests/unit/Makefile test/tap/groups/groups.json
git commit -m "feat(duckdb): add templated session handler and intercepts

One handler serves both protocols, branching with if constexpr for packet
extraction exactly as admin_session_handler does. The PG error path uses
its own emitter so errors carry 42601 rather than SQLite3_to_Postgres's
hardcoded 28000."
```

---

### Task 8: Listener, connection threads, and lifecycle wiring

**Files:**
- Create: `plugins/duckdb/include/duckdb_listener.h`, `plugins/duckdb/src/duckdb_listener.cpp`
- Create: `test/tap/tests/unit/duckdb_listener_unit-t.cpp`
- Modify: `plugins/duckdb/src/duckdb_plugin.cpp`, `plugins/duckdb/Makefile`, `test/tap/tests/unit/Makefile`, `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: `DuckDBConfigStore` (Task 3), `DuckDBEngine` (Task 4), `duckdb_session_handler<S>` and `duckdb_session_state()` (Task 7).
- Produces: `class DuckDBListener` with `bool start(DuckDBConfigStore& cfg, DuckDBEngine& engine, std::string& err)`, `void stop()`, `bool is_running() const`, `size_t listener_count() const`, `size_t connection_thread_count() const`.

- [ ] **Step 1: Write the failing test**

Create `test/tap/tests/unit/duckdb_listener_unit-t.cpp`. It proves the sockets really bind and really go away — the property that makes unload safe.

```cpp
#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "duckdb_listener.h"
#include "tap.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>

namespace {

// Returns true if a TCP connect to 127.0.0.1:port succeeds.
bool can_connect(uint16_t port) {
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return false;
	struct sockaddr_in sa {};
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
	const bool ok = (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) == 0);
	close(fd);
	return ok;
}

} // namespace

int main() {
	plan(8);

	// High ports chosen to avoid the documented defaults so a developer
	// running a real proxysql locally does not collide with this test.
	const uint16_t my_port = 26031;
	const uint16_t pg_port = 26032;

	DuckDBConfigStore cfg;
	std::string err;
	cfg.set("mysql_ifaces", "127.0.0.1:" + std::to_string(my_port), err);
	cfg.set("pgsql_ifaces", "127.0.0.1:" + std::to_string(pg_port), err);

	DuckDBEngine engine;
	ok(engine.open(cfg, err), "engine opens");

	DuckDBListener listener;
	ok(listener.is_running() == false, "listener starts stopped");

	err.clear();
	ok(listener.start(cfg, engine, err), "listener starts");
	if (!listener.is_running()) {
		diag("start error: %s", err.c_str());
		BAIL_OUT("listener must start before socket assertions");
	}
	ok(listener.listener_count() == 2, "one MySQL and one PgSQL listener are bound");
	ok(can_connect(my_port), "the MySQL port accepts a TCP connection");
	ok(can_connect(pg_port), "the PgSQL port accepts a TCP connection");

	listener.stop();
	ok(listener.is_running() == false, "listener reports stopped");
	ok(can_connect(my_port) == false, "the MySQL port is closed after stop");

	engine.close();
	return exit_status();
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd test/tap/tests/unit && PROXYSQL40=1 make duckdb_listener_unit-t`
Expected: FAIL — `duckdb_listener.h` not found.

- [ ] **Step 3: Write the header**

Create `plugins/duckdb/include/duckdb_listener.h`:

```cpp
#ifndef __DUCKDB_LISTENER_H
#define __DUCKDB_LISTENER_H

#include <atomic>
#include <cstddef>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class DuckDBConfigStore;
class DuckDBEngine;

// Binds the configured MySQL and PostgreSQL ports and runs one accept
// loop over all of them. Each accepted socket gets its own thread that
// builds a core session and runs it to completion.
//
// stop() joins every connection thread before returning, so the caller
// can safely close the DuckDBEngine afterwards. This is the property
// that makes plugin unload safe, and it is why the threads are tracked
// rather than detached the way SQLite3_Server's are.
class DuckDBListener {
public:
	DuckDBListener() = default;
	~DuckDBListener();

	DuckDBListener(const DuckDBListener&) = delete;
	DuckDBListener& operator=(const DuckDBListener&) = delete;

	bool start(DuckDBConfigStore& cfg, DuckDBEngine& engine, std::string& err);
	void stop();

	bool is_running() const { return running_.load(); }
	size_t listener_count() const;
	size_t connection_thread_count() const;

private:
	enum class Proto { mysql, pgsql };
	struct Listener { int fd; Proto proto; };

	void accept_loop();
	void handle_connection(int client_fd, Proto proto);
	template <typename Thr, typename Sess> void run_session(int client_fd);

	std::atomic<bool> running_ { false };
	std::atomic<bool> shutdown_ { false };
	int signal_pipe_[2] { -1, -1 };

	DuckDBEngine* engine_ { nullptr };

	mutable std::mutex mutex_;
	std::vector<Listener> listeners_;
	std::vector<std::thread> conn_threads_;
	std::thread accept_thread_;
};

#endif // __DUCKDB_LISTENER_H
```

- [ ] **Step 4: Write the implementation**

Create `plugins/duckdb/src/duckdb_listener.cpp`.

`start()` creates the self-pipe with `pipe()`, sets both ends non-blocking, then for each `cfg.mysql_ifaces()` and `cfg.pgsql_ifaces()` calls
`listen_on_port(const_cast<char*>(iface.addr.c_str()), iface.port, 128, true)`
(declared in `include/proxysql.h:108`). A negative return is fatal: close everything already bound, set `err`, return false. On success it stores `engine_`, sets `running_`, and spawns `accept_thread_`.

`accept_loop()` polls every listener fd plus `signal_pipe_[0]`. On a readable listener it `accept()`s and, before creating any session, calls `engine_->try_reserve_connection()`; if that fails it closes the socket immediately (the client sees a dropped connection rather than a half-built session). Otherwise it appends a `std::thread(&DuckDBListener::handle_connection, this, client_fd, proto)` to `conn_threads_` under `mutex_`. On a readable signal pipe it returns.

`handle_connection()` dispatches to `run_session<MySQL_Thread, MySQL_Session*>` or `run_session<PgSQL_Thread, PgSQL_Session*>`, then calls `engine_->release_connection()` on the way out.

`run_session()` is the core of the task, modelled on `src/SQLite3_Server.cpp:1252` (`child_mysql`):

```cpp
template <typename Thr, typename Sess>
void DuckDBListener::run_session(int client_fd) {
	// Plugins start() before phase 3 brings GloMTH/GloPTH up, so wait.
	if (!wait_for_glo_mth()) { close(client_fd); return; }
	if (GloMTH == nullptr)   { close(client_fd); return; }

	DuckDBSessionState& st = duckdb_session_state();
	std::string cerr;
	if (!engine_->connect(&st.conn, cerr)) { close(client_fd); return; }

	Thr* thr = new Thr();
	thr->curtime = monotonic_time();
	// Left null on purpose: core casts gen_args to SQLite3_Session* for
	// PROXYSQL_SESSION_SQLITE and null-checks first. Anything else here
	// would be type confusion.
	thr->gen_args = nullptr;
	thr->refresh_variables();

	auto* sess = thr->template create_new_session_and_client_data_stream<Thr, Sess>(client_fd);
	sess->thread = thr;
	sess->session_type = PROXYSQL_SESSION_SQLITE;
	sess->handler_function = duckdb_session_handler<typename std::remove_pointer<Sess>::type>;

	auto* myds = sess->client_myds;
	struct pollfd fds[1];
	fds[0].fd = client_fd;

	// ... protocol-specific handshake: for MySQL,
	//     myds->myprot.generate_pkt_initial_handshake(true, NULL, NULL,
	//         &sess->thread_session_id, true)
	// PgSQL performs its startup exchange inside sess->handler().

	while (shutdown_.load() == false &&
	       __sync_fetch_and_add(&glovars.shutdown, 0) == 0) {
		fds[0].events = myds->available_data_out() ? (POLLIN | POLLOUT) : POLLIN;
		fds[0].revents = 0;
		const int rc = poll(fds, 1, 100);
		if (rc == -1) { if (errno == EINTR) continue; break; }
		myds->revents = fds[0].revents;
		int rb = myds->read_from_net();
		if (myds->net_failure) break;
		myds->read_pkts();
		if (myds->encrypted) {
			while (rb > 0) {
				rb = myds->read_from_net();
				if (myds->net_failure) break;
				myds->read_pkts();
			}
			if (myds->net_failure) break;
		}
		sess->to_process = 1;
		if (sess->handler() == -1) break;
	}

	engine_->disconnect(&st.conn);
	thr->gen_args = nullptr;
	delete thr;
}
```

The 100 ms poll timeout, rather than a blocking poll, is what lets `shutdown_` be observed promptly by a thread with an idle client.

`stop()` sets `shutdown_`, writes one byte to `signal_pipe_[1]`, joins `accept_thread_`, closes every listener fd and clears `listeners_`, then moves `conn_threads_` out under the lock and joins each one **outside** the lock (a connection thread finishing concurrently would otherwise deadlock trying to take `mutex_`). Finally it closes the pipe fds, clears `running_`, and resets `shutdown_` so a later `start()` works. The destructor calls `stop()`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd test/tap/tests/unit && PROXYSQL40=1 make duckdb_listener_unit-t && ./duckdb_listener_unit-t`
Expected: `1..8`, all `ok`.

- [ ] **Step 6: Wire the listener into the plugin lifecycle**

In `plugins/duckdb/src/duckdb_plugin.cpp`, replace the `duckdb_start` and `duckdb_stop` stubs:

```cpp
bool duckdb_start() {
	DuckDBPluginContext& ctx = duckdb_context();

	if (ctx.services != nullptr && ctx.services->get_admindb != nullptr) {
		if (SQLite3DB* admindb = ctx.services->get_admindb()) {
			// disk -> memory, then memory -> module, the canonical order.
			std::string err;
			if (!duckdb_sync_variables_disk_to_memory(*admindb, err)) log_warn(err);
			err.clear();
			if (!duckdb_install_variables_from_admin(*admindb, *ctx.config_store, err) || !err.empty())
				log_warn(err);
		}
	}

	std::string err;
	ctx.engine = std::make_unique<DuckDBEngine>();
	if (!ctx.engine->open(*ctx.config_store, err)) {
		log_error("duckdb: engine open failed: " + err);
		ctx.engine.reset();
		return false;
	}

	ctx.listener = std::make_unique<DuckDBListener>();
	if (!ctx.listener->start(*ctx.config_store, *ctx.engine, err)) {
		log_error("duckdb: listener start failed: " + err);
		ctx.listener.reset();
		ctx.engine->close();
		ctx.engine.reset();
		return false;
	}

	ctx.started = true;
	return true;
}

// Order matters: the listener joins every connection thread, so no thread
// can still hold a duckdb_connection by the time the engine closes.
bool duckdb_stop() {
	DuckDBPluginContext& ctx = duckdb_context();
	if (ctx.listener) { ctx.listener->stop(); ctx.listener.reset(); }
	if (ctx.engine)   { ctx.engine->close(); ctx.engine.reset(); }
	ctx.started = false;
	return true;
}
```

`log_warn` / `log_error` are file-local helpers calling
`ctx.services->log_message(2 /*warn*/ or 3 /*error*/, msg.c_str())` when `services` and `log_message` are non-null.

Also extend `duckdb_status_json()` to report the database path and `engine->open_connections()`, writing into a `static std::string` so the returned pointer has static storage duration as the ABI requires.

- [ ] **Step 7: Add build rules and re-run the plugin-load test**

Append `$(PLUGIN_DIR)/src/duckdb_listener.cpp` to `SRCS`, add `duckdb_listener_unit-t` to the unit `Makefile` list and to `groups.json`.

Run:
```bash
PROXYSQL40=1 make -j$(nproc) && cd test/tap/tests/unit && \
  PROXYSQL40=1 make test_duckdb_plugin_load-t && ./test_duckdb_plugin_load-t
```
Expected: `1..5`, all `ok`. `stop_all` now tears down a real listener and engine; a hang here means `stop()` is not joining correctly.

- [ ] **Step 8: Commit**

```bash
git add plugins/duckdb test/tap/tests/unit/duckdb_listener_unit-t.cpp \
        test/tap/tests/unit/Makefile test/tap/groups/groups.json
git commit -m "feat(duckdb): add listener, connection threads and lifecycle

stop() joins every connection thread before the engine closes, unlike
SQLite3_Server's detached children, so the plugin can be unloaded without
a use-after-free on duckdb_connection."
```

---

### Task 9: End-to-end over the MySQL protocol

**Files:**
- Create: `test/tap/tests/test_duckdb_e2e_mysql-t.cpp`
- Create: `test/infra/infra-duckdb/` (group infra), including `setup-infras.bash`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: everything from Tasks 1-8.
- Produces: TAP group `duckdb-e2e-g1` running against a ProxySQL with the plugin loaded on `127.0.0.1:6031` (MySQL) and `127.0.0.1:6032` (PgSQL).

- [ ] **Step 1: Create the group infra**

Copy the smallest existing single-backend infra (`test/infra/infra-pgsql17-repl` or `test/infra/infra-mysql84`) to `test/infra/infra-duckdb/`, strip it to just the ProxySQL container, and add a `setup-infras.bash` that appends to the group's `proxysql.cnf`:

```
plugins=(
	"/usr/lib/proxysql/plugins/ProxySQL_DuckDB_Plugin.so"
)
```

Follow the mechanism documented at `test/infra/control/start-proxysql-isolated.bash:138` — a per-group cnf, not an edit to the generic one. The DuckDB plugin needs no backend database, so no dbdeployer or docker MySQL/PG service is required.

- [ ] **Step 2: Write the failing test**

Create `test/tap/tests/test_duckdb_e2e_mysql-t.cpp`:

```cpp
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include <cstring>
#include <string>

namespace {

const int DUCKDB_MYSQL_PORT = 6031;

MYSQL* connect_duckdb(CommandLine& cl, const char* user, const char* pass) {
	MYSQL* c = mysql_init(NULL);
	if (c == NULL) return NULL;
	if (!mysql_real_connect(c, cl.host, user, pass, NULL, DUCKDB_MYSQL_PORT, NULL, 0)) {
		mysql_close(c);
		return NULL;
	}
	return c;
}

// Runs `q` and returns the single cell of the single row, or "" on failure.
std::string one_cell(MYSQL* c, const char* q) {
	if (mysql_query(c, q) != 0) return "";
	MYSQL_RES* r = mysql_store_result(c);
	if (r == NULL) return "";
	std::string out;
	if (MYSQL_ROW row = mysql_fetch_row(r)) if (row[0]) out = row[0];
	mysql_free_result(r);
	return out;
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("Failed to get the required environment variables"); return -1; }

	plan(9);

	MYSQL* c = connect_duckdb(cl, cl.username, cl.password);
	ok(c != NULL, "connect to the DuckDB MySQL port with mysql_users credentials");
	if (c == NULL) BAIL_OUT("cannot continue without a connection");

	ok(one_cell(c, "SELECT 42 AS answer") == "42", "integer literal round-trips");
	ok(one_cell(c, "SELECT 'hello' AS s") == "hello", "string literal round-trips");
	ok(one_cell(c, "SELECT CAST(1.5 AS DOUBLE) AS d") == "1.5", "double round-trips");

	// NULL must arrive as a real NULL, not the string "NULL".
	{
		ok(mysql_query(c, "SELECT NULL AS n") == 0, "NULL select executes");
		MYSQL_RES* r = mysql_store_result(c);
		MYSQL_ROW row = r ? mysql_fetch_row(r) : NULL;
		ok(r != NULL && row != NULL && row[0] == NULL, "NULL arrives as a null field");
		if (r) mysql_free_result(r);
	}

	// DDL + DML must report affected rows.
	ok(mysql_query(c, "CREATE TABLE t_e2e(a INTEGER)") == 0, "CREATE TABLE succeeds");
	ok(mysql_query(c, "INSERT INTO t_e2e VALUES (1),(2),(3)") == 0 &&
	   mysql_affected_rows(c) == 3, "INSERT reports three affected rows");

	// A syntax error must come back as an error, not a silent empty set.
	ok(mysql_query(c, "SELECT FROM WHERE") != 0 && mysql_errno(c) != 0,
	   "a malformed query returns a protocol error");

	mysql_close(c);

	// Authentication must actually be enforced.
	MYSQL* bad = connect_duckdb(cl, cl.username, "definitely-not-the-password");
	ok(bad == NULL, "a wrong password is rejected");
	if (bad) mysql_close(bad);

	return exit_status();
}
```

Register it in `groups.json`:

```json
  "test_duckdb_e2e_mysql-t" : [ "duckdb-e2e-g1","@proxysql_min_version:4.0" ],
```

- [ ] **Step 3: Build everything and bring up the infra**

Run:
```bash
PROXYSQL40=1 make clean && PROXYSQL40=1 make debug -j$(nproc) && \
PROXYSQL40=1 make build_tap_test_debug -j$(nproc) && \
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=duckdb-e2e-g1 \
  test/infra/control/ensure-infras.bash
```

Do not create Docker networks or start containers by hand; `ensure-infras.bash` does all of it.

- [ ] **Step 4: Run the test and confirm it fails for the right reason**

Run:
```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=duckdb-e2e-g1 \
  TEST_PY_TAP_INCL="test_duckdb_e2e_mysql-t" \
  test/infra/control/run-tests-isolated.bash
```

Expected on the first run: a connection failure. Read the ProxySQL log the run produced and confirm the plugin actually loaded (`grep -i duckdb` in it). A "plugin load failed" line means the `.so` was not installed into the container image — fix the infra, not the test.

- [ ] **Step 5: Iterate until it passes**

After each plugin rebuild, recreate only the ProxySQL container:

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=duckdb-e2e-g1 \
  test/infra/control/start-proxysql-isolated.bash
```

`ensure-infras.bash` will not pick up a rebuilt binary if ProxySQL is already running, and `docker restart` is not the supported mechanism.

Expected final state: `1..9`, all `ok`.

- [ ] **Step 6: Commit**

```bash
git add test/tap/tests/test_duckdb_e2e_mysql-t.cpp test/infra/infra-duckdb \
        test/tap/groups/groups.json
git commit -m "test(duckdb): end-to-end MySQL protocol coverage

Covers connect + mysql_users auth, scalar round-trips, NULL as a real
null field, affected-rows on DML, error propagation, and rejection of a
wrong password."
```

---

### Task 10: End-to-end over the PostgreSQL protocol

**Files:**
- Create: `test/tap/tests/test_duckdb_e2e_pgsql-t.cpp`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: Tasks 1-9, plus the `duckdb-e2e-g1` infra from Task 9.
- Produces: nothing new for later tasks.

- [ ] **Step 1: Write the failing test**

Create `test/tap/tests/test_duckdb_e2e_pgsql-t.cpp`. Model the libpq usage on an existing `pgsql-*-t.cpp` test in `test/tap/tests/`.

```cpp
#include "libpq-fe.h"
#include "tap.h"
#include "command_line.h"

#include <cstring>
#include <string>

namespace {

const char* DUCKDB_PGSQL_PORT = "6032";

PGconn* connect_duckdb(CommandLine& cl, const char* user, const char* pass) {
	std::string conninfo = "host=" + std::string(cl.host) +
		" port=" + DUCKDB_PGSQL_PORT +
		" user=" + user + " password=" + pass +
		" dbname=main connect_timeout=10";
	PGconn* c = PQconnectdb(conninfo.c_str());
	if (PQstatus(c) != CONNECTION_OK) { PQfinish(c); return NULL; }
	return c;
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("Failed to get the required environment variables"); return -1; }

	plan(8);

	PGconn* c = connect_duckdb(cl, cl.pgsql_username, cl.pgsql_password);
	ok(c != NULL, "connect to the DuckDB PgSQL port with pgsql_users credentials");
	if (c == NULL) BAIL_OUT("cannot continue without a connection");

	{
		PGresult* r = PQexec(c, "SELECT 42 AS answer");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "42") == 0, "integer literal round-trips");
		ok(PQnfields(r) == 1 && std::strcmp(PQfname(r, 0), "answer") == 0,
		   "the column name is preserved");
		PQclear(r);
	}

	{
		PGresult* r = PQexec(c, "SELECT NULL AS n");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQgetisnull(r, 0, 0) == 1,
		   "NULL arrives as a real SQL NULL");
		PQclear(r);
	}

	{
		// CommandComplete tag: SQLite3_to_Postgres derives it from the
		// first word of the query, so "SELECT n" must come back.
		PGresult* r = PQexec(c, "SELECT 1 UNION ALL SELECT 2");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK &&
		   std::strncmp(PQcmdStatus(r), "SELECT", 6) == 0,
		   "the CommandComplete tag says SELECT");
		PQclear(r);
	}

	{
		PGresult* r = PQexec(c, "CREATE TABLE t_pg_e2e(a INTEGER)");
		ok(PQresultStatus(r) == PGRES_COMMAND_OK, "CREATE TABLE succeeds");
		PQclear(r);
	}

	{
		// The error must carry a syntax-error SQLSTATE, not core's
		// hardcoded 28000 (invalid authorization).
		PGresult* r = PQexec(c, "SELECT FROM WHERE");
		const char* state = PQresultErrorField(r, PG_DIAG_SQLSTATE);
		ok(PQresultStatus(r) == PGRES_FATAL_ERROR, "a malformed query returns an error");
		ok(state != NULL && std::strcmp(state, "28000") != 0,
		   "the error SQLSTATE is not the misleading 28000");
		PQclear(r);
	}

	PQfinish(c);
	return exit_status();
}
```

Register it: `"test_duckdb_e2e_pgsql-t" : [ "duckdb-e2e-g1","@proxysql_min_version:4.0" ],`

- [ ] **Step 2: Run it to confirm it fails**

Run:
```bash
PROXYSQL40=1 make build_tap_test_debug -j$(nproc) && \
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=duckdb-e2e-g1 \
  TEST_PY_TAP_INCL="test_duckdb_e2e_pgsql-t" \
  test/infra/control/run-tests-isolated.bash
```
Expected: failures. Read the ProxySQL log before changing anything.

- [ ] **Step 3: Fix the PG path until the test passes**

The likely gaps, in the order they will surface:

1. **Startup/auth.** `PgSQL_Protocol` handles `PROXYSQL_SESSION_SQLITE` at `lib/PgSQL_Protocol.cpp:946`; if the handshake never completes, check that `run_session` lets `sess->handler()` drive the startup exchange rather than sending a MySQL-style handshake.
2. **`default_schema`.** `lib/PgSQL_Session.cpp:3926` treats `PROXYSQL_SESSION_SQLITE` specially for `default_hostgroup`; if the session is rejected before the first query, that is where to look.
3. **CommandComplete.** If `PQcmdStatus` is empty, `duckdb_send_result` is passing the rewritten `effective` SQL instead of the original `sql`.

- [ ] **Step 4: Run both e2e tests together**

Run:
```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=duckdb-e2e-g1 \
  test/infra/control/run-tests-isolated.bash
```
Expected: both `test_duckdb_e2e_mysql-t` and `test_duckdb_e2e_pgsql-t` pass. Running them together also proves the two listeners coexist in one process.

- [ ] **Step 5: Commit**

```bash
git add test/tap/tests/test_duckdb_e2e_pgsql-t.cpp test/tap/groups/groups.json
git commit -m "test(duckdb): end-to-end PostgreSQL protocol coverage

Asserts CommandComplete tags and that query errors do not carry the
misleading 28000 SQLSTATE that SQLite3_to_Postgres hardcodes."
```

---

### Task 11: Admin end-to-end, documentation, and CI timing

**Files:**
- Create: `test/tap/tests/test_duckdb_admin_tables-t.cpp`, `plugins/duckdb/README.md`
- Modify: `test/tap/groups/groups.json`, `deps/duckdb/README.md`

**Interfaces:**
- Consumes: Tasks 1-10.
- Produces: the finished sub-project.

- [ ] **Step 1: Write the failing admin test**

Create `test/tap/tests/test_duckdb_admin_tables-t.cpp`, modelled on `test_mysqlx_admin_tables-t.cpp`. It connects to the Admin interface (port 6032 on the admin iface, via `CommandLine`) and asserts:

```cpp
	// 1. The plugin's table exists and is seeded.
	ok(rows_of("SELECT COUNT(*) FROM duckdb_variables") > 0,
	   "duckdb_variables is registered and seeded");

	// 2. The runtime view projects module state, not stored rows.
	ok(cell("SELECT variable_value FROM runtime_duckdb_variables "
	        "WHERE variable_name='threads'") ==
	   cell("SELECT variable_value FROM duckdb_variables "
	        "WHERE variable_name='threads'"),
	   "runtime view agrees with the editable table at rest");

	// 3. An edit is invisible to the runtime view until LOAD.
	exec("UPDATE duckdb_variables SET variable_value='7' WHERE variable_name='threads'");
	ok(cell("SELECT variable_value FROM runtime_duckdb_variables "
	        "WHERE variable_name='threads'") != "7",
	   "an uncommitted edit is not visible in the runtime view");

	// 4. LOAD ... TO RUNTIME installs it.
	exec("LOAD DUCKDB VARIABLES TO RUNTIME");
	ok(cell("SELECT variable_value FROM runtime_duckdb_variables "
	        "WHERE variable_name='threads'") == "7",
	   "LOAD DUCKDB VARIABLES TO RUNTIME installs the edit");

	// 5. The documented alias resolves to the same command.
	exec("UPDATE duckdb_variables SET variable_value='5' WHERE variable_name='threads'");
	exec("LOAD DUCKDB VARIABLES FROM MEMORY");
	ok(cell("SELECT variable_value FROM runtime_duckdb_variables "
	        "WHERE variable_name='threads'") == "5",
	   "the FROM MEMORY alias resolves to the canonical command");

	// 6. SAVE ... TO DISK persists.
	exec("SAVE DUCKDB VARIABLES TO DISK");
	ok(true, "SAVE DUCKDB VARIABLES TO DISK executes without error");
```

Write `exec`, `cell` and `rows_of` as small helpers over `mysql_query` / `mysql_store_result` against the admin connection, failing the test on a non-zero `mysql_query` return rather than returning silently.

Register: `"test_duckdb_admin_tables-t" : [ "duckdb-e2e-g1","@proxysql_min_version:4.0" ],`

- [ ] **Step 2: Run it, read the failure, fix, re-run**

Run:
```bash
PROXYSQL40=1 make build_tap_test_debug -j$(nproc) && \
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=duckdb-e2e-g1 \
  TEST_PY_TAP_INCL="test_duckdb_admin_tables-t" \
  test/infra/control/run-tests-isolated.bash
```
Expected: passes once the runtime-view refresh and the command registrations from Task 6 are correct end-to-end. A failure on assertion 3 means the refresh callback is reading the admin table instead of the module — re-read the separation-of-duties contract in `include/ProxySQL_Plugin.h`.

- [ ] **Step 3: Run the whole group plus the unit group**

Run:
```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=duckdb-e2e-g1 \
  test/infra/control/run-tests-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=unit-tests-g1 \
  test/infra/control/run-tests-isolated.bash
```
Expected: every test passes. If a pre-existing `unit-tests-g1` test now fails, that is this change's problem — read the log and find the root cause. Do not label it flaky or pre-existing.

- [ ] **Step 4: Write the plugin README**

Create `plugins/duckdb/README.md` covering:

- **What it is** — an embedded DuckDB served over the MySQL and PostgreSQL wire protocols; v4.0 plugin, not part of the core binary.
- **Build** — `PROXYSQL40=1 make`, and that `git lfs pull` is required before the first build.
- **Load** — the `plugins=(...)` stanza in `proxysql.cnf` with the installed path.
- **Configure** — the seven `duckdb_variables` rows, their defaults, and the `LOAD`/`SAVE` commands with their aliases.
- **Connect** — worked examples:
  `mysql -h 127.0.0.1 -P 6031 -u <mysql_users user> -p`
  `psql -h 127.0.0.1 -p 6032 -U <pgsql_users user> main`
- **Limitations, stated plainly** — every column arrives as VARCHAR/text (spec §7); no prepared statements; no query timeout; sessions appear as `PROXYSQL_SESSION_SQLITE` in logs and `stats_*_processlist`; clients must write DuckDB SQL, not MySQL SQL, beyond the small intercept list in `duckdb_classify_query`.
- **Design note** — one shared `duckdb_database`, one `duckdb_connection` per connection thread held in `thread_local` storage, and why `stop()` joins connection threads before closing the engine.

- [ ] **Step 5: Measure and record the CI cost**

The spec (§4 D2) commits to measuring the dep build's real cost rather than leaving the 10–30 minute estimate standing.

```bash
make -C deps PROXYSQL40=1 cleanall >/dev/null 2>&1 || true
/usr/bin/time -v make -C deps PROXYSQL40=1 duckdb 2>&1 | tail -20
```

Record the wall-clock time and peak RSS in `deps/duckdb/README.md` under a "Build cost" heading, alongside the machine's core count. Report the number in the PR description so the gating decision (D2) can be revisited with data.

- [ ] **Step 6: Commit**

```bash
git add test/tap/tests/test_duckdb_admin_tables-t.cpp plugins/duckdb/README.md \
        deps/duckdb/README.md test/tap/groups/groups.json
git commit -m "test(duckdb): admin table coverage; docs: plugin README

Covers the LOAD/SAVE commands, their aliases, and that the runtime view
projects module state rather than the editable table. Records the
measured deps build cost promised by the design."
```
