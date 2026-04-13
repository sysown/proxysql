# Remove `sqlite-rembed` and the Rust Toolchain Dependency — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete the `sqlite-rembed` sqlite extension from ProxySQL. This removes the only consumer of the Rust toolchain, so the Rust detection block in `deps/Makefile` disappears too, and `PROXYSQLGENAI=1` builds no longer require `rustc`/`cargo`.

**Architecture:** `sqlite-rembed` is currently built, linked into `libproxysql.a` and test binaries, but **never registered at runtime** — `lib/proxy_sqlite3_symbols.cpp:61` defines `proxy_sqlite3_rembed_init` as permanently `NULL` with a `TODO` comment, and the call site at `lib/Admin_Bootstrap.cpp:619` is null-guarded, so the auto-extension is never installed. Removal is therefore **pure dead-code deletion plus build-system cleanup**, with zero runtime behavior change. Work is staged so every commit leaves the tree buildable:

1. Source dead-code deletion (harmless; libraries still linked, just no symbols referenced).
2. Link-time references removed from `src/Makefile`, `lib/Makefile`, and test Makefiles.
3. Build rule + Rust detection removed from `deps/Makefile`.
4. Tarball + `.gitignore` entry removed.
5. Rembed-only docs/scripts deleted; mixed-content docs surgically edited.
6. End-to-end verification that `PROXYSQLGENAI=1` builds without `rustc`/`cargo` on `PATH`.

**Tech Stack:** GNU Make, C++17 (affected files: `lib/proxy_sqlite3_symbols.cpp`, `lib/Admin_Bootstrap.cpp`), shell, Markdown docs.

**Prerequisites:**
- Work on a dedicated branch or git worktree off `v3.0` — **do not commit directly to `v3.0`**. The superpowers `using-git-worktrees` skill is the preferred way to create one.
- Current `deps/` must be already built once before starting (so you don't conflate "I broke something" with "deps never built"). If you haven't, run `make` once from the repo root on a clean `v3.0` checkout before starting Task 1.
- At task completion, a full `make cleanall && make PROXYSQLCLICKHOUSE=1 PROXYSQLGENAI=1` must succeed **without** `rustc` or `cargo` installed. The final task describes how to verify this.

**Out of scope (these are Plan #2 — GenAI as a plugin):**
- Moving any GenAI source files into `plugins/genai/`.
- Adding hot-path hook services to `ProxySQL_Plugin.h`.
- Extracting the ~970-line `detect_ai_anomaly` block out of `MySQL_Session.cpp`.
- Any changes to `MCP_*`, `GenAI_Thread`, `LLM_Bridge`, `Anomaly_Detector`, `AI_Features_Manager`, or the tool handlers.

---

## File Structure

### Files to modify

| Path | Change type | Responsibility after change |
|---|---|---|
| `lib/proxy_sqlite3_symbols.cpp` | Edit | Update comment on line 53 to mention only `sqlite-vec`; delete the `TODO` + unconditional `proxy_sqlite3_rembed_init = NULL` on lines 60-61. |
| `lib/Admin_Bootstrap.cpp` | Edit | Delete the `extern` on line 96 and the null-guarded call on line 619. `proxy_sqlite3_vec_init` extern + call remain. |
| `src/Makefile` | Edit | Delete `SQLITE_REMBED_LIB` definition (line 154) and remove `$(SQLITE_REMBED_LIB)` from the `PROXYSQLGENAI=1` branch of `LIBPROXYSQLAR` additions (line 179). `$(SQLITE_VEC_OBJ)` stays. |
| `lib/Makefile` | Edit | Delete the unused `SQLITE_REMBED_LIB` definition (line 9). |
| `test/tap/tests/Makefile` | Edit | Drop `$(SQLITE3_LDIR)/../libsqlite_rembed.a` from `STATIC_LIBS` (line 83) and from every explicit link command (lines 183, 211, 230, 240, 250). `vec.o` stays. |
| `test/tap/tests/unit/Makefile` | Edit | Drop `$(SQLITE3_LDIR)/../libsqlite_rembed.a` from `STATIC_LIBS` (lines 115-117). `vec.o` stays. |
| `test/rag/Makefile` | Edit | Drop `../../deps/sqlite3/libsqlite_rembed.a` from the `test_rag_schema` link line. |
| `deps/Makefile` | Edit | Delete Rust toolchain check (lines 7-17), delete `SQLITE3_*` env exports (lines 19-22), change `sqlite-vec sqlite-rembed` → `sqlite-vec` in the GENAI targets block (line 70), delete the `sqlite3/libsqlite_rembed.a` build rule (lines 297-302), simplify the `sqlite3:` target (lines 304-308) to drop the rembed dependency, delete the `sqlite-rembed:` phony target (lines 313-314), delete rembed clean lines (411, 426). |
| `.gitignore` | Edit | Delete the `deps/sqlite3/sqlite-rembed-*/` line (line 132). |
| `doc/GENAI.md` | Edit | Delete two rembed-referring links in the "Related Documentation" section (lines 457, 459). |
| `doc/SQLite3-Server.md` | Edit | Delete the entire "Embedding Generation (with sqlite-rembed)" section (lines 72-103) and delete items 3-4 in the "Use Cases" list (lines 123-124), renumbering subsequent items. |

### Files to delete

| Path | Reason |
|---|---|
| `deps/sqlite3/sqlite-rembed-0.0.1-alpha.9.tar.gz` | The vendored rembed crate, no longer built. |
| `doc/sqlite-rembed-demo.sh` | Rembed demo shell script. |
| `doc/sqlite-rembed-examples.sh` | Rembed examples. |
| `doc/sqlite-rembed-examples.sql` | Rembed SQL examples. |
| `doc/sqlite-rembed-integration.md` | Rembed integration guide. |
| `doc/sqlite-rembed-test.sh` | Rembed test script. |
| `doc/SQLITE-REMBED-TEST-README.md` | Rembed test README. |
| `doc/posts-embeddings-setup.md` | Guide for posts-table embeddings using rembed; entire document is rembed-specific. |
| `doc/MCP/Vector_Embeddings_Implementation_Plan.md` | Planned-feature doc whose premise ("Use sqlite-rembed (placeholder for future GenAI module)") is being withdrawn. |
| `scripts/process_posts_embeddings.py` | Python script that configures `temp.rembed_clients` and calls `rembed()`; broken once the extension is gone. |

### Files NOT touched

- `deps/sqlite3/sqlite-vec-source/` and `deps/sqlite3/sqlite3/vec.o` — `sqlite-vec` stays, it's C code with no Rust involvement.
- Any file under `lib/` or `include/` that is guarded by `#ifdef PROXYSQLGENAI` but does not mention `rembed` — left alone for Plan #2 (GenAI as a plugin).
- `scripts/copy_stackexchange_Posts_mysql_to_sqlite3.py`, `scripts/nlp_search_demo.py`, `scripts/verify_vector_features.sh`, `scripts/stackexchange_posts.py` — none reference `rembed` (verified by grep). These may reference `vec` or embeddings generally, but `sqlite-vec` stays.

---

## Task 1: Establish baseline — prove the dead-code claim and confirm build

**Purpose:** Before touching anything, make two independent checks: (a) the code really does leave `proxy_sqlite3_rembed_init` permanently null (the premise of the whole plan), and (b) the tree builds cleanly on this checkout. If either fails, stop and investigate — don't proceed.

**Files:** None modified.

- [ ] **Step 1: Confirm the dead-code claim in source**

Run:
```bash
grep -n "proxy_sqlite3_rembed_init" lib/proxy_sqlite3_symbols.cpp
grep -n "proxy_sqlite3_rembed_init" lib/Admin_Bootstrap.cpp
```

Expected output (exact lines may shift by ±1 as the files evolve):
```
lib/proxy_sqlite3_symbols.cpp:61:int (*proxy_sqlite3_rembed_init)(sqlite3*, char**, const sqlite3_api_routines*) = NULL;
lib/Admin_Bootstrap.cpp:96:extern int (*proxy_sqlite3_rembed_init)(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi);
lib/Admin_Bootstrap.cpp:619:	if (proxy_sqlite3_rembed_init) (*proxy_sqlite3_auto_extension)( (void(*)(void))proxy_sqlite3_rembed_init);
```

**Pass condition:** the declaration assigns `= NULL` (not `= sqlite3_rembed_init`), AND the call site is guarded by `if (proxy_sqlite3_rembed_init)`. If instead the pointer is assigned to a real function (e.g. via a future PR that "fixed the TODO"), **stop and replan** — removal is no longer dead-code elimination.

- [ ] **Step 2: Confirm there is no other assignment or re-initialization of the pointer**

Run:
```bash
grep -rn "proxy_sqlite3_rembed_init\s*=" lib include src
```

Expected output (one line only):
```
lib/proxy_sqlite3_symbols.cpp:61:int (*proxy_sqlite3_rembed_init)(sqlite3*, char**, const sqlite3_api_routines*) = NULL;
```

**Pass condition:** Exactly one match — the null assignment. Any other match means the pointer is reassigned somewhere and the "permanently null" claim is wrong.

- [ ] **Step 3: Build the current tree with PROXYSQLGENAI=1 to establish a known-good baseline**

This requires `rustc`/`cargo` on `PATH` (the state you're trying to move away from).

Run:
```bash
make cleanall
make PROXYSQLCLICKHOUSE=1 PROXYSQLGENAI=1
```

Expected: build succeeds, `src/proxysql` exists, no errors. This is the last time you'll need Rust installed; every subsequent task builds with the new state.

If `rustc`/`cargo` aren't available, skip this step and note it — the final verification (Task 9) still proves the end-state without Rust, which is what matters.

- [ ] **Step 4: Confirm `proxy_sqlite3_rembed_init` is actually never invoked at runtime**

Optional but cheap. Run:
```bash
./src/proxysql --no-start --initial 2>&1 | head -40 || true
```

Expected: ProxySQL initializes, the null-guarded `if (proxy_sqlite3_rembed_init)` in `Admin_Bootstrap.cpp:619` short-circuits on the null pointer, and the extension is never registered. This is not a pass/fail gate — it's just context. If ProxySQL does print anything about "rembed extension registered", stop and replan.

- [ ] **Step 5: No commit**

This task changes no files.

---

## Task 2: Remove source-level dead-code references

**Purpose:** Delete the permanently-null function pointer and its lone null-guarded caller. This is the smallest possible first step — after it, the tree still builds because the removed symbols were never referenced outside these two sites.

**Files:**
- Modify: `lib/proxy_sqlite3_symbols.cpp:53-61`
- Modify: `lib/Admin_Bootstrap.cpp:95-96,618-619`

- [ ] **Step 1: Edit `lib/proxy_sqlite3_symbols.cpp`**

Find the block (lines 53-61 as of writing):

```cpp
// Hooks for sqlite-vec and sqlite-rembed (only available when PROXYSQLGENAI is enabled)
#ifdef PROXYSQLGENAI
#include "sqlite-vec.h"
int (*proxy_sqlite3_vec_init)(sqlite3*, char**, const sqlite3_api_routines*) = sqlite3_vec_init;
#else
int (*proxy_sqlite3_vec_init)(sqlite3*, char**, const sqlite3_api_routines*) = NULL;
#endif /* PROXYSQLGENAI */
// TODO: Fix sqlite-rembed header inclusion and assign the function pointer properly
int (*proxy_sqlite3_rembed_init)(sqlite3*, char**, const sqlite3_api_routines*) = NULL;
```

Replace with:

```cpp
// Hook for sqlite-vec (only available when PROXYSQLGENAI is enabled)
#ifdef PROXYSQLGENAI
#include "sqlite-vec.h"
int (*proxy_sqlite3_vec_init)(sqlite3*, char**, const sqlite3_api_routines*) = sqlite3_vec_init;
#else
int (*proxy_sqlite3_vec_init)(sqlite3*, char**, const sqlite3_api_routines*) = NULL;
#endif /* PROXYSQLGENAI */
```

- [ ] **Step 2: Edit `lib/Admin_Bootstrap.cpp` — remove the extern**

Find the block around line 95-96:

```cpp
extern int (*proxy_sqlite3_vec_init)(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi);
extern int (*proxy_sqlite3_rembed_init)(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi);
```

Replace with:

```cpp
extern int (*proxy_sqlite3_vec_init)(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi);
```

- [ ] **Step 3: Edit `lib/Admin_Bootstrap.cpp` — remove the null-guarded call**

Find the block around line 618-619:

```cpp
	if (proxy_sqlite3_vec_init) (*proxy_sqlite3_auto_extension)( (void(*)(void))proxy_sqlite3_vec_init);
	if (proxy_sqlite3_rembed_init) (*proxy_sqlite3_auto_extension)( (void(*)(void))proxy_sqlite3_rembed_init);
```

Replace with:

```cpp
	if (proxy_sqlite3_vec_init) (*proxy_sqlite3_auto_extension)( (void(*)(void))proxy_sqlite3_vec_init);
```

- [ ] **Step 4: Verify no source references to `rembed_init` remain**

Run:
```bash
grep -rn "rembed_init\|proxy_sqlite3_rembed" lib/ include/ src/
```

Expected: empty output (exit code 1).

- [ ] **Step 5: Build incrementally to prove nothing broke**

The deps are already built from Task 1 (if you did that step), so a partial rebuild is sufficient:

```bash
cd lib && make
cd ../src && make
```

Expected: both succeed. If the linker fails with "undefined reference to `sqlite3_rembed_init`" or similar, it means the rembed `.a` was trying to resolve a symbol against core code, which it shouldn't — investigate. With the pointer gone, nothing in `libproxysql.a` should reference rembed symbols.

**Diagnostic if build fails:** rerun `grep -rn "rembed" lib/ src/` and look for any reference other than in Makefiles. All remaining source-level rembed references are Makefile-side at this point (handled in Tasks 3-5).

- [ ] **Step 6: Commit**

```bash
git add lib/proxy_sqlite3_symbols.cpp lib/Admin_Bootstrap.cpp
git commit -m "$(cat <<'EOF'
chore(sqlite): remove dead-code sqlite-rembed hook pointer

proxy_sqlite3_rembed_init was declared unconditionally as NULL
with a TODO comment ("Fix sqlite-rembed header inclusion and assign
the function pointer properly") and never reassigned anywhere in
the tree. The sole caller in Admin_Bootstrap::__bootstrap was
null-guarded, so the sqlite-rembed auto-extension was never
registered at runtime in any build tier, stable or GENAI.

This commit removes the pointer, its extern declaration, and the
null-guarded call. No runtime behavior changes; subsequent commits
remove the build-system wiring and the Rust toolchain dependency
that existed solely to produce libsqlite_rembed.a.
EOF
)"
```

---

## Task 3: Remove link-time references from `src/Makefile` and `lib/Makefile`

**Purpose:** Stop linking `libsqlite_rembed.a` into `libproxysql.a` and the `proxysql` executable. The library is still built at this point (Task 5 removes the build rule), but nothing in the binary references any of its symbols, so dropping it from the link line is safe.

**Files:**
- Modify: `src/Makefile:154,178-180`
- Modify: `lib/Makefile:9`

- [ ] **Step 1: Edit `src/Makefile` — delete `SQLITE_REMBED_LIB` definition**

Find line 154:

```makefile
SQLITE_REMBED_LIB := $(DEPS_PATH)/sqlite3/libsqlite_rembed.a
SQLITE_VEC_OBJ := $(DEPS_PATH)/sqlite3/sqlite3/vec.o
LIBPROXYSQLAR := $(PROXYSQL_LDIR)/libproxysql.a
```

Replace with:

```makefile
SQLITE_VEC_OBJ := $(DEPS_PATH)/sqlite3/sqlite3/vec.o
LIBPROXYSQLAR := $(PROXYSQL_LDIR)/libproxysql.a
```

- [ ] **Step 2: Edit `src/Makefile` — remove `$(SQLITE_REMBED_LIB)` from the conditional link**

Find the block around lines 178-180:

```makefile
ifeq ($(PROXYSQLGENAI),1)
LIBPROXYSQLAR += $(SQLITE_REMBED_LIB) $(SQLITE_VEC_OBJ)
endif
```

Replace with:

```makefile
ifeq ($(PROXYSQLGENAI),1)
LIBPROXYSQLAR += $(SQLITE_VEC_OBJ)
endif
```

- [ ] **Step 3: Edit `lib/Makefile` — delete the unused `SQLITE_REMBED_LIB` definition**

Find line 9:

```makefile
SQLITE_REMBED_LIB := $(SQLITE3_LDIR)/../libsqlite_rembed.a
```

Delete the entire line. This variable is defined but never referenced in the rest of `lib/Makefile`, so deletion is a pure cleanup.

- [ ] **Step 4: Verify no references remain in these two Makefiles**

Run:
```bash
grep -n "SQLITE_REMBED_LIB\|sqlite_rembed\|libsqlite_rembed" src/Makefile lib/Makefile
```

Expected: empty output.

- [ ] **Step 5: Build to prove the link still works**

```bash
cd lib && make clean && make
cd ../src && make clean && make
```

Expected: both succeed. If PROXYSQLGENAI is not set, this builds the stable tier. For a GENAI-tier check, additionally run:
```bash
make cleanall && make PROXYSQLCLICKHOUSE=1 PROXYSQLGENAI=1
```

but this still triggers the rembed build rule in `deps/Makefile` (removed in Task 5), so it requires Rust installed at this point. If you don't have Rust installed, it's OK to skip the GENAI rebuild here — Task 9 does the authoritative rustless verification.

- [ ] **Step 6: Commit**

```bash
git add src/Makefile lib/Makefile
git commit -m "build: drop libsqlite_rembed.a from src/lib link order"
```

---

## Task 4: Remove link-time references from test Makefiles

**Purpose:** Stop linking `libsqlite_rembed.a` into TAP test binaries and the rag-schema test. `vec.o` (from `sqlite-vec`) stays in all cases.

**Files:**
- Modify: `test/tap/tests/Makefile:83,183,211,230,240,250`
- Modify: `test/tap/tests/unit/Makefile:115-117`
- Modify: `test/rag/Makefile:4`

- [ ] **Step 1: Edit `test/tap/tests/Makefile` — STATIC_LIBS block**

Find the block around lines 82-84:

```makefile
ifeq ($(PROXYSQLGENAI),1)
	STATIC_LIBS += $(SQLITE3_LDIR)/../libsqlite_rembed.a $(SQLITE3_LDIR)/vec.o
endif
```

Replace with:

```makefile
ifeq ($(PROXYSQLGENAI),1)
	STATIC_LIBS += $(SQLITE3_LDIR)/vec.o
endif
```

- [ ] **Step 2: Edit `test/tap/tests/Makefile` — explicit link commands**

There are five explicit link lines that include `$(SQLITE3_LDIR)/../libsqlite_rembed.a` (lines 183, 211, 230, 240, 250 in the current file — these are the `ifeq ($(PROXYSQLGENAI),1)` branches of specific test targets). For each of the five lines, delete the `$(SQLITE3_LDIR)/../libsqlite_rembed.a` token and the single preceding or trailing space. Keep `$(SQLITE3_LDIR)/vec.o` and every other link fragment untouched.

**Example transformation for line 183** (current):

```makefile
	$(CXX) -DEXCLUDE_TRACKING_VARIABLES $< ../tap/SQLite3_Server.cpp -I$(CLICKHOUSE_CPP_IDIR) $(IDIRS) $(LDIRS) -L$(CLICKHOUSE_CPP_LDIR) -L$(LZ4_LDIR) $(OPT) $(OBJ) $(MYLIBSJEMALLOC) $(MYLIBS) $(STATIC_LIBS) $(CLICKHOUSE_CPP_LDIR)/libclickhouse-cpp-lib.a $(CLICKHOUSE_CPP_PATH)/contrib/zstd/zstd/libzstdstatic.a $(LZ4_LDIR)/liblz4.a $(SQLITE3_LDIR)/../libsqlite_rembed.a -lscram -lusual -Wl,--allow-multiple-definition -o $@
```

After:

```makefile
	$(CXX) -DEXCLUDE_TRACKING_VARIABLES $< ../tap/SQLite3_Server.cpp -I$(CLICKHOUSE_CPP_IDIR) $(IDIRS) $(LDIRS) -L$(CLICKHOUSE_CPP_LDIR) -L$(LZ4_LDIR) $(OPT) $(OBJ) $(MYLIBSJEMALLOC) $(MYLIBS) $(STATIC_LIBS) $(CLICKHOUSE_CPP_LDIR)/libclickhouse-cpp-lib.a $(CLICKHOUSE_CPP_PATH)/contrib/zstd/zstd/libzstdstatic.a $(LZ4_LDIR)/liblz4.a -lscram -lusual -Wl,--allow-multiple-definition -o $@
```

**For the remaining four lines (211, 230, 240, 250)**, the pattern is the same: each has `$(SQLITE3_LDIR)/../libsqlite_rembed.a $(SQLITE3_LDIR)/vec.o` near the end of the link command. Delete `$(SQLITE3_LDIR)/../libsqlite_rembed.a ` (including the trailing space). Leave `$(SQLITE3_LDIR)/vec.o` intact. After edits, each line goes from `... $(SQLITE3_LDIR)/../libsqlite_rembed.a $(SQLITE3_LDIR)/vec.o -o $@` to `... $(SQLITE3_LDIR)/vec.o -o $@`.

Use a global find-and-replace to avoid missing one:

```bash
sed -i 's| \$(SQLITE3_LDIR)/\.\./libsqlite_rembed\.a||g' test/tap/tests/Makefile
```

Then re-check:

```bash
grep -n "libsqlite_rembed" test/tap/tests/Makefile
```

Expected: empty output.

- [ ] **Step 3: Edit `test/tap/tests/unit/Makefile` — STATIC_LIBS block**

Find the block around lines 115-117:

```makefile
ifeq ($(PROXYSQLGENAI),1)
	STATIC_LIBS += $(SQLITE3_LDIR)/../libsqlite_rembed.a $(SQLITE3_LDIR)/vec.o
endif
```

Replace with:

```makefile
ifeq ($(PROXYSQLGENAI),1)
	STATIC_LIBS += $(SQLITE3_LDIR)/vec.o
endif
```

- [ ] **Step 4: Edit `test/rag/Makefile`**

Find line 4:

```makefile
test_rag_schema: test_rag_schema.cpp
	g++ -ggdb test_rag_schema.cpp ../../deps/sqlite3/libsqlite_rembed.a ../../deps/sqlite3/sqlite3/libsqlite3.so  -o test_rag_schema -I../../deps/sqlite3/sqlite3 -lssl -lcrypto
```

Replace with:

```makefile
test_rag_schema: test_rag_schema.cpp
	g++ -ggdb test_rag_schema.cpp ../../deps/sqlite3/sqlite3/libsqlite3.so  -o test_rag_schema -I../../deps/sqlite3/sqlite3 -lssl -lcrypto
```

(The `test_rag_schema.cpp` source does not reference any `rembed_*` symbol — `grep -n rembed test/rag/test_rag_schema.cpp` is empty — so the link was carrying dead weight.)

- [ ] **Step 5: Verify no remaining references**

Run:
```bash
grep -rn "libsqlite_rembed\|sqlite_rembed" test/tap test/rag
```

Expected: empty output.

- [ ] **Step 6: Optional smoke build of a TAP test**

Only run this if you want extra confidence and have deps built. Most TAP tests can be built individually from `test/tap/tests`:

```bash
cd test/tap/tests && make test_server_stall-t
```

Expected: succeeds, produces binary. Any link error pointing at missing symbols from `libsqlite_rembed.a` means a reference was missed — go back and grep.

- [ ] **Step 7: Commit**

```bash
git add test/tap/tests/Makefile test/tap/tests/unit/Makefile test/rag/Makefile
git commit -m "build(test): drop libsqlite_rembed.a from TAP and rag test link order"
```

---

## Task 5: Remove the build rule and Rust toolchain check from `deps/Makefile`

**Purpose:** This is the task where the Rust dependency actually disappears. Once this commits, `make` (at any tier) stops invoking `cargo` and stops expecting `rustc` on `PATH`.

**Files:**
- Modify: `deps/Makefile:7-22,69-71,296-308,313-314,411,426`

- [ ] **Step 1: Delete the Rust toolchain check and the SQLite env exports**

Find lines 7-22:

```makefile
# Rust toolchain detection (only needed for PROXYSQLGENAI)
ifeq ($(PROXYSQLGENAI),1)
RUSTC := $(shell type rustc 2>/dev/null | sed 's/.* //')
CARGO := $(shell type cargo 2>/dev/null | sed 's/.* //')
ifndef RUSTC
$(error "rustc not found. Please install Rust toolchain (required for PROXYSQLGENAI)")
endif
ifndef CARGO
$(error "cargo not found. Please install Rust toolchain (required for PROXYSQLGENAI)")
endif
endif

# SQLite environment variables for sqlite-rembed build
export SQLITE3_INCLUDE_DIR=$(shell pwd)/sqlite3/sqlite3
export SQLITE3_LIB_DIR=$(shell pwd)/sqlite3/sqlite3
export SQLITE3_STATIC=1

```

Delete all of it (replace with a single blank line for readability).

These `SQLITE3_*` environment variables are **only** consumed by the `cargo build` invocation for rembed. Confirmed by earlier grep — they appear only in `deps/Makefile` and in `doc/sqlite-rembed-integration.md` (which Task 7 will delete).

- [ ] **Step 2: Drop `sqlite-rembed` from the GENAI targets list**

Find the block around lines 69-71:

```makefile
ifeq ($(PROXYSQLGENAI),1)
	targets += sqlite-vec sqlite-rembed
endif
```

Replace with:

```makefile
ifeq ($(PROXYSQLGENAI),1)
	targets += sqlite-vec
endif
```

- [ ] **Step 3: Delete the `libsqlite_rembed.a` build rule**

Find the block around lines 297-302:

```makefile
sqlite3/libsqlite_rembed.a: sqlite3/sqlite-rembed-0.0.1-alpha.9.tar.gz
	cd sqlite3 && rm -rf sqlite-rembed-*/ sqlite-rembed-source/ || true
	cd sqlite3 && tar -zxf sqlite-rembed-0.0.1-alpha.9.tar.gz
	mv sqlite3/sqlite-rembed-0.0.1-alpha.9 sqlite3/sqlite-rembed-source
	cd sqlite3/sqlite-rembed-source && SQLITE3_INCLUDE_DIR=$(SQLITE3_INCLUDE_DIR) SQLITE3_LIB_DIR=$(SQLITE3_LIB_DIR) SQLITE3_STATIC=1 $(CARGO) build --locked --release --features=sqlite-loadable/static --lib
	cp sqlite3/sqlite-rembed-source/target/release/libsqlite_rembed.a sqlite3/libsqlite_rembed.a

```

Delete the whole rule (all 6 lines plus the trailing blank line).

- [ ] **Step 4: Simplify the `sqlite3:` target**

Find the block around lines 304-308:

```makefile
ifeq ($(PROXYSQLGENAI),1)
sqlite3: sqlite3/sqlite3/sqlite3.o sqlite3/sqlite3/vec.o sqlite3/libsqlite_rembed.a
else
sqlite3: sqlite3/sqlite3/sqlite3.o
endif
```

Replace with:

```makefile
ifeq ($(PROXYSQLGENAI),1)
sqlite3: sqlite3/sqlite3/sqlite3.o sqlite3/sqlite3/vec.o
else
sqlite3: sqlite3/sqlite3/sqlite3.o
endif
```

- [ ] **Step 5: Delete the `sqlite-rembed:` phony target**

Find the block around lines 313-314:

```makefile
# sqlite-rembed: Remote embedding extension (Rust-based, for GenAI)
sqlite-rembed: sqlite3/libsqlite_rembed.a

```

Delete the comment, the phony target, and the blank line after it (3 lines total).

- [ ] **Step 6: Remove rembed-related lines from the clean rules**

Find line 411 (inside `cleanpart:`):

```makefile
	cd sqlite3 && rm -rf libsqlite_rembed.a sqlite-rembed-source/ sqlite-rembed-*/ || true
```

Delete the entire line.

Find line 426 (inside `cleanall:`), same text:

```makefile
	cd sqlite3 && rm -rf libsqlite_rembed.a sqlite-rembed-source/ sqlite-rembed-*/ || true
```

Delete the entire line.

- [ ] **Step 7: Verify the Makefile is rembed-free and Rust-free**

Run:
```bash
grep -n "rembed\|rustc\|cargo\|RUSTC\|CARGO\|SQLITE3_INCLUDE_DIR\|SQLITE3_LIB_DIR\|SQLITE3_STATIC" deps/Makefile
```

Expected: empty output.

- [ ] **Step 8: Rebuild deps end-to-end to prove the GENAI build no longer touches Rust**

```bash
make cleanall
make PROXYSQLCLICKHOUSE=1 PROXYSQLGENAI=1
```

**Key observation during the build:** the console output must not contain `cargo build`, `rustc`, `Compiling sqlite-rembed`, or similar Rust-toolchain chatter. If you see any of those, a build rule was missed — grep `deps/Makefile` again.

Expected end state: `src/proxysql` exists, `deps/sqlite3/libsqlite_rembed.a` does **not** exist.

To double-check:
```bash
ls deps/sqlite3/libsqlite_rembed.a 2>&1 || echo "GONE"
```

Expected: `GONE` (or `No such file or directory`).

- [ ] **Step 9: Commit**

```bash
git add deps/Makefile
git commit -m "$(cat <<'EOF'
build(deps): remove sqlite-rembed build rule and Rust toolchain check

libsqlite_rembed.a is no longer linked into any ProxySQL binary or
test as of the preceding commits, so the build rule, the Rust
toolchain detection block, the SQLITE3_* environment exports, the
sqlite-rembed phony target, and the rembed clean lines can go. The
sqlite-vec extension stays (it is C, not Rust).

After this commit, PROXYSQLGENAI=1 builds no longer require rustc
or cargo on PATH.
EOF
)"
```

---

## Task 6: Delete the vendored tarball and update `.gitignore`

**Files:**
- Delete: `deps/sqlite3/sqlite-rembed-0.0.1-alpha.9.tar.gz`
- Modify: `.gitignore:132`

- [ ] **Step 1: Confirm the tarball is git-tracked, then remove it**

```bash
git ls-files deps/sqlite3/sqlite-rembed-0.0.1-alpha.9.tar.gz
```

Expected output: `deps/sqlite3/sqlite-rembed-0.0.1-alpha.9.tar.gz`

Then:
```bash
git rm deps/sqlite3/sqlite-rembed-0.0.1-alpha.9.tar.gz
```

Expected: `rm 'deps/sqlite3/sqlite-rembed-0.0.1-alpha.9.tar.gz'`

- [ ] **Step 2: Remove the `.gitignore` entry**

Find line 132 of `.gitignore`:

```
deps/sqlite3/sqlite-rembed-*/
```

Delete the entire line.

- [ ] **Step 3: Verify**

```bash
grep -n rembed .gitignore
ls deps/sqlite3/ | grep rembed
```

Expected: both empty.

- [ ] **Step 4: Commit**

```bash
git add .gitignore
git commit -m "chore: remove vendored sqlite-rembed-0.0.1-alpha.9 tarball"
```

---

## Task 7: Delete rembed-only documentation and scripts

**Purpose:** These files describe or implement features that no longer exist. Their entire reason to exist is rembed integration.

**Files to delete (all via `git rm`):**
- `doc/sqlite-rembed-demo.sh`
- `doc/sqlite-rembed-examples.sh`
- `doc/sqlite-rembed-examples.sql`
- `doc/sqlite-rembed-integration.md`
- `doc/sqlite-rembed-test.sh`
- `doc/SQLITE-REMBED-TEST-README.md`
- `doc/posts-embeddings-setup.md`
- `doc/MCP/Vector_Embeddings_Implementation_Plan.md`
- `scripts/process_posts_embeddings.py`

- [ ] **Step 1: Delete all nine files in one command**

```bash
git rm \
  doc/sqlite-rembed-demo.sh \
  doc/sqlite-rembed-examples.sh \
  doc/sqlite-rembed-examples.sql \
  doc/sqlite-rembed-integration.md \
  doc/sqlite-rembed-test.sh \
  doc/SQLITE-REMBED-TEST-README.md \
  doc/posts-embeddings-setup.md \
  doc/MCP/Vector_Embeddings_Implementation_Plan.md \
  scripts/process_posts_embeddings.py
```

Expected: 9 `rm '…'` lines printed.

- [ ] **Step 2: Verify no accidental deletion of other files**

```bash
git status --short | grep '^D '
```

Expected: exactly 9 `D ` lines, each one of the files above. If additional files appear, they were deleted by mistake — `git restore --staged --worktree <path>` each unintended one.

- [ ] **Step 3: Check for dangling references to the deleted files elsewhere**

```bash
grep -rn "posts-embeddings-setup\|Vector_Embeddings_Implementation_Plan\|sqlite-rembed-demo\|sqlite-rembed-examples\|sqlite-rembed-integration\|sqlite-rembed-test\|SQLITE-REMBED-TEST-README\|process_posts_embeddings" doc/ scripts/ README.md 2>/dev/null
```

Expected: empty, or only matches inside `doc/GENAI.md` and `doc/SQLite3-Server.md` (handled by Task 8).

If anything else shows up — e.g. a top-level README linking to one of these docs — fix the link in the same commit.

- [ ] **Step 4: Commit**

```bash
git commit -m "docs: remove sqlite-rembed guides, examples, and embeddings script"
```

---

## Task 8: Surgical edits to mixed-content docs

**Purpose:** `doc/GENAI.md` and `doc/SQLite3-Server.md` document features beyond rembed. Only the rembed-specific sections get removed.

**Files:**
- Modify: `doc/GENAI.md:455-460`
- Modify: `doc/SQLite3-Server.md:72-103,123-124`

- [ ] **Step 1: Edit `doc/GENAI.md` — remove two links in "Related Documentation"**

Find the block around lines 455-460:

```markdown
## Related Documentation

- [Posts Table Embeddings Setup](./posts-embeddings-setup.md) - Using sqlite-rembed with GenAI
- [SQLite3 Server Documentation](./SQLite3-Server.md) - SQLite3 backend integration
- [sqlite-rembed Integration](./sqlite-rembed-integration.md) - Embedding generation

```

Replace with:

```markdown
## Related Documentation

- [SQLite3 Server Documentation](./SQLite3-Server.md) - SQLite3 backend integration

```

(Two lines deleted, one retained — `SQLite3-Server.md` still exists and is relevant.)

- [ ] **Step 2: Edit `doc/SQLite3-Server.md` — delete the rembed section**

Find the block from line 72 through line 104 (the section starts with the `### Embedding Generation (with sqlite-rembed)` heading and ends with the `See [sqlite-rembed integration documentation]...` line followed by a blank line, before `### Available Databases`):

```markdown
### Embedding Generation (with sqlite-rembed)

```sql
-- Register an embedding API client
INSERT INTO temp.rembed_clients(name, format, model, key)
VALUES ('openai', 'openai', 'text-embedding-3-small', 'your-api-key');

-- Generate text embeddings
SELECT rembed('openai', 'Hello world') as embedding;

-- Complete AI pipeline: generate embedding and search
CREATE VECTOR TABLE documents (embedding float[1536]);

INSERT INTO documents(rowid, embedding)
VALUES (1, rembed('openai', 'First document text'));

INSERT INTO documents(rowid, embedding)
VALUES (2, rembed('openai', 'Second document text'));

-- Search for similar documents
SELECT rowid, distance FROM documents
WHERE embedding MATCH rembed('openai', 'Search query');
```

#### Supported Embedding Providers
- **OpenAI**: `format='openai', model='text-embedding-3-small'`
- **Ollama** (local): `format='ollama', model='nomic-embed-text'`
- **Cohere**: `format='cohere', model='embed-english-v3.0'`
- **Nomic**: `format='nomic', model='nomic-embed-text-v1.5'`
- **Llamafile** (local): `format='llamafile'`

See [sqlite-rembed integration documentation](./sqlite-rembed-integration.md) for full details.

```

Delete the entire block (the `### Embedding Generation` heading through the blank line after the "See..." sentence, inclusive). The next heading `### Available Databases` should now follow immediately after the preceding `-- Search similar vectors` code block's closing triple-backtick and its trailing blank line.

- [ ] **Step 3: Edit `doc/SQLite3-Server.md` — remove rembed-dependent Use Cases**

Find the block around lines 119-127:

```markdown
### Use Cases

1. **Data Analysis**: Store and analyze temporary data
2. **Vector Search**: Perform similarity searches with sqlite-vec
3. **Embedding Generation**: Create text embeddings with sqlite-rembed (OpenAI, Ollama, Cohere, etc.)
4. **AI Pipelines**: Complete RAG workflows: embedding generation → vector storage → similarity search
5. **Testing**: Test SQLite features with MySQL clients
6. **Prototyping**: Quick data storage and retrieval
7. **Custom Applications**: Build applications using SQLite with MySQL tools
```

Replace with:

```markdown
### Use Cases

1. **Data Analysis**: Store and analyze temporary data
2. **Vector Search**: Perform similarity searches with sqlite-vec
3. **Testing**: Test SQLite features with MySQL clients
4. **Prototyping**: Quick data storage and retrieval
5. **Custom Applications**: Build applications using SQLite with MySQL tools
```

(Items 3 and 4 — Embedding Generation and AI Pipelines — both depend on rembed and are removed. Item 2 "Vector Search with sqlite-vec" stays. Items 5-7 are renumbered to 3-5.)

- [ ] **Step 4: Verify both docs are rembed-free**

```bash
grep -n rembed doc/GENAI.md doc/SQLite3-Server.md
```

Expected: empty output.

- [ ] **Step 5: Commit**

```bash
git add doc/GENAI.md doc/SQLite3-Server.md
git commit -m "docs: excise sqlite-rembed sections from GENAI.md and SQLite3-Server.md"
```

---

## Task 9: End-to-end verification (the Rust-free build)

**Purpose:** Prove the top-level goal — that `PROXYSQLGENAI=1` builds cleanly without `rustc` or `cargo` anywhere on `PATH`.

**Files:** None modified. This task is pure verification.

- [ ] **Step 1: Global grep for any remaining references**

```bash
grep -rn \
  --exclude-dir=.git \
  --exclude-dir=deps \
  'sqlite.rembed\|sqlite_rembed\|libsqlite_rembed\|rembed_init\|proxy_sqlite3_rembed\|rembed_clients' \
  .
```

Expected: empty output.

Then the same search **inside** `deps/`, which should only match the tarball name (which is gone) and historical patch context:

```bash
grep -rn 'rembed' deps/
```

Expected: empty output, or at most matches inside `deps/sqlite3/sqlite-vec-source/` that reference rembed as a third-party comparison point (harmless — it's inside an unrelated vendored source tree). If matches appear in `deps/Makefile`, something was missed in Task 5 — go back.

- [ ] **Step 2: Confirm `libsqlite_rembed.a` no longer exists on disk after a clean build**

```bash
make cleanall
ls deps/sqlite3/libsqlite_rembed.a 2>&1 || echo GONE
```

Expected: `GONE` (the file never existed after `cleanall`) — and more importantly, nothing will recreate it.

- [ ] **Step 3: Build without Rust on `PATH`**

This is the load-bearing verification. Run the full clean build with `rustc` and `cargo` explicitly hidden:

```bash
env -u CARGO_HOME -u RUSTUP_HOME PATH=$(echo "$PATH" | tr ':' '\n' | grep -v -i -E 'cargo|rust' | tr '\n' ':') make PROXYSQLCLICKHOUSE=1 PROXYSQLGENAI=1
```

(The `PATH` filter strips any entry with `cargo` or `rust` in the name — e.g. `~/.cargo/bin` or `~/.rustup/...`. Both `CARGO_HOME` and `RUSTUP_HOME` are unset so cargo can't self-locate.)

**Pass condition:** build succeeds, `src/proxysql` exists, and the build output contains no `cargo`, `rustc`, `Compiling sqlite-rembed`, or `sqlite-loadable` strings.

Inspect the build log if in doubt:

```bash
env -u CARGO_HOME -u RUSTUP_HOME PATH=$(echo "$PATH" | tr ':' '\n' | grep -v -i -E 'cargo|rust' | tr '\n' ':') make PROXYSQLCLICKHOUSE=1 PROXYSQLGENAI=1 2>&1 | tee /tmp/build.log
grep -iE 'cargo|rustc|rembed|sqlite-loadable' /tmp/build.log
```

Expected: empty output from the second `grep`.

- [ ] **Step 4: Smoke-test the binary**

```bash
./src/proxysql --version
```

Expected: version string prints, no crashes.

Then a minimal startup check (use a temporary datadir so you don't clobber anything):

```bash
mkdir -p /tmp/proxysql_rust_removal_smoke/var
./src/proxysql --initial --datadir=/tmp/proxysql_rust_removal_smoke/var --no-start 2>&1 | head -20
```

Expected: ProxySQL initializes admin DB and exits. No messages about missing extensions.

Clean up:
```bash
rm -rf /tmp/proxysql_rust_removal_smoke
```

- [ ] **Step 5: Optional — run a TAP smoke test**

If you have a TAP infrastructure up (Docker-based MySQL), pick a fast, non-rembed test to confirm no regressions:

```bash
cd test/tap && make build
cd tests && ./test_server_stall-t || echo "check this failure against the current baseline"
```

Only fail the plan if this test was previously passing on the same branch. Otherwise it's informational.

- [ ] **Step 6: No commit**

This task is verification only. If everything passed, the plan is complete.

---

## Self-Review Checklist (run this before handing off to the engineer)

**Spec coverage:** Does every item in the brief get covered by a task?

- ✅ Remove `sqlite-rembed` from source (Task 2)
- ✅ Remove `sqlite-rembed` from build system at all layers: deps (Task 5), src/lib link (Task 3), test link (Task 4) — three separate tasks because they belong to different owners of their respective Makefiles
- ✅ Remove the tarball (Task 6)
- ✅ Remove the Rust toolchain dependency (Task 5 — happens as a side effect of deleting the only consumer)
- ✅ Clean up `.gitignore` (Task 6)
- ✅ Delete rembed-only docs and scripts (Task 7)
- ✅ Surgical edits to mixed-content docs (Task 8)
- ✅ Verify the end state: Rust-free build of GENAI tier (Task 9)

**Placeholder scan:** No TODOs, no "add appropriate X", no "similar to Task N", no undefined symbols. All edits show exact old and new content. The only non-concrete step is Task 9 Step 5 (optional TAP test), which is explicitly marked optional and has a deterministic fallback.

**Type / symbol consistency:** The only symbol this plan deletes is `proxy_sqlite3_rembed_init`. It's defined in exactly one place (`lib/proxy_sqlite3_symbols.cpp:61`), externally declared in exactly one place (`lib/Admin_Bootstrap.cpp:96`), and called from exactly one place (`lib/Admin_Bootstrap.cpp:619`). All three sites are addressed in Task 2 with exact pre/post content. No symbol is used later than where it is defined.

**Build invariant:** The tree must be buildable after every commit. Verified by walking the tasks:

| After task | Build state |
|---|---|
| Task 2 | `libsqlite_rembed.a` still linked but no code references any of its symbols → link succeeds. |
| Task 3 | `libsqlite_rembed.a` no longer linked into `libproxysql.a`/`proxysql` → link succeeds. |
| Task 4 | `libsqlite_rembed.a` no longer linked into TAP/rag tests → link succeeds. |
| Task 5 | `libsqlite_rembed.a` no longer built; nothing references it → build succeeds, no Rust needed. |
| Task 6 | Tarball gone; build rule was already gone (Task 5), so nothing tried to untar it. |
| Tasks 7-8 | Doc/script deletion only; no build impact. |

---

## Out of Scope (Plan #2 preview)

After this plan merges, **Plan #2 — GenAI as a plugin** will follow. It will:

1. Extend `include/ProxySQL_Plugin.h` with hot-path hook services (`register_mysql_pre_query_hook`, `register_mysql_query_prefix_hook`) so a plugin can install anomaly-detection and `GENAI:` prefix handlers without `#ifdef` pollution in `MySQL_Session.cpp`.
2. Extract the ~970-line `detect_ai_anomaly` block from `lib/MySQL_Session.cpp` (lines 3634-4605) into `Anomaly_Detector` proper with a session-context accessor.
3. Create `plugins/genai/` with modular internal structure (`src/mcp/`, `src/ai_core/`, `src/bridge/`) that anticipates a future physical split into `mcp.so` + `genai.so` + `genai-mcp-tools.so`.
4. Move 30+ GenAI-guarded source/header files from `lib/`+`include/` into `plugins/genai/`, replacing direct `#ifdef PROXYSQLGENAI` globals with plugin context.
5. Migrate GenAI admin tables and commands from `ProxySQL_Admin.cpp` / `Admin_Handler.cpp` (currently ~32 `#ifdef` sites) to plugin-registered tables and commands via existing v1 services.
6. Update packaging so the AI tier ships as `proxysql + genai.so` instead of a `PROXYSQLGENAI=1` compile-time flag.
7. Update TAP tests to load `genai.so` via `plugins =` in the test `proxysql.cnf`.

Plan #2 is a much larger undertaking and will be written as its own plan document once Plan #1 has merged and the plugin ABI from the ProtocolX branch has been reviewed for suitability of hot-path hooks.

---

**Plan complete.**
