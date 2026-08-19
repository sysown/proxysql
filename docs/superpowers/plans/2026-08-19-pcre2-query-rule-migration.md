# PCRE2 Query-Rule Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace vendored PCRE1 and `pcrecpp` with vendored PCRE2 10.47 while preserving MySQL and PostgreSQL query-rule matching and rewrite behavior.

**Architecture:** Build the PCRE2 8-bit static library under `deps` and remove the PCRE1 paths from every ProxySQL linker. Replace the private `pcrecpp` objects in `lib/Query_Processor.cpp` with a private RAII PCRE2 adapter that compiles immutable `pcre2_code` objects, creates match data per operation, and translates legacy query-rule rewrite escapes before substitution.

**Tech Stack:** C++17, PCRE2 10.47 8-bit C API, GNU Make, Autoconf, TAP C++ tests, MySQL client API, libpq.

**Spec:** `docs/superpowers/specs/2026-08-19-pcre2-query-rule-migration-design.md`

## Global Constraints

- Vendor official PCRE2 **10.47**; do not use a system PCRE2 package or runtime dependency.
- Build only static PCRE2 8-bit support; disable shared, 16-bit, 32-bit, and dependency test builds.
- `query_processor_regex=2` remains RE2; all other values select PCRE2.
- Preserve the query-rule schema, `CASELESS`, `GLOBAL`, unanchored matching, negated-match behavior, and pcrecpp rewrite escapes `\\0` through `\\9` and `\\\\`.
- Keep PCRE2 types private to `lib/Query_Processor.cpp`; do not add a public PCRE2 API.
- Do not introduce JIT in this PR.
- Before every source build in a previously-used worktree run `PROXYSQL31=1 make cleanall`.

---

## File structure

- `deps/pcre2/pcre2-10.47.tar.gz` — official vendored PCRE2 source archive.
- `deps/Makefile` — PCRE2 extraction, static 8-bit configure options, and dependency target.
- `include/makefiles_paths.mk` — PCRE2 include and archive locations shared by all Makefiles.
- `lib/Query_Processor.cpp` — private PCRE2 adapter and the shared MySQL/PostgreSQL query-rule path.
- `src/Makefile`, `lib/Makefile`, `test/Makefile`, `test/deps/cluster_simulator/Makefile`, `test/tap/tests/Makefile`, `test/tap/tests/unit/Makefile`, `test/tap/tests_with_deps/deprecate_eof_support/Makefile`, and `plugins/genai/Makefile` — remove PCRE1 includes and static link flags.
- `test/tap/tests/unit/rule_matching_unit-t.cpp` — direct shared matching coverage for PCRE2 mode.
- `test/tap/tests/pcre2_query_rules-t.cpp` and `test/tap/tests/pgsql-pcre2_query_rules-t.cpp` — live rewrite compatibility coverage through MySQL and PostgreSQL frontends.
- `test/tap/groups/groups.json` — register each new TAP binary in its existing CI group.

### Task 1: Establish failing PCRE2 compatibility tests

**Files:**

- Modify: `test/tap/tests/unit/rule_matching_unit-t.cpp:120-170`
- Create: `test/tap/tests/pcre2_query_rules-t.cpp`
- Create: `test/tap/tests/pgsql-pcre2_query_rules-t.cpp`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**

- Consumes: `bool rule_matches_query(const QP_rule_t*, int, const char*, const char*, const char*, const char*, int, uint64_t, const char*, const char*, const char*, int)` from `query_processor.h`.
- Produces: coverage proving PCRE mode supports PCRE2 variable-length lookbehind and keeps existing rewrite semantics.

- [ ] **Step 1: Add the failing unit assertion for a PCRE2-only construct**

  In `test_match_digest_pcre`, add a second rule using PCRE2 variable-length lookbehind. Keep `query_processor_regex` set to `1`, which is the PCRE-compatible branch.

  ```cpp
  static void test_match_digest_pcre2() {
      QP_rule_t r = make_rule();
      r.match_digest = const_cast<char *>("(?<=A{1,2})B");
      ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
          "127.0.0.1", 6033, 0, "AAB", "SELECT 1", nullptr, 1),
          "PCRE-compatible mode accepts PCRE2 variable-length lookbehind");
  }
  ```

  Increase `plan()` by one and call `test_match_digest_pcre2()` from `main()`.

- [ ] **Step 2: Compile and run the focused unit test to verify RED**

  Run:

  ```bash
  PROXYSQL31=1 make cleanall
  PROXYSQL31=1 make debug
  make -C test/tap/tests/unit rule_matching_unit-t
  ./test/tap/tests/unit/rule_matching_unit-t
  ```

  Expected: the new assertion fails because PCRE 8.45 rejects a variable-length lookbehind and the current `pcrecpp` rule does not match.

- [ ] **Step 3: Add live rewrite tests without changing production code**

  Copy the connection and checked-query helpers from `issue5384-t.cpp` for MySQL and `pgsql-issue5384-t.cpp` for PostgreSQL. Each new test must delete only rule IDs `61190` through `61194`, load the relevant runtime rules, and restore the original `*-query_processor_regex` value in teardown.

  Both frontend tests must insert and execute these rule cases with the PCRE-compatible engine selected:

  ```sql
  -- one replacement: SELECT 1 + 2 becomes SELECT 9 + 2
  (61190, 1, '[0-9]', '9', 'CASELESS', 1)

  -- global replacement: SELECT 1 + 2 becomes SELECT 9 + 9
  (61191, 1, '[0-9]', '9', 'CASELESS,GLOBAL', 1)

  -- pcrecpp whole match and capture expansion
  (61192, 1, '^SELECT ([0-9]+)$', 'SELECT ''\\0:'' || ''\\1''', 'CASELESS', 1)

  -- literal backslash in a pcrecpp replacement
  (61193, 1, '^SELECT 1$', 'SELECT ''\\\\''', 'CASELESS', 1)

  -- malformed legacy escape: query remains SELECT 7
  (61194, 1, '^SELECT 7$', 'SELECT \\x', 'CASELESS', 1)
  ```

  Use dialect-specific string concatenation for the whole-match case: `CONCAT('\\0:', '\\1')` for MySQL and `''\\0:'' || ''\\1''` for PostgreSQL. Fetch the sole result value and assert the exact rewritten result for every valid case; for the malformed case assert `7` is returned.

- [ ] **Step 4: Register the tests before building them**

  Add the MySQL test to the same groups as `issue5384-t` and the PostgreSQL test to the same groups as `pgsql-issue5384-t`:

  ```json
  "pcre2_query_rules-t" : [ "legacy-g10", "mysql-auto_increment_delay_multiplex=0-g4", "mysql-multiplexing=false-g4", "mysql-query_digests=0-g4", "mysql-query_digests_keep_comment=1-g4", "mysql84-g4", "mysql90-g4", "mysql95-g4" ],
  "pgsql-pcre2_query_rules-t" : [ "legacy-g4", "mysql-auto_increment_delay_multiplex=0-g4", "mysql-multiplexing=false-g4", "mysql-query_digests=0-g4", "mysql-query_digests_keep_comment=1-g4" ],
  ```

- [ ] **Step 5: Commit the red tests**

  ```bash
  git add test/tap/tests/unit/rule_matching_unit-t.cpp test/tap/tests/pcre2_query_rules-t.cpp test/tap/tests/pgsql-pcre2_query_rules-t.cpp test/tap/groups/groups.json
  git commit -m "test: define PCRE2 query-rule compatibility"
  ```

### Task 2: Vendor static PCRE2 and replace build references

**Files:**

- Create: `deps/pcre2/pcre2-10.47.tar.gz`
- Modify: `deps/Makefile:35-55,384-391`
- Modify: `include/makefiles_paths.mk:43-45`
- Modify: `src/Makefile`, `lib/Makefile`, `test/Makefile`, `test/deps/cluster_simulator/Makefile`, `test/tap/tests/Makefile`, `test/tap/tests/unit/Makefile`, `test/tap/tests_with_deps/deprecate_eof_support/Makefile`, and `plugins/genai/Makefile`

**Interfaces:**

- Consumes: the PCRE2 10.47 source archive.
- Produces: `$(PCRE2_LDIR)/libpcre2-8.a`, `$(PCRE2_IDIR)/pcre2.h`, and the shared Make variables `PCRE2_PATH`, `PCRE2_IDIR`, and `PCRE2_LDIR`.

- [ ] **Step 1: Add the official source archive and build target**

  Download the official `pcre2-10.47.tar.gz` release archive into `deps/pcre2`. Replace the `pcre` target in `deps/Makefile` with this target and include `pcre2` in `targets`:

  ```make
  pcre2/pcre2/.libs/libpcre2-8.a:
  	cd pcre2 && rm -rf pcre2-*/ || true
  	cd pcre2 && tar -zxf pcre2-10.47.tar.gz
  	cd pcre2/pcre2 && ./configure --disable-shared --enable-static \
  		--enable-pcre2-8 --disable-pcre2-16 --disable-pcre2-32 \
  		--disable-jit --disable-pcre2test-libreadline
  	cd pcre2/pcre2 && CC=${CC} CXX=${CXX} ${MAKE}

  pcre2: pcre2/pcre2/.libs/libpcre2-8.a
  ```

  Keep `--disable-jit`: this migration is a compatibility and maintenance change, not a performance claim.

- [ ] **Step 2: Replace shared include and link variables**

  In `include/makefiles_paths.mk`, replace the PCRE1 variables with:

  ```make
  PCRE2_PATH := $(DEPS_PATH)/pcre2/pcre2
  PCRE2_IDIR := $(PCRE2_PATH)/src
  PCRE2_LDIR := $(PCRE2_PATH)/.libs
  PCRE2_LIBS := -lpcre2-8
  ```

  Update each Makefile listed above so `-I$(PCRE_IDIR)` and `-L$(PCRE_LDIR)` become their PCRE2 equivalents, `-lpcrecpp -lpcre` becomes `$(PCRE2_LIBS)`, and direct PCRE archive paths become `$(PCRE2_LDIR)/libpcre2-8.a`. After the search below returns no production references, remove the entire obsolete `deps/pcre` directory, including its 8.45 source archive and patch.

- [ ] **Step 3: Build the dependency and verify the intended artifacts**

  Run:

  ```bash
  PROXYSQL31=1 make cleanall
  make -C deps pcre2
  test -f deps/pcre2/pcre2/.libs/libpcre2-8.a
  test -f deps/pcre2/pcre2/src/pcre2.h
  rg -n 'pcrecpp|libpcre\.a|libpcrecpp\.a|PCRE_LDIR|PCRE_IDIR' --glob '!docs/**' --glob '!\.git/**'
  ```

  Expected: both PCRE2 artifacts exist and the final search prints no active source or Makefile references.

- [ ] **Step 4: Commit the vendoring and linker conversion**

  ```bash
  git add deps include/makefiles_paths.mk src/Makefile lib/Makefile test/Makefile test/deps/cluster_simulator/Makefile test/tap/tests/Makefile test/tap/tests/unit/Makefile test/tap/tests_with_deps/deprecate_eof_support/Makefile plugins/genai/Makefile
  git commit -m "deps: vendor PCRE2 10.47"
  ```

### Task 3: Implement the private PCRE2 adapter

**Files:**

- Modify: `lib/Query_Processor.cpp:1-100,220-275,2076-2094`

**Interfaces:**

- Consumes: `QP_rule_t::match_digest`, `match_pattern`, `replace_pattern`, and `re_modifiers`.
- Produces: private `Pcre2Regex` with `bool partial_match(const char*) const` and `bool replace(std::string*, const char*, bool) const`.

- [ ] **Step 1: Replace the PCRE1 include and storage fields**

  Define the PCRE2 width before its header and remove `pcrecpp.h`:

  ```cpp
  #define PCRE2_CODE_UNIT_WIDTH 8
  #include <pcre2.h>

  class Pcre2Regex {
  public:
      explicit Pcre2Regex(const char* pattern, uint32_t options);
      ~Pcre2Regex();
      Pcre2Regex(const Pcre2Regex&) = delete;
      bool valid() const;
      bool partial_match(const char* subject) const;
      bool replace(std::string* subject, const char* legacy_rewrite, bool global) const;
  private:
      pcre2_code* code_ {nullptr};
  };
  ```

  Replace `opt1` and `re1` in `__RE2_objects_t` with `Pcre2Regex* re1`. Update the destructor and memory estimate to own and free only this pointer.

- [ ] **Step 2: Implement matching and verify RED becomes GREEN**

  Compile with `PCRE2_CASELESS` only when `QP_RE_MOD_CASELESS` is set. Call `pcre2_compile`, turn a null code object into `valid() == false`, and report both the numeric error offset and text using `pcre2_get_error_message`. Implement `partial_match` with fresh `pcre2_match_data_create_from_pattern`, `pcre2_match`, and `pcre2_match_data_free`; return true only for a non-negative result.

  Wire `compile_query_rule` to construct `Pcre2Regex` for the non-RE2 branch and wire `rule_matches_regex` to call `partial_match`.

  Run:

  ```bash
  PROXYSQL31=1 make cleanall
  PROXYSQL31=1 make debug
  make -C test/tap/tests/unit rule_matching_unit-t
  ./test/tap/tests/unit/rule_matching_unit-t
  ```

  Expected: every TAP assertion passes, including the PCRE2 variable-length lookbehind test added in Task 1.

- [ ] **Step 3: Implement rewrite translation and substitution**

  Add a private helper that converts only the legacy rewrite forms: `\\0` through `\\9` become `${0}` through `${9}`, and `\\\\` becomes a literal backslash escaped for PCRE2 substitution. Return false for every other backslash escape. In `replace`, call `pcre2_substitute` first with a null/zero output buffer and `PCRE2_SUBSTITUTE_OVERFLOW_LENGTH`; allocate the reported size plus one byte, then rerun with `PCRE2_SUBSTITUTE_GLOBAL` when `global` is true. Assign to `*subject` only after a successful second call.

  Replace the current `re1->Replace` and `re1->GlobalReplace` branch with:

  ```cpp
  re2p->re1->replace(
      ret->new_query,
      qr->replace_pattern,
      (qr->re_modifiers & QP_RE_MOD_GLOBAL) == QP_RE_MOD_GLOBAL
  );
  ```

- [ ] **Step 4: Run the focused checks**

  Run:

  ```bash
  make -C test/tap/tests/unit rule_matching_unit-t
  ./test/tap/tests/unit/rule_matching_unit-t
  git diff --check
  ```

  Expected: the unit binary exits zero and `git diff --check` emits nothing.

- [ ] **Step 5: Commit the adapter**

  ```bash
  git add lib/Query_Processor.cpp test/tap/tests/unit/rule_matching_unit-t.cpp
  git commit -m "feat: use PCRE2 for query rules"
  ```

### Task 4: Run live compatibility regressions and lint registration

**Files:**

- Modify: `test/tap/tests/pcre2_query_rules-t.cpp`
- Modify: `test/tap/tests/pgsql-pcre2_query_rules-t.cpp`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**

- Consumes: a built ProxySQL, configured test MySQL/PostgreSQL backends, and the query-rule admin tables.
- Produces: deterministic TAP evidence for first/global replacements, capture expansion, literal backslashes, and malformed rewrites.

- [ ] **Step 1: Build the new TAP binaries**

  Run:

  ```bash
  make -C test/tap/tests pcre2_query_rules-t pgsql-pcre2_query_rules-t
  ```

  Expected: both binaries link against `libpcre2-8.a`; the link command contains neither `-lpcre` nor `-lpcrecpp`.

- [ ] **Step 2: Run MySQL and PostgreSQL regression tests**

  With the standard TAP environment running, execute:

  ```bash
  ./test/tap/tests/pcre2_query_rules-t
  ./test/tap/tests/pgsql-pcre2_query_rules-t
  ./test/tap/tests/issue5384-t
  ./test/tap/tests/pgsql-issue5384-t
  ./test/tap/tests/pgsql-extended_query_protocol_query_rules_test-t
  ```

  Expected: every test returns zero and the explicit teardown removes only IDs `61190` through `61194`.

- [ ] **Step 3: Run repository lint checks**

  Run:

  ```bash
  python3 scripts/lint/check_format.py --base origin/v3.0
  python3 test/tap/groups/check_groups.py --source
  ```

  Expected: both commands return zero; the new test binaries are registered exactly once in `groups.json`.

- [ ] **Step 4: Commit regression coverage**

  ```bash
  git add test/tap/tests/pcre2_query_rules-t.cpp test/tap/tests/pgsql-pcre2_query_rules-t.cpp test/tap/groups/groups.json
  git commit -m "test: cover PCRE2 query-rule rewrites"
  ```

### Task 5: Perform clean build verification

**Files:**

- Modify: none.

**Interfaces:**

- Consumes: the full PCRE2 migration branch.
- Produces: fresh build and test evidence for the PR description.

- [ ] **Step 1: Verify no PCRE1 reference remains**

  Run:

  ```bash
  rg -n 'pcrecpp|pcre-8\.45|libpcre\.a|libpcrecpp\.a|PCRE_LDIR|PCRE_IDIR' --glob '!docs/**' --glob '!\.git/**'
  ```

  Expected: no output.

- [ ] **Step 2: Build from clean state**

  Run:

  ```bash
  PROXYSQL31=1 make cleanall
  PROXYSQL31=1 make -j"$(nproc)" debug
  make -C test/tap/tests/unit rule_matching_unit-t
  make -C test/deps/cluster_simulator
  ```

  Expected: all commands return zero.

- [ ] **Step 3: Re-run focused tests and lint**

  Run:

  ```bash
  ./test/tap/tests/unit/rule_matching_unit-t
  ./test/tap/tests/pcre2_query_rules-t
  ./test/tap/tests/pgsql-pcre2_query_rules-t
  python3 scripts/lint/check_format.py --base origin/v3.0
  python3 test/tap/groups/check_groups.py --source
  git status --short
  ```

  Expected: tests and lint return zero; status contains only intentional, committed changes.

- [ ] **Step 4: Commit any verification-only correction and publish**

  If verification required a source correction, add a focused commit using its affected paths, push `agent/issue-6119-pcre2`, and update draft PR #6120 with the exact build and test commands that passed.
