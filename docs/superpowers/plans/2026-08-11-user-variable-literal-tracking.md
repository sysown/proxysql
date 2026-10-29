# Literal User-Variable Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in, ParserSQL-backed tracking and replay of literal MySQL user-defined-variable assignments so supported `SET @name = literal` statements remain multiplexable without leaking state between frontend sessions.

**Architecture:** ParserSQL supplies lossless user-variable and literal AST nodes, full-input coverage, and read/write usage classification. ProxySQL keeps bounded, symmetric user-variable maps on frontend and backend `MySQL_Connection` objects, stages client assignments until the original backend SET succeeds, includes the maps in pool selection, and replays deterministic SET batches after ordinary session-variable synchronization. Anything outside the proven subset follows the current connection-bound fallback.

**Tech Stack:** C++17, ParserSQL recursive-descent parser and GoogleTest, ProxySQL MySQL session state machine, MariaDB Connector/C async APIs, GNU Make, TAP, nlohmann JSON, SpookyHash, OpenSSL `RAND_bytes`, Prometheus counters.

## Global Constraints

- Treat [the approved design](../specs/2026-08-11-user-variable-literal-tracking-design.md) as authoritative. Do not widen the supported syntax while implementing.
- The configuration variable is the integer `mysql-user_variable_tracking`, default `0`, with the initial accepted range `0..1`. Do not make it a boolean; later integer modes are reserved for different semantics.
- Mode `1` accepts new assignments only when `mysql-set_parser_algorithm=3` or `mysql-query_processor_parser=1`. Existing tracked sessions drain safely when either the feature or its parser prerequisite is disabled at runtime.
- Only text-protocol, single-statement SET commands whose targets are all user variables and whose right-hand sides are all approved literals are tracked. Prepared SETs, mixed system/user SETs, expressions, and partial parses retain current fallback behavior.
- Forward the client's original supported SET. Commit frontend and backend maps only after the backend returns OK; discard pending state on every error or retry path.
- Raw string replay is valid only under the interpretation context in which the assignment succeeded. If a session with tracked state later changes `sql_mode`, `character_set_client`, `character_set_connection`, `collation_connection`, `SET NAMES`, or `SET CHARACTER SET`, synchronize the old state first and take the existing connection-bound fallback before applying that context change. Do the same if backend session tracking reports one of those context changes. This preserves value/type/charset/collation correctness without evaluating literals in ProxySQL.
- Never use hashes as the correctness test. Hash first for speed, then compare literal kind, replay target, and raw literal exactly.
- Never emit variable names, replay targets, values, raw literals, or per-entry hashes through logs, stats, or `PROXYSQL INTERNAL SESSION`. Diagnostics expose only counts, byte totals, and one process-keyed aggregate fingerprint.
- Append new ParserSQL public enum members; never insert them in the middle. This preserves ordinal compatibility with existing consumers.
- Follow `doc/agents/common-mistakes.md`: validate the changed ParserSQL through the real ProxySQL adapter and the legacy SET-parser comparison tests before creating the ParserSQL tag. Produce one ParserSQL release and one downstream version bump.
- Do not modify or remove the unrelated `blogs/` tree or `docs/superpowers/plans/2026-08-11-gtid-from-ok-packets.md` currently present in the ProxySQL working tree.
- Run each test first in its failing state, make the smallest production change, rerun it green, and commit at the task boundary shown below. Do not refactor adjacent code.

---

### Task 1: Add the lossless ParserSQL contract and prove it through ProxySQL before release

**Files:**

- Modify in the isolated ParserSQL worktree: `include/sql_parser/token.h`
- Modify in the isolated ParserSQL worktree: `include/sql_parser/common.h`
- Modify in the isolated ParserSQL worktree: `include/sql_parser/tokenizer.h`
- Modify in the isolated ParserSQL worktree: `include/sql_parser/ast.h`
- Modify in the isolated ParserSQL worktree: `include/sql_parser/expression_parser.h`
- Modify in the isolated ParserSQL worktree: `include/sql_parser/set_parser.h`
- Modify in the isolated ParserSQL worktree: `include/sql_parser/parse_result.h`
- Modify in the isolated ParserSQL worktree: `include/sql_parser/parser.h`
- Create in the isolated ParserSQL worktree: `include/sql_parser/user_variable.h`
- Modify in the isolated ParserSQL worktree: `src/sql_parser/parser.cpp`
- Modify in the isolated ParserSQL worktree: `tests/test_tokenizer.cpp`
- Modify in the isolated ParserSQL worktree: `tests/test_expression.cpp`
- Modify in the isolated ParserSQL worktree: `tests/test_set.cpp`
- Create in the isolated ParserSQL worktree: `tests/test_user_variable.cpp`
- Modify in the isolated ParserSQL worktree: `Makefile`
- Create in ProxySQL: `include/MySQL_User_Variables.h`
- Modify in ProxySQL: `include/Query_Processor_ParserSQL.h`
- Modify in ProxySQL: `lib/Query_Processor_ParserSQL.cpp`
- Modify in ProxySQL: `test/tap/tests/unit/parsersql_unit-t.cpp`
- Modify in ProxySQL: `test/tap/tests/setparser_parsersql_test.cpp`

**Interfaces:**

Append these ParserSQL enum members at the end of their respective enums:

```cpp
// TokenType, appended after every existing token.
TK_USER_VARIABLE,
TK_HEX_LITERAL,
TK_BIT_LITERAL,

// NodeType, appended after every existing node.
NODE_USER_VARIABLE,
NODE_LITERAL_HEX,
NODE_LITERAL_BIT,
```

Extend tokens and AST nodes with an exact source span while keeping `text` / `value()` semantics unchanged for existing emitters:

```cpp
struct Token {
    TokenType type = TokenType::TK_EOF;
    StringRef text;
    StringRef source;
    uint32_t offset = 0;
};

struct AstNode {
    AstNode* first_child;
    AstNode* next_sibling;
    const char* value_ptr;
    const char* source_ptr;
    uint32_t value_len;
    uint32_t source_len;
    NodeType type;
    uint16_t flags;

    StringRef value() const;
    StringRef source() const;
    void set_value(StringRef ref);
    void set_source(StringRef ref);
    void add_child(AstNode* child);
};

AstNode* make_node_from_token(
    Arena& arena, NodeType type, const Token& token, uint16_t flags = 0);

static_assert(sizeof(AstNode) == 48, "AstNode layout changed unexpectedly");
```

Add strict parse metadata and the upstream usage API:

```cpp
struct ParseResult {
    enum Status : uint8_t { OK = 0, PARTIAL, ERROR };
    Status status = ERROR;
    StmtType stmt_type = StmtType::UNKNOWN;
    AstNode* ast = nullptr;
    ErrorInfo error;
    StringRef remaining;
    bool full_input = false;
    bool has_user_variables = false;
    // existing fields remain unchanged
};

enum class UserVariableUsage : uint8_t {
    NO_USER_VARIABLE,
    READ_ONLY,
    UNSAFE_OR_UNKNOWN
};

UserVariableUsage classify_mysql_user_variable_usage(const ParseResult& result);
```

Define the downstream typed contract in `include/MySQL_User_Variables.h` exactly once so both the adapter and connection state can use it without a circular dependency:

```cpp
enum class UserVariableSetStatus : uint8_t {
    NOT_USER_VARIABLE_SET,
    SUPPORTED,
    UNSUPPORTED,
    PARSE_ERROR
};

enum class UserVariableLiteralKind : uint8_t {
    STRING,
    INTEGER,
    DECIMAL,
    HEXADECIMAL,
    BIT,
    NULL_VALUE
};

enum class UserVariableUsage : uint8_t {
    NO_USER_VARIABLE,
    READ_ONLY,
    UNSAFE_OR_UNKNOWN
};

struct UserVariableAssignment {
    std::string canonical_name;
    std::string replay_target;
    std::string raw_literal;
    UserVariableLiteralKind kind;
    uint64_t hash;
};

struct UserVariableSetAnalysis {
    UserVariableSetStatus status { UserVariableSetStatus::NOT_USER_VARIABLE_SET };
    std::vector<UserVariableAssignment> assignments;
};

UserVariableSetAnalysis parsersql_analyze_user_variable_set_mysql(
    const char* query, size_t query_length);
UserVariableUsage parsersql_classify_user_variable_usage_mysql(
    const char* query, size_t query_length);
```

- [ ] **Step 1: Create an isolated upstream worktree from the current vendored release**

```bash
git -C /data/rene/ParserSQL fetch origin --tags
git -C /data/rene/ParserSQL worktree add \
  /data/rene/ParserSQL-user-variable-literals \
  -b feature/user-variable-literals v1.0.10
git -C /data/rene/ParserSQL-user-variable-literals status --short
```

Expected: the new ParserSQL worktree is clean and based on `v1.0.10`. Leave the unrelated untracked `.claude/` and `third_party/libpg_query/` in `/data/rene/ParserSQL` untouched.

- [ ] **Step 2: Add failing upstream tokenizer, AST, coverage, and usage tests**

Add focused GoogleTests covering all of these cases:

- exact source and typed tokens for `1`, `1.25`, `.25`, `1.`, `1e3`, `1.2E-3`, `0xCAFE`, `X'CAFE'`, `0b101`, `B'101'`, single/double-quoted strings, and `NULL`;
- malformed or incomplete hex, bit, exponent, quoted string, and quoted user-variable forms;
- `@plain`, `@with.dot`, `@with$dollar`, `@'quoted-name'`, `@"quoted-name"`, and ``@`quoted-name` `` represented as `NODE_USER_VARIABLE`, with decoded value and exact replayable source;
- doubled quote/backtick escapes in quoted variable names, with their exact source retained;
- quoted variable names containing backslashes remain parseable upstream but are rejected by the ProxySQL tracking adapter because their decoded identity depends on session SQL mode;
- direct unary `+` and `-` retaining a `NODE_UNARY_OP` source span, while parentheses and operators remain expression nodes;
- `full_input=true` only for EOF or one optional trailing semicolon followed by EOF; trailing commas, tokens, or a second statement are false;
- `NO_USER_VARIABLE` for `SELECT 1` and `SELECT '@x'`, `READ_ONLY` for `SELECT @x` / supported predicates that read `@x`, and `UNSAFE_OR_UNKNOWN` for `SET @x=1`, `SELECT @x:=1`, `SELECT id INTO @x FROM test.uv_source`, calls/functions/placeholders/subqueries containing `@x`, malformed input, and incomplete parsing.

Register `tests/test_user_variable.cpp` in `TEST_SRCS`, then run:

```bash
make -C /data/rene/ParserSQL-user-variable-literals test
```

Expected: new tests fail because the tokenizer lacks these literal/user-variable types, source spans, full-input status, and usage classification.

- [ ] **Step 3: Implement the upstream lexical and AST contract**

Implement these rules in ParserSQL:

1. `TK_USER_VARIABLE` consumes a whole MySQL user variable beginning at `@`, but `@@` remains `TK_DOUBLE_AT`. Unquoted names accept alphanumeric bytes plus `.`, `_`, and `$`. Quoted names accept MySQL string/backtick forms and reject missing closing delimiters.
2. The user-variable token keeps the full `@...` bytes in `source`. `SetParser` / `ExpressionParser` decode unquoted names and doubled-delimiter quoted names into arena storage, enforce the 64-byte decoded-name limit, and build `NODE_USER_VARIABLE` with decoded `value()` plus exact `source()`. Backslash-containing quoted names retain lossless source but are not eligible for downstream tracking.
3. `scan_number()` supports fixed and exponent forms without accepting a bare dot or incomplete exponent.
4. `0x...` / `0b...` and `X'...'` / `B'...'` receive distinct literal token and node types. Reject characters outside each base lexically; leave server-specific semantic validation to the backend.
5. Every literal node carries its exact source, including quote delimiters and escapes. Unary `+` and `-` both produce `NODE_UNARY_OP` and span from the sign through the operand.
6. `Parser::parse()` copies `tokenizer_.has_user_variables()` into the result. `scan_to_end()` sets `full_input` only when the grammar stopped at EOF or at a single trailing semicolon followed by EOF; it records the first unconsumed token in `remaining` otherwise.
7. `classify_mysql_user_variable_usage()` traverses the AST with an explicit read-context allowlist. Any `NODE_USER_VARIABLE` below `NODE_VAR_TARGET` or `NODE_INTO_CLAUSE` is a write. A user-variable query containing `NODE_FUNCTION_CALL`, `NODE_CALL_STMT`, `NODE_DO_STMT`, `NODE_PLACEHOLDER`, `NODE_SUBQUERY`, or an unknown ancestor shape is unsafe. Direct SELECT items and ordinary unary/binary predicate expressions are read-only. A parse with `has_user_variables` but without `OK`, `full_input`, or an AST is unsafe.

Run the upstream suite and grammar build:

```bash
make -C /data/rene/ParserSQL-user-variable-literals clean
make -C /data/rene/ParserSQL-user-variable-literals test
make -C /data/rene/ParserSQL-user-variable-literals build-corpus-test
```

Expected: all ParserSQL tests pass and `corpus_test` builds without warnings or enum-index regressions.

- [ ] **Step 4: Add failing ProxySQL adapter tests against the new contract**

In `parsersql_unit-t.cpp`, test the typed API with exact assertions for:

- the reported four-assignment browser metadata SET;
- all supported literal families, signs, source order, repeated names, case-insensitive canonical keys, safely decoded quoted names, and exact raw replay text;
- backslash-containing quoted target names return `UNSUPPORTED`, while backslashes in RHS string literals remain supported because ProxySQL stores/replays their raw source without decoding;
- mixed user/system targets, expressions, casts, parentheses, introducers, collations, subqueries, placeholders, prepared-looking forms, trailing commas, multi-statements, malformed SQL, and names over 64 bytes;
- all-or-nothing results with an empty assignment vector for `UNSUPPORTED` and `PARSE_ERROR`;
- usage results for no variable, read-only, writes, malformed input, and an `@` inside a string/comment.

In `setparser_parsersql_test.cpp`, add regressions proving the existing lossy system-variable SET adapter still returns the same maps after the AST/source changes.

Build the upstream library, overlay only generated build products and changed headers into ProxySQL's ignored extracted dependency, then run the downstream tests:

```bash
make -C /data/rene/ParserSQL-user-variable-literals lib
cp -a /data/rene/ParserSQL-user-variable-literals/include/sql_parser/. \
  deps/parsersql/parsersql/include/sql_parser/
cp /data/rene/ParserSQL-user-variable-literals/libsqlparser.a \
  deps/parsersql/parsersql/libsqlparser.a
make -C lib clean
make -j4 debug
make -C test/tap/tests/unit parsersql_unit-t
./test/tap/tests/unit/parsersql_unit-t
make -C test/tap/tests setparser_parsersql_test setparser_test setparser_test2 setparser_test3
./test/tap/tests/setparser_parsersql_test
./test/tap/tests/setparser_test
./test/tap/tests/setparser_test2
./test/tap/tests/setparser_test3
```

Expected before adapter implementation: the ProxySQL unit test fails to compile because the typed functions do not exist.

- [ ] **Step 5: Implement the typed ProxySQL adapter and rerun the real consumer gate**

Implement `parsersql_analyze_user_variable_set_mysql()` as an all-or-nothing AST walk:

- `PARSE_ERROR` for non-OK or non-full input;
- `NOT_USER_VARIABLE_SET` for non-SET input or a SET without any user-variable target;
- `UNSUPPORTED` for mixed targets, malformed assignment shape, any RHS outside the approved literal/unary forms, or an invalid target;
- `SUPPORTED` only after every assignment is converted.

Use the decoded `NODE_USER_VARIABLE::value()` for ASCII-lowercased `canonical_name`, the validated target `source()` for `replay_target`, and the literal/unary `source()` for `raw_literal`. Reject a quoted target source containing a backslash so canonical identity is independent of session SQL mode. Compute the fast entry hash over a length-delimited tuple of kind, target, and literal with `SpookyHash::Hash64`; retain exact strings for collision-safe comparison.

Map the upstream classifier enum one-for-one in `parsersql_classify_user_variable_usage_mysql()`. Reset the thread-local parser only after all source spans have been copied into owning `std::string` values.

Rerun every command from Step 4, plus:

```bash
git -C /data/rene/ParserSQL-user-variable-literals diff --check
git diff --check -- \
  include/MySQL_User_Variables.h \
  include/Query_Processor_ParserSQL.h \
  lib/Query_Processor_ParserSQL.cpp \
  test/tap/tests/unit/parsersql_unit-t.cpp \
  test/tap/tests/setparser_parsersql_test.cpp
```

Expected: upstream tests, ProxySQL typed adapter tests, the ParserSQL SET comparison, and all three legacy SET parsers pass.

- [ ] **Step 6: Commit upstream only after the downstream gate is green**

```bash
git -C /data/rene/ParserSQL-user-variable-literals add \
  include/sql_parser/token.h \
  include/sql_parser/common.h \
  include/sql_parser/tokenizer.h \
  include/sql_parser/ast.h \
  include/sql_parser/expression_parser.h \
  include/sql_parser/set_parser.h \
  include/sql_parser/parse_result.h \
  include/sql_parser/parser.h \
  include/sql_parser/user_variable.h \
  src/sql_parser/parser.cpp \
  tests/test_tokenizer.cpp \
  tests/test_expression.cpp \
  tests/test_set.cpp \
  tests/test_user_variable.cpp \
  Makefile
git -C /data/rene/ParserSQL-user-variable-literals commit \
  -m "feat: expose lossless MySQL user variables"
```

Leave the ProxySQL adapter/test changes uncommitted until the official archive is installed in Task 2; that keeps every ProxySQL commit buildable from a clean checkout.

---

### Task 2: Create ParserSQL v1.0.11 and vendor it exactly once

**Files:**

- Delete: `deps/parsersql/parsersql-1.0.10.tar.gz`
- Create: `deps/parsersql/parsersql-1.0.11.tar.gz`
- Modify symlink: `deps/parsersql/parsersql`
- Modify: `deps/parsersql/README.md`
- Include the already-tested downstream files from Task 1:
  `include/MySQL_User_Variables.h`, `include/Query_Processor_ParserSQL.h`,
  `lib/Query_Processor_ParserSQL.cpp`,
  `test/tap/tests/unit/parsersql_unit-t.cpp`, and
  `test/tap/tests/setparser_parsersql_test.cpp`

- [ ] **Step 1: Tag the validated upstream commit locally and create the canonical archive**

```bash
git -C /data/rene/ParserSQL-user-variable-literals status --short
git -C /data/rene/ParserSQL-user-variable-literals tag -a v1.0.11 \
  -m "ParserSQL 1.0.11"
git -C /data/rene/ParserSQL-user-variable-literals archive \
  --format=tar.gz \
  --prefix=ParserSQL-1.0.11/ \
  v1.0.11 \
  -o /tmp/parsersql-1.0.11.tar.gz
sha256sum /tmp/parsersql-1.0.11.tar.gz
```

Expected: upstream status is clean before tagging, and the archive is generated from the validated tag. Do not push the branch or tag unless the user separately authorizes that external write.

- [ ] **Step 2: Install the single downstream version bump**

```bash
git rm deps/parsersql/parsersql-1.0.10.tar.gz
cp /tmp/parsersql-1.0.11.tar.gz deps/parsersql/parsersql-1.0.11.tar.gz
ln -sfn parsersql-1.0.11 deps/parsersql/parsersql
```

Update the audit history in `deps/parsersql/README.md` with one v1.0.11 entry describing lossless literal/user-variable nodes, full-input coverage, and usage classification.

- [ ] **Step 3: Rebuild and retest from the official tarball rather than the overlay**

```bash
make -C deps parsersql/parsersql/libsqlparser.a
make -C lib clean
make -j4 debug
make -C test/tap/tests/unit parsersql_unit-t
./test/tap/tests/unit/parsersql_unit-t
make -C test/tap/tests setparser_parsersql_test setparser_test setparser_test2 setparser_test3
./test/tap/tests/setparser_parsersql_test
./test/tap/tests/setparser_test
./test/tap/tests/setparser_test2
./test/tap/tests/setparser_test3
```

Expected: the official archive gives the same green result as the pre-tag overlay.

- [ ] **Step 4: Commit the vendored release and typed adapter together**

```bash
git add \
  deps/parsersql/parsersql-1.0.11.tar.gz \
  deps/parsersql/parsersql \
  deps/parsersql/README.md \
  include/MySQL_User_Variables.h \
  include/Query_Processor_ParserSQL.h \
  lib/Query_Processor_ParserSQL.cpp \
  test/tap/tests/unit/parsersql_unit-t.cpp \
  test/tap/tests/setparser_parsersql_test.cpp
git commit -m "vendor: add ParserSQL user-variable support"
```

---

### Task 3: Build the bounded, collision-safe user-variable state model

**Files:**

- Modify: `include/MySQL_User_Variables.h`
- Create: `lib/MySQL_User_Variables.cpp`
- Modify: `lib/Makefile`
- Create: `test/tap/tests/unit/mysql_user_variables_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**

```cpp
struct MySQL_User_Variable_Entry {
    std::string replay_target;
    std::string raw_literal;
    UserVariableLiteralKind kind;
    uint64_t hash;

    size_t stored_bytes() const;
    bool exactly_equals(const MySQL_User_Variable_Entry& other) const;
};

enum class MySQL_User_Variable_Apply_Result : uint8_t {
    OK,
    VARIABLE_LIMIT,
    BYTE_LIMIT
};

struct MySQL_User_Variable_Replay_Batch {
    std::string sql;
    std::vector<UserVariableAssignment> assignments;
};

enum class MySQL_User_Variable_Replay_Status : uint8_t {
    OK,
    ASSIGNMENT_TOO_LARGE
};

struct MySQL_User_Variable_Replay_Plan {
    MySQL_User_Variable_Replay_Status status;
    std::vector<MySQL_User_Variable_Replay_Batch> batches;
};

class MySQL_User_Variable_State {
public:
    static constexpr size_t kMaxVariables = 128;
    static constexpr size_t kMaxStoredBytes = 64 * 1024;

    MySQL_User_Variable_Apply_Result stage(
        const std::vector<UserVariableAssignment>& assignments,
        MySQL_User_Variable_State& staged) const;
    void apply(const std::vector<UserVariableAssignment>& assignments);
    void clear();
    size_t size() const;
    size_t stored_bytes() const;
    bool has_names_absent_from(const MySQL_User_Variable_State& desired) const;
    unsigned int count_matches(
        const MySQL_User_Variable_State& desired,
        unsigned int& not_matching) const;
    MySQL_User_Variable_Replay_Plan build_replay_plan(
        const MySQL_User_Variable_State& actual,
        size_t max_query_bytes) const;
    std::string diagnostic_fingerprint() const;
};
```

- [ ] **Step 1: Add a failing unit target and state tests**

Register `mysql_user_variables_unit-t` in `UNIT_TESTS` and `unit-tests-g1`. Test:

- empty state, insertion, replacement, repeated assignment order, and byte-accounting shrink/growth;
- 128 distinct names accepted, the 129th rejected atomically, exactly 64 KiB accepted, and the next byte rejected atomically;
- hash collisions simulated by giving two unequal entries the same `hash`; `exactly_equals()` and matching must still report a mismatch;
- backend-extra-name detection and exact match/mismatch counts;
- deterministic canonical-name replay order, batching without exceeding `max_query_bytes`, raw target/literal preservation, already-equal entries skipped, and a single over-limit assignment returning `ASSIGNMENT_TOO_LARGE` without a partial plan;
- fingerprint stability inside one process, changes when state changes, and output that contains none of the input name/target/literal text.

```bash
make -C test/tap/tests/unit mysql_user_variables_unit-t
```

Expected: compilation fails because the state class and implementation do not exist.

- [ ] **Step 2: Implement state staging, comparison, and replay planning**

Use `std::map<std::string, MySQL_User_Variable_Entry>` for deterministic order. `stage()` must copy the current state, apply assignments sequentially to the copy, check distinct-name and stored-byte limits after replacement accounting, and leave both the caller and output unchanged on failure. `apply()` is only called after a successful `stage()` or successful backend command.

Replay SQL concatenates only ParserSQL-validated targets and raw literals, without injecting spaces into their syntax. For example:

```text
SET @browser_lang='en-US',@browser_timezone='GMT+2'
```

Initialize two process-random 64-bit SpookyHash seeds once with `RAND_bytes`. Hash a deterministic length-delimited serialization of every canonical name, target, kind, and literal to produce the single aggregate diagnostic fingerprint. If `RAND_bytes` fails, log one warning and return an empty fingerprint so callers omit the field rather than expose an unkeyed value.

Add `MySQL_User_Variables.oo` to `_OBJ_CXX` and run:

```bash
make -C lib obj/MySQL_User_Variables.oo
make -C test/tap/tests/unit mysql_user_variables_unit-t
./test/tap/tests/unit/mysql_user_variables_unit-t
```

Expected: all state and replay-builder tests pass.

- [ ] **Step 3: Commit the state model**

```bash
git add \
  include/MySQL_User_Variables.h \
  lib/MySQL_User_Variables.cpp \
  lib/Makefile \
  test/tap/tests/unit/mysql_user_variables_unit-t.cpp \
  test/tap/tests/unit/Makefile \
  test/tap/groups/groups.json
git commit -m "feat: add bounded MySQL user-variable state"
```

---

### Task 4: Register the integer configuration mode and prerequisite warning

**Files:**

- Modify: `include/MySQL_Thread.h`
- Modify: `include/proxysql_structs.h`
- Modify: `lib/MySQL_Thread.cpp`
- Modify: `lib/Admin_FlushVariables.cpp`
- Modify: `test/tap/tests/unit/mysql_variables_unit-t.cpp`

- [ ] **Step 1: Write failing variable-registration tests**

Extend `mysql_variables_unit-t.cpp` to assert:

- `user_variable_tracking` appears in `get_variables_list()`;
- its compiled default is integer `0`;
- `set_variable("user_variable_tracking", "1")` succeeds and reads back as `1`;
- `-1` and `2` are rejected and preserve the prior value.

```bash
make -C test/tap/tests/unit mysql_variables_unit-t
./test/tap/tests/unit/mysql_variables_unit-t
```

Expected: registration/default assertions fail.

- [ ] **Step 2: Add the integer variable through every runtime layer**

Add:

```cpp
// MySQL_Threads_Handler::variables
int user_variable_tracking;

// thread-local declaration and extern
__thread int mysql_thread___user_variable_tracking;
```

Register `user_variable_tracking`, initialize it to `0`, add it to `VariablesPointers_int` with range `0..1`, and refresh it beside `query_processor_parser` / `set_parser_algorithm`.

In `LOAD MYSQL VARIABLES TO RUNTIME`, emit one warning when the loaded values satisfy:

```cpp
user_variable_tracking == 1 &&
set_parser_algorithm != 3 &&
query_processor_parser != 1
```

The warning must name all three fully qualified variables, explain that tracking remains inactive, and must not rewrite either parser setting.

Rerun the unit test and compile the admin path:

```bash
make -C test/tap/tests/unit mysql_variables_unit-t
./test/tap/tests/unit/mysql_variables_unit-t
make -C lib obj/Admin_FlushVariables.oo obj/MySQL_Thread.oo
```

Expected: validation passes and the admin/thread objects compile.

- [ ] **Step 3: Commit configuration support**

```bash
git add \
  include/MySQL_Thread.h \
  include/proxysql_structs.h \
  lib/MySQL_Thread.cpp \
  lib/Admin_FlushVariables.cpp \
  test/tap/tests/unit/mysql_variables_unit-t.cpp
git commit -m "feat: add MySQL user-variable tracking mode"
```

---

### Task 5: Attach state to connections, pool matching, resets, and safe diagnostics

**Files:**

- Modify: `include/mysql_connection.h`
- Modify: `lib/mysql_connection.cpp`
- Modify: `lib/mysql_data_stream.cpp`
- Modify: `test/tap/tests/unit/mysql_user_variables_unit-t.cpp`

- [ ] **Step 1: Add failing connection-state tests**

Extend the state unit test with small `MySQL_Connection` fixtures to verify:

- `requires_CHANGE_USER()` is true when the backend has a user-variable name absent from the frontend;
- exact equal entries contribute to `number_of_matching_session_variables()`;
- same-hash/different-value entries increment `not_matching` and do not count as matches;
- `reset()` clears user variables along with ordinary variables;
- diagnostic JSON reports only `count`, `stored_bytes`, and optional `fingerprint`, never the source strings.

```bash
make -C test/tap/tests/unit mysql_user_variables_unit-t
./test/tap/tests/unit/mysql_user_variables_unit-t
```

Expected: the new connection assertions fail.

- [ ] **Step 2: Add symmetric connection maps and pool semantics**

Add this public member to `MySQL_Connection`:

```cpp
MySQL_User_Variable_State user_variables;
```

Extend `requires_CHANGE_USER()` with backend-extra-name detection. Extend `number_of_matching_session_variables()` with exact user-variable match/mismatch accounting. Clear the map in `MySQL_Connection::reset()`; this automatically covers successful backend `COM_CHANGE_USER`, reset algorithms, frontend `COM_RESET_CONNECTION`, frontend `COM_CHANGE_USER`, and disconnect teardown because those paths already call `reset()`.

Add aggregate JSON under:

```text
conn.user_variables
backends[].conn.user_variables
```

with `count`, `stored_bytes`, and `fingerprint` only. Omit `fingerprint` if keyed initialization failed.

```bash
make -C lib obj/mysql_connection.oo obj/mysql_data_stream.oo
make -C test/tap/tests/unit mysql_user_variables_unit-t
./test/tap/tests/unit/mysql_user_variables_unit-t
```

Expected: connection matching, reset, and redaction tests pass.

- [ ] **Step 3: Commit connection and pool integration**

```bash
git add \
  include/mysql_connection.h \
  lib/mysql_connection.cpp \
  lib/mysql_data_stream.cpp \
  test/tap/tests/unit/mysql_user_variables_unit-t.cpp
git commit -m "feat: match pooled connections by user variables"
```

---

### Task 6: Add user-variable counters to stats and Prometheus

**Files:**

- Modify: `include/MySQL_Thread.h`
- Modify: `lib/MySQL_Thread.cpp`
- Modify: `test/tap/tests/unit/statistics_unit-t.cpp`

**Counters:**

```text
User_variable_assignments_tracked
User_variable_replay_commands
User_variable_replay_failures
User_variable_fallback_unsupported
User_variable_fallback_limits
```

```text
proxysql_mysql_user_variable_assignments_tracked_total
proxysql_mysql_user_variable_replay_commands_total
proxysql_mysql_user_variable_replay_failures_total
proxysql_mysql_user_variable_fallback_unsupported_total
proxysql_mysql_user_variable_fallback_limits_total
```

- [ ] **Step 1: Add failing stats-registration assertions**

Extend `statistics_unit-t.cpp` to assert the five new status names and Prometheus metric descriptors are registered exactly once.

```bash
make -C test/tap/tests/unit statistics_unit-t
./test/tap/tests/unit/statistics_unit-t
```

Expected: all five names are absent.

- [ ] **Step 2: Register thread status and Prometheus counters**

Append five `MySQL_Thread_status_variable` members before `MY_st_var_END`, append five `p_th_counter::metric` values before `SIZE_`, and add the one-to-one mappings/descriptions in `lib/MySQL_Thread.cpp`. Keep assignments-count semantics separate from SET-command semantics: a four-target successful SET increments assignments by four, while each internal replay batch increments replay commands by one.

```bash
make -C lib obj/MySQL_Thread.oo
make -C test/tap/tests/unit statistics_unit-t
./test/tap/tests/unit/statistics_unit-t
```

Expected: stats registration passes.

- [ ] **Step 3: Commit observability registration**

```bash
git add include/MySQL_Thread.h lib/MySQL_Thread.cpp \
  test/tap/tests/unit/statistics_unit-t.cpp
git commit -m "feat: expose MySQL user-variable tracking counters"
```

---

### Task 7: Add deterministic backend replay to the session state machine

**Files:**

- Modify: `include/proxysql_structs.h`
- Modify: `include/MySQL_Session.h`
- Modify: `lib/MySQL_Session.cpp`
- Modify: `test/tap/tests/unit/mysql_user_variables_unit-t.cpp`

**Session additions:**

```cpp
// Append to session_status.
SETTING_USER_VARIABLES,

std::vector<MySQL_User_Variable_Replay_Batch> user_variable_replay_batches;
size_t user_variable_replay_batch_index { 0 };

bool handler_again___verify_backend_user_variables(MySQL_Connection* myconn);
bool handler_again___status_SETTING_USER_VARIABLES(int* rc);
```

- [ ] **Step 1: Add failing replay-transition decision tests**

Factor the non-I/O completion decision into a small function in `MySQL_User_Variables.h/.cpp` and test:

- successful batch applies only that batch to backend state;
- another batch remains in `SETTING_USER_VARIABLES`;
- the last successful batch resumes the saved client-query state;
- replay error applies nothing from the failed batch, chooses `FAIL_CLIENT_QUERY_AND_RETIRE_BACKEND`, and leaves frontend desired state intact.

```bash
make -C test/tap/tests/unit mysql_user_variables_unit-t
./test/tap/tests/unit/mysql_user_variables_unit-t
```

Expected: replay transition tests fail until the helper exists.

- [ ] **Step 2: Implement verification after ordinary variables**

Call `handler_again___verify_backend_user_variables(myconn)` immediately after `handler_again___verify_multiple_variables(myconn)` and before the client query is sent. It must:

1. compare the frontend desired map with the selected backend map;
2. build deterministic batches bounded by `myconn->options.max_allowed_pkt` and ProxySQL's query packet framing;
3. save the current processing status, initialize the batch index, and enter `SETTING_USER_VARIABLES` when work exists;
4. do nothing when maps already match.

This preserves the required order: user/schema, autocommit and regular session variables including charset/`sql_mode`, then user variables, then the client query.

- [ ] **Step 3: Implement async batch execution and failure retirement**

Dispatch `SETTING_USER_VARIABLES` from `handler_again___multiple_statuses()`. Send each batch through `async_send_simple_command()` using the batch's exact SQL. On OK, apply that batch's assignments to the backend map and increment `st_var_user_variable_replay_commands`; then send the next batch or resume the saved client-query status.

On server or client-library error:

- increment `st_var_user_variable_replay_failures`;
- forward a backend-derived ERR packet for the pending client query;
- call `RequestEnd()` once;
- destroy/retire the backend connection so its partially replayed map cannot return to the pool;
- clear replay queue/index and do not execute the client query.

Treat `ASSIGNMENT_TOO_LARGE` from the planner as the same replay failure disposition. Emit the fixed debug reason `REPLAY_FAILURE` without serializing batch SQL, targets, literals, or hashes.

```bash
make -C lib obj/MySQL_Session.oo
make -C test/tap/tests/unit mysql_user_variables_unit-t
./test/tap/tests/unit/mysql_user_variables_unit-t
```

Expected: the session object compiles and every replay success/failure decision test passes.

- [ ] **Step 4: Commit replay support**

```bash
git add \
  include/proxysql_structs.h \
  include/MySQL_Session.h \
  include/MySQL_User_Variables.h \
  lib/MySQL_Session.cpp \
  lib/MySQL_User_Variables.cpp \
  test/tap/tests/unit/mysql_user_variables_unit-t.cpp
git commit -m "feat: replay tracked user variables on backends"
```

---

### Task 8: Stage literal SETs and commit state only on backend OK

**Files:**

- Modify: `include/MySQL_Session.h`
- Modify: `include/mysql_connection.h`
- Modify: `lib/MySQL_Session.cpp`
- Modify: `lib/mysql_connection.cpp`
- Modify: `test/tap/tests/unit/parsersql_unit-t.cpp`

**Session query state:**

```cpp
std::optional<UserVariableSetAnalysis> pending_user_variable_set;
bool current_query_user_variable_safe { false };
bool user_variable_tracking_latched { false };
```

- [ ] **Step 1: Add failing adapter/session-policy assertions**

Extend `parsersql_unit-t.cpp` with a pure policy helper test matrix proving that tracking new assignments requires all of:

- mode `1`;
- ParserSQL SET mode or full-query ParserSQL mode;
- plain text `COM_QUERY`, not prepare/execute;
- no prior connection-bound fallback.

Also assert resource preflight happens against a staged post-SET map and never mutates committed state.

```bash
make -C test/tap/tests/unit parsersql_unit-t
./test/tap/tests/unit/parsersql_unit-t
```

Expected: policy helpers are missing.

- [ ] **Step 2: Analyze user-variable SETs before the legacy lossy SET map**

At the start of the existing `SET` branch in `handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo()`:

1. clear stale per-query pending/safety state;
2. when the mode/prerequisite/text-protocol policy is active, call `parsersql_analyze_user_variable_set_mysql()` on `CurrentQuery.QueryPointer` and `QueryLength`;
3. for `SUPPORTED`, stage the post-SET frontend state. On success, retain the analysis in `pending_user_variable_set`, mark the query safe, and forward the original packet without passing it through the old system-variable walker;
4. on variable/byte limit, increment `st_var_user_variable_fallback_limits`, synchronize prior tracked state through Task 7, forward the original SET, and call the existing `unable_to_parse_set_statement()` fallback;
5. on `UNSUPPORTED` or `PARSE_ERROR` for a user-variable SET, increment `st_var_user_variable_fallback_unsupported`, preserve the existing digest/raw warning behavior, and use `unable_to_parse_set_statement()`;
6. on `NOT_USER_VARIABLE_SET`, continue unchanged through the existing system-variable SET parser.

Mixed user/system SETs must enter step 5 before any ordinary frontend variable is mutated.

Add fixed debug reasons for `PARSER_PREREQUISITE_MISSING`, `UNSUPPORTED_AST`, and `RESOURCE_LIMIT`. They may follow the existing parse-failure logging choice of raw query versus digest, but must not introduce any new value/name logging independent of that existing policy.

- [ ] **Step 3: Commit pending state in the backend success path**

In the `rc==0` query-completion path, before `RequestEnd(myds)` can return the backend to the pool:

- if `status == PROCESSING_QUERY` and `pending_user_variable_set` exists, apply its assignments atomically to both `client_myds->myconn->user_variables` and `myconn->user_variables`;
- set `user_variable_tracking_latched=true` on the first commit;
- increment `st_var_user_variable_assignments_tracked` by assignment count;
- clear pending state.

In every `rc==-1`, retry, disconnect, `RequestEnd()` error, and session `reset()` path, discard pending state without changing either map.

- [ ] **Step 4: Suppress only the legacy UDV status flag for proven-safe queries**

Change the status API to:

```cpp
void ProcessQueryAndSetStatusFlags(
    char* query_digest_text,
    bool user_variable_usage_is_safe);
```

Pass `current_query_user_variable_safe` from `RequestEnd()`. The new boolean suppresses only `ProcessQueryAndSetStatusFlags_UserVariables()`; query-rule `multiplex=0/1`, warnings, temporary tables, savepoints, locks, prepared statements, and every other status classifier remain unchanged.

Clear the per-query safety boolean after `RequestEnd()`.

```bash
make -C lib obj/MySQL_Session.oo obj/mysql_connection.oo
make -C test/tap/tests/unit parsersql_unit-t
./test/tap/tests/unit/parsersql_unit-t
```

Expected: supported SETs take the staging path, the code compiles, and parser/policy tests pass.

- [ ] **Step 5: Commit initial SET tracking**

```bash
git add \
  include/MySQL_Session.h \
  include/mysql_connection.h \
  lib/MySQL_Session.cpp \
  lib/mysql_connection.cpp \
  test/tap/tests/unit/parsersql_unit-t.cpp
git commit -m "feat: commit literal user-variable SETs on backend OK"
```

---

### Task 9: Classify reads and unsafe uses, including runtime drain semantics

**Files:**

- Modify: `include/MySQL_Session.h`
- Modify: `include/Query_Processor_ParserSQL.h`
- Modify: `lib/MySQL_Session.cpp`
- Modify: `lib/Query_Processor_ParserSQL.cpp`
- Modify: `test/tap/tests/unit/parsersql_unit-t.cpp`

- [ ] **Step 1: Add failing query-disposition tests**

Test a pure disposition helper with these inputs:

- no `@`: do not call ParserSQL and mark the UDV status path safe;
- `@` only inside string/comment: classifier returns no user variable and remains safe;
- read-only `@x`: safe and multiplexable after synchronization;
- `SET @x=1` supported: handled by Task 8;
- `SELECT @x:=1`, `SELECT id INTO @x FROM test.uv_source`, function/call AST shapes containing a real user-variable occurrence, partial/multi-statements, and prepared SETs: unsafe fallback;
- feature/prerequisite disabled before any commit: current behavior;
- feature/prerequisite disabled after a commit: usage classification and backend synchronization remain latched, but no new assignments enter the map;
- once unsafe fallback binds a session, later literal SETs do not update the frontend map because the selected backend is authoritative.
- after any tracked assignment, SETs that change `sql_mode`, client/connection charset, connection collation, NAMES, or CHARACTER SET synchronize the old user-variable state and bind before changing interpretation context;
- a context change reported by backend session tracking binds the session after the query and prevents that backend from returning to the pool.

```bash
make -C test/tap/tests/unit parsersql_unit-t
./test/tap/tests/unit/parsersql_unit-t
```

Expected: runtime/latch cases fail until the disposition helper is added.

- [ ] **Step 2: Add the `@` fast gate and ParserSQL usage classification**

For plain `COM_QUERY` not already handled as a supported SET:

1. use `memchr(query, '@', query_length)` as the only no-parse fast gate;
2. when no `@` exists, leave routing unchanged and mark UDV classification safe;
3. when `@` exists and either new tracking is active or `user_variable_tracking_latched` is true, call `parsersql_classify_user_variable_usage_mysql()`;
4. mark `NO_USER_VARIABLE` and `READ_ONLY` safe; Task 7 will synchronize any desired map before the query;
5. for `UNSAFE_OR_UNKNOWN`, synchronize prior state, invoke the existing connection-bound/hostgroup-lock policy while honoring explicit `qpo->multiplex`, and leave the legacy UDV status classifier unsuppressed.

Do not apply the safe-read relaxation to prepared statement prepare/execute paths; the initial implementation tracks text protocol only.

- [ ] **Step 3: Implement latching and authoritative-backend behavior**

Use two predicates:

```cpp
bool accepts_new_user_variable_assignments() const;
bool must_classify_and_sync_user_variables() const;
```

The first requires current mode/prerequisite and an unbound session. The second is true when the first is true or `user_variable_tracking_latched` is true. Never clear the latch on runtime variable refresh; clear it only through session `reset()` / change-user / disconnect lifecycle.

Once an unsafe query causes connection-bound fallback, stop updating the tracked map. The bound backend remains authoritative, while any previously tracked map stays available only for the already-selected backend's prior synchronization and aggregate diagnostics.

Add this adapter predicate using the same strict full-input ParserSQL AST:

```cpp
bool parsersql_set_changes_user_variable_replay_context_mysql(
    const char* query, size_t query_length);
```

It returns true for SET assignments affecting `sql_mode`, `character_set_client`, `character_set_connection`, or `collation_connection`, plus SET NAMES and SET CHARACTER SET nodes. When the frontend map is nonempty, check this predicate before the legacy SET parser mutates ordinary frontend state. Synchronize the old map, forward the original context-changing SET through the existing fallback, and bind the selected backend; do not update the frontend user-variable map afterward.

In `handler_rc0_Process_Variables()`, if backend session tracking reports any of those context variables changed while the frontend user-variable map is nonempty, set the existing connection-bound/user-variable status before `RequestEnd()` so the current backend cannot return to the pool. This handles context mutation hidden inside backend-side code while leaving hidden user-variable writes themselves documented as unsupported.

```bash
make -C lib obj/MySQL_Session.oo
make -C test/tap/tests/unit parsersql_unit-t
./test/tap/tests/unit/parsersql_unit-t
```

Expected: all disposition, runtime-disable, and latch tests pass.

- [ ] **Step 4: Commit usage classification and drain behavior**

```bash
git add \
  include/MySQL_Session.h \
  include/Query_Processor_ParserSQL.h \
  lib/MySQL_Session.cpp \
  lib/Query_Processor_ParserSQL.cpp \
  test/tap/tests/unit/parsersql_unit-t.cpp
git commit -m "feat: classify user-variable reads and unsafe uses"
```

---

### Task 10: Add end-to-end literal, replay, routing, and isolation coverage

**Files:**

- Create: `test/tap/tests/mysql-user-variable-tracking-t.cpp`
- Modify: `test/tap/groups/groups.json`

- [ ] **Step 1: Write the failing TAP happy-path fixture**

Create a dedicated test that:

1. saves `mysql-user_variable_tracking`, `mysql-set_parser_algorithm`, `mysql-query_processor_parser`, and `mysql-set_query_lock_on_hostgroup`;
2. selects one ONLINE backend from `runtime_mysql_servers`, mirrors it into temporary hostgroups `18110` and `18111`, and installs comment-scoped query rules for `/* uv_hg_a */` and `/* uv_hg_b */` for the test user only;
3. sets tracking to `1`, SET parser to `3`, full-query parser to `0`, hostgroup locking to `1`, and loads MySQL variables/rules/servers;
4. runs the exact reported four-assignment SET and asserts all four values through `SELECT`;
5. exercises strings with escapes, signed integers, decimals, exponent forms, `0x`/`X''`, `0b`/`B''`, and NULL;
6. executes the same assignments on a direct backend connection and compares result bytes, `MYSQL_FIELD::type`, `HEX(@name)`, `CHARSET(@name)`, `COLLATION(@name)`, and `COERCIBILITY(@name)` after each replay-sensitive hostgroup switch;
7. creates a temporary read-only stored function `test.proxysql_uv_read()` that returns `@browser_lang`, routes `SELECT test.proxysql_uv_read()`—which contains no `@` byte—to a different hostgroup, and proves tracked state is still synchronized for backend-side readers;
8. routes alternating reads to both temporary hostgroups, verifies different backend `CONNECTION_ID()` values are observed, and verifies every tracked value survives each switch;
9. seeks `$REGULAR_INFRA_DATADIR/proxysql.log` to EOF before the reported SET and asserts no new `Unable to parse unknown SET query` record contains that statement;
10. asserts `PROXYSQL INTERNAL SESSION` reports the expected frontend count/byte total/fingerprint and contains none of the variable names or values;
11. checks `locked_on_hostgroup == -1` and that no backend acquires `status.user_variable=true` for supported SET/read traffic;
12. opens a second frontend session with no assignments, routes it through both hostgroups, and asserts every `@name IS NULL`, proving pooled backend state is reset rather than leaked;
13. drops only `test.proxysql_uv_read`, removes only hostgroups `18110`/`18111` and test-comment query rules, restores saved variables, and loads runtime state even when an assertion fails.

Register the test in `legacy-g4`, `mariadb10-galera-g4`, `mysql-multiplexing=false-g4`, `mysql84-g4`, `mysql90-g4`, `mysql95-g4`, and `set_parser_algorithm_3-g1`.

```bash
make -C test/tap/tests mysql-user-variable-tracking-t
./test/tap/tests/mysql-user-variable-tracking-t
```

Expected before the completed feature: the reported SET locks the session or tracked values disappear/leak while changing hostgroups.

- [ ] **Step 2: Fix only integration defects exposed by the happy path**

Trace failures to parser analysis, commit-on-OK, pool matching, normal-variable-before-UDV ordering, or replay. Do not loosen syntax classification or make the test reuse a single backend connection merely to pass.

Rerun:

```bash
make -j4 debug
make -C test/tap/tests mysql-user-variable-tracking-t
./test/tap/tests/mysql-user-variable-tracking-t
```

Expected: the exact client statement remains multiplexable, survives hostgroup changes, and does not contaminate another frontend.

- [ ] **Step 3: Commit the happy-path integration test and any scoped fixes**

```bash
git add \
  test/tap/tests/mysql-user-variable-tracking-t.cpp \
  test/tap/groups/groups.json \
  include/MySQL_Session.h \
  lib/MySQL_Session.cpp \
  include/mysql_connection.h \
  lib/mysql_connection.cpp
git commit -m "test: cover multiplexed literal user variables"
```

---

### Task 11: Cover errors, fallbacks, limits, reset, and runtime changes end to end

**Files:**

- Modify: `test/tap/tests/mysql-user-variable-tracking-t.cpp`
- Modify when a defect is exposed: `lib/MySQL_Session.cpp`
- Modify when a defect is exposed: `lib/mysql_connection.cpp`
- Modify when a defect is exposed: `lib/MySQL_User_Variables.cpp`

- [ ] **Step 1: Add failing negative and lifecycle TAP phases**

Use a fresh frontend connection per connection-bound case and add assertions for:

- backend rejection of a syntactically typed but server-invalid literal leaves frontend count and assignment counter unchanged;
- expressions, mixed system/user SET, parentheses, casts, introducers, collations, malformed/partial statements, a trailing comma, a second statement, prepared SET, `SELECT @x:=...`, and `SELECT ... INTO @x` retain the current fallback and lock under the default policy;
- read-only `SELECT @x`, comparisons using `@x`, and `@` inside a string/comment do not lock;
- a 129th distinct variable and a state over 64 KiB increment only the limit-fallback counter, apply no partial tracked state, and use existing fallback;
- after `SET @context_value='A\\n'`, changing `sql_mode` or `SET NAMES` binds the session before the change and preserves `HEX(@context_value)`, `CHARSET(@context_value)`, and `COLLATION(@context_value)` on the authoritative backend rather than replaying under the new context;
- mode `1` without either ParserSQL prerequisite is inactive and locks the reported SET; changing parser configuration must not be forced by the load;
- the prerequisite warning appears once in `$REGULAR_INFRA_DATADIR/proxysql.log` after the misconfigured `LOAD MYSQL VARIABLES TO RUNTIME` and names `mysql-user_variable_tracking`, `mysql-set_parser_algorithm`, and `mysql-query_processor_parser` without printing the SET value;
- full-query ParserSQL mode (`mysql-query_processor_parser=1`) activates tracking while `mysql-set_parser_algorithm=2`, proving both documented prerequisite alternatives;
- after a tracked commit, setting mode to `0` or moving both parser settings away from ParserSQL still lets that existing session read/synchronize prior state across both hostgroups, while a new SET on it falls back and a fresh session gets current disabled behavior;
- an explicit query rule with `multiplex=0` remains authoritative for a supported read/SET, and an explicit `multiplex=1` retains the existing override behavior for an unsafe use;
- `mysql-set_query_lock_on_hostgroup=0` retains the pre-2.0.6 connection-status fallback for unsafe user-variable use rather than silently using mode-1 tracking;
- `mysql_reset_connection()` clears frontend diagnostics and makes subsequent `SELECT @x IS NULL` true;
- `mysql_change_user()` to the same fixture credentials clears the state and value;
- disconnect followed by a fresh frontend observes NULL rather than stale pooled state;
- counter deltas match supported assignments, replay SET batches, unsupported fallback, limit fallback, and zero replay failures in the normal test.

Also force a replay failure at the pure replay-completion seam from Task 7 in the unit test and assert the action retires the backend and fails the pending query; do not add a production runtime failpoint solely for TAP.

```bash
make -C test/tap/tests mysql-user-variable-tracking-t
./test/tap/tests/mysql-user-variable-tracking-t
make -C test/tap/tests/unit mysql_user_variables_unit-t
./test/tap/tests/unit/mysql_user_variables_unit-t
```

Expected: at least runtime drain, reset, or error accounting fails before final lifecycle wiring is complete.

- [ ] **Step 2: Close lifecycle and failure-path gaps**

Ensure `pending_user_variable_set`, replay queue/index, current-query safety, and the tracking latch are cleared in `MySQL_Session::reset()`. Ensure backend map changes occur only after successful original SET/replay commands. Verify connection destroy paths cannot return a partially replayed backend to the pool.

Keep the documented limitation intact: writes hidden inside procedures/functions/triggers are not detected. Do not claim correctness for those paths and do not add heuristic SQL scanning.

Rerun both commands from Step 1 until green.

- [ ] **Step 3: Commit negative, resource, and lifecycle coverage**

```bash
git add \
  test/tap/tests/mysql-user-variable-tracking-t.cpp \
  test/tap/tests/unit/mysql_user_variables_unit-t.cpp \
  include/MySQL_Session.h \
  lib/MySQL_Session.cpp \
  lib/mysql_connection.cpp \
  lib/MySQL_User_Variables.cpp
git commit -m "test: cover user-variable fallback and lifecycle"
```

---

### Task 12: Document operator behavior and run the complete regression gate

**Files:**

- Create: `doc/mysql-user-variable-tracking.md`
- Modify: `deps/parsersql/README.md` only if the final archive audit needs a correction
- Verify: every production/test file changed above

- [ ] **Step 1: Write operator-facing documentation**

Document:

- integer modes, default/range, and both ParserSQL prerequisites;
- the exact supported literals and all-or-nothing SET rule;
- initial SET forwarding and commit-on-OK behavior;
- frontend/backend maps, resource limits, pool reset on backend extras, replay order, and batching;
- read-only versus unsafe usage behavior;
- runtime-disable/prerequisite drain semantics;
- COM reset/change-user/disconnect clearing;
- all five counters and aggregate-only internal-session diagnostics;
- the explicit hidden-backend-write limitation for stored procedures, functions, and triggers;
- the connection-bound safeguard when interpretation context changes after tracked assignments;
- a deployment example using the reported browser metadata statement.

- [ ] **Step 2: Run focused upstream and downstream verification from clean build products**

```bash
make -C /data/rene/ParserSQL-user-variable-literals clean
make -C /data/rene/ParserSQL-user-variable-literals test
make -C /data/rene/ParserSQL-user-variable-literals build-corpus-test
make -C deps parsersql/parsersql/libsqlparser.a
make -C lib clean
make -j4 debug
make -C test/tap/tests/unit \
  parsersql_unit-t \
  mysql_user_variables_unit-t \
  mysql_variables_unit-t \
  statistics_unit-t
./test/tap/tests/unit/parsersql_unit-t
./test/tap/tests/unit/mysql_user_variables_unit-t
./test/tap/tests/unit/mysql_variables_unit-t
./test/tap/tests/unit/statistics_unit-t
make -C test/tap/tests \
  setparser_parsersql_test \
  setparser_test \
  setparser_test2 \
  setparser_test3 \
  mysql-user-variable-tracking-t
./test/tap/tests/setparser_parsersql_test
./test/tap/tests/setparser_test
./test/tap/tests/setparser_test2
./test/tap/tests/setparser_test3
./test/tap/tests/mysql-user-variable-tracking-t
```

Expected: every command exits zero. Investigate any failure; do not label it baseline or flaky without a deterministic root cause.

- [ ] **Step 3: Run existing status/reset regressions most likely to catch collateral behavior**

```bash
make -C test/tap/tests \
  reg_test_3327-process_query_set_status_flags-t \
  test_com_reset_connection_com_change_user-t \
  set_testing-t \
  set_testing-multi-t \
  test_filtered_set_statements-t
./test/tap/tests/reg_test_3327-process_query_set_status_flags-t
./test/tap/tests/test_com_reset_connection_com_change_user-t
./test/tap/tests/set_testing-t
./test/tap/tests/set_testing-multi-t
./test/tap/tests/test_filtered_set_statements-t
```

Expected: existing SET status flags, reset/change-user behavior, ParserSQL SET mode, and legacy filtered SET handling remain green.

- [ ] **Step 4: Self-review specification coverage and accidental exposure**

```bash
git diff --check 309ca545f
git status --short
git diff 309ca545f -- \
  include/MySQL_User_Variables.h \
  lib/MySQL_User_Variables.cpp \
  lib/MySQL_Session.cpp \
  lib/mysql_connection.cpp \
  test/tap/tests/mysql-user-variable-tracking-t.cpp \
  doc/mysql-user-variable-tracking.md | \
  rg -n "TODO|FIXME|placeholder|not implemented"
git diff 309ca545f -- \
  lib/mysql_data_stream.cpp \
  lib/mysql_connection.cpp \
  lib/MySQL_Session.cpp | \
  rg -n "canonical_name|replay_target|raw_literal|\.hash"
```

Review the last search manually: uses in internal state/replay are expected; no logging or JSON serialization of those fields is allowed. Confirm enum types match across ParserSQL and ProxySQL adapters, byte limits use `size_t`, query lengths never narrow unsafely, and every pending-state error path clears exactly once.

- [ ] **Step 5: Commit documentation and any verification-only corrections**

If Step 2, 3, or 4 requires a production correction, return to the owning task's focused test, rerun it, and commit that correction before the documentation commit. Do not hide production changes inside a docs-only commit.

```bash
git add doc/mysql-user-variable-tracking.md
git commit -m "docs: explain literal user-variable tracking"
```

Do not include unrelated working-tree files in this or any earlier commit.
