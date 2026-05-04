# ParserSQL Static Library Integration

## Summary

Integrate the standalone ParserSQL library (`ProxySQL/ParserSQL`) into ProxySQL as a vendored static library, exposing it through two runtime-selectable modes:

1. **SET-only mode** (`set_parser_algorithm = 3`): Replace the regex-based SET statement parser with ParserSQL's recursive descent parser. Lowest risk, smallest blast radius.

2. **Full mode** (`query_processor_parser = 1`): Use ParserSQL for all query processing — digest generation, command type detection, table name extraction, and SET parsing. Replaces the hand-written `c_tokenizer` and string-matching command classifier.

Both repos remain fully independent. ParserSQL ships release tarballs; ProxySQL vendors one in `deps/`.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  MySQL_Session / PgSQL_Session                      │
│    query_parser_init()                               │
│         │                                            │
│         ├── query_processor_parser == 0 (legacy)     │
│         │     ├── Digest: c_tokenizer / pgsql_token  │
│         │     ├── Cmd type: string matcher            │
│         │     └── SET: set_parser_algorithm 1|2|3    │
│         │           └── 3 = ParserSQL SET adapter    │
│         │                                            │
│         └── query_processor_parser == 1 (ParserSQL)  │
│               └── Single parse → ParseResult         │
│                     ├── digest text (Emitter::Digest) │
│                     ├── digest hash (SpookyHash)      │
│                     ├── command type (StmtType map)   │
│                     ├── table name (StringRef)        │
│                     └── SET vars (AST walk)           │
└─────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **SpookyHash preserved.** The digest hash function does not change. Only the normalization logic changes (ParserSQL's `Emitter::Digest` replaces the hand-written tokenizer). Existing `mysql_query_rules.digest` values will change for some edge cases; users must re-capture digests after switching.

2. **Per-thread parser instances.** `thread_local Parser<Dialect::MySQL>` and `Parser<Dialect::PostgreSQL>` — zero shared state, no locks. O(1) arena reset between queries. Matches ProxySQL's threading model.

3. **Backward-compatible interface.** The adapter layer produces the same `SQP_par_t` and `map<string, vector<string>>` that existing code consumes. No changes to query rules, firewall, or stats downstream.

4. **Default off.** Both variables default to legacy values. Users opt-in at runtime without restart.

---

## Repositories Stay Independent

### ParserSQL side
- Remains a standalone repo with its own CI, releases, and versioning
- Adds a `make dist` target producing `parsersql-$VERSION.tar.gz` containing `include/`, `src/`, and a `Makefile`
- No ProxySQL references in its build system

### ProxySQL side
- Vendors a release tarball in `deps/parsersql/` (identical to libinjection, re2, etc.)
- Upgrading = swapping the tarball
- Compiles `libsqlparser.a` as part of `make deps`

---

## Variable 1: `set_parser_algorithm` (existing, add value 3)

**Current:** `1` = legacy `parse1()`, `2` = improved `parse1v2()`. Default: `2`.

| Value | Behavior |
|-------|----------|
| `1` | Legacy regex-based SET parser (unchanged) |
| `2` | Per-thread regex SET parser (current default, unchanged) |
| `3` | **ParserSQL**: `Parser<D>::parse()` → walk SET AST → extract variables |

Range extended from `[1, 2]` to `[1, 3]`.

### SET Adapter Behavior (`set_parser_algorithm = 3`)

The adapter function `parsersql_parse_set()` must produce the same `map<string, vector<string>>` as the existing parsers:

- Keys are **lowercase** variable names
- Scope prefixes (`SESSION`, `@@session.`, `@@local.`, `@@`, `GLOBAL`) are **stripped** from keys
- `transaction_isolation` is renamed to `tx_isolation`
- `transaction_read_only` is renamed to `tx_read_only`
- Quotes are stripped from string values
- Multi-variable SET (`SET a=1, b=2`) produces multiple map entries
- `SET NAMES charset [COLLATE collation]` produces key `"names"` with 1-2 values
- `SET CHARACTER SET charset` is handled similarly
- Unparseable queries return an empty map (triggers `unable_to_parse_set_statement`)

**Only used when `query_processor_parser = 0`.** When `query_processor_parser = 1`, the SET extraction comes from the same `ParseResult` and this variable is ignored.

---

## Variable 2: `query_processor_parser` (new)

**Range:** `0` = legacy (default), `1` = ParserSQL.

Admin-controllable at runtime:
```sql
SET mysql-query_processor_parser = 1;
LOAD MYSQL VARIABLES TO RUNTIME;
```

When enabled, replaces these code paths:

| Concern | Legacy | ParserSQL |
|---------|--------|-----------|
| Digest text | `c_tokenizer.cpp` / `pgsql_tokenizer.cpp` (stage_1-4 pipeline) | `Emitter<D>::emit(ast, EmitMode::Digest)` |
| Digest hash | `SpookyHash::Hash64(digest_text, ...)` | Same — SpookyHash on the new normalized text |
| Command type | `query_parser_command_type()` — 400-line string matcher | `ParseResult::stmt_type` → `MYSQL_COM_QUERY_command` mapping |
| Table name | Not available | `ParseResult::table_name` (zero-copy StringRef) |
| Schema name | Not available | `ParseResult::schema_name` |
| Database name | Not available | `ParseResult::database_name` |
| SET parsing | `MySQL_Set_Stmt_Parser` / `PgSQL_Set_Stmt_Parser` | Walk `NODE_SET_STMT` AST |
| First comment | `mysql_query_digest_and_first_comment()` extracts it | To be evaluated — may need a separate pass |

### Interaction Matrix

| `query_processor_parser` | `set_parser_algorithm` | Digest source | Cmd type source | SET source |
|---|---|---|---|---|
| 0 | 1 | c_tokenizer | string matcher | parse1() |
| 0 | 2 | c_tokenizer | string matcher | parse1v2() |
| 0 | **3** | c_tokenizer | string matcher | **ParserSQL** |
| **1** | any | **ParserSQL** | **ParserSQL** | **ParserSQL** |

---

## Dependency Integration

### Build system changes (ProxySQL)

Follows the libinjection pattern exactly:

**`deps/parsersql/`**: Contains `parsersql-$VERSION.tar.gz`

**`deps/Makefile`**: New target `parsersql` that extracts, builds `libsqlparser.a`

**`include/makefiles_paths.mk`**: Add `PARSERSQL_PATH`, `PARSERSQL_IDIR`, `PARSERSQL_LDIR`

**`lib/Makefile` and `src/Makefile`**: Add `-I$(PARSERSQL_IDIR)`, `-L$(PARSERSQL_LDIR)`, `-lsqlparser`

### ParserSQL `make dist` target (ParserSQL)

Produces a self-contained tarball:
```
parsersql-1.0.0/
  include/sql_parser/   (all headers)
  src/sql_parser/       (arena.cpp, parser.cpp)
  Makefile              (builds libsqlparser.a)
```

---

## Adapter Layer: `lib/Query_Processor_ParserSQL.cpp`

A new file providing three adapter functions:

1. **`parsersql_digest_init()`** — Called from `Query_Processor::query_parser_init()` when `query_processor_parser = 1`. Parses the query, produces normalized digest text, computes SpookyHash, populates `SQP_par_t`.

2. **`parsersql_command_type()`** — Called from `MySQL_Query_Processor::query_parser_command_type()` and `PgSQL_Query_Processor::query_parser_command_type()` when `query_processor_parser = 1`. Maps `StmtType` enum to `MYSQL_COM_QUERY_command` / `PGSQL_QUERY_command`.

3. **`parsersql_parse_set()`** — Called from `MySQL_Session.cpp` / `PgSQL_Session.cpp` when `set_parser_algorithm = 3` or `query_processor_parser = 1`. Walks the SET AST and produces `map<string, vector<string>>`.

Per-thread parser instances:
```cpp
static thread_local sql_parser::Parser<sql_parser::Dialect::MySQL> tl_mysql_parser;
static thread_local sql_parser::Parser<sql_parser::Dialect::PostgreSQL> tl_pgsql_parser;
```

---

## Command Type Mapping

`StmtType` (~30 values) → `MYSQL_COM_QUERY_command` (~60 values). Most are 1:1. For types ProxySQL doesn't distinguish (e.g., ProxySQL has `MYSQL_COM_QUERY_ALTER_TABLE` but ParserSQL just has `StmtType::ALTER`), the adapter falls back to the coarse type.

Fallback: when `ParseResult::status != OK`, fall through to the legacy string matcher.

---

## Files Changed

### New files
| File | Purpose |
|------|---------|
| `deps/parsersql/parsersql-$VER.tar.gz` | Vendored source |
| `lib/Query_Processor_ParserSQL.cpp` | Adapter layer |
| `include/Query_Processor_ParserSQL.h` | Adapter declarations |

### Modified files
| File | Change |
|------|--------|
| `deps/Makefile` | Add `parsersql` target |
| `include/makefiles_paths.mk` | Add PARSERSQL_* paths |
| `lib/Makefile` | Add include/lib/link flags |
| `src/Makefile` | Add include/lib/link flags |
| `include/MySQL_Thread.h` | Add `query_processor_parser` field |
| `include/PgSQL_Thread.h` | Add `query_processor_parser` field |
| `lib/MySQL_Thread.cpp` | Register variable, extend set_parser_algorithm range |
| `lib/PgSQL_Thread.cpp` | Same |
| `lib/Query_Processor.cpp` | Branch in `query_parser_init()` |
| `lib/MySQL_Query_Processor.cpp` | Branch in `query_parser_command_type()` |
| `lib/PgSQL_Query_Processor.cpp` | Same |
| `lib/MySQL_Session.cpp` | Branch for `set_parser_algorithm == 3` |
| `lib/PgSQL_Session.cpp` | Same |
| `include/proxysql_structs.h` | Thread variable declarations |
| `lib/ProxySQL_Admin.cpp` | Admin variable registration |

---

## Migration Path

1. Ship with both variables at default values — zero behavior change
2. Users test SET-only mode: `SET mysql-set_parser_algorithm = 3; LOAD MYSQL VARIABLES TO RUNTIME;`
3. Users test full mode: `SET mysql-query_processor_parser = 1; LOAD MYSQL VARIABLES TO RUNTIME;`
4. Can switch back at any time without restart
5. After broad adoption, consider flipping the default

---

## Out of Scope

- Removing the legacy `c_tokenizer.cpp` / `pgsql_tokenizer.cpp` (kept as fallback)
- Plugin interface integration (ParserSQL is a library, not a plugin subsystem)
- Query rewrite rules using the AST (future work)
- `first_comment` extraction in ParserSQL mode (evaluate separately)
- Hot-loading / runtime parser switching per-session
