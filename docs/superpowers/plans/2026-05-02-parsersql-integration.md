# ParserSQL Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate ParserSQL as a vendored static library into ProxySQL with two runtime-selectable modes (SET-only and full).

**Architecture:** ParserSQL is vendored as a tarball in `deps/parsersql/`, compiled to `libsqlparser.a`, and statically linked. A new adapter layer (`lib/Query_Processor_ParserSQL.cpp`) bridges ParserSQL's API to ProxySQL's existing data structures. Two thread variables control behavior: `set_parser_algorithm` (extended to value 3) and `query_processor_parser` (new).

**Tech Stack:** C++17, GNU Make, ParserSQL (hand-written recursive descent parser)

---

## File Structure

| File | Responsibility |
|------|----------------|
| `deps/parsersql/parsersql-1.0.0.tar.gz` | Vendored ParserSQL source |
| `deps/Makefile` | Add parsersql build target |
| `include/makefiles_paths.mk` | PARSERSQL_* path variables |
| `lib/Makefile` | Add include/lib/link flags |
| `src/Makefile` | Add include/lib/link flags |
| `include/Query_Processor_ParserSQL.h` | Adapter declarations |
| `lib/Query_Processor_ParserSQL.cpp` | Adapter implementation (SET, digest, command type) |
| `include/MySQL_Thread.h` | `query_processor_parser` field |
| `include/PgSQL_Thread.h` | `query_processor_parser` field |
| `lib/MySQL_Thread.cpp` | Register variable, extend set_parser_algorithm range |
| `lib/PgSQL_Thread.cpp` | Same as MySQL_Thread.cpp |
| `include/proxysql_structs.h` | Thread variable declarations |
| `lib/Query_Processor.cpp` | Branch in `query_parser_init()` |
| `lib/MySQL_Query_Processor.cpp` | Branch in `query_parser_command_type()` |
| `lib/PgSQL_Query_Processor.cpp` | Branch in `query_parser_command_type()` |
| `lib/MySQL_Session.cpp` | Branch for `set_parser_algorithm == 3` |
| `lib/PgSQL_Session.cpp` | Branch for `set_parser_algorithm == 3` |
| `lib/ProxySQL_Admin.cpp` | Admin variable registration |

---

### Task 1: Vendor ParserSQL Tarball

**Files:**
- Create: `deps/parsersql/` directory
- Copy: ParserSQL release tarball

- [ ] **Step 1: Create the deps directory and prepare the tarball**

Create a tarball from the ParserSQL repo that contains only the files needed to build `libsqlparser.a`:

```bash
cd /home/rene/proxysql-parsersql/ParserSQL
tar -czf /home/rene/proxysql-parsersql/proxysql/deps/parsersql/parsersql-1.0.0.tar.gz \
  --transform='s,^,parsersql-1.0.0/,' \
  include/sql_parser/ \
  src/sql_parser/ \
  Makefile
```

Verify the tarball structure:
```bash
tar -tzf /home/rene/proxysql-parsersql/proxysql/deps/parsersql/parsersql-1.0.0.tar.gz | head -20
```

Expected: paths like `parsersql-1.0.0/include/sql_parser/...`, `parsersql-1.0.0/src/sql_parser/...`, `parsersql-1.0.0/Makefile`.

- [ ] **Step 2: Commit the tarball**

```bash
cd /home/rene/proxysql-parsersql/proxysql
git add deps/parsersql/parsersql-1.0.0.tar.gz
git commit -m "vendor: add ParserSQL 1.0.0 source tarball"
```

---

### Task 2: Build System Integration — deps/Makefile

**Files:**
- Modify: `deps/Makefile`

- [ ] **Step 1: Add the parsersql build target to deps/Makefile**

Find the `libinjection` target (the reference pattern) and add a matching `parsersql` target after it. The target should:

1. Extract the tarball
2. Build `libsqlparser.a` using the ParserSQL Makefile's `lib` target
3. Depend on the `lib` target being called

The Makefile rule pattern (following libinjection at ~line 66-80):

```makefile
parsersql/parsersql-1.0.0/libsqlparser.a:
	cd parsersql && rm -rf parsersql-1.0.0 || true
	cd parsersql && tar -zxf parsersql-1.0.0.tar.gz
	cd parsersql/parsersql-1.0.0 && CC=${CC} CXX=${CXX} ${MAKE} lib

parsersql: parsersql/parsersql-1.0.0/libsqlparser.a
```

Also add `parsersql` to the default target's dependencies (the `all` or first target that calls `libinjection re2 sqlite3 ...`).

- [ ] **Step 2: Verify the build target works in isolation**

```bash
cd /home/rene/proxysql-parsersql/proxysql
cd deps && make parsersql
ls -la parsersql/parsersql-1.0.0/libsqlparser.a
```

Expected: `libsqlparser.a` exists and is non-empty.

- [ ] **Step 3: Commit**

```bash
git add deps/Makefile
git commit -m "build: add parsersql target to deps/Makefile"
```

---

### Task 3: Build System Integration — Path Variables and Flags

**Files:**
- Modify: `include/makefiles_paths.mk`
- Modify: `lib/Makefile`
- Modify: `src/Makefile`

- [ ] **Step 1: Add path variables to `include/makefiles_paths.mk`**

Add after the existing dependency path blocks (around line 66-100):

```makefile
PARSERSQL_PATH := $(DEPS_PATH)/parsersql/parsersql-1.0.0
PARSERSQL_IDIR := $(PARSERSQL_PATH)/include
PARSERSQL_LDIR := $(PARSERSQL_PATH)
```

- [ ] **Step 2: Add include and lib flags to `lib/Makefile`**

Add to the `IDIRS` variable (around line 9-30):
```makefile
-I$(PARSERSQL_IDIR) \
```

Add to the `LDIRS` variable:
```makefile
-L$(PARSERSQL_LDIR) \
```

- [ ] **Step 3: Add include, lib, and link flags to `src/Makefile`**

Add to `IDIRS`:
```makefile
-I$(PARSERSQL_IDIR) \
```

Add to `LDIRS`:
```makefile
-L$(PARSERSQL_LDIR) \
```

Add `-lsqlparser` to `STATICMYLIBS` (inside the `-Wl,-Bstatic` block, around line 108-130):
```makefile
-lsqlparser \
```

- [ ] **Step 4: Verify compilation**

```bash
cd /home/rene/proxysql-parsersql/proxysql
make clean && make deps
# Spot-check that parsersql headers are findable:
echo '#include "sql_parser/parser.h"' | g++ -std=c++17 -I deps/parsersql/parsersql-1.0.0/include -fsyntax-only -x c++ -
```

Expected: no errors from the include.

- [ ] **Step 5: Commit**

```bash
git add include/makefiles_paths.mk lib/Makefile src/Makefile
git commit -m "build: add ParserSQL include paths, lib paths, and link flags"
```

---

### Task 4: Register the `query_processor_parser` Thread Variable

**Files:**
- Modify: `include/MySQL_Thread.h`
- Modify: `include/PgSQL_Thread.h`
- Modify: `include/proxysql_structs.h`
- Modify: `lib/MySQL_Thread.cpp`
- Modify: `lib/PgSQL_Thread.cpp`
- Modify: `lib/ProxySQL_Admin.cpp`

This follows the exact pattern used by `query_processor_regex` (values 1=PCRE, 2=RE2).

- [ ] **Step 1: Add the variable to thread variable structs**

In `include/MySQL_Thread.h`, find `int query_processor_regex;` (around line 576) and add after it:
```cpp
int query_processor_parser;
```

In `include/PgSQL_Thread.h`, find `int query_processor_regex;` (around line 1024) and add after it:
```cpp
int query_processor_parser;
```

- [ ] **Step 2: Add the `__thread` declarations in `proxysql_structs.h`**

Find `__thread int mysql_thread___query_processor_regex;` (around line 1289) and add:
```cpp
__thread int mysql_thread___query_processor_parser;
```

Find `__thread int pgsql_thread___query_processor_regex;` (around line 1199) and add:
```cpp
__thread int pgsql_thread___query_processor_parser;
```

Find `extern __thread int mysql_thread___query_processor_regex;` (around line 1625) and add:
```cpp
extern __thread int mysql_thread___query_processor_parser;
```

Find `extern __thread int pgsql_thread___query_processor_regex;` (around line 1535) and add:
```cpp
extern __thread int pgsql_thread___query_processor_parser;
```

- [ ] **Step 3: Register the variable in MySQL_Thread.cpp**

Find the `VariablesPointers_int` insertion for `query_processor_regex` (around line 2636):
```cpp
VariablesPointers_int["query_processor_regex"] = make_tuple(&variables.query_processor_regex, 1, 2, false);
```

Add after it:
```cpp
VariablesPointers_int["query_processor_parser"] = make_tuple(&variables.query_processor_parser, 0, 1, false);
```

Set the default value (find `variables.query_processor_regex=1;` around line 1348 and add):
```cpp
variables.query_processor_parser=0;
```

Add the variable name to the string list (find `"query_processor_regex"` in the variables vector around line 467 and add `"query_processor_parser"` in the same section).

Add `REFRESH_VARIABLE_INT(query_processor_parser);` near `REFRESH_VARIABLE_INT(query_processor_regex);` (around line 4607).

Add `pgsql_thread___query_processor_parser = ...` refresh assignment near the existing `pgsql_thread___query_processor_regex` line (around line 4607).

- [ ] **Step 4: Register the variable in PgSQL_Thread.cpp**

Same pattern as MySQL_Thread.cpp:
- Add to `VariablesPointers_int` with range `[0, 1]`
- Set default to `0`
- Add to variable name list
- Add `REFRESH_VARIABLE_INT(query_processor_parser);`
- Add thread variable refresh assignment

- [ ] **Step 5: Extend `set_parser_algorithm` range from `[1,2]` to `[1,3]`**

In `MySQL_Thread.cpp`, find:
```cpp
VariablesPointers_int["set_parser_algorithm"] = make_tuple(&variables.set_parser_algorithm, 1, 2, false);
```

Change `2` to `3`:
```cpp
VariablesPointers_int["set_parser_algorithm"] = make_tuple(&variables.set_parser_algorithm, 1, 3, false);
```

Do the same in `PgSQL_Thread.cpp`.

- [ ] **Step 6: Commit**

```bash
git add include/MySQL_Thread.h include/PgSQL_Thread.h include/proxysql_structs.h \
        lib/MySQL_Thread.cpp lib/PgSQL_Thread.cpp
git commit -m "feat: register query_processor_parser variable, extend set_parser_algorithm to 3"
```

---

### Task 5: Create the Adapter Layer — Header

**Files:**
- Create: `include/Query_Processor_ParserSQL.h`

- [ ] **Step 1: Create the adapter header**

```cpp
#ifndef PROXYSQL_QUERY_PROCESSOR_PARSERSQL_H
#define PROXYSQL_QUERY_PROCESSOR_PARSERSQL_H

#include "proxysql_structs.h"
#include <map>
#include <string>
#include <vector>

void parsersql_digest_init_mysql(SQP_par_t* qp, const char* query, int query_length);
void parsersql_digest_init_pgsql(SQP_par_t* qp, const char* query, int query_length);

enum MYSQL_COM_QUERY_command parsersql_command_type_mysql(const char* query, int query_length);
enum PGSQL_QUERY_command parsersql_command_type_pgsql(const char* query, int query_length);

std::map<std::string, std::vector<std::string>> parsersql_parse_set_mysql(const std::string& query);
std::map<std::string, std::vector<std::string>> parsersql_parse_set_pgsql(const std::string& query);

#endif
```

- [ ] **Step 2: Commit**

```bash
git add include/Query_Processor_ParserSQL.h
git commit -m "feat: add ParserSQL adapter header"
```

---

### Task 6: Create the Adapter Layer — Digest and Command Type

**Files:**
- Create: `lib/Query_Processor_ParserSQL.cpp` (part 1)

- [ ] **Step 1: Implement the digest adapter**

```cpp
#include "Query_Processor_ParserSQL.h"
#include "sql_parser/parser.h"
#include "sql_parser/digest.h"
#include "sql_parser/emitter.h"
#include "SpookyV2.h"

using namespace sql_parser;

static thread_local Parser<Dialect::MySQL> tl_mysql_parser;
static thread_local Parser<Dialect::PostgreSQL> tl_pgsql_parser;

void parsersql_digest_init_mysql(SQP_par_t* qp, const char* query, int query_length) {
    qp->digest_text = NULL;
    qp->first_comment = NULL;
    qp->query_prefix = NULL;

    auto result = tl_mysql_parser.parse(query, query_length);

    if (result.status == ParseResult::OK || result.status == ParseResult::PARTIAL) {
        std::string digest_text = Emitter<Dialect::MySQL>::emit(result.ast, EmitMode::Digest);
        qp->digest_text = strdup(digest_text.c_str());
        const int digest_text_length = static_cast<int>(digest_text.size());
        qp->digest = SpookyHash::Hash64(digest_text.c_str(), digest_text_length, 0);
    }

    tl_mysql_parser.reset();
}

void parsersql_digest_init_pgsql(SQP_par_t* qp, const char* query, int query_length) {
    qp->digest_text = NULL;
    qp->first_comment = NULL;
    qp->query_prefix = NULL;

    auto result = tl_pgsql_parser.parse(query, query_length);

    if (result.status == ParseResult::OK || result.status == ParseResult::PARTIAL) {
        std::string digest_text = Emitter<Dialect::PostgreSQL>::emit(result.ast, EmitMode::Digest);
        qp->digest_text = strdup(digest_text.c_str());
        const int digest_text_length = static_cast<int>(digest_text.size());
        qp->digest = SpookyHash::Hash64(digest_text.c_str(), digest_text_length, 0);
    }

    tl_pgsql_parser.reset();
}
```

- [ ] **Step 2: Implement the command type mapping**

Add to `lib/Query_Processor_ParserSQL.cpp`:

```cpp
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"

static enum MYSQL_COM_QUERY_command stmt_type_to_mysql_command(StmtType st) {
    switch (st) {
        case StmtType::SELECT:        return MYSQL_COM_QUERY_SELECT;
        case StmtType::INSERT:        return MYSQL_COM_QUERY_INSERT;
        case StmtType::UPDATE:        return MYSQL_COM_QUERY_UPDATE;
        case StmtType::DELETE:        return MYSQL_COM_QUERY_DELETE;
        case StmtType::SET:           return MYSQL_COM_QUERY_SET;
        case StmtType::BEGIN:         return MYSQL_COM_QUERY_BEGIN;
        case StmtType::COMMIT:        return MYSQL_COM_QUERY_COMMIT;
        case StmtType::ROLLBACK:      return MYSQL_COM_QUERY_ROLLBACK;
        case StmtType::CREATE:        return MYSQL_COM_QUERY_CREATE;
        case StmtType::ALTER:         return MYSQL_COM_QUERY_ALTER;
        case StmtType::DROP:          return MYSQL_COM_QUERY_DROP;
        case StmtType::SHOW:          return MYSQL_COM_QUERY_SHOW;
        case StmtType::USE:           return MYSQL_COM_QUERY_USE;
        case StmtType::EXPLAIN:       return MYSQL_COM_QUERY_EXPLAIN;
        case StmtType::CALL:          return MYSQL_COM_QUERY_CALL;
        case StmtType::DESCRIBE:      return MYSQL_COM_QUERY_DESCRIBE;
        case StmtType::GRANT:         return MYSQL_COM_QUERY_GRANT;
        case StmtType::REVOKE:        return MYSQL_COM_QUERY_REVOKE;
        case StmtType::KILL:          return MYSQL_COM_QUERY_KILL;
        case StmtType::TRUNCATE:      return MYSQL_COM_QUERY_TRUNCATE;
        case StmtType::LOCK:          return MYSQL_COM_QUERY_LOCK;
        case StmtType::UNLOCK:        return MYSQL_COM_QUERY_UNLOCK;
        case StmtType::LOAD_DATA:     return MYSQL_COM_QUERY_LOAD;
        case StmtType::DO_STMT:       return MYSQL_COM_QUERY_DO;
        case StmtType::REPLACE:       return MYSQL_COM_QUERY_REPLACE;
        case StmtType::RENAME:        return MYSQL_COM_QUERY_RENAME;
        case StmtType::START:         return MYSQL_COM_QUERY_START;
        case StmtType::PREPARE:       return MYSQL_COM_QUERY_PREPARE;
        case StmtType::EXECUTE:       return MYSQL_COM_QUERY_EXECUTE;
        case StmtType::DEALLOCATE:    return MYSQL_COM_QUERY_DEALLOCATE;
        default:                      return MYSQL_COM_QUERY_OTHER;
    }
}

enum MYSQL_COM_QUERY_command parsersql_command_type_mysql(const char* query, int query_length) {
    auto result = tl_mysql_parser.parse(query, query_length);
    tl_mysql_parser.reset();

    if (result.status == ParseResult::OK || result.status == ParseResult::PARTIAL) {
        return stmt_type_to_mysql_command(result.stmt_type);
    }
    return MYSQL_COM_QUERY_OTHER;
}

enum PGSQL_QUERY_command parsersql_command_type_pgsql(const char* query, int query_length) {
    auto result = tl_pgsql_parser.parse(query, query_length);
    tl_pgsql_parser.reset();

    if (result.status == ParseResult::OK || result.status == ParseResult::PARTIAL) {
        return static_cast<PGSQL_QUERY_command>(stmt_type_to_mysql_command(result.stmt_type));
    }
    return PGSQL_QUERY_UNKNOWN;
}
```

**Note:** The `PGSQL_QUERY_command` mapping may need adjustment based on the actual enum values. Check `include/proxysql_structs.h` for the PgSQL command enum and adjust the cast or create a separate mapping function accordingly.

- [ ] **Step 3: Commit**

```bash
git add lib/Query_Processor_ParserSQL.cpp
git commit -m "feat: implement ParserSQL digest and command type adapters"
```

---

### Task 7: Create the Adapter Layer — SET Parser

**Files:**
- Modify: `lib/Query_Processor_ParserSQL.cpp` (append SET adapter)

- [ ] **Step 1: Implement the SET AST walker**

The SET adapter must produce the same `map<string, vector<string>>` as `MySQL_Set_Stmt_Parser::parse1v2()`. Key behaviors:
- Lowercase variable names
- Strip scope prefixes (`SESSION`, `@@session.`, `@@local.`, `@@`)
- Rename `transaction_isolation` → `tx_isolation`, `transaction_read_only` → `tx_read_only`
- Strip quotes from values
- Return empty map on parse failure

Add to `lib/Query_Processor_ParserSQL.cpp`:

```cpp
#include "sql_parser/ast.h"
#include "sql_parser/common.h"
#include <algorithm>
#include <cstring>

static std::string str_ref_to_string(const sql_parser::StringRef& ref) {
    return std::string(ref.ptr, ref.len);
}

static std::string node_value(const AstNode* node) {
    if (!node) return "";
    return std::string(node->value_ptr, node->value_len);
}

static std::string lowercase(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static std::string strip_quotes(const std::string& s) {
    if (s.size() >= 2) {
        char first = s.front();
        if ((first == '\'' || first == '"' || first == '`') && s.back() == first) {
            return s.substr(1, s.size() - 2);
        }
    }
    return s;
}

static std::string strip_scope_prefix(std::string var_name) {
    if (var_name.size() > 2 && var_name[0] == '@' && var_name[1] == '@') {
        var_name = var_name.substr(2);
        for (const char* prefix : {"session.", "local."}) {
            size_t plen = strlen(prefix);
            if (var_name.size() > plen &&
                strncasecmp(var_name.c_str(), prefix, plen) == 0) {
                var_name = var_name.substr(plen);
                break;
            }
        }
    }
    return var_name;
}

static std::string normalize_set_var_name(std::string var_name) {
    var_name = strip_scope_prefix(var_name);
    var_name = lowercase(var_name);
    if (var_name == "transaction_isolation") var_name = "tx_isolation";
    if (var_name == "transaction_read_only") var_name = "tx_read_only";
    return var_name;
}

static void walk_set_stmt(const AstNode* set_stmt,
                          std::map<std::string, std::vector<std::string>>& out) {
    const AstNode* child = set_stmt->first_child;
    while (child) {
        if (child->type == NodeType::NODE_SET_NAMES) {
            std::vector<std::string> values;
            const AstNode* id_child = child->first_child;
            while (id_child) {
                if (id_child->type == NodeType::NODE_IDENTIFIER) {
                    values.push_back(strip_quotes(node_value(id_child)));
                }
                id_child = id_child->next_sibling;
            }
            out["names"] = values;
        } else if (child->type == NodeType::NODE_SET_CHARSET) {
            std::vector<std::string> values;
            const AstNode* id_child = child->first_child;
            while (id_child) {
                if (id_child->type == NodeType::NODE_IDENTIFIER) {
                    values.push_back(strip_quotes(node_value(id_child)));
                }
                id_child = id_child->next_sibling;
            }
            if (!values.empty()) {
                out["character_set_results"] = values;
            }
        } else if (child->type == NodeType::NODE_VAR_ASSIGNMENT) {
            const AstNode* target = child->first_child;
            const AstNode* value_node = target ? target->next_sibling : nullptr;

            std::string var_name;
            if (target && target->type == NodeType::NODE_VAR_TARGET) {
                const AstNode* id_child = target->first_child;
                std::vector<std::string> parts;
                while (id_child) {
                    if (id_child->type == NodeType::NODE_IDENTIFIER) {
                        parts.push_back(node_value(id_child));
                    }
                    id_child = id_child->next_sibling;
                }
                if (parts.size() == 2) {
                    var_name = parts[1];
                } else if (parts.size() == 1) {
                    var_name = parts[0];
                }
            }

            if (!var_name.empty()) {
                var_name = normalize_set_var_name(var_name);
                std::string value;
                if (value_node) {
                    value = strip_quotes(node_value(value_node));
                }
                out[var_name] = {value};
            }
        }
        child = child->next_sibling;
    }
}

std::map<std::string, std::vector<std::string>>
parsersql_parse_set_mysql(const std::string& query) {
    std::map<std::string, std::vector<std::string>> result;
    auto parse_result = tl_mysql_parser.parse(query.c_str(), query.size());

    if (parse_result.status == ParseResult::OK && parse_result.ast) {
        walk_set_stmt(parse_result.ast, result);
    }

    tl_mysql_parser.reset();
    return result;
}

std::map<std::string, std::vector<std::string>>
parsersql_parse_set_pgsql(const std::string& query) {
    std::map<std::string, std::vector<std::string>> result;
    auto parse_result = tl_pgsql_parser.parse(query.c_str(), query.size());

    if (parse_result.status == ParseResult::OK && parse_result.ast) {
        walk_set_stmt(parse_result.ast, result);
    }

    tl_pgsql_parser.reset();
    return result;
}
```

**Note:** The `walk_set_stmt` implementation above handles the common cases. It must be tested against the existing SET parser test suite (see Task 10) and adjusted for any edge cases the AST structure differs from what's assumed here. In particular:
- Function call values (e.g., `CONCAT(@@sql_mode, ',STRICT')`) may need to emit the full expression text rather than just the node's `value_ptr`/`value_len`.
- `SET TRANSACTION` handling depends on how `NODE_SET_TRANSACTION` children are structured — the adapter may need to produce keys like `"tx_isolation"` or special handling for `parse2()`-style results.

- [ ] **Step 2: Commit**

```bash
git add lib/Query_Processor_ParserSQL.cpp
git commit -m "feat: implement ParserSQL SET statement adapter"
```

---

### Task 8: Wire Adapter into Query Processor — Digest Path

**Files:**
- Modify: `lib/Query_Processor.cpp`

- [ ] **Step 1: Add the branch in `query_parser_init()`**

Find `Query_Processor<QP_DERIVED>::query_parser_init()` (around line 2124). After the `if (GET_THREAD_VARIABLE(query_digests))` check, add a branch before the existing tokenizer calls:

```cpp
if (GET_THREAD_VARIABLE(query_processor_parser) == 1) {
    if constexpr (std::is_same_v<QP_DERIVED, MySQL_Query_Processor>) {
        parsersql_digest_init_mysql(qp, query, query_length);
    } else if constexpr (std::is_same_v<QP_DERIVED, PgSQL_Query_Processor>) {
        parsersql_digest_init_pgsql(qp, query, query_length);
    }
} else {
    // existing code: options opts, mysql_query_digest_and_first_comment, etc.
}
```

The `else` block contains all the existing tokenizer code unchanged.

Add the include at the top of the file:
```cpp
#include "Query_Processor_ParserSQL.h"
```

- [ ] **Step 2: Commit**

```bash
git add lib/Query_Processor.cpp
git commit -m "feat: wire ParserSQL digest adapter into query_parser_init"
```

---

### Task 9: Wire Adapter into Query Processor — Command Type and SET

**Files:**
- Modify: `lib/MySQL_Query_Processor.cpp`
- Modify: `lib/PgSQL_Query_Processor.cpp`
- Modify: `lib/MySQL_Session.cpp`
- Modify: `lib/PgSQL_Session.cpp`

- [ ] **Step 1: Add command type branch in MySQL_Query_Processor.cpp**

Find `MySQL_Query_Processor::query_parser_command_type()` (around line 155). At the top of the function, before the existing string-matching code:

```cpp
#include "Query_Processor_ParserSQL.h"

enum MYSQL_COM_QUERY_command MySQL_Query_Processor::query_parser_command_type(SQP_par_t* qp) {
    if (mysql_thread___query_processor_parser == 1) {
        return parsersql_command_type_mysql(qp->digest_text ? qp->digest_text : "", 0);
    }
    // ... existing code unchanged ...
}
```

**Note:** The adapter needs the original query text, not the digest text. Check what's available in `SQP_par_t` at this call site. If the original query is not in `qp`, the adapter may need to be called differently — perhaps passing the query from the caller. Investigate the call chain (`Query_Info::query_parser_command_type()` → `GloMyQPro->query_parser_command_type(&QueryParserArgs)`) to determine what query text is accessible.

- [ ] **Step 2: Add command type branch in PgSQL_Query_Processor.cpp**

Same pattern for `PgSQL_Query_Processor::query_parser_command_type()` (around line 659).

- [ ] **Step 3: Add SET parser branch in MySQL_Session.cpp**

Find the SET parser dispatch (around line 7474):

```cpp
if (mysql_thread___set_parser_algorithm == 1) {
    set = parser.parse1();
} else if (mysql_thread___set_parser_algorithm == 2) {
    thread->thr_SetParser->set_query(nq);
    set = thread->thr_SetParser->parse1v2();
} else if (mysql_thread___set_parser_algorithm == 3 || mysql_thread___query_processor_parser == 1) {
    set = parsersql_parse_set_mysql(nq);
}
```

The `query_processor_parser == 1` check ensures that full mode also uses ParserSQL for SET statements, regardless of `set_parser_algorithm`.

Add include:
```cpp
#include "Query_Processor_ParserSQL.h"
```

- [ ] **Step 4: Add SET parser branch in PgSQL_Session.cpp**

Same pattern for the PgSQL session SET handling (around line 4453).

- [ ] **Step 5: Commit**

```bash
git add lib/MySQL_Query_Processor.cpp lib/PgSQL_Query_Processor.cpp \
        lib/MySQL_Session.cpp lib/PgSQL_Session.cpp
git commit -m "feat: wire ParserSQL into command type detection and SET parsing"
```

---

### Task 10: Test the SET Parser Adapter

**Files:**
- Create: `test/tap/tests/setparser_parsersql_test.cpp`
- Modify: `test/tap/tests/Makefile` (or appropriate test Makefile)

- [ ] **Step 1: Write a test that validates the SET adapter against the existing test cases**

Create a test file that uses the same test cases from `setparser_test_common.h` but calls `parsersql_parse_set_mysql()` instead of `parse1()`/`parse1v2()`. This ensures the adapter produces identical output to the existing SET parsers for all known inputs.

```cpp
#include "setparser_test_common.h"
#include "../../../include/Query_Processor_ParserSQL.h"

// Reuse the test infrastructure from setparser_test3.cpp
// but call parsersql_parse_set_mysql() instead of parse1v2()

int main() {
    // For each test category in setparser_test_common.h:
    //   auto result = parsersql_parse_set_mysql(test_query);
    //   assert(result == expected_map);
    return 0;
}
```

**Note:** This task requires adapting the existing test infrastructure. The `setparser_test_common.h` header uses the `ok()` macro from ProxySQL's test framework. The test should compile against both the ProxySQL test framework and the ParserSQL adapter.

- [ ] **Step 2: Run the test and fix any AST walking issues**

```bash
cd /home/rene/proxysql-parsersql/proxysql
# Build and run the test
```

Expected: All test cases from `setparser_test_common.h` pass. If any fail, adjust the `walk_set_stmt` function in `lib/Query_Processor_ParserSQL.cpp` to match the expected output.

- [ ] **Step 3: Commit**

```bash
git add test/tap/tests/setparser_parsersql_test.cpp
git commit -m "test: add ParserSQL SET adapter validation tests"
```

---

### Task 11: Test the Digest Adapter

**Files:**
- Create: `test/tap/tests/parsersql_digest_test.cpp`

- [ ] **Step 1: Write a digest comparison test**

Parse a set of representative queries with both the legacy tokenizer and the ParserSQL adapter. Compare:

1. Both produce non-empty digest text
2. Digest hashes are valid (non-zero)
3. The ParserSQL digest text is a reasonable normalization of the input

```cpp
#include "Query_Processor_ParserSQL.h"
#include "c_tokenizer.h"
#include "SpookyV2.h"

struct test_case {
    const char* query;
};

static test_case queries[] = {
    {"SELECT * FROM users WHERE id = 1"},
    {"INSERT INTO t (a, b) VALUES (1, 'hello')"},
    {"UPDATE t SET a = 5 WHERE b = 10"},
    {"DELETE FROM t WHERE id = 1"},
    {"SET autocommit = 1"},
    {"SET NAMES utf8"},
    {"SET sql_mode = 'TRADITIONAL'"},
    {"SELECT a, b FROM t1 JOIN t2 ON t1.id = t2.id WHERE t1.x > 5"},
    {"BEGIN"},
    {"COMMIT"},
    {nullptr}
};

int main() {
    for (int i = 0; queries[i].query; i++) {
        SQP_par_t qp = {};
        // Test legacy path
        options opts = {};
        opts.lowercase = true;
        opts.replace_null = true;
        opts.replace_number = true;
        qp.digest_text = mysql_query_digest_and_first_comment(
            queries[i].query, strlen(queries[i].query),
            &qp.first_comment, NULL, &opts);
        std::string legacy_digest(qp.digest_text ? qp.digest_text : "");

        // Test ParserSQL path
        SQP_par_t qp2 = {};
        parsersql_digest_init_mysql(&qp2, queries[i].query, strlen(queries[i].query));
        std::string parsersql_digest(qp2.digest_text ? qp2.digest_text : "");

        // Both should produce non-empty output
        ok(!legacy_digest.empty(), "Legacy digest non-empty for: %s", queries[i].query);
        ok(!parsersql_digest.empty(), "ParserSQL digest non-empty for: %s", queries[i].query);
    }
    return 0;
}
```

- [ ] **Step 2: Run and validate**

```bash
# Build and run
```

Expected: Both paths produce non-empty digests for all test queries. Inspect any differences to understand normalization behavior changes.

- [ ] **Step 3: Commit**

```bash
git add test/tap/tests/parsersql_digest_test.cpp
git commit -m "test: add ParserSQL digest adapter comparison tests"
```

---

### Task 12: Full Build Verification

**Files:** None new — verification only.

- [ ] **Step 1: Clean build**

```bash
cd /home/rene/proxysql-parsersql/proxysql
make clean && make -j$(nproc)
```

Expected: Build succeeds with no linker errors. `libsqlparser.a` is linked into the `proxysql` binary.

- [ ] **Step 2: Verify the binary has the new symbols**

```bash
nm proxysql | grep parsersql_
```

Expected: `parsersql_digest_init_mysql`, `parsersql_command_type_mysql`, `parsersql_parse_set_mysql`, etc. are visible.

- [ ] **Step 3: Run the existing test suite**

```bash
cd test/tap && make -j$(nproc)
# Run existing tests to ensure no regressions:
./run_tests.sh
```

Expected: All existing tests pass (legacy paths unchanged by default).

---

## Notes for the Implementer

1. **ParserSQL namespace**: All ParserSQL types are in `sql_parser::` namespace. The header includes are `sql_parser/parser.h`, `sql_parser/digest.h`, `sql_parser/emitter.h`, `sql_parser/ast.h`, `sql_parser/common.h`.

2. **Per-thread parser lifecycle**: The `thread_local` parser instances are lazily initialized on first use. The `reset()` call after each parse is O(1) — it rewinds the arena allocator. Do NOT destroy/recreate parsers between queries.

3. **PGSQL_QUERY_command mapping**: The `PGSQL_QUERY_command` enum values may not match `MYSQL_COM_QUERY_command` exactly. Check `include/proxysql_structs.h` for the actual enum and create a dedicated mapping function if the values differ.

4. **AST node value extraction**: `AstNode::value_ptr` and `AstNode::value_len` provide zero-copy access to the original query text. For expression values (like `CONCAT(...)`), you may need to use `Emitter` to reconstruct the text rather than relying on the node's value fields.

5. **Feature flag guard**: All ParserSQL code should be wrapped in `#ifdef PROXYSQL40` (or a new `PROXYSQL_PARSERSQL` flag) to allow building without ParserSQL on systems where it's not yet available. This matches how the plugin chassis is guarded.

6. **Memory management**: The adapter uses `strdup()` for digest text to match the existing convention (the caller frees via `free()`). Do not mix `new[]`/`delete[]` with `malloc`/`free`.
