/**
 * @file Query_Processor_ParserSQL.cpp
 * @brief Implementation of the ParserSQL adapter layer for ProxySQL's query processor.
 *
 * @details Architecture
 * ----------
 * Each dialect (MySQL, PostgreSQL) has a `thread_local` `Parser<D>` instance that
 * persists for the lifetime of the thread.  Parsers use arena allocators — after each
 * query, `reset()` recycles the arena in O(1) without freeing individual nodes, making
 * per-query overhead negligible.
 *
 * The file is organised into three sections:
 *
 *   **Section 1 — Digest adapter**
 *   Uses `Emitter::DIGEST` mode to produce normalised query text from a full AST, then
 *   hashes it with SpookyHash for backward compatibility with ProxySQL's existing digest
 *   infrastructure.  For statements that parse only to the token level (Tier 2 — no full
 *   AST), it falls back to `Digest<D>` which normalises at the token level instead.
 *
 *   **Section 2 — Command type mapping**
 *   Translates ParserSQL's `StmtType` enum to ProxySQL's `MYSQL_COM_QUERY_command` /
 *   `PGSQL_QUERY_command` enums via static lookup functions.  Any `StmtType` value not
 *   present in the switch maps to UNKNOWN.
 *
 *   **Section 3 — SET AST walker**
 *   Traverses the children of a `NODE_SET_STMT` AST node, normalises variable names
 *   (scope prefix stripping, lowercasing, legacy alias resolution for tx_isolation and
 *   tx_read_only), and produces a `map<string, vector<string>>` identical in format to
 *   the output of `MySQL_Set_Stmt_Parser`.
 */

#include "proxysql.h"
#include "Query_Processor_ParserSQL.h"
#include "sql_parser/parser.h"
#include "sql_parser/digest.h"
#include "sql_parser/emitter.h"
#include "sql_parser/ast.h"
#include "sql_parser/common.h"
#include "sql_parser/user_variable.h"
#include "SpookyV2.h"

#include <algorithm>
#include <cctype>
#include <cstring>

using namespace sql_parser;

// Per-thread parser instances. Arena memory is reused across parses via reset(),
// so there is no per-query allocation overhead.
static thread_local Parser<Dialect::MySQL> tl_mysql_parser;
static thread_local Parser<Dialect::PostgreSQL> tl_pgsql_parser;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string lowercase(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

/** Strips a single layer of matching quotes ('' or "" or ``) from a string. */
static std::string strip_quotes(const std::string& s) {
    if (s.size() >= 2) {
        char first = s.front();
        if ((first == '\'' || first == '"' || first == '`') && s.back() == first) {
            return s.substr(1, s.size() - 2);
        }
    }
    return s;
}

/**
 * Removes scope prefixes from @-style variable names.
 * For example, "@@session.wait_timeout" becomes "wait_timeout".
 * Non-@ variables (system names like "SESSION wait_timeout") are left untouched
 * here; they are handled by normalize_set_var_name below.
 */
static std::string strip_scope_prefix(std::string var_name) {
    if (var_name.size() > 2 && var_name[0] == '@' && var_name[1] == '@') {
        var_name = var_name.substr(2);
        for (const char* prefix : {"session.", "local.", "global.", "persist.", "persist_only."}) {
            size_t plen = strlen(prefix); // NOSONAR: prefix is a string literal, strlen is evaluated at compile-time
            if (var_name.size() > plen &&
                strncasecmp(var_name.c_str(), prefix, plen) == 0) {
                var_name = var_name.substr(plen);
                break;
            }
        }
    }
    return var_name;
}

/**
 * Normalises a SET variable name for consistent lookup.
 *
 * Steps:
 *   1. Strip keyword scope prefix (SESSION/GLOBAL/LOCAL/PERSIST/PERSIST_ONLY).
 *   2. Strip @@-style scope prefix (@@session. → "").
 *   3. Lowercase the result.
 *   4. Resolve legacy aliases: "transaction_isolation" → "tx_isolation",
 *      "transaction_read_only" → "tx_read_only".
 *
 * This ensures the same variable name is produced regardless of how the user
 * wrote the SET statement, matching the behaviour of the regex-based parser.
 */
static std::string normalize_set_var_name(std::string var_name) {
    for (const char* prefix : {"SESSION ", "GLOBAL ", "LOCAL ", "PERSIST ", "PERSIST_ONLY "}) {
        size_t plen = strlen(prefix); // NOSONAR: prefix is a string literal, strlen is evaluated at compile-time
        if (var_name.size() > plen &&
            strncasecmp(var_name.c_str(), prefix, plen) == 0) {
            var_name = var_name.substr(plen);
            break;
        }
    }
    var_name = strip_scope_prefix(var_name);
    var_name = lowercase(var_name);
    // Legacy aliases — older MySQL versions used tx_isolation/tx_read_only,
    // newer ones use transaction_isolation/transaction_read_only.
    if (var_name == "transaction_isolation") var_name = "tx_isolation";
    if (var_name == "transaction_read_only") var_name = "tx_read_only";
    return var_name;
}

/**
 * Reconstructs the textual representation of an AST subtree.
 *
 * This is used in the SET walker to extract variable names and values from
 * individual AST nodes (e.g. NODE_VAR_TARGET, literal values). The emitter
 * runs in NORMAL mode so that the original token spellings are preserved.
 *
 * @tparam D  SQL dialect (MySQL or PostgreSQL).
 * @param node  Root of the subtree to emit.
 * @param arena Arena used for temporary allocation during emission.
 * @return      The emitted text, or "" if node is null.
 */
template <Dialect D>
static std::string emit_node_text(const AstNode* node, Arena& arena) {
    if (!node) return "";
    Emitter<D> emitter(arena, EmitMode::NORMAL);
    emitter.emit(node);
    StringRef ref = emitter.result();
    return std::string(ref.ptr, ref.len);
}

static void skip_quoted_char(const char*& p, const char* end) {
    char q = *p;
    p++;
    while (p < end && *p != q) {
        if (*p == '\\' && p + 1 < end) p++;
        p++;
    }
}

static bool is_sql_space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static std::string trim_copy(const char* start, const char* end) {
    while (start < end && is_sql_space(*start)) start++;
    while (end > start && is_sql_space(*(end - 1))) end--;
    return std::string(start, end);
}

static bool is_single_sql_token_value(const std::string& s) {
    if (s.size() < 2) return false;
    char q = s.front();
    if (q != '\'' && q != '"' && q != '`') return false;
    const char* p = s.data() + 1;
    const char* end = s.data() + s.size();
    while (p < end) {
        if (*p == '\\' && p + 1 < end) {
            p += 2;
            continue;
        }
        if (*p == q) {
            p++;
            while (p < end && is_sql_space(*p)) p++;
            return p == end;
        }
        p++;
    }
    return false;
}

static std::string strip_single_sql_token_quotes(const std::string& s) {
    if (!is_single_sql_token_value(s)) return s;
    size_t start = 1;
    size_t end = s.size() - 1;
    while (end > start && is_sql_space(s[end - 1])) end--;
    return s.substr(start, end - start);
}

static bool is_assignment_operator_at(const char* p, const char* end) {
    if (p >= end) return false;
    if (*p == '=') return true;
    return *p == ':' && p + 1 < end && *(p + 1) == '=';
}

static const char* skip_assignment_operator(const char* p, const char* end) {
    if (p < end && *p == ':' && p + 1 < end && *(p + 1) == '=') return p + 2;
    if (p < end && *p == '=') return p + 1;
    return p;
}

static std::string extract_mysql_assignment_value(
    const char*& scan, const char* query, int query_len)
{
    const char* qstart = query;
    const char* qend = query + query_len;
    if (!scan || scan < qstart || scan > qend) scan = qstart;

    const char* p = scan;
    int depth = 0;
    while (p < qend) {
        if (*p == '\'' || *p == '"' || *p == '`') {
            skip_quoted_char(p, qend);
        } else if (*p == '(' || *p == '[') {
            depth++;
        } else if ((*p == ')' || *p == ']') && depth > 0) {
            depth--;
        } else if (depth == 0 && is_assignment_operator_at(p, qend)) {
            break;
        }
        p++;
    }
    if (p >= qend) return "";

    const char* value_start = skip_assignment_operator(p, qend);
    while (value_start < qend && is_sql_space(*value_start)) value_start++;

    p = value_start;
    depth = 0;
    while (p < qend) {
        if (*p == '\'' || *p == '"' || *p == '`') {
            skip_quoted_char(p, qend);
        } else if (*p == '(' || *p == '[') {
            depth++;
        } else if ((*p == ')' || *p == ']') && depth > 0) {
            depth--;
        } else if (depth == 0 && (*p == ',' || *p == ';')) {
            break;
        }
        p++;
    }

    scan = (p < qend && *p == ',') ? p + 1 : p;
    return trim_copy(value_start, p);
}

static std::string extract_paren_expr(const char* query, int query_len,
                                       const char* after_var) {
    if (!after_var || after_var >= query + query_len) return "";
    const char* p = after_var;
    const char* end = query + query_len;
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (p >= end || (*p != '=' && *p != ':')) return "";
    while (p < end && *p != '(') p++;
    if (p >= end) return "";
    const char* start = p;
    int depth = 0;
    while (p < end) {
        if (*p == '(') depth++;
        else if (*p == ')') { depth--; if (depth == 0) { p++; break; } }
        else if (*p == '\'' || *p == '"') { skip_quoted_char(p, end); }
        p++;
    }
    return std::string(start, p);
}

// Extract the verbatim source text of a function-call AST node by paren-matching
// from the function name in the original input. Used to avoid emit_function_call's
// "name(arg, arg)" normalisation (which adds a space after every comma) so that the
// SET walker preserves the exact source the user wrote, matching the regex-based
// SET parsers (algorithms 0-2) byte-for-byte. Returns empty string if value_ptr is
// not inside [query, query+query_len) or no balanced paren is found.
static std::string extract_function_call_source(
    const AstNode* node, const char* query, int query_len)
{
    if (!node || !node->value_ptr || node->value_len == 0) return "";
    const char* qstart = query;
    const char* qend = query + query_len;
    if (node->value_ptr < qstart || node->value_ptr >= qend) return "";
    const char* start = node->value_ptr;
    const char* p = start + node->value_len;
    while (p < qend && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    if (p >= qend || *p != '(') return "";
    int depth = 0;
    while (p < qend) {
        if (*p == '\'' || *p == '"' || *p == '`') { skip_quoted_char(p, qend); }
        else if (*p == '(') depth++;
        else if (*p == ')') { depth--; if (depth == 0) { p++; break; } }
        p++;
    }
    if (depth != 0) return "";
    return std::string(start, p);
}

// Find the rightmost byte covered by any descendant of `node` whose value_ptr
// lies inside [qstart, qend). Used to detect "trailing junk after a valid
// statement" cases where ParserSQL accepts a partial AST (status OK) but
// stopped before consuming all the input. E.g. `SET search_path = public,,schema1`
// produces an OK status with an AST covering only `SET search_path = public`;
// the `,,schema1` tail is silently ignored, which would otherwise let proxysql
// track a malformed SET as successful. Returns nullptr if no descendant lies
// inside the buffer.
static const char* find_rightmost_ast_byte(
    const AstNode* node, const char* qstart, const char* qend)
{
    if (!node) return nullptr;
    const char* best = nullptr;
    if (node->value_ptr && node->value_ptr >= qstart &&
        (node->value_ptr + node->value_len) <= qend) {
        const char* end = node->value_ptr + node->value_len;
        // Delimited identifier / string-literal nodes store value_ptr inside
        // the quotes and value_len covering only the content, so the closing
        // quote/backtick byte lives at end. Advance past it so the full-input
        // check at the call site doesn't mistake the closing delimiter for
        // unconsumed trailing junk.
        if (end < qend && (*end == '"' || *end == '`' || *end == '\'')) {
            // Only treat as a delimiter close if there's a matching opener
            // immediately before value_ptr (cheap sanity check; avoids
            // accidentally consuming an unrelated quote that follows).
            if (node->value_ptr > qstart && *(node->value_ptr - 1) == *end) {
                end++;
            }
        }
        best = end;
    }
    for (const AstNode* c = node->first_child; c; c = c->next_sibling) {
        const char* cb = find_rightmost_ast_byte(c, qstart, qend);
        if (cb && (!best || cb > best)) best = cb;
    }
    return best;
}

// True iff the AST consumed every meaningful byte of `query` (ignoring trailing
// whitespace and a single trailing semicolon). Used as a stricter gate than
// just checking parse status: ParserSQL can return status OK while the parser
// only matched a prefix of the input, leaving the rest as unconsumed trailing
// junk. For SET-statement walking we treat such cases as parse failures so
// the session can fall through to the backend (which will reject the
// malformed SQL) instead of tracking a misleadingly-partial assignment.
static bool ast_covers_full_input(
    const AstNode* root, const char* query, int query_len)
{
    if (!root) return false;
    const char* qstart = query;
    const char* qend = query + query_len;
    const char* rightmost = find_rightmost_ast_byte(root, qstart, qend);
    if (!rightmost) return false;
    // Anything past the AST's coverage must be cosmetic: trailing whitespace,
    // a single trailing comma (which the regex SET parser strips and many
    // existing tests rely on, e.g. `SET search_path TO "$user" ,`),
    // a single trailing semicolon, and embedded null bytes (QueryPointer
    // buffers occasionally include a trailing \0 byte we shouldn't bounce on).
    auto is_skippable = [](char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\0';
    };
    const char* p = rightmost;
    while (p < qend && is_skippable(*p)) p++;
    if (p < qend && *p == ',') {
        p++;
        while (p < qend && is_skippable(*p)) p++;
    }
    if (p < qend && *p == ';') {
        p++;
        while (p < qend && is_skippable(*p)) p++;
    }
    return p == qend;
}

// Re-emit a delimited identifier ("name" in PG, `name` in MySQL) with its outer
// quote chars restored. The AST stores value_ptr pointing inside the quotes and
// value_len covering only the identifier content, so the surrounding quote chars
// live at value_ptr-1 and value_ptr+value_len in the original query buffer.
// Returns empty string if the node is not in-buffer or the surrounding chars
// don't look like recognised quote chars.
static std::string emit_delimited_ident_raw(
    const AstNode* node, const char* query, int query_len)
{
    if (!node || !node->value_ptr || node->value_len == 0) return "";
    const char* qstart = query;
    const char* qend = query + query_len;
    if (node->value_ptr <= qstart) return "";
    if (node->value_ptr + node->value_len >= qend) return "";
    char open_q = *(node->value_ptr - 1);
    char close_q = *(node->value_ptr + node->value_len);
    if (open_q != '"' && open_q != '`') return "";
    if (open_q != close_q) return "";
    return std::string(node->value_ptr - 1, node->value_ptr + node->value_len + 1);
}

// ---------------------------------------------------------------------------
// Section 1: Digest adapter
// ---------------------------------------------------------------------------

/**
 * @brief MySQL digest: normalise then SpookyHash.
 *
 * Two-tier strategy:
 *   - If the parser produces a full AST (Tier 1), `Emitter::DIGEST` mode walks
 *     it and emits normalised text with literals replaced by placeholders (?).
 *   - If the parser only reached the token level (Tier 2 — partial parse of
 *     unsupported statement types), `Digest<D>` performs token-level
 *     normalisation as a fallback.
 *
 * The resulting normalised text is hashed with SpookyHash::Hash64 to produce
 * the 64-bit digest that ProxySQL uses for query rule matching and statistics.
 */
void parsersql_digest_init_mysql(SQP_par_t* qp, const char* query, int query_length) {
    qp->digest_text = NULL;
    qp->first_comment = NULL;
    qp->query_prefix = NULL;
    qp->digest = 0;

    auto result = tl_mysql_parser.parse(query, query_length);

    if (result.status == ParseResult::OK || result.status == ParseResult::PARTIAL) {
        std::string normalized;
        if (result.ast) {
            // Tier 1: full AST available — use Emitter in DIGEST mode
            Emitter<Dialect::MySQL> emitter(tl_mysql_parser.arena(), EmitMode::DIGEST);
            emitter.emit(result.ast);
            StringRef ref = emitter.result();
            normalized.assign(ref.ptr, ref.len);
        } else {
            // Tier 2: token-level fallback for statements without full AST support
            Digest<Dialect::MySQL> digest(tl_mysql_parser.arena());
            DigestResult dr = digest.compute(query, query_length);
            normalized.assign(dr.normalized.ptr, dr.normalized.len);
        }
        qp->digest_text = strdup(normalized.c_str());
        // SpookyHash is preserved for backward compatibility with existing digest stats
        qp->digest = SpookyHash::Hash64(normalized.c_str(), normalized.size(), 0);
    }

    tl_mysql_parser.reset();
}

/** PostgreSQL variant of the digest adapter. See parsersql_digest_init_mysql for details. */
void parsersql_digest_init_pgsql(SQP_par_t* qp, const char* query, int query_length) {
    qp->digest_text = NULL;
    qp->first_comment = NULL;
    qp->query_prefix = NULL;
    qp->digest = 0;

    auto result = tl_pgsql_parser.parse(query, query_length);

    if (result.status == ParseResult::OK || result.status == ParseResult::PARTIAL) {
        std::string normalized;
        if (result.ast) {
            Emitter<Dialect::PostgreSQL> emitter(tl_pgsql_parser.arena(), EmitMode::DIGEST);
            emitter.emit(result.ast);
            StringRef ref = emitter.result();
            normalized.assign(ref.ptr, ref.len);
        } else {
            Digest<Dialect::PostgreSQL> digest(tl_pgsql_parser.arena());
            DigestResult dr = digest.compute(query, query_length);
            normalized.assign(dr.normalized.ptr, dr.normalized.len);
        }
        qp->digest_text = strdup(normalized.c_str());
        qp->digest = SpookyHash::Hash64(normalized.c_str(), normalized.size(), 0);
    }

    tl_pgsql_parser.reset();
}

// ---------------------------------------------------------------------------
// Section 2: Command type mapping
// ---------------------------------------------------------------------------
// Each function maps ParserSQL's StmtType enum to ProxySQL's protocol-specific
// command enum.  Types that have no meaningful equivalent in the target protocol
// (e.g. REPLACE is MySQL-only, USE has no PostgreSQL counterpart) return UNKNOWN.

/**
 * Maps StmtType → MYSQL_COM_QUERY_command.
 * RESET and DO have no dedicated enum in ProxySQL and are mapped to UNKNOWN.
 */
static enum MYSQL_COM_QUERY_command stmt_type_to_mysql_command(StmtType st) {
    switch (st) {
        case StmtType::SELECT:           return MYSQL_COM_QUERY_SELECT;
        case StmtType::INSERT:           return MYSQL_COM_QUERY_INSERT;
        case StmtType::UPDATE:           return MYSQL_COM_QUERY_UPDATE;
        case StmtType::DELETE_STMT:      return MYSQL_COM_QUERY_DELETE;
        case StmtType::REPLACE:          return MYSQL_COM_QUERY_REPLACE;
        case StmtType::SET:              return MYSQL_COM_QUERY_SET;
        case StmtType::USE:              return MYSQL_COM_QUERY_USE;
        case StmtType::SHOW:             return MYSQL_COM_QUERY_SHOW;
        case StmtType::BEGIN:            return MYSQL_COM_QUERY_BEGIN;
        case StmtType::START_TRANSACTION: return MYSQL_COM_QUERY_START_TRANSACTION;
        case StmtType::COMMIT:           return MYSQL_COM_QUERY_COMMIT;
        case StmtType::ROLLBACK:         return MYSQL_COM_QUERY_ROLLBACK;
        case StmtType::SAVEPOINT:        return MYSQL_COM_QUERY_SAVEPOINT;
        case StmtType::PREPARE:          return MYSQL_COM_QUERY_PREPARE;
        case StmtType::EXECUTE:          return MYSQL_COM_QUERY_EXECUTE;
        case StmtType::DEALLOCATE:       return MYSQL_COM_QUERY_DEALLOCATE;
        case StmtType::CREATE:           return MYSQL_COM_QUERY_CREATE_TABLE;
        case StmtType::ALTER:            return MYSQL_COM_QUERY_ALTER_TABLE;
        case StmtType::DROP:             return MYSQL_COM_QUERY_DROP_TABLE;
        case StmtType::TRUNCATE:         return MYSQL_COM_QUERY_TRUNCATE_TABLE;
        case StmtType::GRANT:            return MYSQL_COM_QUERY_GRANT;
        case StmtType::REVOKE:           return MYSQL_COM_QUERY_REVOKE;
        case StmtType::LOCK:             return MYSQL_COM_QUERY_LOCK_TABLE;
        case StmtType::UNLOCK:           return MYSQL_COM_QUERY_UNLOCK_TABLES;
        case StmtType::LOAD_DATA:        return MYSQL_COM_QUERY_LOAD;
        case StmtType::EXPLAIN:          return MYSQL_COM_QUERY_EXPLAIN;
        case StmtType::DESCRIBE:         return MYSQL_COM_QUERY_DESCRIBE;
        case StmtType::CALL:             return MYSQL_COM_QUERY_CALL;
        case StmtType::RESET:            return MYSQL_COM_QUERY_UNKNOWN;
        case StmtType::DO_STMT:          return MYSQL_COM_QUERY_UNKNOWN;
        default:                         return MYSQL_COM_QUERY_UNKNOWN;
    }
}

/**
 * Maps StmtType → PGSQL_QUERY_command.
 * MySQL-only types (REPLACE, USE, UNLOCK, LOAD_DATA, DESCRIBE, DO) have no
 * PostgreSQL equivalent and are mapped to UNKNOWN.  Both BEGIN and
 * START_TRANSACTION map to PGSQL_QUERY_BEGIN since PostgreSQL treats them
 * identically.
 */
static enum PGSQL_QUERY_command stmt_type_to_pgsql_command(StmtType st) {
    switch (st) {
        case StmtType::SELECT:           return PGSQL_QUERY_SELECT;
        case StmtType::INSERT:           return PGSQL_QUERY_INSERT;
        case StmtType::UPDATE:           return PGSQL_QUERY_UPDATE;
        case StmtType::DELETE_STMT:      return PGSQL_QUERY_DELETE;
        case StmtType::SET:              return PGSQL_QUERY_SET;
        case StmtType::SHOW:             return PGSQL_QUERY_SHOW;
        case StmtType::BEGIN:            return PGSQL_QUERY_BEGIN;
        case StmtType::START_TRANSACTION: return PGSQL_QUERY_BEGIN;
        case StmtType::COMMIT:           return PGSQL_QUERY_COMMIT;
        case StmtType::ROLLBACK:         return PGSQL_QUERY_ROLLBACK;
        case StmtType::SAVEPOINT:        return PGSQL_QUERY_SAVEPOINT;
        case StmtType::PREPARE:          return PGSQL_QUERY_PREPARE;
        case StmtType::EXECUTE:          return PGSQL_QUERY_EXECUTE;
        case StmtType::DEALLOCATE:       return PGSQL_QUERY_DEALLOCATE;
        case StmtType::CREATE:           return PGSQL_QUERY_CREATE_TABLE;
        case StmtType::ALTER:            return PGSQL_QUERY_ALTER_TABLE;
        case StmtType::DROP:             return PGSQL_QUERY_DROP_TABLE;
        case StmtType::TRUNCATE:         return PGSQL_QUERY_TRUNCATE;
        case StmtType::GRANT:            return PGSQL_QUERY_GRANT;
        case StmtType::REVOKE:           return PGSQL_QUERY_REVOKE;
        case StmtType::LOCK:             return PGSQL_QUERY_LOCK;
        case StmtType::EXPLAIN:          return PGSQL_QUERY_EXPLAIN;
        case StmtType::CALL:             return PGSQL_QUERY_CALL;
        case StmtType::RESET:            return PGSQL_QUERY_RESET;
        case StmtType::REPLACE:          return PGSQL_QUERY_UNKNOWN;
        case StmtType::USE:              return PGSQL_QUERY_UNKNOWN;
        case StmtType::UNLOCK:           return PGSQL_QUERY_UNKNOWN;
        case StmtType::LOAD_DATA:        return PGSQL_QUERY_UNKNOWN;
        case StmtType::DESCRIBE:         return PGSQL_QUERY_UNKNOWN;
        case StmtType::DO_STMT:          return PGSQL_QUERY_UNKNOWN;
        default:                         return PGSQL_QUERY_UNKNOWN;
    }
}

enum MYSQL_COM_QUERY_command parsersql_command_type_mysql(const char* query, int query_length) {
    auto result = tl_mysql_parser.parse(query, query_length);
    tl_mysql_parser.reset();
    if (result.status == ParseResult::OK || result.status == ParseResult::PARTIAL) {
        return stmt_type_to_mysql_command(result.stmt_type);
    }
    return MYSQL_COM_QUERY_UNKNOWN;
}

enum PGSQL_QUERY_command parsersql_command_type_pgsql(const char* query, int query_length) {
    auto result = tl_pgsql_parser.parse(query, query_length);
    tl_pgsql_parser.reset();
    if (result.status == ParseResult::OK || result.status == ParseResult::PARTIAL) {
        return stmt_type_to_pgsql_command(result.stmt_type);
    }
    return PGSQL_QUERY_UNKNOWN;
}

// ---------------------------------------------------------------------------
// MySQL user-variable tracking contract
// ---------------------------------------------------------------------------

static std::string copy_ref(StringRef ref) {
    return ref.ptr ? std::string(ref.ptr, ref.len) : std::string();
}

static std::string lowercase_ascii(StringRef ref) {
    std::string value = copy_ref(ref);
    for (char& c : value) {
        unsigned char byte = static_cast<unsigned char>(c);
        if (byte >= 'A' && byte <= 'Z') c = static_cast<char>(byte + ('a' - 'A'));
    }
    return value;
}

static void append_length(std::string& tuple, size_t length) {
    uint64_t value = static_cast<uint64_t>(length);
    for (unsigned int shift = 0; shift < 64; shift += 8) {
        tuple.push_back(static_cast<char>((value >> shift) & 0xff));
    }
}

static uint64_t hash_user_variable_assignment(const UserVariableAssignment& assignment) {
    std::string tuple;
    tuple.reserve(1 + 16 + assignment.replay_target.size() + assignment.raw_literal.size());
    tuple.push_back(static_cast<char>(assignment.kind));
    append_length(tuple, assignment.replay_target.size());
    tuple.append(assignment.replay_target);
    append_length(tuple, assignment.raw_literal.size());
    tuple.append(assignment.raw_literal);
    return SpookyHash::Hash64(tuple.data(), tuple.size(), 0);
}

static bool literal_kind(const AstNode* rhs, UserVariableLiteralKind& kind) {
    switch (rhs->type) {
        case NodeType::NODE_LITERAL_STRING:
            kind = UserVariableLiteralKind::STRING;
            return true;
        case NodeType::NODE_LITERAL_INT:
            kind = UserVariableLiteralKind::INTEGER;
            return true;
        case NodeType::NODE_LITERAL_FLOAT:
            kind = UserVariableLiteralKind::DECIMAL;
            return true;
        case NodeType::NODE_LITERAL_HEX:
            kind = UserVariableLiteralKind::HEXADECIMAL;
            return true;
        case NodeType::NODE_LITERAL_BIT:
            kind = UserVariableLiteralKind::BIT;
            return true;
        case NodeType::NODE_LITERAL_NULL:
            kind = UserVariableLiteralKind::NULL_VALUE;
            return true;
        default:
            return false;
    }
}

static bool supported_user_variable_rhs(
    const AstNode* rhs, UserVariableLiteralKind& kind)
{
    if (!rhs || rhs->next_sibling || !rhs->source_ptr || rhs->source_len == 0) return false;
    if (literal_kind(rhs, kind)) return true;
    if (rhs->type != NodeType::NODE_UNARY_OP || !rhs->first_child ||
        rhs->first_child->next_sibling || rhs->value_len != 1 ||
        (rhs->value_ptr[0] != '+' && rhs->value_ptr[0] != '-')) {
        return false;
    }
    const AstNode* operand = rhs->first_child;
    if (operand->type == NodeType::NODE_LITERAL_INT) {
        kind = UserVariableLiteralKind::INTEGER;
        return true;
    }
    if (operand->type == NodeType::NODE_LITERAL_FLOAT) {
        kind = UserVariableLiteralKind::DECIMAL;
        return true;
    }
    return false;
}

static bool assignment_has_user_target(const AstNode* assignment) {
    if (!assignment || assignment->type != NodeType::NODE_VAR_ASSIGNMENT) return false;
    const AstNode* target = assignment->first_child;
    return target && target->type == NodeType::NODE_VAR_TARGET &&
        target->first_child && target->first_child->type == NodeType::NODE_USER_VARIABLE;
}

UserVariableSetAnalysis parsersql_analyze_user_variable_set_mysql(
    const char* query, size_t query_length)
{
    UserVariableSetAnalysis analysis;
    if (!query) {
        analysis.status = UserVariableSetStatus::PARSE_ERROR;
        return analysis;
    }

    auto result = tl_mysql_parser.parse(query, query_length);
    if (result.status != ParseResult::OK || !result.full_input) {
        if (result.has_user_variables) {
            analysis.status = UserVariableSetStatus::PARSE_ERROR;
        }
        tl_mysql_parser.reset();
        return analysis;
    }
    if (result.stmt_type != StmtType::SET || !result.ast ||
        result.ast->type != NodeType::NODE_SET_STMT) {
        tl_mysql_parser.reset();
        return analysis;
    }

    bool has_user_target = false;
    for (const AstNode* child = result.ast->first_child; child; child = child->next_sibling) {
        if (assignment_has_user_target(child)) has_user_target = true;
    }
    if (!has_user_target) {
        tl_mysql_parser.reset();
        return analysis;
    }

    std::vector<UserVariableAssignment> assignments;
    for (const AstNode* child = result.ast->first_child; child; child = child->next_sibling) {
        if (!assignment_has_user_target(child)) {
            analysis.status = UserVariableSetStatus::UNSUPPORTED;
            tl_mysql_parser.reset();
            return analysis;
        }

        const AstNode* target = child->first_child;
        const AstNode* variable = target->first_child;
        const AstNode* rhs = target->next_sibling;
        if (target->next_sibling == nullptr || target->first_child->next_sibling ||
            variable->value_len == 0 || variable->value_len > 64 ||
            !variable->source_ptr || variable->source_len < 2) {
            analysis.status = UserVariableSetStatus::UNSUPPORTED;
            tl_mysql_parser.reset();
            return analysis;
        }

        StringRef target_source = variable->source();
        char name_start = target_source.ptr[1];
        bool quoted = name_start == '\'' || name_start == '"' || name_start == '`';
        if (quoted && std::memchr(target_source.ptr, '\\', target_source.len)) {
            analysis.status = UserVariableSetStatus::UNSUPPORTED;
            tl_mysql_parser.reset();
            return analysis;
        }

        UserVariableLiteralKind kind;
        if (!supported_user_variable_rhs(rhs, kind)) {
            analysis.status = UserVariableSetStatus::UNSUPPORTED;
            tl_mysql_parser.reset();
            return analysis;
        }

        UserVariableAssignment assignment;
        assignment.canonical_name = lowercase_ascii(variable->value());
        assignment.replay_target = copy_ref(target_source);
        assignment.raw_literal = copy_ref(rhs->source());
        assignment.kind = kind;
        assignment.hash = hash_user_variable_assignment(assignment);
        assignments.push_back(std::move(assignment));
    }

    analysis.status = UserVariableSetStatus::SUPPORTED;
    analysis.assignments = std::move(assignments);
    tl_mysql_parser.reset();
    return analysis;
}

::UserVariableUsage parsersql_classify_user_variable_usage_mysql(
    const char* query, size_t query_length)
{
    if (!query) return ::UserVariableUsage::UNSAFE_OR_UNKNOWN;
    auto result = tl_mysql_parser.parse(query, query_length);
    sql_parser::UserVariableUsage upstream =
        sql_parser::classify_mysql_user_variable_usage(result);
    tl_mysql_parser.reset();
    switch (upstream) {
        case sql_parser::UserVariableUsage::NO_USER_VARIABLE:
            return ::UserVariableUsage::NO_USER_VARIABLE;
        case sql_parser::UserVariableUsage::READ_ONLY:
            return ::UserVariableUsage::READ_ONLY;
        case sql_parser::UserVariableUsage::UNSAFE_OR_UNKNOWN:
            return ::UserVariableUsage::UNSAFE_OR_UNKNOWN;
    }
    return ::UserVariableUsage::UNSAFE_OR_UNKNOWN;
}

UserVariableQueryDecision mysql_user_variable_query_disposition(
    const char* query, size_t query_length,
    bool must_classify_and_sync, bool plain_text_com_query,
    bool supported_user_variable_set)
{
    if (!plain_text_com_query || !must_classify_and_sync) {
        return {UserVariableQueryDisposition::LEGACY, false, false};
    }
    if (supported_user_variable_set) {
        return {UserVariableQueryDisposition::SUPPORTED_SET, false, true};
    }
    if (!query || std::memchr(query, '@', query_length) == nullptr) {
        return {UserVariableQueryDisposition::SAFE, false, true};
    }

    const ::UserVariableUsage usage =
        parsersql_classify_user_variable_usage_mysql(query, query_length);
    if (usage == ::UserVariableUsage::NO_USER_VARIABLE ||
        usage == ::UserVariableUsage::READ_ONLY) {
        return {UserVariableQueryDisposition::SAFE, true, true};
    }
    return {UserVariableQueryDisposition::UNSAFE_FALLBACK, true, false};
}

bool mysql_user_variable_is_replay_context_name(
    const char* variable, size_t variable_length)
{
    if (!variable) return false;
    const char* names[] = {
        "sql_mode",
        "character_set_client",
        "character_set_connection",
        "collation_connection"
    };
    for (const char* name : names) {
        const size_t name_length = std::strlen(name);
        if (name_length == variable_length &&
            strncasecmp(variable, name, name_length) == 0) {
            return true;
        }
    }
    return false;
}

bool mysql_user_variable_unsafe_query_locks_hostgroup(
    int query_rule_multiplex, bool already_locked)
{
    return query_rule_multiplex == -1 && !already_locked;
}

static std::string replay_context_target_name(const AstNode* target) {
    if (!target || target->type != NodeType::NODE_VAR_TARGET) return {};

    const AstNode* name_node = nullptr;
    for (const AstNode* child = target->first_child; child;
         child = child->next_sibling) {
        if (child->type == NodeType::NODE_USER_VARIABLE) return {};
        if (child->type == NodeType::NODE_IDENTIFIER) name_node = child;
    }
    if (!name_node || !name_node->value_ptr || name_node->value_len == 0) return {};

    std::string name(name_node->value_ptr, name_node->value_len);
    if (!name.empty() && name[0] == '@' &&
        (name.size() == 1 || name[1] != '@')) {
        return {};
    }
    return normalize_set_var_name(std::move(name));
}

bool parsersql_set_changes_user_variable_replay_context_mysql(
    const char* query, size_t query_length)
{
    if (!query) return false;
    auto result = tl_mysql_parser.parse(query, query_length);
    if (result.status != ParseResult::OK || !result.full_input ||
        result.stmt_type != StmtType::SET || !result.ast ||
        result.ast->type != NodeType::NODE_SET_STMT) {
        tl_mysql_parser.reset();
        return false;
    }

    bool changes_context = false;
    for (const AstNode* child = result.ast->first_child; child;
         child = child->next_sibling) {
        if (child->type == NodeType::NODE_SET_NAMES ||
            child->type == NodeType::NODE_SET_CHARSET) {
            changes_context = true;
            break;
        }
        if (child->type != NodeType::NODE_VAR_ASSIGNMENT) continue;
        const std::string name = replay_context_target_name(child->first_child);
        if (mysql_user_variable_is_replay_context_name(name.data(), name.size())) {
            changes_context = true;
            break;
        }
    }
    tl_mysql_parser.reset();
    return changes_context;
}

// ---------------------------------------------------------------------------
// Section 3: SET AST walker
// ---------------------------------------------------------------------------
// Walks the immediate children of a NODE_SET_STMT, handling three node types:
//   - NODE_SET_NAMES   → key "names" with [charset] or [charset, collation]
//   - NODE_SET_CHARSET  → key "character_set" with [charset_name]
//   - NODE_VAR_ASSIGNMENT → normalised variable name → [value]
//
// The output format (map<string, vector<string>>) is identical to that produced
// by the regex-based MySQL_Set_Stmt_Parser, ensuring drop-in compatibility.

template <Dialect D>
static std::string resolve_var_value(
    const AstNode* target, const AstNode* rhs,
    const char* query, int query_len, Arena& arena)
{
    if (!rhs) return "";
    if (rhs->type == NodeType::NODE_SUBQUERY
        && !rhs->first_child && rhs->value_len == 0) {
        const AstNode* var_id = target->first_child;
        if (var_id && var_id->value_ptr && var_id->value_len) {
            const char* after = var_id->value_ptr + var_id->value_len;
            return extract_paren_expr(query, query_len, after);
        }
        return "";
    }
    // Function calls round-trip lossily through emit_function_call (it injects
    // ", " between arguments regardless of the input). Reach back into the
    // original query and copy the source verbatim instead. Matches the
    // behaviour of the regex-based SET parsers used in algorithms 0-2.
    if (rhs->type == NodeType::NODE_FUNCTION_CALL) {
        std::string raw = extract_function_call_source(rhs, query, query_len);
        if (!raw.empty()) return raw;
    }
    // Delimited identifiers (`"$user"`, `"MixedCase"`, `"sch-1"`) carry
    // FLAG_IDENT_DELIMITED but value_ptr/value_len cover only the content
    // between the quotes -- the emitter would re-emit the bare identifier,
    // losing the delimiters that downstream validators need (e.g. the PG
    // search_path validator distinguishes literal "$user" from the $user
    // current-user substitution token, "MixedCase" from case-folded
    // mixedcase, etc.). Splice the quotes back in from the original buffer.
    if ((rhs->type == NodeType::NODE_IDENTIFIER ||
         rhs->type == NodeType::NODE_COLUMN_REF) &&
        (rhs->flags & FLAG_IDENT_DELIMITED)) {
        std::string raw = emit_delimited_ident_raw(rhs, query, query_len);
        if (!raw.empty()) return raw;
    }
    return emit_node_text<D>(rhs, arena);
}

static std::string finalize_var_value(std::string val) {
    if (val == "''" || val == "\"\"") return "";
    return strip_single_sql_token_quotes(val);
}

template <Dialect D>
static std::vector<std::string> extract_names_values(const AstNode* node, Arena& arena) {
    std::vector<std::string> values;
    const AstNode* charset = node->first_child;
    if (charset) {
        values.push_back(strip_quotes(emit_node_text<D>(charset, arena)));
        const AstNode* collation = charset->next_sibling;
        if (collation) {
            values.push_back(strip_quotes(emit_node_text<D>(collation, arena)));
        }
    }
    return values;
}

template <Dialect D>
static std::vector<std::string> extract_charset_values(const AstNode* node, Arena& arena) {
    std::vector<std::string> values;
    if (node->first_child) {
        values.push_back(strip_quotes(emit_node_text<D>(node->first_child, arena)));
    }
    return values;
}

/**
 * Walks the children of a NODE_SET_STMT AST and extracts variable assignments.
 *
 * @tparam D       SQL dialect (MySQL or PostgreSQL).
 * @param set_stmt The NODE_SET_STMT root node.
 * @param arena    Arena for temporary allocations during node text emission.
 * @return         Map from normalised variable name to its value(s).
 */
template <Dialect D>
static std::map<std::string, std::vector<std::string>> walk_set_stmt(
    const AstNode* set_stmt, Arena& arena, const char* query, int query_len)
{
    std::map<std::string, std::vector<std::string>> result;
    if (!set_stmt) return result;

    const char* mysql_assignment_scan = query;

    for (const AstNode* child = set_stmt->first_child;
         child; child = child->next_sibling)
    {
        switch (child->type) {
            case NodeType::NODE_SET_NAMES: {
                result["names"] = extract_names_values<D>(child, arena);
                break;
            }
            case NodeType::NODE_SET_CHARSET: {
                result["character_set_results"] = extract_charset_values<D>(child, arena);
                break;
            }
            case NodeType::NODE_VAR_ASSIGNMENT: {
                const AstNode* target = child->first_child;
                if (!target || target->type != NodeType::NODE_VAR_TARGET) break;

                std::string target_text;
                if constexpr (D == Dialect::MySQL) {
                    const AstNode* variable = target->first_child;
                    if (variable && variable->type == NodeType::NODE_USER_VARIABLE) {
                        target_text.assign("@");
                        target_text.append(variable->value_ptr, variable->value_len);
                    }
                }
                if (target_text.empty()) target_text = emit_node_text<D>(target, arena);
                std::string var_name = normalize_set_var_name(target_text);

                // Collect every RHS sibling of the target. For MySQL there is
                // always exactly one. For PostgreSQL, multi-value lists such
                // as `SET search_path TO 'a', 'b', 'c'` produce one VAR_TARGET
                // followed by N value-expression siblings (see set_parser.h).
                //
                // For PostgreSQL we preserve outer quotes on each value: the
                // session handler honors NO_STRIP_VALUE flags per-variable
                // (e.g. search_path, where `"$user"` vs `$user` is
                // semantically distinct), and falls back to its own
                // unquote_if_quoted() for variables that want stripping.
                // Pre-stripping in the walker breaks the NO_STRIP_VALUE
                // contract.  MySQL keeps the historical strip-quotes
                // behavior (single-value, simpler semantics).
                std::vector<std::string> vals;
                for (const AstNode* rhs = target->next_sibling;
                     rhs; rhs = rhs->next_sibling) {
                    if constexpr (D == Dialect::PostgreSQL) {
                        std::string raw = resolve_var_value<D>(
                            target, rhs, query, query_len, arena);
                        vals.push_back(std::move(raw));
                    } else {
                        std::string raw = extract_mysql_assignment_value(
                            mysql_assignment_scan, query, query_len);
                        if (raw.empty()) {
                            raw = resolve_var_value<D>(
                                target, rhs, query, query_len, arena);
                        }
                        vals.push_back(finalize_var_value(std::move(raw)));
                    }
                }
                if (vals.empty()) vals.push_back("");

                result[var_name] = std::move(vals);
                break;
            }
            // SET TRANSACTION is handled separately by MySQL_Session::parse2()
            // and never reaches this walker in the current code flow. Included
            // here as a defensive no-op so that a future code path change does
            // not silently drop transaction SET statements.
            case NodeType::NODE_SET_TRANSACTION:
                break;
            default:
                break;
        }
    }
    return result;
}

std::map<std::string, std::vector<std::string>> parsersql_parse_set_mysql(
    const std::string& query)
{
    auto result = tl_mysql_parser.parse(query.c_str(), query.size());
    if (result.status == ParseResult::OK || result.status == ParseResult::PARTIAL) {
        if (result.ast && result.ast->type == NodeType::NODE_SET_STMT) {
            auto parsed = walk_set_stmt<Dialect::MySQL>(
                result.ast, tl_mysql_parser.arena(), query.c_str(), query.size());
            tl_mysql_parser.reset();
            return parsed;
        }
    }
    tl_mysql_parser.reset();
    return {};
}

std::map<std::string, std::vector<std::string>> parsersql_parse_set_pgsql(
    const std::string& query)
{
    auto result = tl_pgsql_parser.parse(query.c_str(), query.size());
    // PG walker: only act on a clean OK parse. PARTIAL means the parser hit
    // unexpected syntax mid-statement (e.g. `public,,schema1` -> the empty
    // element after the first comma) and produced an AST that captures only
    // part of the input. If we walked that, we'd hand a misleadingly-partial
    // map to the session (e.g. `[public]` for the example above), the
    // validator would accept the partial value, proxysql would track it as
    // a successful SET, and the backend would receive a different command
    // than the client sent. Returning an empty map drops us into the
    // "Unable to parse SET query" path which forwards the original SET to
    // PG without locking the hostgroup, letting PG be the source of truth
    // for malformed-input rejection (which is what algorithms 0/1/2 do for
    // these cases too).
    //
    // The MySQL walker keeps accepting PARTIAL: MySQL SET frequently uses
    // PARTIAL legitimately for un-parseable RHS expressions (e.g.
    // `SET x = (SELECT ...)`), where the walker falls back to
    // `extract_paren_expr` on a NODE_SUBQUERY placeholder. PG search_path
    // tracked variables don't have analogous shapes.
    if (result.status == ParseResult::OK) {
        if (result.ast && result.ast->type == NodeType::NODE_SET_STMT &&
            ast_covers_full_input(result.ast, query.c_str(), (int)query.size())) {
            auto parsed = walk_set_stmt<Dialect::PostgreSQL>(
                result.ast, tl_pgsql_parser.arena(), query.c_str(), query.size());
            tl_pgsql_parser.reset();
            return parsed;
        }
    }
    tl_pgsql_parser.reset();
    return {};
}
