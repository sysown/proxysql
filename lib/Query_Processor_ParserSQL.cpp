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
#include "SpookyV2.h"

#include <algorithm>
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
    for (const char* prefix : {"session.", "local.", "global."}) {
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
 *   1. Strip keyword scope prefix (SESSION/GLOBAL/LOCAL).
 *   2. Strip @@-style scope prefix (@@session. → "").
 *   3. Lowercase the result.
 *   4. Resolve legacy aliases: "transaction_isolation" → "tx_isolation",
 *      "transaction_read_only" → "tx_read_only".
 *
 * This ensures the same variable name is produced regardless of how the user
 * wrote the SET statement, matching the behaviour of the regex-based parser.
 */
static std::string normalize_set_var_name(std::string var_name) {
    for (const char* prefix : {"SESSION ", "GLOBAL ", "LOCAL "}) {
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
    return strip_quotes(val);
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

                std::string var_name = normalize_set_var_name(
                    emit_node_text<D>(target, arena));

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
                    std::string raw = resolve_var_value<D>(
                        target, rhs, query, query_len, arena);
                    if constexpr (D == Dialect::PostgreSQL) {
                        vals.push_back(std::move(raw));
                    } else {
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
    if (result.status == ParseResult::OK || result.status == ParseResult::PARTIAL) {
        if (result.ast && result.ast->type == NodeType::NODE_SET_STMT) {
            auto parsed = walk_set_stmt<Dialect::PostgreSQL>(
                result.ast, tl_pgsql_parser.arena(), query.c_str(), query.size());
            tl_pgsql_parser.reset();
            return parsed;
        }
    }
    tl_pgsql_parser.reset();
    return {};
}
