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

static thread_local Parser<Dialect::MySQL> tl_mysql_parser;
static thread_local Parser<Dialect::PostgreSQL> tl_pgsql_parser;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
        for (const char* prefix : {"session.", "local.", "global."}) {
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
    for (const char* prefix : {"SESSION ", "GLOBAL ", "LOCAL "}) {
        size_t plen = strlen(prefix);
        if (var_name.size() > plen &&
            strncasecmp(var_name.c_str(), prefix, plen) == 0) {
            var_name = var_name.substr(plen);
            break;
        }
    }
    var_name = strip_scope_prefix(var_name);
    var_name = lowercase(var_name);
    if (var_name == "transaction_isolation") var_name = "tx_isolation";
    if (var_name == "transaction_read_only") var_name = "tx_read_only";
    return var_name;
}

template <Dialect D>
static std::string emit_node_text(const AstNode* node, Arena& arena) {
    if (!node) return "";
    Emitter<D> emitter(arena, EmitMode::NORMAL);
    emitter.emit(node);
    StringRef ref = emitter.result();
    return std::string(ref.ptr, ref.len);
}

// ---------------------------------------------------------------------------
// Section 1: Digest adapter
// ---------------------------------------------------------------------------

void parsersql_digest_init_mysql(SQP_par_t* qp, const char* query, int query_length) {
    qp->digest_text = NULL;
    qp->first_comment = NULL;
    qp->query_prefix = NULL;

    auto result = tl_mysql_parser.parse(query, query_length);

    if (result.status == ParseResult::OK || result.status == ParseResult::PARTIAL) {
        std::string normalized;
        if (result.ast) {
            Emitter<Dialect::MySQL> emitter(tl_mysql_parser.arena(), EmitMode::DIGEST);
            emitter.emit(result.ast);
            StringRef ref = emitter.result();
            normalized.assign(ref.ptr, ref.len);
        } else {
            Digest<Dialect::MySQL> digest(tl_mysql_parser.arena());
            DigestResult dr = digest.compute(query, query_length);
            normalized.assign(dr.normalized.ptr, dr.normalized.len);
        }
        qp->digest_text = strdup(normalized.c_str());
        qp->digest = SpookyHash::Hash64(normalized.c_str(), normalized.size(), 0);
    }

    tl_mysql_parser.reset();
}

void parsersql_digest_init_pgsql(SQP_par_t* qp, const char* query, int query_length) {
    qp->digest_text = NULL;
    qp->first_comment = NULL;
    qp->query_prefix = NULL;

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

template <Dialect D>
static std::map<std::string, std::vector<std::string>> walk_set_stmt(
    const AstNode* set_stmt, Arena& arena)
{
    std::map<std::string, std::vector<std::string>> result;
    if (!set_stmt) return result;

    for (const AstNode* child = set_stmt->first_child;
         child; child = child->next_sibling)
    {
        switch (child->type) {
            case NodeType::NODE_SET_NAMES: {
                std::vector<std::string> values;
                const AstNode* charset = child->first_child;
                if (charset) {
                    values.push_back(
                        strip_quotes(emit_node_text<D>(charset, arena)));
                    const AstNode* collation = charset->next_sibling;
                    if (collation) {
                        values.push_back(
                            strip_quotes(emit_node_text<D>(collation, arena)));
                    }
                }
                result["names"] = values;
                break;
            }
            case NodeType::NODE_SET_CHARSET: {
                std::vector<std::string> values;
                if (child->first_child) {
                    values.push_back(
                        strip_quotes(emit_node_text<D>(child->first_child, arena)));
                }
                result["character_set"] = values;
                break;
            }
            case NodeType::NODE_VAR_ASSIGNMENT: {
                const AstNode* target = child->first_child;
                const AstNode* rhs = target ? target->next_sibling : nullptr;
                if (!target || target->type != NodeType::NODE_VAR_TARGET) break;

                std::string var_name = emit_node_text<D>(target, arena);
                var_name = normalize_set_var_name(var_name);

                std::string val;
                if (rhs) {
                    val = emit_node_text<D>(rhs, arena);
                }
                if (val == "''" || val == "\"\"") {
                    val = "";
                } else {
                    val = strip_quotes(val);
                }

                result[var_name] = {val};
                break;
            }
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
                result.ast, tl_mysql_parser.arena());
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
                result.ast, tl_pgsql_parser.arena());
            tl_pgsql_parser.reset();
            return parsed;
        }
    }
    tl_pgsql_parser.reset();
    return {};
}
