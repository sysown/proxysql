#include "duckdb_mysql_select_compat.h"
#include <algorithm>
#include <cstdint>
#include <limits>
#include <set>
#include <sql_parser/ast_walk.h>
#include <sql_parser/parser.h>
#include <utility>

namespace {
using namespace sql_parser;
using N = AstNode;
using K = NodeType;
std::string val(const N *n) {
    return std::string(n->value_ptr ? n->value_ptr : "", n->value_len);
}
std::string ident(const N *n) {
    std::string v = val(n), out;
    if (!(n->flags & FLAG_IDENT_DELIMITED))
        return v;
    for (size_t i = 0; i < v.size(); ++i) {
        out += v[i];
        if (v[i] == '`' && i + 1 < v.size() && v[i + 1] == '`')
            ++i;
    }
    return out;
}
bool safe_identifier(const N *n) {
    return !(n->flags & FLAG_IDENT_DELIMITED) ||
           (n->source_ptr && n->source_len >= 2 && n->source_ptr[0] == '`' &&
            n->source_ptr[n->source_len - 1] == '`');
}
bool known_type(DuckDBMySQLTypeKind kind) {
    switch (kind) {
    case DuckDBMySQLTypeKind::signed_integer:
    case DuckDBMySQLTypeKind::unsigned_integer:
    case DuckDBMySQLTypeKind::exact_decimal:
    case DuckDBMySQLTypeKind::text:
    case DuckDBMySQLTypeKind::binary:
    case DuckDBMySQLTypeKind::date:
    case DuckDBMySQLTypeKind::datetime:
        return true;
    default:
        return false;
    }
}
std::string quote(const std::string &s) {
    std::string o = "\"";
    for (char c : s) {
        if (c == '\"')
            o += '\"';
        o += c;
    }
    return o + '\"';
}
bool integer(const N *n, std::string &out) {
    if (!n || n->type != K::NODE_LITERAL_INT || n->first_child || n->flags)
        return false;
    auto s = val(n);
    if (s.empty())
        return false;
    uint64_t x = 0;
    for (char c : s) {
        if (c < '0' || c > '9' ||
            x > (uint64_t(std::numeric_limits<int64_t>::max()) - (c - '0')) / 10)
            return false;
        x = x * 10 + (c - '0');
    }
    out = s;
    return true;
}
struct Translator {
    const std::string &input;
    const DuckDBMySQLSelectContext &ctx;
    DuckDBMySQLRelation relation;
    bool has_relation = false;
    std::string reason = "unsupported_ast";
    std::vector<std::string> required;
    Translator(const std::string &in, const DuckDBMySQLSelectContext &c) : input(in), ctx(c) {}
    bool valid_name(const std::string &s) const {
        return !s.empty() && s.size() <= std::min(ctx.max_output_bytes, size_t(4096)) &&
               s.find('\0') == std::string::npos;
    }
    std::set<std::string> aliases;
    std::string qualifier;
    bool alias_conflicts(const std::string &name) const {
        auto fold = [](std::string s) {
            for (char &c : s) {
                if (static_cast<unsigned char>(c) >= 128)
                    return std::string();
                if (c >= 'A' && c <= 'Z')
                    c += 'a' - 'A';
            }
            return s;
        };
        auto folded = fold(name);
        if (folded.empty())
            return !aliases.empty();
        for (const auto &alias : aliases) {
            auto a = fold(alias);
            if (a.empty() || a == folded)
                return true;
        }
        return false;
    }
    const DuckDBMySQLColumn *column(const N *n) {
        if (!has_relation)
            return nullptr;
        if (n->type == K::NODE_QUALIFIED_NAME && !n->flags) {
            auto q = n->first_child;
            auto field = q ? q->next_sibling : nullptr;
            if (!q || q->type != K::NODE_IDENTIFIER || q->first_child ||
                (q->flags & ~FLAG_IDENT_DELIMITED) || !safe_identifier(q) ||
                ident(q) != qualifier || !field || field->type != K::NODE_IDENTIFIER ||
                field->next_sibling || field->first_child ||
                (field->flags & ~FLAG_IDENT_DELIMITED) || !safe_identifier(field))
                return nullptr;
            n = field;
        } else if (n->type != K::NODE_COLUMN_REF || n->first_child ||
                   (n->flags & ~FLAG_IDENT_DELIMITED) || !safe_identifier(n))
            return nullptr;
        std::string name = ident(n);
        if (name.empty() || name[0] == '@')
            return nullptr;
        const DuckDBMySQLColumn *found = nullptr;
        for (const auto &c : relation.columns)
            if (c.canonical_name == name) {
                if (found)
                    return nullptr;
                found = &c;
            }
        return found;
    }
    bool expr(const N *n, std::string &out, DuckDBMySQLTypeKind &type) {
        if (!n)
            return false;
        if (auto c = column(n)) {
            if (!known_type(c->type.kind))
                return false;
            out = quote(c->canonical_name);
            type = c->type.kind;
            return true;
        }
        if (integer(n, out)) {
            type = DuckDBMySQLTypeKind::signed_integer;
            return true;
        }
        if (n->type == K::NODE_LITERAL_NULL && !n->first_child && !n->flags) {
            out = "NULL";
            type = DuckDBMySQLTypeKind::unknown;
            return true;
        }
        return false;
    }
    bool pred(const N *n, std::string &out) {
        if (!n || n->flags)
            return false;
        if (n->type == K::NODE_IS_NULL || n->type == K::NODE_IS_NOT_NULL) {
            auto a = n->first_child;
            std::string x;
            DuckDBMySQLTypeKind t;
            if (!a || a->next_sibling || !expr(a, x, t))
                return false;
            out = "(" + x + (n->type == K::NODE_IS_NULL ? " IS NULL)" : " IS NOT NULL)");
            return true;
        }
        if (n->type != K::NODE_BINARY_OP)
            return false;
        auto a = n->first_child;
        auto b = a ? a->next_sibling : nullptr;
        if (!b || b->next_sibling)
            return false;
        auto op = val(n);
        std::string x, y;
        if (op == "AND" || op == "OR") {
            if (!pred(a, x) || !pred(b, y))
                return false;
        } else {
            if (op != "=" && op != "<>" && op != "!=" && op != "<" && op != "<=" && op != ">" &&
                op != ">=")
                return false;
            DuckDBMySQLTypeKind ta, tb;
            if (!expr(a, x, ta) || !expr(b, y, tb) || ta != tb ||
                ta != DuckDBMySQLTypeKind::signed_integer)
                return false;
        }
        out = "(" + x + " " + op + " " + y + ")";
        return true;
    }
    bool run(const N *root, std::string &out) {
        const N *items = nullptr, *from = nullptr, *where = nullptr, *order = nullptr,
                *limit = nullptr;
        if (root->flags || root->next_sibling)
            return false;
        for (auto n = root->first_child; n; n = n->next_sibling) {
            const N **slot = nullptr;
            switch (n->type) {
            case K::NODE_SELECT_ITEM_LIST:
                slot = &items;
                break;
            case K::NODE_FROM_CLAUSE:
                slot = &from;
                break;
            case K::NODE_WHERE_CLAUSE:
                slot = &where;
                break;
            case K::NODE_ORDER_BY_CLAUSE:
                slot = &order;
                break;
            case K::NODE_LIMIT_CLAUSE:
                slot = &limit;
                break;
            default:
                return false;
            }
            if (*slot || (n->flags && n->type != K::NODE_LIMIT_CLAUSE))
                return false;
            *slot = n;
        }
        if (!items || !items->first_child)
            return false;
        if (from) {
            auto t = from->first_child;
            auto name = t ? t->first_child : nullptr;
            auto alias = name ? name->next_sibling : nullptr;
            if (!t || t->type != K::NODE_TABLE_REF || t->flags || t->next_sibling || !name ||
                name->type != K::NODE_IDENTIFIER || name->first_child ||
                (name->flags & ~FLAG_IDENT_DELIMITED) || !safe_identifier(name))
                return false;
            if (alias &&
                (alias->type != K::NODE_ALIAS || alias->next_sibling || alias->first_child ||
                 (alias->flags & ~FLAG_IDENT_DELIMITED) || !safe_identifier(alias)))
                return false;
            qualifier = ident(alias ? alias : name);
            if (!ctx.resolve_relation || !ctx.max_resolver_calls) {
                reason = "missing_context";
                required.push_back("relation_resolver");
                return false;
            }
            if (!ctx.resolve_relation({ident(name)}, relation) || !relation.exact_name_resolution ||
                relation.canonical_name.empty()) {
                reason = "unresolved_relation";
                return false;
            }
            if (relation.columns.size() > ctx.max_nodes || relation.canonical_name.size() > 3 ||
                relation.unique_keys.size() > ctx.max_nodes) {
                reason = "resource_limit";
                return false;
            }
            size_t metadata_bytes = 0, key_parts = 0;
            auto budget = [&](const std::string &s) {
                if (s.size() > ctx.max_output_bytes - metadata_bytes)
                    return false;
                metadata_bytes += s.size();
                return true;
            };
            for (const auto &part : relation.canonical_name)
                if (!budget(part)) {
                    reason = "resource_limit";
                    return false;
                }
            for (const auto &col : relation.columns)
                if (!budget(col.canonical_name)) {
                    reason = "resource_limit";
                    return false;
                }
            for (const auto &key : relation.unique_keys) {
                if (key.size() > ctx.max_nodes - key_parts) {
                    reason = "resource_limit";
                    return false;
                }
                key_parts += key.size();
                for (const auto &part : key)
                    if (!budget(part)) {
                        reason = "resource_limit";
                        return false;
                    }
            }
            for (const auto &part : relation.canonical_name)
                if (!valid_name(part))
                    return false;
            for (const auto &col : relation.columns)
                if (!valid_name(col.canonical_name))
                    return false;
            has_relation = true;
        }
        out = "SELECT ";
        bool first = true;
        bool aggregate = false, plain = false;
        for (auto item = items->first_child; item; item = item->next_sibling) {
            if (item->type != K::NODE_SELECT_ITEM || item->flags)
                return false;
            auto n = item->first_child;
            auto alias = n ? n->next_sibling : nullptr;
            if (!n || (alias && (alias->type != K::NODE_ALIAS || alias->next_sibling ||
                                 alias->first_child || (alias->flags & ~FLAG_IDENT_DELIMITED))))
                return false;
            if (out.size() > ctx.max_output_bytes) {
                reason = "resource_limit";
                return false;
            }
            if (!first)
                out += ", ";
            first = false;
            if (n->type == K::NODE_ASTERISK && !n->first_child && !n->flags && !alias &&
                has_relation) {
                for (const auto &c : relation.columns)
                    if (!known_type(c.type.kind))
                        return false;
                plain = true;
                out += "*";
                continue;
            }
            std::string s;
            DuckDBMySQLTypeKind type;
            if (n->type == K::NODE_FUNCTION_CALL && val(n) == "COUNT" && !n->flags) {
                auto arg = n->first_child;
                if (!arg || arg->next_sibling)
                    return false;
                if (arg->type == K::NODE_ASTERISK && !arg->flags && !arg->first_child)
                    s = "COUNT(*)";
                else {
                    auto c = column(arg);
                    if (!c || !known_type(c->type.kind))
                        return false;
                    s = "COUNT(" + quote(c->canonical_name) + ")";
                }
                aggregate = true;
            } else {
                if (!expr(n, s, type))
                    return false;
                plain = true;
            }
            out += s;
            if (alias) {
                if (!safe_identifier(alias))
                    return false;
                auto a = ident(alias);
                if (!valid_name(a))
                    return false;
                aliases.insert(a);
                out += " AS " + quote(a);
            } else if (n->type != K::NODE_COLUMN_REF && n->type != K::NODE_QUALIFIED_NAME) {
                // ParserSQL records the original expression span; validate it belongs to input.
                auto p = reinterpret_cast<uintptr_t>(item->source_ptr),
                     begin = reinterpret_cast<uintptr_t>(input.data());
                if (!item->source_ptr || p < begin || p - begin > input.size() ||
                    item->source_len > input.size() - (p - begin))
                    return false;
                out += " AS " + quote(std::string(item->source_ptr, item->source_len));
            }
        }
        if (aggregate && (plain || order || limit))
            return false;
        if (from) {
            out += " FROM ";
            bool sep = false;
            for (auto &part : relation.canonical_name) {
                if (part.empty())
                    return false;
                if (sep)
                    out += '.';
                out += quote(part);
                sep = true;
            }
        }
        if (where) {
            std::string p;
            auto n = where->first_child;
            if (!n || n->next_sibling || !pred(n, p))
                return false;
            out += " WHERE " + p;
        }
        std::set<std::string> ordered;
        if (order) {
            out += " ORDER BY ";
            bool sep = false;
            for (auto item = order->first_child; item; item = item->next_sibling) {
                if (item->type != K::NODE_ORDER_BY_ITEM || item->flags)
                    return false;
                auto n = item->first_child;
                auto dir = n ? n->next_sibling : nullptr;
                auto c = n ? column(n) : nullptr;
                if (!c || alias_conflicts(c->canonical_name) ||
                    (c->type.kind != DuckDBMySQLTypeKind::signed_integer &&
                     c->type.kind != DuckDBMySQLTypeKind::unsigned_integer &&
                     c->type.kind != DuckDBMySQLTypeKind::exact_decimal))
                    return false;
                std::string d = "ASC";
                if (dir) {
                    if (dir->type != K::NODE_IDENTIFIER || dir->next_sibling || dir->first_child ||
                        dir->flags)
                        return false;
                    d = val(dir);
                    if (d != "ASC" && d != "DESC")
                        return false;
                }
                if (out.size() > ctx.max_output_bytes) {
                    reason = "resource_limit";
                    return false;
                }
                if (sep)
                    out += ", ";
                sep = true;
                out += quote(c->canonical_name) + " " + d +
                       (d == "ASC" ? " NULLS FIRST" : " NULLS LAST");
                ordered.insert(c->canonical_name);
            }
            if (!sep)
                return false;
        }
        if (limit) {
            bool unique = false;
            for (const auto &key : relation.unique_keys) {
                if (!key.empty() && std::all_of(key.begin(), key.end(), [&](const std::string &s) {
                        return ordered.count(s) != 0;
                    }))
                    unique = true;
            }
            if (!unique) {
                reason = "nondeterministic_limit";
                return false;
            }
            auto count = limit->first_child;
            auto offset = count ? count->next_sibling : nullptr;
            std::string c, o;
            if ((limit->flags & ~FLAG_LIMIT_COMMA) || !integer(count, c) ||
                (offset && (!integer(offset, o) || offset->next_sibling)))
                return false;
            out += " LIMIT " + c;
            if (offset)
                out += " OFFSET " + o;
        }
        if (out.size() > ctx.max_output_bytes) {
            reason = "resource_limit";
            return false;
        }
        return true;
    }
};
} // namespace
static DuckDBMySQLSelectTranslation translate(const std::string &input,
                                              const DuckDBMySQLSelectContext &ctx) {
    DuckDBMySQLSelectTranslation result;
    if (input.size() > ctx.max_input_bytes) {
        result.reason = "resource_limit";
        return result;
    }
    if (input.find('\0') != std::string::npos) {
        result.reason = "invalid_input";
        result.decision = DuckDBMySQLSelectDecision::invalid;
        return result;
    }
    // Use ParserSQL's tokenizer to avoid invoking unrelated statement grammars.
    // This only selects the candidate path; full AST/provenance checks follow.
    sql_parser::Tokenizer<sql_parser::Dialect::MySQL> framing;
    framing.reset(input.data(), input.size());
    if (framing.next_token().type != sql_parser::TokenType::TK_SELECT) {
        result.reason = "incomplete_or_non_select";
        return result;
    }
    sql_parser::Parser<sql_parser::Dialect::MySQL> parser;
    // parse_all intentionally skips empty segments; the single-parse framing
    // check rejects additional semicolons and trailing input before batching.
    auto single = parser.parse(input.data(), input.size());
    if (single.status == sql_parser::ParseResult::ERROR) {
        result.decision = DuckDBMySQLSelectDecision::invalid;
        result.reason = "parse_error";
        return result;
    }
    if (single.status != sql_parser::ParseResult::OK || !single.full_input ||
        single.has_remaining()) {
        result.reason = "incomplete_or_non_select";
        return result;
    }
    if (single.has_executable_comments || single.has_comments || single.has_user_variables) {
        result.reason = "unsupported_provenance";
        return result;
    }
    auto batch = parser.parse_all(input.data(), input.size());
    if (batch.statements.size() != 1) {
        result.reason = "statement_count";
        return result;
    }
    auto &parsed = batch.statements[0].result;
    if (parsed.status == sql_parser::ParseResult::ERROR) {
        result.decision = DuckDBMySQLSelectDecision::invalid;
        result.reason = "parse_error";
        return result;
    }
    if (parsed.status != sql_parser::ParseResult::OK || !parsed.full_input ||
        parsed.has_remaining() || !parsed.ast || parsed.stmt_type != sql_parser::StmtType::SELECT ||
        parsed.ast->type != sql_parser::NodeType::NODE_SELECT_STMT) {
        result.reason = "incomplete_or_non_select";
        return result;
    }
    if (parsed.has_executable_comments || parsed.has_comments || parsed.has_user_variables) {
        result.reason = "unsupported_provenance";
        return result;
    }
    auto walk =
        sql_parser::walk_ast(parsed.ast,
                             [](const sql_parser::AstNode &, const sql_parser::AstVisitContext &) {
                                 return sql_parser::AstVisitAction::Continue;
                             },
                             {ctx.max_nodes, ctx.max_depth});
    if (walk.status != sql_parser::AstWalkStatus::Completed) {
        result.reason = "resource_limit";
        return result;
    }
    Translator t{input, ctx};
    std::string sql;
    if (!t.run(parsed.ast, sql)) {
        result.reason = t.reason;
        result.required_context = std::move(t.required);
        return result;
    }
    result.decision = DuckDBMySQLSelectDecision::supported;
    result.sql = std::move(sql);
    result.reason = "supported";
    return result;
}

DuckDBMySQLSelectTranslation
duckdb_translate_mysql_select(const std::string &input, const DuckDBMySQLSelectContext &context) {
    try {
        auto ctx = context;
        ctx.max_input_bytes = std::min(ctx.max_input_bytes, size_t(65536));
        ctx.max_output_bytes = std::min(ctx.max_output_bytes, size_t(262144));
        ctx.max_nodes = std::min(ctx.max_nodes, size_t(4096));
        ctx.max_depth = std::min(ctx.max_depth, size_t(128));
        ctx.max_resolver_calls = std::min(ctx.max_resolver_calls, size_t(1));
        return translate(input, ctx);
    } catch (const std::bad_alloc &) {
        DuckDBMySQLSelectTranslation result;
        result.reason = "resource_limit";
        return result;
    } catch (...) {
        DuckDBMySQLSelectTranslation result;
        result.reason = "provider_failure";
        return result;
    }
}
