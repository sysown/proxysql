#include "duckdb_mysql_select_compat.h"
#include <algorithm>
#include <cstdint>
#include <limits>
#include <new>
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
    const std::vector<const N *> &parameters;
    size_t parameter_index = 0;
    Translator(const std::string &in, const DuckDBMySQLSelectContext &c,
               const std::vector<const N *> &p)
        : input(in), ctx(c), parameters(p) {}
    bool valid_name(const std::string &s) const {
        return !s.empty() && s.size() <= std::min(ctx.max_output_bytes, size_t(4096)) &&
               s.find('\0') == std::string::npos;
    }
    bool output_label(const std::string &name, size_t maximum = 256) {
        const auto whitespace = [](unsigned char c) {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
        };
        if (!valid_name(name) || name.size() > maximum || whitespace(name.front()) ||
            std::any_of(name.begin(), name.end(), [](unsigned char c) { return c >= 0xf0; })) {
            reason = "unsupported_metadata_label";
            return false;
        }
        return true;
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
    struct ExactNumber {
        std::string sql;
        unsigned integer_digits = 0;
        unsigned scale = 0;
        bool decimal = false;
    };
    static bool valid_decimal(const DuckDBMySQLType &type) {
        return type.kind == DuckDBMySQLTypeKind::exact_decimal && type.precision >= 1 &&
               type.precision <= 38 && type.scale <= 30 && type.scale <= type.precision;
    }
    static bool projectable_decimal(const DuckDBMySQLType &type) {
        return valid_decimal(type) || (type.kind == DuckDBMySQLTypeKind::exact_decimal &&
                                       type.precision == 39 && type.scale == 0);
    }
    static bool fraction_only(const DuckDBMySQLType &type) {
        return valid_decimal(type) && type.precision == type.scale;
    }
    static std::string projected_column(const DuckDBMySQLColumn &column) {
        const auto name = quote(column.canonical_name);
        if (!fraction_only(column.type))
            return name;
        return "CAST(" + name + " AS DECIMAL(" + std::to_string(column.type.precision + 1) + "," +
               std::to_string(column.type.scale) + "))";
    }
    // Inspect only ParserSQL's literal token; no SQL scanning or syntax reconstruction.
    bool exact_literal(const N *node, ExactNumber &number) {
        if (!node || (node->type != K::NODE_LITERAL_FLOAT && node->type != K::NODE_LITERAL_INT) ||
            node->flags || node->first_child || !node->value_ptr || !node->source_ptr ||
            node->source_ptr != node->value_ptr || node->value_len != node->source_len ||
            !node->value_len)
            return false;
        const auto begin = reinterpret_cast<uintptr_t>(input.data());
        const auto ptr = reinterpret_cast<uintptr_t>(node->value_ptr);
        if (ptr < begin || ptr - begin > input.size() ||
            node->value_len > input.size() - (ptr - begin))
            return false;
        const auto text = std::string(input.data() + (ptr - begin), node->value_len);
        unsigned before = 0, after = 0;
        bool dot = false;
        for (char ch : text) {
            if (ch == '.') {
                if (dot)
                    return false;
                dot = true;
            } else if (ch >= '0' && ch <= '9') {
                if (dot)
                    ++after;
                else
                    ++before;
            } else
                return false;
            if (before > 38 || after > 30)
                return false;
        }
        if ((!before && !after) || (node->type == K::NODE_LITERAL_FLOAT && !dot) ||
            (node->type == K::NODE_LITERAL_INT && dot) || before + after > 38)
            return false;
        const unsigned precision = std::max(1u, before) + after;
        if (precision > 38)
            return false;
        number.sql = "CAST('" + text + "' AS DECIMAL(" + std::to_string(precision) + "," +
                     std::to_string(after) + "))";
        number.integer_digits = std::max(1u, before);
        number.scale = after;
        number.decimal = node->type == K::NODE_LITERAL_FLOAT;
        return true;
    }
    bool exact_number(const N *node, ExactNumber &number) {
        if (const auto *c = column(node)) {
            if (!output_label(c->canonical_name))
                return false;
            if (c->type.kind == DuckDBMySQLTypeKind::signed_integer)
                number.integer_digits = 19;
            else if (c->type.kind == DuckDBMySQLTypeKind::unsigned_integer)
                number.integer_digits = 20;
            else if (valid_decimal(c->type)) {
                number.integer_digits = c->type.precision - c->type.scale;
                number.scale = c->type.scale;
                number.decimal = true;
            } else
                return false;
            number.sql = quote(c->canonical_name);
            return true;
        }
        return exact_literal(node, number);
    }
    bool expr(const N *n, std::string &out, DuckDBMySQLTypeKind &type) {
        if (!n)
            return false;
        if (auto c = column(n)) {
            if (!known_type(c->type.kind) || !output_label(c->canonical_name) ||
                (c->type.kind == DuckDBMySQLTypeKind::exact_decimal &&
                 !projectable_decimal(c->type)))
                return false;
            out = projected_column(*c);
            type = c->type.kind;
            return true;
        }
        if (integer(n, out)) {
            type = DuckDBMySQLTypeKind::signed_integer;
            return true;
        }
        if (n->type == K::NODE_LITERAL_FLOAT) {
            ExactNumber number;
            if (!exact_literal(n, number))
                return false;
            out = std::move(number.sql);
            type = DuckDBMySQLTypeKind::exact_decimal;
            return true;
        }
        if (n->type == K::NODE_LITERAL_NULL && !n->first_child && !n->flags) {
            out = "NULL";
            type = DuckDBMySQLTypeKind::unknown;
            return true;
        }
        return false;
    }
    bool unambiguous_builtin(const N *node, const std::string &name) {
        const auto begin = reinterpret_cast<uintptr_t>(input.data());
        const auto source = reinterpret_cast<uintptr_t>(node->source_ptr);
        if (!node->source_ptr || source < begin || source - begin > input.size() ||
            node->source_len > input.size() - (source - begin))
            return false;
        Tokenizer<Dialect::MySQL> tokens;
        tokens.reset(node->source_ptr, node->source_len);
        const auto function = tokens.next_token();
        const auto open = tokens.next_token();
        const auto expected = name == "COUNT" ? TokenType::TK_COUNT
                              : name == "MIN" ? TokenType::TK_MIN
                              : name == "MAX" ? TokenType::TK_MAX
                                              : TokenType::TK_IDENTIFIER;
        // IGNORE_SPACE changes MySQL's resolution of spaced native names.
        // ParserSQL supplies token/source identity; no private SQL lexer is used.
        if (function.type != expected || function.source.ptr != node->source_ptr ||
            function.text.ptr != function.source.ptr || function.text.len != function.source.len ||
            !function.text.equals_ci(name.data(), name.size()) ||
            open.type != TokenType::TK_LPAREN ||
            function.source.ptr + function.source.len != open.source.ptr) {
            reason = "session_sensitive_function_syntax";
            return false;
        }
        return true;
    }
    bool aggregate_expr(const N *node, std::string &out, DuckDBMySQLTypeKind &type) {
        if (!node || node->type != K::NODE_FUNCTION_CALL || node->flags)
            return false;
        const std::string name = val(node);
        if (name != "COUNT" && name != "MIN" && name != "MAX")
            return false;
        if (!unambiguous_builtin(node, name))
            return false;
        const N *arg = node->first_child;
        if (!arg || arg->next_sibling)
            return false;
        if (name == "COUNT" && arg->type == K::NODE_ASTERISK && !arg->flags && !arg->first_child) {
            out = "COUNT(*)";
            type = DuckDBMySQLTypeKind::signed_integer;
            return true;
        }
        const auto *c = column(arg);
        if (!c || !known_type(c->type.kind))
            return false;
        if (name != "COUNT" && c->type.kind != DuckDBMySQLTypeKind::signed_integer &&
            c->type.kind != DuckDBMySQLTypeKind::unsigned_integer)
            return false;
        out = name + "(" + quote(c->canonical_name) + ")";
        type = name == "COUNT" ? DuckDBMySQLTypeKind::signed_integer : c->type.kind;
        return true;
    }
    // The accepted format is one fixed literal, so its rendering cannot depend
    // on a format-token parser, charset, locale or sql_mode.
    bool year_month_literal(const N *node) {
        if (!node || node->type != K::NODE_LITERAL_STRING || node->flags || node->first_child ||
            !node->source_ptr || !node->value_ptr)
            return false;
        const auto begin = reinterpret_cast<uintptr_t>(input.data());
        const auto inside = [&](const char *p, size_t len) {
            const auto at = reinterpret_cast<uintptr_t>(p);
            return at >= begin && at - begin <= input.size() && len <= input.size() - (at - begin);
        };
        if (!inside(node->source_ptr, node->source_len) ||
            !inside(node->value_ptr, node->value_len))
            return false;
        // Exact source bytes: rejects escapes, prefixes, introducers and
        // double quotes (identifier under a possible ANSI_QUOTES session).
        return node->source_len == 7 &&
               std::string(node->source_ptr, node->source_len) == "'%Y-%m'" &&
               node->value_len == 5 && std::string(node->value_ptr, node->value_len) == "%Y-%m";
    }
    // SELECT-list only: DATE_FORMAT in predicates, grouping or ordering stays
    // outside this slice and never reaches expr().
    bool date_format_expr(const N *node, std::string &out, DuckDBMySQLTypeKind &type) {
        if (!node || node->type != K::NODE_FUNCTION_CALL || node->flags ||
            val(node) != "DATE_FORMAT" || !unambiguous_builtin(node, "DATE_FORMAT"))
            return false;
        const N *arg = node->first_child;
        const N *format = arg ? arg->next_sibling : nullptr;
        if (!arg || !format || format->next_sibling || !year_month_literal(format))
            return false;
        const auto *c = column(arg);
        if (c && c->type.kind == DuckDBMySQLTypeKind::datetime) {
            // A native TIMESTAMP may be a replicated MySQL TIMESTAMP, which MySQL renders in
            // the session time zone; native metadata cannot tell it from DATETIME.
            reason = "session_time_zone_unknown";
            required.push_back("source_column_type_provenance");
            return false;
        }
        if (!c || c->type.kind != DuckDBMySQLTypeKind::date)
            return false;
        // DuckDB's numeric strftime directives are locale-independent and
        // return VARCHAR without converting a timezone-naive value.
        out = "strftime(" + quote(c->canonical_name) + ", '%Y-%m')";
        type = DuckDBMySQLTypeKind::text;
        return true;
    }
    bool having_pred(const N *node, std::string &out) {
        if (!node || node->flags)
            return false;
        if (node->type == K::NODE_IS_NULL || node->type == K::NODE_IS_NOT_NULL) {
            auto arg = node->first_child;
            std::string x;
            DuckDBMySQLTypeKind type;
            if (!arg || arg->next_sibling || !aggregate_expr(arg, x, type))
                return false;
            out = "(" + x + (node->type == K::NODE_IS_NULL ? " IS NULL)" : " IS NOT NULL)");
            if (out.size() > ctx.max_output_bytes) {
                reason = "resource_limit";
                return false;
            }
            return true;
        }
        if (node->type != K::NODE_BINARY_OP)
            return false;
        auto a = node->first_child;
        auto b = a ? a->next_sibling : nullptr;
        if (!b || b->next_sibling)
            return false;
        const auto op = val(node);
        std::string x, y;
        if (op == "AND" || op == "OR") {
            if (!having_pred(a, x) || !having_pred(b, y))
                return false;
        } else {
            if (op != "=" && op != "<>" && op != "!=" && op != "<" && op != "<=" && op != ">" &&
                op != ">=")
                return false;
            DuckDBMySQLTypeKind type;
            if (!aggregate_expr(a, x, type) || type != DuckDBMySQLTypeKind::signed_integer ||
                !integer(b, y))
                return false;
        }
        out = "(" + x + " " + op + " " + y + ")";
        if (out.size() > ctx.max_output_bytes) {
            reason = "resource_limit";
            return false;
        }
        return true;
    }
    bool pred(const N *n, std::string &out) {
        if (!n || n->flags)
            return false;
        if (n->type == K::NODE_EXPRESSION) {
            auto child = n->first_child;
            if (!child || child->next_sibling || n->value_len)
                return false;
            std::string nested;
            if (!pred(child, nested))
                return false;
            out = "(" + nested + ")";
            if (out.size() > ctx.max_output_bytes) {
                reason = "resource_limit";
                return false;
            }
            return true;
        }
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
            const bool a_param = a->type == K::NODE_PLACEHOLDER;
            const bool b_param = b->type == K::NODE_PLACEHOLDER;
            if (a_param || b_param) {
                if (a_param == b_param || ctx.parameter_mode == DuckDBMySQLParameterMode::forbidden)
                    return false;
                const N *parameter = a_param ? a : b;
                const N *column_node = a_param ? b : a;
                const auto *c = column(column_node);
                if (!c || c->type.kind != DuckDBMySQLTypeKind::signed_integer)
                    return false;
                if (parameter_index >= parameters.size() ||
                    parameters[parameter_index] != parameter) {
                    reason = "parameter_order";
                    return false;
                }
                ++parameter_index;
                const auto column_sql = "CAST(" + quote(c->canonical_name) + " AS BIGINT)";
                if (a_param) {
                    x = "CAST(? AS BIGINT)";
                    y = column_sql;
                } else {
                    x = column_sql;
                    y = "CAST(? AS BIGINT)";
                }
            } else {
                ExactNumber lhs, rhs;
                if (exact_number(a, lhs) && exact_number(b, rhs) && (lhs.decimal || rhs.decimal)) {
                    const unsigned scale = std::max(lhs.scale, rhs.scale);
                    const unsigned precision =
                        std::max(1u, std::max(lhs.integer_digits, rhs.integer_digits) + scale);
                    if (precision > 38 || scale > 30)
                        return false;
                    const std::string target = " AS DECIMAL(" + std::to_string(precision) + "," +
                                               std::to_string(scale) + "))";
                    x = "CAST(" + lhs.sql + target;
                    y = "CAST(" + rhs.sql + target;
                } else {
                    DuckDBMySQLTypeKind ta, tb;
                    if (!expr(a, x, ta) || !expr(b, y, tb) || ta != tb ||
                        ta != DuckDBMySQLTypeKind::signed_integer)
                        return false;
                }
            }
        }
        out = "(" + x + " " + op + " " + y + ")";
        if (out.size() > ctx.max_output_bytes) {
            reason = "resource_limit";
            return false;
        }
        return true;
    }
    bool run(const N *root, std::string &out) {
        const N *items = nullptr, *from = nullptr, *where = nullptr, *group = nullptr,
                *having = nullptr, *order = nullptr, *limit = nullptr;
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
            case K::NODE_GROUP_BY_CLAUSE:
                slot = &group;
                break;
            case K::NODE_HAVING_CLAUSE:
                slot = &having;
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
        // MySQL permits output aliases in GROUP BY. Refuse any possible alias
        // collision rather than guessing whether it shadows a source column.
        for (auto item = items->first_child; item; item = item->next_sibling) {
            auto expr_node = item->first_child;
            auto alias = expr_node ? expr_node->next_sibling : nullptr;
            if (alias) {
                if (alias->type != K::NODE_ALIAS || alias->next_sibling || alias->first_child ||
                    (alias->flags & ~FLAG_IDENT_DELIMITED) || !safe_identifier(alias))
                    return false;
                auto name = ident(alias);
                if (!output_label(name))
                    return false;
                aliases.insert(name);
            }
        }
        std::set<std::string> group_keys;
        std::string group_sql;
        if (group) {
            if (!has_relation || group->value_len || !group->first_child)
                return false;
            for (auto n = group->first_child; n; n = n->next_sibling) {
                const auto *c = column(n);
                if (!c || alias_conflicts(c->canonical_name) ||
                    (c->type.kind != DuckDBMySQLTypeKind::signed_integer &&
                     c->type.kind != DuckDBMySQLTypeKind::unsigned_integer))
                    return false;
                if (!group_sql.empty())
                    group_sql += ", ";
                group_sql += quote(c->canonical_name);
                if (group_sql.size() > ctx.max_output_bytes) {
                    reason = "resource_limit";
                    return false;
                }
                group_keys.insert(c->canonical_name);
            }
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
                bool expand = false;
                for (const auto &c : relation.columns) {
                    if (!known_type(c.type.kind) || !output_label(c.canonical_name) ||
                        (c.type.kind == DuckDBMySQLTypeKind::exact_decimal &&
                         !projectable_decimal(c.type)))
                        return false;
                    expand = expand || fraction_only(c.type);
                }
                if (group)
                    return false;
                plain = true;
                if (!expand)
                    out += "*";
                else {
                    std::set<std::string> seen;
                    bool sep = false;
                    for (const auto &c : relation.columns) {
                        // DuckDB identifiers are case-insensitive; an ambiguous
                        // expanded column cannot be resolved safely.
                        std::string folded = c.canonical_name;
                        for (char &ch : folded) {
                            if (ch >= 'A' && ch <= 'Z')
                                ch += 'a' - 'A';
                        }
                        if (!seen.insert(folded).second)
                            return false;
                        if (sep)
                            out += ", ";
                        sep = true;
                        out += projected_column(c);
                        if (fraction_only(c.type))
                            out += " AS " + quote(c.canonical_name);
                        if (out.size() > ctx.max_output_bytes) {
                            reason = "resource_limit";
                            return false;
                        }
                    }
                }
                continue;
            }
            std::string s;
            DuckDBMySQLTypeKind type;
            if (aggregate_expr(n, s, type)) {
                aggregate = true;
            } else {
                if (!expr(n, s, type) && !date_format_expr(n, s, type))
                    return false;
                if (group) {
                    const auto *c = column(n);
                    if (!c || !group_keys.count(c->canonical_name))
                        return false;
                }
                plain = true;
            }
            out += s;
            if (alias) {
                if (!safe_identifier(alias))
                    return false;
                auto a = ident(alias);
                if (!output_label(a))
                    return false;
                aliases.insert(a);
                out += " AS " + quote(a);
            } else if ((n->type == K::NODE_COLUMN_REF || n->type == K::NODE_QUALIFIED_NAME) &&
                       column(n) && fraction_only(column(n)->type)) {
                out += " AS " + quote(column(n)->canonical_name);
            } else if (n->type != K::NODE_COLUMN_REF && n->type != K::NODE_QUALIFIED_NAME) {
                // ParserSQL records the original expression span; validate it belongs to input.
                auto p = reinterpret_cast<uintptr_t>(item->source_ptr),
                     begin = reinterpret_cast<uintptr_t>(input.data());
                if (!item->source_ptr || p < begin || p - begin > input.size() ||
                    item->source_len > input.size() - (p - begin))
                    return false;
                std::string label = n->type == K::NODE_LITERAL_NULL
                                        ? "NULL"
                                        : std::string(item->source_ptr, item->source_len);
                if (n->type == K::NODE_FUNCTION_CALL && !output_label(label, 255))
                    return false;
                out += " AS " + quote(label);
            }
        }
        if ((!group && aggregate && (plain || order || limit)) || (having && !group && !aggregate))
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
        if (group)
            out += " GROUP BY " + group_sql;
        if (having) {
            std::string p;
            auto n = having->first_child;
            if (!n || n->next_sibling || !having_pred(n, p))
                return false;
            out += " HAVING " + p;
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
                if (!c || (group && !group_keys.count(c->canonical_name)) ||
                    alias_conflicts(c->canonical_name) ||
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
            bool unique = group && std::all_of(group_keys.begin(), group_keys.end(),
                                               [&](const std::string &key) {
                                                   return ordered.count(key) != 0;
                                               });
            for (const auto &key : relation.unique_keys) {
                if (group)
                    break;
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
    std::vector<std::pair<size_t, const sql_parser::AstNode *>> found;
    bool bad_parameter_source = false, too_many_parameters = false;
    auto walk = sql_parser::walk_ast(
        parsed.ast,
        [&](const sql_parser::AstNode &node, const sql_parser::AstVisitContext &) {
            if (node.type != sql_parser::NodeType::NODE_PLACEHOLDER)
                return sql_parser::AstVisitAction::Continue;
            if (found.size() >= 256) {
                too_many_parameters = true;
                return sql_parser::AstVisitAction::Stop;
            }
            const auto begin = reinterpret_cast<uintptr_t>(input.data());
            const auto ptr = reinterpret_cast<uintptr_t>(node.value_ptr);
            if (!node.value_ptr || ptr < begin || ptr - begin >= input.size() ||
                node.value_len != 1 || input[ptr - begin] != '?' || node.first_child ||
                node.flags ||
                (node.source_ptr && (node.source_ptr != node.value_ptr || node.source_len != 1)) ||
                (!node.source_ptr && node.source_len)) {
                bad_parameter_source = true;
                return sql_parser::AstVisitAction::Stop;
            }
            found.emplace_back(static_cast<size_t>(ptr - begin), &node);
            return sql_parser::AstVisitAction::Continue;
        },
        {ctx.max_nodes, ctx.max_depth});
    if (too_many_parameters || walk.status == sql_parser::AstWalkStatus::LimitExceeded) {
        result.reason = "resource_limit";
        return result;
    }
    if (bad_parameter_source || walk.status != sql_parser::AstWalkStatus::Completed) {
        result.reason = "parameter_provenance";
        return result;
    }
    std::sort(found.begin(), found.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });
    std::vector<const sql_parser::AstNode *> parameters;
    for (size_t i = 0; i < found.size(); ++i) {
        if (i && found[i - 1].first == found[i].first) {
            result.reason = "parameter_provenance";
            return result;
        }
        parameters.push_back(found[i].second);
    }
    if ((ctx.parameter_mode != DuckDBMySQLParameterMode::execute && !ctx.parameter_kinds.empty()) ||
        (ctx.parameter_mode == DuckDBMySQLParameterMode::execute &&
         ctx.parameter_kinds.size() != parameters.size())) {
        result.reason = "parameter_count_mismatch";
        return result;
    }
    if (ctx.parameter_mode == DuckDBMySQLParameterMode::execute) {
        for (auto kind : ctx.parameter_kinds) {
            if (kind != DuckDBMySQLParameterKind::signed_integer &&
                kind != DuckDBMySQLParameterKind::null_value) {
                result.reason = "unsupported_parameter_type";
                return result;
            }
        }
    }
    Translator t{input, ctx, parameters};
    std::string sql;
    if (!t.run(parsed.ast, sql)) {
        result.reason = t.reason;
        result.required_context = std::move(t.required);
        return result;
    }
    if (t.parameter_index != parameters.size()) {
        result.reason = "unsupported_ast";
        return result;
    }
    result.decision = DuckDBMySQLSelectDecision::supported;
    result.parameter_count = parameters.size();
    result.sql = std::move(sql);
    result.reason = "supported";
    return result;
}

DuckDBMySQLSelectTranslation
duckdb_translate_mysql_select(const std::string &input, const DuckDBMySQLSelectContext &context) {
    try {
        DuckDBMySQLSelectTranslation rejected;
        if (context.parameter_kinds.size() > 256) {
            rejected.reason = "resource_limit";
            return rejected;
        }
        if (context.parameter_mode != DuckDBMySQLParameterMode::forbidden &&
            context.parameter_mode != DuckDBMySQLParameterMode::prepare &&
            context.parameter_mode != DuckDBMySQLParameterMode::execute) {
            rejected.reason = "invalid_parameter_mode";
            return rejected;
        }
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
