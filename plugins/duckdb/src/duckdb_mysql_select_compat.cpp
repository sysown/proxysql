#include "duckdb_mysql_select_compat.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
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
enum class AggregateKind { count, min, max, sum, avg };
// Unsigned decimal text for 10^-n as a fraction-only decimal literal.
std::string reciprocal_of_power_of_ten(unsigned n) {
    return "0." + std::string(n - 1, '0') + "1";
}
// The admitted literal bound keeps one predicate from dominating the output
// budget; longer literals stay outside the proven subset.
constexpr size_t max_text_literal_bytes = 4096;
bool valid_utf8(const std::string &s) {
    size_t i = 0;
    while (i < s.size()) {
        const auto first = static_cast<unsigned char>(s[i]);
        if (first < 0x80) {
            ++i;
            continue;
        }
        unsigned need = 0, code = 0;
        if ((first & 0xe0) == 0xc0) {
            need = 1;
            code = first & 0x1f;
        } else if ((first & 0xf0) == 0xe0) {
            need = 2;
            code = first & 0x0f;
        } else if ((first & 0xf8) == 0xf0) {
            need = 3;
            code = first & 0x07;
        } else {
            return false;
        }
        if (need >= s.size() - i)
            return false;
        for (unsigned k = 1; k <= need; ++k) {
            const auto next = static_cast<unsigned char>(s[i + k]);
            if ((next & 0xc0) != 0x80)
                return false;
            code = (code << 6) | (next & 0x3f);
        }
        if ((need == 1 && code < 0x80) || (need == 2 && code < 0x800) ||
            (need == 3 && code < 0x10000) || (code >= 0xd800 && code <= 0xdfff) || code > 0x10ffff)
            return false;
        i += need + 1;
    }
    return true;
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
    // A query has at most three base relations. Every relation is resolved
    // exactly once, in FROM order, and receives a private emitted alias so
    // DuckDB never has to resolve a user alias or table name.
    struct Relation {
        DuckDBMySQLRelation meta;
        std::string reference;
        std::string emit_alias;
        bool aliased = false;
        bool left_join = false;
        std::string on_sql;
    };
    struct ColumnRef {
        const DuckDBMySQLColumn *column = nullptr;
        size_t relation = 0;
        // MySQL labels a plain column with the identifier spelling in the
        // select list, not with the declared column name.
        std::string label;
    };
    std::vector<Relation> relations;
    bool has_relation = false;
    std::string reason = "unsupported_ast";
    std::vector<std::string> required;
    const std::vector<const N *> &parameters;
    size_t parameter_index = 0;
    size_t metadata_bytes = 0;
    size_t key_parts = 0;
    Translator(const std::string &in, const DuckDBMySQLSelectContext &c,
               const std::vector<const N *> &p)
        : input(in), ctx(c), parameters(p) {}
    bool multi_relation() const {
        return relations.size() > 1;
    }
    // MySQL compares column names case-insensitively. Only ASCII folding is
    // proven here; non-ASCII bytes still have to match exactly rather than
    // guessing the identifier collation of the source metadata.
    static std::string fold_identifier(std::string s) {
        for (char &c : s)
            if (c >= 'A' && c <= 'Z')
                c += 'a' - 'A';
        return s;
    }
    std::string column_sql(const ColumnRef &ref) const {
        if (multi_relation())
            return quote(relations[ref.relation].emit_alias) + "." +
                   quote(ref.column->canonical_name);
        return quote(ref.column->canonical_name);
    }
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
    bool column_ref(const N *n, ColumnRef &out) {
        if (relations.empty() || !n)
            return false;
        const N *field = n;
        std::vector<size_t> candidates;
        if (n->type == K::NODE_QUALIFIED_NAME && !n->flags) {
            const N *qualifier = n->first_child;
            field = qualifier ? qualifier->next_sibling : nullptr;
            if (!qualifier || qualifier->type != K::NODE_IDENTIFIER || qualifier->first_child ||
                (qualifier->flags & ~FLAG_IDENT_DELIMITED) || !safe_identifier(qualifier) || !field)
                return false;
            if (field->next_sibling) {
                // MySQL's three-part database.table.column form is outside the
                // resolved-relation contract.
                reason = "unsupported_column_reference";
                return false;
            }
            if (field->type != K::NODE_IDENTIFIER || field->first_child ||
                (field->flags & ~FLAG_IDENT_DELIMITED) || !safe_identifier(field))
                return false;
            const std::string qualifier_name = ident(qualifier);
            for (size_t i = 0; i < relations.size(); ++i)
                if (relations[i].reference == qualifier_name)
                    candidates.push_back(i);
            if (candidates.empty()) {
                // A table alias hides the table name, and an unknown alias is
                // never allowed to fall back to an unqualified lookup.
                reason = "unknown_relation_alias";
                return false;
            }
        } else if (n->type != K::NODE_COLUMN_REF || n->first_child ||
                   (n->flags & ~FLAG_IDENT_DELIMITED) || !safe_identifier(n)) {
            return false;
        }
        const std::string name = ident(field);
        if (name.empty() || name[0] == '@')
            return false;
        const std::string folded = fold_identifier(name);
        if (candidates.empty())
            for (size_t i = 0; i < relations.size(); ++i)
                candidates.push_back(i);
        const DuckDBMySQLColumn *found = nullptr;
        size_t found_relation = 0;
        for (size_t index : candidates) {
            const DuckDBMySQLColumn *local = nullptr;
            for (const auto &c : relations[index].meta.columns) {
                if (fold_identifier(c.canonical_name) != folded)
                    continue;
                if (local) {
                    reason = "ambiguous_column";
                    return false;
                }
                local = &c;
            }
            if (!local)
                continue;
            if (found) {
                reason = "ambiguous_column";
                return false;
            }
            found = local;
            found_relation = index;
        }
        if (!found) {
            reason = "unknown_column";
            return false;
        }
        out.column = found;
        out.relation = found_relation;
        out.label = name;
        return true;
    }
    std::string projected_column(const ColumnRef &ref) {
        const auto name = column_sql(ref);
        if (!fraction_only(ref.column->type))
            return name;
        return "CAST(" + name + " AS DECIMAL(" + std::to_string(ref.column->type.precision + 1) +
               "," + std::to_string(ref.column->type.scale) + "))";
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
        ColumnRef ref;
        if (column_ref(node, ref)) {
            if (!output_label(ref.label))
                return false;
            if (ref.column->type.kind == DuckDBMySQLTypeKind::signed_integer)
                number.integer_digits = 19;
            else if (ref.column->type.kind == DuckDBMySQLTypeKind::unsigned_integer)
                number.integer_digits = 20;
            else if (valid_decimal(ref.column->type)) {
                number.integer_digits = ref.column->type.precision - ref.column->type.scale;
                number.scale = ref.column->type.scale;
                number.decimal = true;
            } else
                return false;
            number.sql = column_sql(ref);
            return true;
        }
        return exact_literal(node, number);
    }
    bool expr(const N *n, std::string &out, DuckDBMySQLTypeKind &type) {
        if (!n)
            return false;
        if (n->type == K::NODE_SUBQUERY) {
            reason = "unsupported_subquery";
            return false;
        }
        ColumnRef ref;
        if (column_ref(n, ref)) {
            if (!known_type(ref.column->type.kind) || !output_label(ref.label) ||
                (ref.column->type.kind == DuckDBMySQLTypeKind::exact_decimal &&
                 !projectable_decimal(ref.column->type)))
                return false;
            out = projected_column(ref);
            type = ref.column->type.kind;
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
                              : name == "SUM" ? TokenType::TK_SUM
                              : name == "AVG" ? TokenType::TK_AVG
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
    // MySQL SUM of a DECIMAL(p,s) column is DECIMAL(p+22,s) and DuckDB's
    // DECIMAL(38,s) is wide enough only while the row-count bound proves no
    // overflow; see the precision rule in doc/duckdb/mysql-query-compatibility.md.
    static bool summable_decimal(const DuckDBMySQLType &type) {
        return valid_decimal(type) && type.precision <= 19;
    }
    // MySQL AVG of an exact value has scale s + div_precision_increment (4 by
    // default). Native DuckDB AVG is DOUBLE, so emit exact integer arithmetic
    // on SUM and COUNT and round half away from zero at the target scale.
    std::string exact_average(const std::string &column_sql, unsigned precision, unsigned scale,
                              unsigned integer_digits) {
        const unsigned result_scale = scale + 4;
        // Recover the decimal's stored integer without a decimal multiply: the
        // text always carries exactly `scale` fraction digits, so dropping the
        // point yields SUM * 10^scale exactly and cannot overflow the way
        // DECIMAL(38,scale) multiplication can.
        const std::string sum_scaled =
            scale ? "CAST(replace(CAST(SUM(" + column_sql + ") AS VARCHAR), '.', '') AS HUGEINT)"
                  : "CAST(SUM(" + column_sql + ") AS HUGEINT)";
        const std::string count = "COUNT(" + column_sql + ")";
        const std::string quotient = "(" + sum_scaled + " // " + count + ")";
        const std::string remainder = "(" + sum_scaled + " % " + count + ")";
        const std::string rounded = "(CASE WHEN " + remainder + " < 0 THEN -((" + "abs(" +
                                    remainder + ") * 20000 + " + count + ") // (2 * " + count +
                                    ")) ELSE ((" + "abs(" + remainder + ") * 20000 + " + count +
                                    ") // (2 * " + count + ")) END)";
        const std::string scaled = "(" + quotient + " * 10000 + " + rounded + ")";
        // MySQL reports precision p+4. A fraction-only DECIMAL(p,p) result would
        // render without a leading zero in DuckDB, so widen that one case by a
        // digit, mirroring the plain fraction-only column projection above.
        const unsigned width = precision == scale ? result_scale + 1 : integer_digits + 4;
        return "CAST(CAST(" + scaled + " AS DECIMAL(38,0)) * CAST('" +
               reciprocal_of_power_of_ten(result_scale) + "' AS DECIMAL(" +
               std::to_string(result_scale + 1) + "," + std::to_string(result_scale) +
               ")) AS DECIMAL(" + std::to_string(width) + "," + std::to_string(result_scale) + "))";
    }
    bool aggregate_expr(const N *node, std::string &out, DuckDBMySQLTypeKind &type,
                        AggregateKind *kind = nullptr) {
        if (!node || node->type != K::NODE_FUNCTION_CALL || node->flags)
            return false;
        const std::string name = val(node);
        if (name != "COUNT" && name != "MIN" && name != "MAX" && name != "SUM" && name != "AVG")
            return false;
        if (!unambiguous_builtin(node, name))
            return false;
        const N *arg = node->first_child;
        if (!arg || arg->next_sibling)
            return false;
        const AggregateKind selected = name == "COUNT" ? AggregateKind::count
                                       : name == "MIN" ? AggregateKind::min
                                       : name == "MAX" ? AggregateKind::max
                                       : name == "SUM" ? AggregateKind::sum
                                                       : AggregateKind::avg;
        if (name == "COUNT" && arg->type == K::NODE_ASTERISK && !arg->flags && !arg->first_child) {
            out = "COUNT(*)";
            type = DuckDBMySQLTypeKind::signed_integer;
            if (kind)
                *kind = selected;
            return true;
        }
        ColumnRef ref;
        if (!column_ref(arg, ref) || !known_type(ref.column->type.kind))
            return false;
        if (name == "COUNT") {
            out = "COUNT(" + column_sql(ref) + ")";
            type = DuckDBMySQLTypeKind::signed_integer;
        } else if (name == "MIN" || name == "MAX") {
            if (ref.column->type.kind != DuckDBMySQLTypeKind::signed_integer &&
                ref.column->type.kind != DuckDBMySQLTypeKind::unsigned_integer)
                return false;
            out = name + "(" + column_sql(ref) + ")";
            type = ref.column->type.kind;
        } else {
            unsigned precision = 0, scale = 0, integer_digits = 0;
            if (ref.column->type.kind == DuckDBMySQLTypeKind::signed_integer)
                precision = integer_digits = 19;
            else if (ref.column->type.kind == DuckDBMySQLTypeKind::unsigned_integer)
                precision = integer_digits = 20;
            else if (summable_decimal(ref.column->type)) {
                precision = ref.column->type.precision;
                scale = ref.column->type.scale;
                integer_digits = precision;
            } else
                return false;
            if (name == "SUM")
                out = "SUM(" + column_sql(ref) + ")";
            else
                out = exact_average(column_sql(ref), precision, scale, integer_digits);
            type = DuckDBMySQLTypeKind::exact_decimal;
            if (out.size() > ctx.max_output_bytes) {
                reason = "resource_limit";
                return false;
            }
        }
        if (kind)
            *kind = selected;
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
        ColumnRef ref;
        if (column_ref(arg, ref) && ref.column->type.kind == DuckDBMySQLTypeKind::datetime &&
            ref.column->source.type != DuckDBMySQLSourceType::datetime) {
            // A native TIMESTAMP may be a replicated MySQL TIMESTAMP, which MySQL renders in
            // the session time zone. Only a recorded MySQL DATETIME has no time zone.
            if (ref.column->source.type == DuckDBMySQLSourceType::timestamp) {
                reason = "session_time_zone_dependent";
            } else {
                reason = "session_time_zone_unknown";
                required.push_back("source_column_type_provenance");
            }
            return false;
        }
        if (!ref.column || (ref.column->type.kind != DuckDBMySQLTypeKind::date &&
                            ref.column->type.kind != DuckDBMySQLTypeKind::datetime))
            return false;
        // DuckDB's numeric strftime directives are locale-independent and
        // return VARCHAR without converting a timezone-naive value.
        out = "strftime(" + column_sql(ref) + ", '%Y-%m')";
        type = DuckDBMySQLTypeKind::text;
        return true;
    }
    // Only utf8mb4_0900_bin is proven byte-for-byte against DuckDB VARCHAR.
    // Every padded or non-binary collation (including utf8mb4_bin, ai_ci and
    // as_cs) stays outside the admitted subset.
    bool text_collation(const DuckDBMySQLColumn &c) {
        if (!c.source.known() || c.source.collation.empty()) {
            reason = "collation_unproven";
            required.push_back("source_column_collation_provenance");
            return false;
        }
        if (c.source.collation != "utf8mb4_0900_bin") {
            reason = "unsupported_collation";
            return false;
        }
        return true;
    }
    // A plain single-quoted literal whose exact source bytes were recorded by
    // ParserSQL. Backslash is an escape unless NO_BACKSLASH_ESCAPES holds, and
    // a double-quoted token is an identifier under ANSI_QUOTES, so both stay
    // refused. Introducers, prefixes and adjacent literals are separate AST
    // shapes and never reach this function.
    bool text_literal(const N *node, std::string &out) {
        if (!node || node->type != K::NODE_LITERAL_STRING || node->flags || node->first_child ||
            !node->source_ptr || node->source_len < 2 || (node->value_len && !node->value_ptr))
            return false;
        const auto begin = reinterpret_cast<uintptr_t>(input.data());
        const auto inside = [&](const char *p, size_t len) {
            if (!p)
                return len == 0;
            const auto at = reinterpret_cast<uintptr_t>(p);
            return at >= begin && at - begin <= input.size() && len <= input.size() - (at - begin);
        };
        if (node->source_ptr[0] != '\'' || node->source_ptr[node->source_len - 1] != '\'' ||
            !inside(node->source_ptr, node->source_len) ||
            !inside(node->value_ptr, node->value_len))
            return false;
        // ParserSQL keeps the raw text between the outer quotes, including any
        // doubled single quotes; verify that provenance before interpreting it.
        if (node->source_len - 2 != node->value_len ||
            (node->value_len &&
             std::memcmp(node->value_ptr, node->source_ptr + 1, node->value_len) != 0))
            return false;
        std::string decoded;
        for (size_t i = 1; i + 1 < node->source_len; ++i) {
            const char c = node->source_ptr[i];
            if (c == '\\')
                return false;
            if (c == '\'') {
                if (i + 2 >= node->source_len || node->source_ptr[i + 1] != '\'')
                    return false;
                decoded += '\'';
                ++i;
            } else {
                decoded += c;
            }
        }
        if (decoded.size() > max_text_literal_bytes) {
            reason = "resource_limit";
            return false;
        }
        if (!valid_utf8(decoded))
            return false;
        out = "'";
        for (char c : decoded) {
            if (c == '\'')
                out += '\'';
            out += c;
        }
        out += '\'';
        if (out.size() > ctx.max_output_bytes) {
            reason = "resource_limit";
            return false;
        }
        return true;
    }
    bool text_operand(const N *n, std::string &out, bool &is_column, bool &is_literal) {
        is_column = is_literal = false;
        ColumnRef ref;
        if (column_ref(n, ref)) {
            if (ref.column->type.kind != DuckDBMySQLTypeKind::text || !text_collation(*ref.column))
                return false;
            out = column_sql(ref);
            is_column = true;
            return true;
        }
        if (!n || n->type != K::NODE_LITERAL_STRING || !text_literal(n, out))
            return false;
        is_literal = true;
        return true;
    }
    bool text_comparison(const N *a, const N *b, std::string &x, std::string &y) {
        bool a_column = false, a_literal = false, b_column = false, b_literal = false;
        if (!text_operand(a, x, a_column, a_literal) || !text_operand(b, y, b_column, b_literal))
            return false;
        // At least one side must be a proven text column, and never two bare
        // literals: the admitted forms are column/literal and column/column.
        return (a_column || b_column) && !(a_literal && b_literal);
    }
    bool having_pred(const N *node, std::string &out) {
        if (!node || node->flags)
            return false;
        if (node->type == K::NODE_IS_NULL || node->type == K::NODE_IS_NOT_NULL) {
            auto arg = node->first_child;
            std::string x;
            DuckDBMySQLTypeKind type;
            AggregateKind kind = AggregateKind::count;
            if (!arg || arg->next_sibling || !aggregate_expr(arg, x, type, &kind))
                return false;
            if (kind == AggregateKind::sum || kind == AggregateKind::avg) {
                // Comparisons over DERIVED exact values stay outside this slice.
                reason = "unsupported_having_aggregate";
                return false;
            }
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
            AggregateKind kind = AggregateKind::count;
            if (!aggregate_expr(a, x, type, &kind))
                return false;
            if (kind == AggregateKind::sum || kind == AggregateKind::avg) {
                reason = "unsupported_having_aggregate";
                return false;
            }
            if (type != DuckDBMySQLTypeKind::signed_integer || !integer(b, y))
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
        if (n->type == K::NODE_SUBQUERY) {
            reason = "unsupported_subquery";
            return false;
        }
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
            ColumnRef ca, cb;
            const bool a_column = column_ref(a, ca), b_column = column_ref(b, cb);
            const bool a_text = a_column && ca.column->type.kind == DuckDBMySQLTypeKind::text;
            const bool b_text = b_column && cb.column->type.kind == DuckDBMySQLTypeKind::text;
            if (a_text || b_text || a->type == K::NODE_LITERAL_STRING ||
                b->type == K::NODE_LITERAL_STRING) {
                if (!text_comparison(a, b, x, y))
                    return false;
            } else {
                const bool a_param = a->type == K::NODE_PLACEHOLDER;
                const bool b_param = b->type == K::NODE_PLACEHOLDER;
                if (a_param || b_param) {
                    // A joined query keeps placeholder support out of the
                    // admitted subset rather than extending the position proof
                    // to several relations.
                    if (multi_relation()) {
                        reason = "unsupported_parameter_join";
                        return false;
                    }
                    if (a_param == b_param ||
                        ctx.parameter_mode == DuckDBMySQLParameterMode::forbidden)
                        return false;
                    const N *parameter = a_param ? a : b;
                    const N *column_node = a_param ? b : a;
                    ColumnRef ref;
                    if (!column_ref(column_node, ref) ||
                        ref.column->type.kind != DuckDBMySQLTypeKind::signed_integer)
                        return false;
                    if (parameter_index >= parameters.size() ||
                        parameters[parameter_index] != parameter) {
                        reason = "parameter_order";
                        return false;
                    }
                    ++parameter_index;
                    const auto bound_column = "CAST(" + column_sql(ref) + " AS BIGINT)";
                    if (a_param) {
                        x = "CAST(? AS BIGINT)";
                        y = bound_column;
                    } else {
                        x = bound_column;
                        y = "CAST(? AS BIGINT)";
                    }
                } else {
                    ExactNumber lhs, rhs;
                    const bool lhs_exact = exact_number(a, lhs);
                    const bool rhs_exact = exact_number(b, rhs);
                    if (lhs_exact && rhs_exact && (lhs.decimal || rhs.decimal)) {
                        const unsigned scale = std::max(lhs.scale, rhs.scale);
                        const unsigned precision =
                            std::max(1u, std::max(lhs.integer_digits, rhs.integer_digits) + scale);
                        if (precision > 38 || scale > 30)
                            return false;
                        const std::string target = " AS DECIMAL(" + std::to_string(precision) +
                                                   "," + std::to_string(scale) + "))";
                        x = "CAST(" + lhs.sql + target;
                        y = "CAST(" + rhs.sql + target;
                    } else {
                        DuckDBMySQLTypeKind ta, tb;
                        if (expr(a, x, ta) && expr(b, y, tb) && ta == tb &&
                            ta == DuckDBMySQLTypeKind::signed_integer) {
                            // The established signed-integer comparison.
                        } else if (lhs_exact && rhs_exact) {
                            // MySQL compares signed and unsigned integers
                            // mathematically. A common DECIMAL(20,0) is exact
                            // over both domains, unlike an unsigned cast that
                            // would turn a negative signed value around.
                            const unsigned precision =
                                std::max(1u, std::max(lhs.integer_digits, rhs.integer_digits));
                            const std::string target =
                                " AS DECIMAL(" + std::to_string(precision) + ",0))";
                            x = "CAST(" + lhs.sql + target;
                            y = "CAST(" + rhs.sql + target;
                        } else {
                            return false;
                        }
                    }
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
    bool add_relation(const N *ref) {
        if (!ref || ref->type != K::NODE_TABLE_REF || ref->flags)
            return false;
        auto name = ref->first_child;
        auto alias = name ? name->next_sibling : nullptr;
        if (!name)
            return false;
        if (alias && alias->next_sibling)
            return false;
        if (name->type == K::NODE_SUBQUERY || name->type == K::NODE_LATERAL) {
            reason = "derived_table";
            return false;
        }
        // A single identifier is resolved in the session's selected
        // database; MySQL's two-part `database.table` names that database
        // explicitly and works from any selected database. Three-part
        // names are a MySQL syntax error and ParserSQL already reports the
        // remainder as unparsed.
        std::vector<std::string> name_parts;
        if (name->type == K::NODE_IDENTIFIER && !name->first_child &&
            !(name->flags & ~FLAG_IDENT_DELIMITED) && safe_identifier(name)) {
            name_parts.push_back(ident(name));
            if (ctx.require_selected_database && ctx.default_schema.empty()) {
                reason = "no_database_selected";
                return false;
            }
        } else if (name->type == K::NODE_QUALIFIED_NAME && !name->flags) {
            const N *schema = name->first_child;
            const N *table = schema ? schema->next_sibling : nullptr;
            if (!schema || !table || table->next_sibling || schema->type != K::NODE_IDENTIFIER ||
                table->type != K::NODE_IDENTIFIER || schema->first_child || table->first_child ||
                (schema->flags & ~FLAG_IDENT_DELIMITED) || (table->flags & ~FLAG_IDENT_DELIMITED) ||
                !safe_identifier(schema) || !safe_identifier(table))
                return false;
            name_parts.push_back(ident(schema));
            name_parts.push_back(ident(table));
            if (duckdb_mysql_reserved_database(name_parts[0])) {
                reason = "reserved_database";
                return false;
            }
        } else {
            return false;
        }
        if (alias && (alias->type != K::NODE_ALIAS || alias->next_sibling || alias->first_child ||
                      (alias->flags & ~FLAG_IDENT_DELIMITED) || !safe_identifier(alias)))
            return false;
        Relation entry;
        entry.reference = ident(alias                    ? alias
                                : name_parts.size() == 1 ? name
                                                         : name->first_child->next_sibling);
        entry.aliased = alias != nullptr;
        if (relations.size() >= 3) {
            reason = "join_relation_limit";
            return false;
        }
        if (!ctx.resolve_relation || !ctx.max_resolver_calls ||
            relations.size() >= ctx.max_resolver_calls) {
            reason = "missing_context";
            required.push_back("relation_resolver");
            return false;
        }
        if (!ctx.resolve_relation(name_parts, entry.meta) || !entry.meta.exact_name_resolution ||
            entry.meta.canonical_name.empty()) {
            reason = "unresolved_relation";
            return false;
        }
        if (entry.meta.columns.size() > ctx.max_nodes || entry.meta.canonical_name.size() > 3 ||
            entry.meta.unique_keys.size() > ctx.max_nodes) {
            reason = "resource_limit";
            return false;
        }
        auto budget = [&](const std::string &s) {
            if (s.size() > ctx.max_output_bytes - metadata_bytes)
                return false;
            metadata_bytes += s.size();
            return true;
        };
        for (const auto &part : entry.meta.canonical_name)
            if (!budget(part)) {
                reason = "resource_limit";
                return false;
            }
        for (const auto &col : entry.meta.columns)
            if (!budget(col.canonical_name)) {
                reason = "resource_limit";
                return false;
            }
        for (const auto &key : entry.meta.unique_keys) {
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
        for (const auto &part : entry.meta.canonical_name)
            if (!valid_name(part))
                return false;
        for (const auto &col : entry.meta.columns)
            if (!valid_name(col.canonical_name))
                return false;
        for (const auto &other : relations) {
            if (other.reference != entry.reference)
                continue;
            // MySQL reports ER_NONUNIQ_TABLE for a duplicate alias, an alias
            // that shadows another reference, or the same unaliased table
            // twice. Distinct tables that merely share a last name are not a
            // FROM error; `t.col` is then ambiguous and is refused there.
            if (entry.aliased || other.aliased ||
                other.meta.canonical_name == entry.meta.canonical_name) {
                reason = "duplicate_relation";
                return false;
            }
        }
        entry.emit_alias = "r" + std::to_string(relations.size());
        relations.push_back(std::move(entry));
        has_relation = true;
        return true;
    }
    bool add_join(const N *join) {
        if (!join || join->type != K::NODE_JOIN_CLAUSE || join->flags)
            return false;
        const std::string kind = val(join);
        bool left = false;
        if (kind == "JOIN" || kind == "INNER JOIN") {
            left = false;
        } else if (kind == "LEFT JOIN" || kind == "LEFT OUTER JOIN") {
            left = true;
        } else {
            if (kind == "CROSS JOIN")
                reason = "cross_join";
            else if (kind.find("NATURAL") != std::string::npos)
                reason = "natural_join";
            else if (kind.find("RIGHT") != std::string::npos)
                reason = "right_join";
            else if (kind.find("FULL") != std::string::npos)
                reason = "full_join";
            else
                reason = "unsupported_join_type";
            return false;
        }
        auto right = join->first_child;
        auto condition = right ? right->next_sibling : nullptr;
        if (!right)
            return false;
        if (!condition) {
            reason = "join_without_condition";
            return false;
        }
        if (condition->next_sibling)
            return false;
        if (condition->type == K::NODE_IDENTIFIER && val(condition) == "USING") {
            reason = "using_join";
            return false;
        }
        if (relations.empty()) {
            reason = "unsupported_join";
            return false;
        }
        if (!add_relation(right))
            return false;
        std::string on;
        reason = "unsupported_join_predicate";
        if (!pred(condition, on))
            return false;
        relations.back().left_join = left;
        relations.back().on_sql = std::move(on);
        reason = "unsupported_ast";
        return true;
    }
    bool star_relation(const N *n, size_t &index) {
        if (!has_relation || !n)
            return false;
        if (n->type == K::NODE_ASTERISK && !n->first_child && !n->flags) {
            index = std::numeric_limits<size_t>::max();
            return true;
        }
        if (n->type != K::NODE_QUALIFIED_NAME || n->flags)
            return false;
        const N *qualifier = n->first_child;
        const N *field = qualifier ? qualifier->next_sibling : nullptr;
        if (!qualifier || qualifier->type != K::NODE_IDENTIFIER || qualifier->first_child ||
            (qualifier->flags & ~FLAG_IDENT_DELIMITED) || !safe_identifier(qualifier) || !field ||
            field->next_sibling || field->type != K::NODE_IDENTIFIER || field->first_child ||
            field->flags || !safe_identifier(field) || ident(field) != "*")
            return false;
        const std::string name = ident(qualifier);
        bool found = false;
        for (size_t i = 0; i < relations.size(); ++i) {
            if (relations[i].reference != name)
                continue;
            if (found) {
                reason = "ambiguous_column";
                return false;
            }
            found = true;
            index = i;
        }
        if (!found) {
            reason = "unknown_relation_alias";
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
            while (t) {
                if (t->type == K::NODE_TABLE_REF) {
                    if (!relations.empty()) {
                        // Comma joins have no explicit ON predicate.
                        reason = "comma_join";
                        return false;
                    }
                    if (!add_relation(t))
                        return false;
                } else if (t->type == K::NODE_JOIN_CLAUSE) {
                    if (relations.empty()) {
                        reason = "unsupported_join";
                        return false;
                    }
                    if (!add_join(t))
                        return false;
                } else {
                    return false;
                }
                t = t->next_sibling;
            }
            if (relations.empty())
                return false;
        }
        if (multi_relation() && !parameters.empty()) {
            // Placeholder positions are proven for one relation only.
            reason = "unsupported_parameter_join";
            return false;
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
        std::set<std::pair<size_t, std::string>> group_keys;
        std::string group_sql;
        if (group) {
            if (!has_relation || group->value_len || !group->first_child)
                return false;
            for (auto n = group->first_child; n; n = n->next_sibling) {
                ColumnRef ref;
                if (!column_ref(n, ref) || alias_conflicts(ref.label) ||
                    (ref.column->type.kind != DuckDBMySQLTypeKind::signed_integer &&
                     ref.column->type.kind != DuckDBMySQLTypeKind::unsigned_integer))
                    return false;
                if (!group_sql.empty())
                    group_sql += ", ";
                group_sql += column_sql(ref);
                if (group_sql.size() > ctx.max_output_bytes) {
                    reason = "resource_limit";
                    return false;
                }
                group_keys.insert({ref.relation, ref.column->canonical_name});
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
            size_t star_index = 0;
            if (n->type == K::NODE_ASTERISK || n->type == K::NODE_QUALIFIED_NAME) {
                const bool star = star_relation(n, star_index);
                if (star && alias)
                    return false;
                if (!star && n->type == K::NODE_QUALIFIED_NAME) {
                    const N *qualifier = n->first_child;
                    const N *field = qualifier ? qualifier->next_sibling : nullptr;
                    if (qualifier && field && !field->next_sibling &&
                        field->type == K::NODE_IDENTIFIER && !field->flags && val(field) == "*")
                        return false;
                }
                if (star) {
                    if (group)
                        return false;
                    plain = true;
                    if (multi_relation()) {
                        const size_t first_relation =
                            star_index == std::numeric_limits<size_t>::max() ? 0 : star_index;
                        const size_t last_relation =
                            star_index == std::numeric_limits<size_t>::max() ? relations.size()
                                                                             : star_index + 1;
                        bool sep = false;
                        for (size_t relation_index = first_relation; relation_index < last_relation;
                             ++relation_index) {
                            const auto &target = relations[relation_index].meta;
                            if (target.columns.empty())
                                return false;
                            std::set<std::string> seen;
                            for (const auto &c : target.columns) {
                                if (!known_type(c.type.kind) || !output_label(c.canonical_name) ||
                                    (c.type.kind == DuckDBMySQLTypeKind::exact_decimal &&
                                     !projectable_decimal(c.type)))
                                    return false;
                                if (!seen.insert(fold_identifier(c.canonical_name)).second) {
                                    reason = "ambiguous_column";
                                    return false;
                                }
                                if (sep)
                                    out += ", ";
                                sep = true;
                                ColumnRef ref{&c, relation_index, c.canonical_name};
                                out += projected_column(ref) + " AS " + quote(c.canonical_name);
                                if (out.size() > ctx.max_output_bytes) {
                                    reason = "resource_limit";
                                    return false;
                                }
                            }
                        }
                    } else {
                        bool expand = false;
                        for (const auto &c : relations[0].meta.columns) {
                            if (!known_type(c.type.kind) || !output_label(c.canonical_name) ||
                                (c.type.kind == DuckDBMySQLTypeKind::exact_decimal &&
                                 !projectable_decimal(c.type)))
                                return false;
                            expand = expand || fraction_only(c.type);
                        }
                        if (!expand)
                            out += "*";
                        else {
                            std::set<std::string> seen;
                            bool sep = false;
                            for (const auto &c : relations[0].meta.columns) {
                                // DuckDB identifiers are case-insensitive; an ambiguous
                                // expanded column cannot be resolved safely.
                                if (!seen.insert(fold_identifier(c.canonical_name)).second)
                                    return false;
                                if (sep)
                                    out += ", ";
                                sep = true;
                                ColumnRef ref{&c, 0, c.canonical_name};
                                out += projected_column(ref);
                                if (fraction_only(c.type))
                                    out += " AS " + quote(c.canonical_name);
                                if (out.size() > ctx.max_output_bytes) {
                                    reason = "resource_limit";
                                    return false;
                                }
                            }
                        }
                    }
                    continue;
                }
            }
            std::string s;
            DuckDBMySQLTypeKind type;
            bool column_projection = false;
            ColumnRef projected_ref;
            if (aggregate_expr(n, s, type)) {
                aggregate = true;
            } else {
                if (!expr(n, s, type) && !date_format_expr(n, s, type))
                    return false;
                column_projection = column_ref(n, projected_ref);
                if (group) {
                    if (!column_projection ||
                        !group_keys.count(
                            {projected_ref.relation, projected_ref.column->canonical_name}))
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
            } else if (column_projection) {
                const bool label_needed =
                    multi_relation() || fraction_only(projected_ref.column->type) ||
                    projected_ref.label != projected_ref.column->canonical_name;
                if (label_needed) {
                    if (!output_label(projected_ref.label))
                        return false;
                    out += " AS " + quote(projected_ref.label);
                }
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
            for (size_t i = 0; i < relations.size(); ++i) {
                const auto &entry = relations[i];
                if (i) {
                    out += entry.left_join ? " LEFT JOIN " : " INNER JOIN ";
                }
                bool sep = false;
                for (auto &part : entry.meta.canonical_name) {
                    if (part.empty())
                        return false;
                    if (sep)
                        out += '.';
                    out += quote(part);
                    sep = true;
                }
                if (multi_relation())
                    out += " AS " + quote(entry.emit_alias);
                if (i)
                    out += " ON " + entry.on_sql;
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
        std::set<std::pair<size_t, std::string>> ordered;
        if (order) {
            out += " ORDER BY ";
            bool sep = false;
            for (auto item = order->first_child; item; item = item->next_sibling) {
                if (item->type != K::NODE_ORDER_BY_ITEM || item->flags)
                    return false;
                auto n = item->first_child;
                auto dir = n ? n->next_sibling : nullptr;
                ColumnRef ref;
                if (!n || !column_ref(n, ref) ||
                    (group && !group_keys.count({ref.relation, ref.column->canonical_name})) ||
                    alias_conflicts(ref.label))
                    return false;
                const bool numeric =
                    ref.column->type.kind == DuckDBMySQLTypeKind::signed_integer ||
                    ref.column->type.kind == DuckDBMySQLTypeKind::unsigned_integer ||
                    ref.column->type.kind == DuckDBMySQLTypeKind::exact_decimal;
                if (!numeric && (ref.column->type.kind != DuckDBMySQLTypeKind::text ||
                                 !text_collation(*ref.column)))
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
                out += column_sql(ref) + " " + d + (d == "ASC" ? " NULLS FIRST" : " NULLS LAST");
                ordered.insert({ref.relation, ref.column->canonical_name});
            }
            if (!sep)
                return false;
        }
        if (limit) {
            // A LIMIT needs a total order. Every joined relation must
            // contribute a declared unique key to ORDER BY: in an INNER join
            // the whole result tuple is then unique; in a LEFT join an
            // unmatched right side is all NULL, and the still-unique left key
            // separates those rows.
            bool unique = false;
            if (group)
                unique = std::all_of(group_keys.begin(), group_keys.end(),
                                     [&](const std::pair<size_t, std::string> &key) {
                                         return ordered.count(key) != 0;
                                     });
            else if (!relations.empty()) {
                unique = true;
                for (size_t i = 0; i < relations.size(); ++i) {
                    bool relation_unique = false;
                    for (const auto &key : relations[i].meta.unique_keys) {
                        if (!key.empty() &&
                            std::all_of(key.begin(), key.end(), [&](const std::string &s) {
                                return ordered.count({i, s}) != 0;
                            })) {
                            relation_unique = true;
                            break;
                        }
                    }
                    if (!relation_unique) {
                        unique = false;
                        break;
                    }
                }
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
        ctx.max_resolver_calls = std::min(ctx.max_resolver_calls, size_t(3));
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
