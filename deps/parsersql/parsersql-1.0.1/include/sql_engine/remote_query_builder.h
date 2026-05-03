#ifndef SQL_ENGINE_REMOTE_QUERY_BUILDER_H
#define SQL_ENGINE_REMOTE_QUERY_BUILDER_H

#include "sql_engine/catalog.h"
#include "sql_parser/arena.h"
#include "sql_parser/string_builder.h"
#include "sql_parser/emitter.h"
#include "sql_parser/common.h"
#include "sql_parser/ast.h"
#include <cstdio>

namespace sql_engine {

template <sql_parser::Dialect D>
class RemoteQueryBuilder {
public:
    explicit RemoteQueryBuilder(sql_parser::Arena& arena)
        : arena_(arena) {}

    // Build a SELECT statement string from plan components.
    // Returns an arena-allocated StringRef.
    sql_parser::StringRef build_select(
            const TableInfo* table,
            const sql_parser::AstNode* where_expr,       // nullable
            const sql_parser::AstNode** project_exprs,    // nullable = SELECT *
            uint16_t project_count,
            const sql_parser::AstNode** group_by,         // nullable
            uint16_t group_count,
            const sql_parser::AstNode** order_keys,       // nullable
            uint8_t* order_dirs,
            uint16_t order_count,
            int64_t limit,                                 // -1 = no limit
            bool distinct)
    {
        sql_parser::StringBuilder sb(arena_, 512);

        sb.append("SELECT ");

        if (distinct) {
            sb.append("DISTINCT ");
        }

        // Projection
        if (project_exprs && project_count > 0) {
            for (uint16_t i = 0; i < project_count; ++i) {
                if (i > 0) sb.append(", ");
                emit_expr(project_exprs[i], sb);
            }
        } else {
            sb.append_char('*');
        }

        // FROM
        if (table) {
            sb.append(" FROM ");
            sb.append(table->table_name.ptr, table->table_name.len);
        }

        // WHERE
        if (where_expr) {
            sb.append(" WHERE ");
            emit_expr(where_expr, sb);
        }

        // GROUP BY
        if (group_by && group_count > 0) {
            sb.append(" GROUP BY ");
            for (uint16_t i = 0; i < group_count; ++i) {
                if (i > 0) sb.append(", ");
                emit_expr(group_by[i], sb);
            }
        }

        // ORDER BY
        if (order_keys && order_count > 0) {
            sb.append(" ORDER BY ");
            for (uint16_t i = 0; i < order_count; ++i) {
                if (i > 0) sb.append(", ");
                emit_expr(order_keys[i], sb);
                if (order_dirs && order_dirs[i] == 1) {
                    sb.append(" DESC");
                }
            }
        }

        // LIMIT
        if (limit >= 0) {
            sb.append(" LIMIT ");
            char buf[32];
            int n = snprintf(buf, sizeof(buf), "%lld", (long long)limit);
            sb.append(buf, n);
        }

        return sb.finish();
    }

    // Build an INSERT statement string.
    sql_parser::StringRef build_insert(
            const TableInfo* table,
            const sql_parser::AstNode** columns,
            uint16_t col_count,
            const sql_parser::AstNode** value_rows,
            uint16_t row_count)
    {
        sql_parser::StringBuilder sb(arena_, 512);
        sb.append("INSERT INTO ");
        if (table) {
            sb.append(table->table_name.ptr, table->table_name.len);
        }

        // Column list
        if (columns && col_count > 0) {
            sb.append(" (");
            for (uint16_t i = 0; i < col_count; ++i) {
                if (i > 0) sb.append(", ");
                emit_expr(columns[i], sb);
            }
            sb.append_char(')');
        }

        // VALUES
        if (value_rows && row_count > 0) {
            sb.append(" VALUES ");
            for (uint16_t r = 0; r < row_count; ++r) {
                if (r > 0) sb.append(", ");
                sb.append_char('(');
                if (value_rows[r]) {
                    uint16_t vi = 0;
                    for (const sql_parser::AstNode* val = value_rows[r]->first_child;
                         val; val = val->next_sibling, ++vi) {
                        if (vi > 0) sb.append(", ");
                        emit_expr(val, sb);
                    }
                }
                sb.append_char(')');
            }
        }

        return sb.finish();
    }

    // Build an UPDATE statement string.
    sql_parser::StringRef build_update(
            const TableInfo* table,
            const sql_parser::AstNode** set_cols,
            const sql_parser::AstNode** set_exprs,
            uint16_t set_count,
            const sql_parser::AstNode* where_expr)
    {
        sql_parser::StringBuilder sb(arena_, 512);
        sb.append("UPDATE ");
        if (table) {
            sb.append(table->table_name.ptr, table->table_name.len);
        }

        sb.append(" SET ");
        for (uint16_t i = 0; i < set_count; ++i) {
            if (i > 0) sb.append(", ");
            emit_expr(set_cols[i], sb);
            sb.append(" = ");
            emit_expr(set_exprs[i], sb);
        }

        if (where_expr) {
            sb.append(" WHERE ");
            emit_expr(where_expr, sb);
        }

        return sb.finish();
    }

    // Build a DELETE statement string.
    sql_parser::StringRef build_delete(
            const TableInfo* table,
            const sql_parser::AstNode* where_expr)
    {
        sql_parser::StringBuilder sb(arena_, 512);
        sb.append("DELETE FROM ");
        if (table) {
            sb.append(table->table_name.ptr, table->table_name.len);
        }

        if (where_expr) {
            sb.append(" WHERE ");
            emit_expr(where_expr, sb);
        }

        return sb.finish();
    }

    sql_parser::StringRef build_update_from_ast(const sql_parser::AstNode* ast) {
        sql_parser::Emitter<D> emitter(arena_);
        emitter.emit(ast);
        return emitter.result();
    }

    sql_parser::StringRef build_delete_from_ast(const sql_parser::AstNode* ast) {
        sql_parser::Emitter<D> emitter(arena_);
        emitter.emit(ast);
        return emitter.result();
    }

private:
    sql_parser::Arena& arena_;

    void emit_expr(const sql_parser::AstNode* expr, sql_parser::StringBuilder& sb) {
        if (!expr) return;
        // Use the parser's emitter to emit the expression
        sql_parser::Emitter<D> emitter(arena_);
        emitter.emit(expr);
        sql_parser::StringRef result = emitter.result();
        sb.append(result.ptr, result.len);
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_REMOTE_QUERY_BUILDER_H
