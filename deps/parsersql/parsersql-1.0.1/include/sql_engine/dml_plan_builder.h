// dml_plan_builder.h -- AST-to-DML-plan translation
//
// DmlPlanBuilder<D> translates INSERT/UPDATE/DELETE AST nodes into
// DML plan nodes (INSERT_PLAN, UPDATE_PLAN, DELETE_PLAN).

#ifndef SQL_ENGINE_DML_PLAN_BUILDER_H
#define SQL_ENGINE_DML_PLAN_BUILDER_H

#include "sql_engine/plan_node.h"
#include "sql_engine/catalog.h"
#include "sql_parser/ast.h"
#include "sql_parser/common.h"
#include "sql_parser/arena.h"
#include <cstring>
#include <vector>

namespace sql_engine {

template <sql_parser::Dialect D>
class DmlPlanBuilder {
public:
    DmlPlanBuilder(const Catalog& catalog, sql_parser::Arena& arena)
        : catalog_(catalog), arena_(arena) {}

    PlanNode* build(const sql_parser::AstNode* stmt_ast) {
        if (!stmt_ast) return nullptr;
        switch (stmt_ast->type) {
            case sql_parser::NodeType::NODE_INSERT_STMT:
                return build_insert(stmt_ast);
            case sql_parser::NodeType::NODE_UPDATE_STMT:
                return build_update(stmt_ast);
            case sql_parser::NodeType::NODE_DELETE_STMT:
                return build_delete(stmt_ast);
            default:
                return nullptr;
        }
    }

    PlanNode* build_insert(const sql_parser::AstNode* insert_ast) {
        if (!insert_ast) return nullptr;

        PlanNode* node = make_plan_node(arena_, PlanNodeType::INSERT_PLAN);
        if (!node) return nullptr;

        // Find TABLE_REF child -> resolve table
        const sql_parser::AstNode* table_ref = find_child(insert_ast, sql_parser::NodeType::NODE_TABLE_REF);
        if (table_ref) {
            node->insert_plan.table = resolve_table(table_ref);
        }

        // Find INSERT_COLUMNS child -> column list
        const sql_parser::AstNode* cols = find_child(insert_ast, sql_parser::NodeType::NODE_INSERT_COLUMNS);
        if (cols) {
            uint16_t cnt = count_children(cols);
            node->insert_plan.column_count = cnt;
            auto** col_arr = static_cast<const sql_parser::AstNode**>(
                arena_.allocate(sizeof(sql_parser::AstNode*) * cnt));
            uint16_t idx = 0;
            for (const sql_parser::AstNode* c = cols->first_child; c; c = c->next_sibling) {
                col_arr[idx++] = c;
            }
            node->insert_plan.columns = col_arr;
        } else {
            node->insert_plan.columns = nullptr;
            node->insert_plan.column_count = 0;
        }

        // Find VALUES_CLAUSE child -> value rows
        const sql_parser::AstNode* values = find_child(insert_ast, sql_parser::NodeType::NODE_VALUES_CLAUSE);
        if (values) {
            uint16_t row_cnt = count_children(values);
            node->insert_plan.row_count = row_cnt;
            auto** row_arr = static_cast<const sql_parser::AstNode**>(
                arena_.allocate(sizeof(sql_parser::AstNode*) * row_cnt));
            uint16_t idx = 0;
            for (const sql_parser::AstNode* r = values->first_child; r; r = r->next_sibling) {
                row_arr[idx++] = r;
            }
            node->insert_plan.value_rows = row_arr;
        } else {
            node->insert_plan.value_rows = nullptr;
            node->insert_plan.row_count = 0;
        }

        // INSERT ... SELECT (check for SELECT_STMT child)
        const sql_parser::AstNode* select = find_child(insert_ast, sql_parser::NodeType::NODE_SELECT_STMT);
        if (select) {
            // Store the SELECT AST in a sentinel plan node so the distributed
            // planner can extract and distribute it later.
            PlanNode* select_node = make_plan_node(arena_, PlanNodeType::SCAN);
            // Repurpose the scan.table pointer to store the AST -- the distributed
            // planner will detect this via the select_source being non-null.
            // Store the AST pointer in remote_scan fields for retrieval.
            select_node = make_plan_node(arena_, PlanNodeType::DERIVED_SCAN);
            select_node->derived_scan.inner_plan = nullptr;
            select_node->derived_scan.alias = reinterpret_cast<const char*>(select);
            select_node->derived_scan.alias_len = 0xFFFF; // sentinel
            node->insert_plan.select_source = select_node;
        } else {
            node->insert_plan.select_source = nullptr;
        }

        return node;
    }

    PlanNode* build_update(const sql_parser::AstNode* update_ast) {
        if (!update_ast) return nullptr;

        PlanNode* node = make_plan_node(arena_, PlanNodeType::UPDATE_PLAN);
        if (!node) return nullptr;

        // Find TABLE_REF child -> resolve table
        const sql_parser::AstNode* table_ref = find_child(update_ast, sql_parser::NodeType::NODE_TABLE_REF);
        if (table_ref) {
            node->update_plan.table = resolve_table(table_ref);
        }

        // Detect multi-table UPDATE: presence of FROM_CLAUSE child means JOINs
        const sql_parser::AstNode* from_clause = find_child(update_ast, sql_parser::NodeType::NODE_FROM_CLAUSE);
        if (from_clause) {
            node->update_plan.original_ast = update_ast;
        }

        // Find UPDATE_SET_CLAUSE -> extract SET items
        const sql_parser::AstNode* set_clause = find_child(update_ast, sql_parser::NodeType::NODE_UPDATE_SET_CLAUSE);
        if (set_clause) {
            uint16_t cnt = count_children(set_clause);
            node->update_plan.set_count = cnt;

            auto** set_cols = static_cast<const sql_parser::AstNode**>(
                arena_.allocate(sizeof(sql_parser::AstNode*) * cnt));
            auto** set_exprs = static_cast<const sql_parser::AstNode**>(
                arena_.allocate(sizeof(sql_parser::AstNode*) * cnt));

            uint16_t idx = 0;
            for (const sql_parser::AstNode* item = set_clause->first_child; item; item = item->next_sibling) {
                // Each item is NODE_UPDATE_SET_ITEM with two children: column, expression
                const sql_parser::AstNode* col = item->first_child;
                const sql_parser::AstNode* expr = col ? col->next_sibling : nullptr;
                set_cols[idx] = col;
                set_exprs[idx] = expr;
                ++idx;
            }
            node->update_plan.set_columns = set_cols;
            node->update_plan.set_exprs = set_exprs;
        } else {
            node->update_plan.set_columns = nullptr;
            node->update_plan.set_exprs = nullptr;
            node->update_plan.set_count = 0;
        }

        // Find WHERE_CLAUSE -> where expression
        const sql_parser::AstNode* where = find_child(update_ast, sql_parser::NodeType::NODE_WHERE_CLAUSE);
        if (where && where->first_child) {
            node->update_plan.where_expr = where->first_child;
        } else {
            node->update_plan.where_expr = nullptr;
        }

        return node;
    }

    PlanNode* build_delete(const sql_parser::AstNode* delete_ast) {
        if (!delete_ast) return nullptr;

        PlanNode* node = make_plan_node(arena_, PlanNodeType::DELETE_PLAN);
        if (!node) return nullptr;

        // Find TABLE_REF child -> resolve table
        const sql_parser::AstNode* table_ref = find_child(delete_ast, sql_parser::NodeType::NODE_TABLE_REF);
        if (table_ref) {
            node->delete_plan.table = resolve_table(table_ref);
        }

        // Detect multi-table DELETE: FROM_CLAUSE (MySQL multi-table) or USING clause
        const sql_parser::AstNode* from_clause = find_child(delete_ast, sql_parser::NodeType::NODE_FROM_CLAUSE);
        const sql_parser::AstNode* using_clause = find_child(delete_ast, sql_parser::NodeType::NODE_DELETE_USING_CLAUSE);
        if (using_clause) {
            // USING always indicates multi-table
            node->delete_plan.original_ast = delete_ast;
        } else if (from_clause) {
            // FROM_CLAUSE with multiple children indicates multi-table
            uint16_t child_count = 0;
            for (const sql_parser::AstNode* c = from_clause->first_child; c; c = c->next_sibling) {
                ++child_count;
            }
            if (child_count > 1) {
                node->delete_plan.original_ast = delete_ast;
            }
        }

        // Find WHERE_CLAUSE
        const sql_parser::AstNode* where = find_child(delete_ast, sql_parser::NodeType::NODE_WHERE_CLAUSE);
        if (where && where->first_child) {
            node->delete_plan.where_expr = where->first_child;
        } else {
            node->delete_plan.where_expr = nullptr;
        }

        return node;
    }

private:
    const Catalog& catalog_;
    sql_parser::Arena& arena_;

    static const sql_parser::AstNode* find_child(const sql_parser::AstNode* node,
                                                   sql_parser::NodeType type) {
        for (const sql_parser::AstNode* c = node->first_child; c; c = c->next_sibling) {
            if (c->type == type) return c;
        }
        return nullptr;
    }

    static uint16_t count_children(const sql_parser::AstNode* node) {
        uint16_t n = 0;
        for (const sql_parser::AstNode* c = node->first_child; c; c = c->next_sibling) ++n;
        return n;
    }

    const TableInfo* resolve_table(const sql_parser::AstNode* table_ref) {
        if (!table_ref) return nullptr;
        const sql_parser::AstNode* name_node = table_ref->first_child;
        if (!name_node) return nullptr;

        if (name_node->type == sql_parser::NodeType::NODE_IDENTIFIER) {
            return catalog_.get_table(name_node->value());
        } else if (name_node->type == sql_parser::NodeType::NODE_QUALIFIED_NAME) {
            const sql_parser::AstNode* schema = name_node->first_child;
            const sql_parser::AstNode* table = schema ? schema->next_sibling : nullptr;
            if (schema && table) {
                return catalog_.get_table(schema->value(), table->value());
            }
        }
        return nullptr;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_DML_PLAN_BUILDER_H
