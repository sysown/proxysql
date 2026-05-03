// plan_builder.h — AST-to-logical-plan translation
//
// PlanBuilder<D> translates a parsed SELECT statement AST into a tree of
// PlanNode objects (arena-allocated). The translation follows standard
// SQL clause ordering:
//
//   FROM   → Scan nodes (one per table), joined via Join nodes
//   WHERE  → Filter node above the scan/join subtree
//   GROUP BY → Aggregate node with group-by expressions
//   HAVING → Filter node above Aggregate
//   SELECT → Project node with expression list and aliases
//   DISTINCT → Distinct node above Project
//   ORDER BY → Sort node with key expressions and directions
//   LIMIT  → Limit node with count and offset
//
// Also handles compound queries (UNION/INTERSECT/EXCEPT) via SetOp nodes.
// Currently supports SELECT statements only; returns nullptr for others.

#ifndef SQL_ENGINE_PLAN_BUILDER_H
#define SQL_ENGINE_PLAN_BUILDER_H

#include "sql_engine/plan_node.h"
#include "sql_engine/catalog.h"
#include "sql_parser/ast.h"
#include "sql_parser/common.h"
#include "sql_parser/arena.h"
#include <cstring>
#include <vector>

namespace sql_engine {

template <sql_parser::Dialect D>
class PlanBuilder {
public:
    PlanBuilder(const Catalog& catalog, sql_parser::Arena& arena)
        : catalog_(catalog), arena_(arena) {}

    // Build a logical plan from a parsed statement AST.
    // Returns nullptr for non-SELECT statements.
    PlanNode* build(const sql_parser::AstNode* stmt_ast) {
        if (!stmt_ast) return nullptr;

        if (stmt_ast->type == sql_parser::NodeType::NODE_SELECT_STMT) {
            return build_select(stmt_ast);
        }
        if (stmt_ast->type == sql_parser::NodeType::NODE_COMPOUND_QUERY) {
            return build_compound(stmt_ast);
        }
        if (stmt_ast->type == sql_parser::NodeType::NODE_CTE) {
            return build_cte(stmt_ast);
        }
        return nullptr;
    }

private:
    const Catalog& catalog_;
    sql_parser::Arena& arena_;

    // Helper: find first child of given type
    static const sql_parser::AstNode* find_child(const sql_parser::AstNode* node,
                                                   sql_parser::NodeType type) {
        for (const sql_parser::AstNode* c = node->first_child; c; c = c->next_sibling) {
            if (c->type == type) return c;
        }
        return nullptr;
    }

    // Helper: count children of a node
    static uint16_t count_children(const sql_parser::AstNode* node) {
        uint16_t n = 0;
        for (const sql_parser::AstNode* c = node->first_child; c; c = c->next_sibling) ++n;
        return n;
    }

    // Helper: check if SELECT has DISTINCT option
    static bool has_distinct(const sql_parser::AstNode* select_ast) {
        const sql_parser::AstNode* opts = find_child(select_ast, sql_parser::NodeType::NODE_SELECT_OPTIONS);
        if (!opts) return false;
        for (const sql_parser::AstNode* c = opts->first_child; c; c = c->next_sibling) {
            if (c->type == sql_parser::NodeType::NODE_IDENTIFIER) {
                sql_parser::StringRef val = c->value();
                if (val.equals_ci("DISTINCT", 8)) return true;
            }
        }
        return false;
    }

    // Determine join type from the NODE_JOIN_CLAUSE value text
    static uint8_t parse_join_type(const sql_parser::AstNode* join_clause) {
        sql_parser::StringRef val = join_clause->value();
        if (val.len == 0) return JOIN_INNER;

        // Check for keywords in the join type text
        // The value spans from the first modifier to JOIN, e.g. "LEFT JOIN", "CROSS JOIN"
        if (contains_ci(val, "CROSS", 5)) return JOIN_CROSS;
        if (contains_ci(val, "LEFT", 4))  return JOIN_LEFT;
        if (contains_ci(val, "RIGHT", 5)) return JOIN_RIGHT;
        if (contains_ci(val, "FULL", 4))  return JOIN_FULL;
        // INNER JOIN or just JOIN
        return JOIN_INNER;
    }

    // Check if an expression is a window function (NODE_WINDOW_FUNCTION)
    static bool is_window_function(const sql_parser::AstNode* expr) {
        if (!expr) return false;
        return expr->type == sql_parser::NodeType::NODE_WINDOW_FUNCTION;
    }

    // Check if SELECT list contains any window functions
    static bool has_window_functions(const sql_parser::AstNode* select_ast) {
        const sql_parser::AstNode* items = find_child(select_ast, sql_parser::NodeType::NODE_SELECT_ITEM_LIST);
        if (!items) return false;
        for (const sql_parser::AstNode* item = items->first_child; item; item = item->next_sibling) {
            if (item->first_child && is_window_function(item->first_child)) return true;
        }
        return false;
    }

    // Check if an expression (or any descendant) contains an aggregate function call.
    // Does NOT recurse into subqueries -- aggregates inside subqueries belong
    // to the subquery's own aggregation, not the outer query.
    // Does NOT recurse into window functions -- aggregates inside OVER() are
    // handled by the window operator, not the aggregate operator.
    static bool has_aggregate(const sql_parser::AstNode* expr) {
        if (!expr) return false;
        // Do not recurse into subqueries
        if (expr->type == sql_parser::NodeType::NODE_SUBQUERY) return false;
        // Do not recurse into window functions - aggregates inside OVER()
        // belong to the window operator
        if (expr->type == sql_parser::NodeType::NODE_WINDOW_FUNCTION) return false;
        if (expr->type == sql_parser::NodeType::NODE_FUNCTION_CALL) {
            sql_parser::StringRef name = expr->value();
            if (name.equals_ci("COUNT", 5) || name.equals_ci("SUM", 3) ||
                name.equals_ci("AVG", 3) || name.equals_ci("MIN", 3) ||
                name.equals_ci("MAX", 3)) {
                return true;
            }
        }
        for (const sql_parser::AstNode* c = expr->first_child; c; c = c->next_sibling) {
            if (has_aggregate(c)) return true;
        }
        return false;
    }

    static bool contains_ci(sql_parser::StringRef haystack, const char* needle, uint32_t nlen) {
        if (haystack.len < nlen) return false;
        for (uint32_t i = 0; i <= haystack.len - nlen; ++i) {
            bool match = true;
            for (uint32_t j = 0; j < nlen; ++j) {
                char a = haystack.ptr[i + j];
                char b = needle[j];
                if (a >= 'a' && a <= 'z') a -= 32;
                if (b >= 'a' && b <= 'z') b -= 32;
                if (a != b) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }

    // Build plan for a SELECT statement
    PlanNode* build_select(const sql_parser::AstNode* select_ast) {
        PlanNode* current = nullptr;

        // 1. FROM clause -> Scan / Join nodes
        const sql_parser::AstNode* from = find_child(select_ast, sql_parser::NodeType::NODE_FROM_CLAUSE);
        if (from) {
            current = build_from(from);
        }

        // 2. WHERE -> Filter
        const sql_parser::AstNode* where = find_child(select_ast, sql_parser::NodeType::NODE_WHERE_CLAUSE);
        if (where && where->first_child) {
            PlanNode* filter = make_plan_node(arena_, PlanNodeType::FILTER);
            if (!filter) return nullptr;
            filter->filter.expr = where->first_child;
            filter->left = current;
            current = filter;
        }

        // 3. GROUP BY -> Aggregate
        // Also create an implicit AGGREGATE when SELECT has aggregate functions
        // but no GROUP BY (e.g., SELECT MAX(age) FROM users).
        const sql_parser::AstNode* group_by = find_child(select_ast, sql_parser::NodeType::NODE_GROUP_BY_CLAUSE);
        bool needs_implicit_agg = false;
        if (!group_by) {
            // Check if SELECT list contains aggregate functions
            const sql_parser::AstNode* items = find_child(select_ast, sql_parser::NodeType::NODE_SELECT_ITEM_LIST);
            if (items) {
                for (const sql_parser::AstNode* item = items->first_child; item; item = item->next_sibling) {
                    if (item->first_child && has_aggregate(item->first_child)) {
                        needs_implicit_agg = true;
                        break;
                    }
                }
            }
        }
        if (group_by || needs_implicit_agg) {
            PlanNode* agg = make_plan_node(arena_, PlanNodeType::AGGREGATE);
            uint16_t gc = 0;
            agg->aggregate.group_by = nullptr;
            if (group_by) {
                gc = count_children(group_by);
                agg->aggregate.group_count = gc;
                if (gc > 0) {
                    auto** gb_arr = static_cast<const sql_parser::AstNode**>(
                        arena_.allocate(sizeof(sql_parser::AstNode*) * gc));
                    uint16_t idx = 0;
                    for (const sql_parser::AstNode* c = group_by->first_child; c; c = c->next_sibling) {
                        gb_arr[idx++] = c;
                    }
                    agg->aggregate.group_by = gb_arr;
                }
            } else {
                agg->aggregate.group_count = 0;
            }
            // Aggregate expressions are extracted from the SELECT list during execution/optimization.
            // For now, store them as null/0.
            agg->aggregate.agg_exprs = nullptr;
            agg->aggregate.agg_count = 0;
            agg->left = current;
            current = agg;
        }

        // 4. HAVING -> Filter (above Aggregate)
        const sql_parser::AstNode* having = find_child(select_ast, sql_parser::NodeType::NODE_HAVING_CLAUSE);
        if (having && having->first_child) {
            PlanNode* filter = make_plan_node(arena_, PlanNodeType::FILTER);
            filter->filter.expr = having->first_child;
            filter->left = current;
            current = filter;
        }

        // 4b. WINDOW -> Window node (if SELECT list has window functions)
        if (has_window_functions(select_ast)) {
            const sql_parser::AstNode* wnd_items = find_child(select_ast, sql_parser::NodeType::NODE_SELECT_ITEM_LIST);
            if (wnd_items) {
                // Collect window function expressions and full select list
                std::vector<const sql_parser::AstNode*> win_exprs;
                uint16_t total_count = count_children(wnd_items);

                auto** sel_exprs = static_cast<const sql_parser::AstNode**>(
                    arena_.allocate(sizeof(sql_parser::AstNode*) * total_count));
                auto** sel_aliases = static_cast<const sql_parser::AstNode**>(
                    arena_.allocate(sizeof(sql_parser::AstNode*) * total_count));
                uint16_t idx = 0;
                for (const sql_parser::AstNode* item = wnd_items->first_child; item; item = item->next_sibling) {
                    sel_exprs[idx] = item->first_child;
                    sel_aliases[idx] = find_child(item, sql_parser::NodeType::NODE_ALIAS);
                    if (item->first_child && is_window_function(item->first_child)) {
                        win_exprs.push_back(item->first_child);
                    }
                    ++idx;
                }

                PlanNode* wnd = make_plan_node(arena_, PlanNodeType::WINDOW);
                uint16_t wc = static_cast<uint16_t>(win_exprs.size());
                auto** warr = static_cast<const sql_parser::AstNode**>(
                    arena_.allocate(sizeof(sql_parser::AstNode*) * wc));
                for (uint16_t i = 0; i < wc; ++i) warr[i] = win_exprs[i];
                wnd->window.window_exprs = warr;
                wnd->window.window_count = wc;
                wnd->window.select_exprs = sel_exprs;
                wnd->window.select_aliases = sel_aliases;
                wnd->window.select_count = total_count;
                wnd->left = current;
                current = wnd;
            }
        }

        // 5. ORDER BY -> Sort (before Project so sort keys resolve against full row)
        const sql_parser::AstNode* order_by = find_child(select_ast, sql_parser::NodeType::NODE_ORDER_BY_CLAUSE);
        if (order_by) {
            PlanNode* sort = make_plan_node(arena_, PlanNodeType::SORT);
            uint16_t cnt = count_children(order_by);
            sort->sort.count = cnt;

            auto** keys = static_cast<const sql_parser::AstNode**>(
                arena_.allocate(sizeof(sql_parser::AstNode*) * cnt));
            auto* dirs = static_cast<uint8_t*>(arena_.allocate(cnt));

            uint16_t idx = 0;
            for (const sql_parser::AstNode* item = order_by->first_child; item; item = item->next_sibling) {
                // First child is the key expression
                keys[idx] = item->first_child;
                // Check for DESC direction (second child with "DESC" value)
                dirs[idx] = 0; // ASC by default
                const sql_parser::AstNode* dir_node = find_child(item, sql_parser::NodeType::NODE_IDENTIFIER);
                if (dir_node) {
                    sql_parser::StringRef dir_val = dir_node->value();
                    if (dir_val.equals_ci("DESC", 4)) dirs[idx] = 1;
                }
                ++idx;
            }
            sort->sort.keys = keys;
            sort->sort.directions = dirs;
            sort->left = current;
            current = sort;
        }

        // 6. SELECT list -> Project (skip if WINDOW node handles it)
        bool has_window = has_window_functions(select_ast);
        const sql_parser::AstNode* item_list = find_child(select_ast, sql_parser::NodeType::NODE_SELECT_ITEM_LIST);
        if (item_list && !has_window) {
            // Check if this is "SELECT *" with a single asterisk and no aliases -- skip Project for bare scan
            bool is_star_only = false;
            const sql_parser::AstNode* first_item = item_list->first_child;
            if (first_item && !first_item->next_sibling) {
                // Single item
                const sql_parser::AstNode* expr = first_item->first_child;
                if (expr && expr->type == sql_parser::NodeType::NODE_ASTERISK &&
                    !find_child(first_item, sql_parser::NodeType::NODE_ALIAS)) {
                    is_star_only = true;
                }
            }

            if (!is_star_only) {
                PlanNode* proj = make_plan_node(arena_, PlanNodeType::PROJECT);
                uint16_t cnt = count_children(item_list);
                proj->project.count = cnt;

                auto** exprs = static_cast<const sql_parser::AstNode**>(
                    arena_.allocate(sizeof(sql_parser::AstNode*) * cnt));
                auto** aliases = static_cast<const sql_parser::AstNode**>(
                    arena_.allocate(sizeof(sql_parser::AstNode*) * cnt));

                uint16_t idx = 0;
                for (const sql_parser::AstNode* item = item_list->first_child; item; item = item->next_sibling) {
                    // First child of SELECT_ITEM is the expression
                    exprs[idx] = item->first_child;
                    // Second child (if present) is the alias
                    aliases[idx] = find_child(item, sql_parser::NodeType::NODE_ALIAS);
                    ++idx;
                }
                proj->project.exprs = exprs;
                proj->project.aliases = aliases;
                proj->left = current;
                current = proj;
            }
        }

        // 7. DISTINCT -> Distinct
        if (has_distinct(select_ast)) {
            PlanNode* dist = make_plan_node(arena_, PlanNodeType::DISTINCT);
            dist->left = current;
            current = dist;
        }

        // 8. LIMIT -> Limit
        const sql_parser::AstNode* limit_clause = find_child(select_ast, sql_parser::NodeType::NODE_LIMIT_CLAUSE);
        if (limit_clause) {
            current = build_limit_node(limit_clause, current);
        }

        return current;
    }

    // Build a Limit plan node from LIMIT clause AST
    PlanNode* build_limit_node(const sql_parser::AstNode* limit_clause, PlanNode* child) {
        PlanNode* limit = make_plan_node(arena_, PlanNodeType::LIMIT);
        limit->limit.count = -1;
        limit->limit.offset = 0;

        const sql_parser::AstNode* first = limit_clause->first_child;
        if (first) {
            // Parse the literal count value
            limit->limit.count = parse_int_literal(first);

            const sql_parser::AstNode* second = first->next_sibling;
            if (second) {
                // LIMIT count OFFSET offset_val  or  LIMIT offset, count (MySQL)
                // In the AST, second child is always the offset value
                limit->limit.offset = parse_int_literal(second);
            }
        }
        limit->left = child;
        return limit;
    }

    // Parse an integer literal from an AST node
    static int64_t parse_int_literal(const sql_parser::AstNode* node) {
        if (!node) return 0;
        sql_parser::StringRef val = node->value();
        if (val.len == 0) return 0;
        int64_t result = 0;
        for (uint32_t i = 0; i < val.len; ++i) {
            char c = val.ptr[i];
            if (c >= '0' && c <= '9') {
                result = result * 10 + (c - '0');
            }
        }
        return result;
    }

    // Build plan for CTE (WITH clause)
    // The CTE node has CTE_DEFINITION children, with the last child being the main SELECT.
    // We build the plan for the main SELECT, and store CTE definitions separately
    // for the executor to materialize.
    PlanNode* build_cte(const sql_parser::AstNode* cte_ast) {
        // The last child is the main query (SELECT_STMT or COMPOUND_QUERY)
        const sql_parser::AstNode* main_query = nullptr;
        for (const sql_parser::AstNode* c = cte_ast->first_child; c; c = c->next_sibling) {
            if (c->type == sql_parser::NodeType::NODE_SELECT_STMT ||
                c->type == sql_parser::NodeType::NODE_COMPOUND_QUERY) {
                main_query = c;
            }
        }
        if (!main_query) return nullptr;
        return build(main_query);
    }

    // Build plan from FROM clause
    PlanNode* build_from(const sql_parser::AstNode* from_clause) {
        PlanNode* current = nullptr;

        for (const sql_parser::AstNode* child = from_clause->first_child; child; child = child->next_sibling) {
            if (child->type == sql_parser::NodeType::NODE_TABLE_REF) {
                PlanNode* scan = build_scan(child);
                if (!current) {
                    current = scan;
                } else {
                    // Comma join -> CROSS JOIN
                    PlanNode* join = make_plan_node(arena_, PlanNodeType::JOIN);
                    join->join.join_type = JOIN_CROSS;
                    join->join.condition = nullptr;
                    join->left = current;
                    join->right = scan;
                    current = join;
                }
            } else if (child->type == sql_parser::NodeType::NODE_JOIN_CLAUSE) {
                current = build_join(child, current);
            }
        }

        return current;
    }

    // Build a Scan node from TABLE_REF
    PlanNode* build_scan(const sql_parser::AstNode* table_ref) {
        const sql_parser::AstNode* name_node = table_ref->first_child;
        if (name_node) {
            // Check for subquery (derived table)
            if (name_node->type == sql_parser::NodeType::NODE_SUBQUERY) {
                return build_derived_scan(table_ref);
            }
            PlanNode* scan = make_plan_node(arena_, PlanNodeType::SCAN);
            if (!scan) return nullptr;
            scan->scan.table = nullptr;
            if (name_node->type == sql_parser::NodeType::NODE_IDENTIFIER) {
                scan->scan.table = catalog_.get_table(name_node->value());
            } else if (name_node->type == sql_parser::NodeType::NODE_QUALIFIED_NAME) {
                const sql_parser::AstNode* schema = name_node->first_child;
                const sql_parser::AstNode* table = schema ? schema->next_sibling : nullptr;
                if (schema && table) {
                    scan->scan.table = catalog_.get_table(schema->value(), table->value());
                }
            }

            // Extract table alias (e.g., FROM users u -> alias "u")
            if (scan->scan.table) {
                for (const sql_parser::AstNode* c = table_ref->first_child; c; c = c->next_sibling) {
                    if (c->type == sql_parser::NodeType::NODE_ALIAS) {
                        // Store alias on the TableInfo (mutable cast -- safe since we own it
                        // via the catalog which allocated it in its arena)
                        const_cast<TableInfo*>(scan->scan.table)->alias = c->value();
                        break;
                    }
                }
            }

            return scan;
        }

        PlanNode* scan = make_plan_node(arena_, PlanNodeType::SCAN);
        scan->scan.table = nullptr;
        return scan;
    }

    // Build a DERIVED_SCAN node from a subquery table reference
    PlanNode* build_derived_scan(const sql_parser::AstNode* table_ref) {
        const sql_parser::AstNode* subquery_node = table_ref->first_child;
        if (!subquery_node || subquery_node->type != sql_parser::NodeType::NODE_SUBQUERY)
            return nullptr;

        // The subquery's parsed SELECT AST is the first child of NODE_SUBQUERY
        const sql_parser::AstNode* inner_ast = subquery_node->first_child;
        if (!inner_ast) return nullptr;

        // Build the inner plan recursively
        PlanNode* inner_plan = build_select(inner_ast);
        if (!inner_plan) return nullptr;

        PlanNode* node = make_plan_node(arena_, PlanNodeType::DERIVED_SCAN);
        node->derived_scan.inner_plan = inner_plan;
        node->derived_scan.alias = nullptr;
        node->derived_scan.alias_len = 0;
        node->derived_scan.column_count = 0;
        node->derived_scan.synth_table = nullptr;

        // Check for alias
        sql_parser::StringRef alias_ref{};
        for (const sql_parser::AstNode* c = table_ref->first_child; c; c = c->next_sibling) {
            if (c->type == sql_parser::NodeType::NODE_ALIAS) {
                alias_ref = c->value();
                node->derived_scan.alias = alias_ref.ptr;
                node->derived_scan.alias_len = static_cast<uint16_t>(alias_ref.len);
                break;
            }
        }

        // Build synthetic TableInfo from the inner SELECT's column names
        node->derived_scan.synth_table = build_synth_table(inner_ast, alias_ref);

        return node;
    }

    // Create a synthetic TableInfo from a SELECT statement's output columns
    const TableInfo* build_synth_table(const sql_parser::AstNode* select_ast,
                                        sql_parser::StringRef alias) {
        const sql_parser::AstNode* item_list = find_child(select_ast,
            sql_parser::NodeType::NODE_SELECT_ITEM_LIST);
        if (!item_list) return nullptr;

        uint16_t col_count = count_children(item_list);
        if (col_count == 0) return nullptr;

        // Allocate column info array in arena
        auto* cols = static_cast<ColumnInfo*>(
            arena_.allocate(sizeof(ColumnInfo) * col_count));
        if (!cols) return nullptr;

        uint16_t idx = 0;
        for (const sql_parser::AstNode* item = item_list->first_child; item;
             item = item->next_sibling, ++idx) {
            cols[idx].ordinal = idx;
            cols[idx].nullable = true;
            cols[idx].type = SqlType::make_varchar(255); // generic type

            // Try to get column name from alias or expression
            const sql_parser::AstNode* alias_node = nullptr;
            const sql_parser::AstNode* expr_node = item->first_child;
            for (const sql_parser::AstNode* c = item->first_child; c; c = c->next_sibling) {
                if (c->type == sql_parser::NodeType::NODE_ALIAS) {
                    alias_node = c;
                }
            }

            if (alias_node) {
                cols[idx].name = alias_node->value();
            } else if (expr_node) {
                // Use expression value (column name) as column name
                if (expr_node->type == sql_parser::NodeType::NODE_COLUMN_REF ||
                    expr_node->type == sql_parser::NodeType::NODE_IDENTIFIER) {
                    cols[idx].name = expr_node->value();
                } else if (expr_node->type == sql_parser::NodeType::NODE_FUNCTION_CALL) {
                    cols[idx].name = expr_node->value(); // function name
                } else if (expr_node->type == sql_parser::NodeType::NODE_ASTERISK) {
                    cols[idx].name = sql_parser::StringRef{"*", 1};
                } else {
                    cols[idx].name = sql_parser::StringRef{"?column?", 8};
                }
            } else {
                cols[idx].name = sql_parser::StringRef{"?column?", 8};
            }
        }

        // Allocate TableInfo in arena
        auto* table = static_cast<TableInfo*>(arena_.allocate(sizeof(TableInfo)));
        if (!table) return nullptr;
        table->schema_name = {};
        table->table_name = alias;
        table->columns = cols;
        table->column_count = col_count;
        return table;
    }

    // Build a Join node from JOIN_CLAUSE
    PlanNode* build_join(const sql_parser::AstNode* join_clause, PlanNode* left) {
        PlanNode* join = make_plan_node(arena_, PlanNodeType::JOIN);
        join->join.join_type = parse_join_type(join_clause);
        join->join.condition = nullptr;
        join->left = left;

        // First child of JOIN_CLAUSE is the right table ref
        const sql_parser::AstNode* right_ref = join_clause->first_child;
        if (right_ref && right_ref->type == sql_parser::NodeType::NODE_TABLE_REF) {
            join->right = build_scan(right_ref);
        }

        // Second child is ON condition (expression) or USING list
        if (right_ref) {
            const sql_parser::AstNode* cond = right_ref->next_sibling;
            if (cond && cond->type != sql_parser::NodeType::NODE_TABLE_REF) {
                join->join.condition = cond;
            }
        }

        return join;
    }

    // Build plan for compound query (UNION/INTERSECT/EXCEPT)
    PlanNode* build_compound(const sql_parser::AstNode* compound_ast) {
        PlanNode* current = nullptr;

        // First child is NODE_SET_OPERATION
        const sql_parser::AstNode* set_op_node = find_child(compound_ast, sql_parser::NodeType::NODE_SET_OPERATION);
        if (set_op_node) {
            current = build_set_op(set_op_node);
        }

        // Trailing ORDER BY
        const sql_parser::AstNode* order_by = find_child(compound_ast, sql_parser::NodeType::NODE_ORDER_BY_CLAUSE);
        if (order_by) {
            PlanNode* sort = make_plan_node(arena_, PlanNodeType::SORT);
            uint16_t cnt = count_children(order_by);
            sort->sort.count = cnt;

            auto** keys = static_cast<const sql_parser::AstNode**>(
                arena_.allocate(sizeof(sql_parser::AstNode*) * cnt));
            auto* dirs = static_cast<uint8_t*>(arena_.allocate(cnt));

            uint16_t idx = 0;
            for (const sql_parser::AstNode* item = order_by->first_child; item; item = item->next_sibling) {
                keys[idx] = item->first_child;
                dirs[idx] = 0;
                const sql_parser::AstNode* dir_node = find_child(item, sql_parser::NodeType::NODE_IDENTIFIER);
                if (dir_node) {
                    sql_parser::StringRef dir_val = dir_node->value();
                    if (dir_val.equals_ci("DESC", 4)) dirs[idx] = 1;
                }
                ++idx;
            }
            sort->sort.keys = keys;
            sort->sort.directions = dirs;
            sort->left = current;
            current = sort;
        }

        // Trailing LIMIT
        const sql_parser::AstNode* limit_clause = find_child(compound_ast, sql_parser::NodeType::NODE_LIMIT_CLAUSE);
        if (limit_clause) {
            current = build_limit_node(limit_clause, current);
        }

        return current;
    }

    // Build a SetOp node from NODE_SET_OPERATION
    PlanNode* build_set_op(const sql_parser::AstNode* set_op_ast) {
        PlanNode* node = make_plan_node(arena_, PlanNodeType::SET_OP);

        // Determine the operation type from the value text
        sql_parser::StringRef val = set_op_ast->value();
        if (val.equals_ci("INTERSECT", 9)) {
            node->set_op.op = SET_OP_INTERSECT;
        } else if (val.equals_ci("EXCEPT", 6)) {
            node->set_op.op = SET_OP_EXCEPT;
        } else {
            node->set_op.op = SET_OP_UNION;
        }
        node->set_op.all = (set_op_ast->flags & sql_parser::FLAG_SET_OP_ALL) != 0;

        // Children: left and right operands (each is SELECT_STMT or SET_OPERATION)
        const sql_parser::AstNode* left_ast = set_op_ast->first_child;
        const sql_parser::AstNode* right_ast = left_ast ? left_ast->next_sibling : nullptr;

        if (left_ast) {
            if (left_ast->type == sql_parser::NodeType::NODE_SET_OPERATION) {
                node->left = build_set_op(left_ast);
            } else {
                node->left = build(left_ast);
            }
        }
        if (right_ast) {
            if (right_ast->type == sql_parser::NodeType::NODE_SET_OPERATION) {
                node->right = build_set_op(right_ast);
            } else {
                node->right = build(right_ast);
            }
        }

        return node;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_PLAN_BUILDER_H
