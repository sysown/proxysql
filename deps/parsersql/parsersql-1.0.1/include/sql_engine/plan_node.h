#ifndef SQL_ENGINE_PLAN_NODE_H
#define SQL_ENGINE_PLAN_NODE_H

#include "sql_engine/catalog.h"
#include "sql_parser/ast.h"
#include "sql_parser/arena.h"
#include <cstdint>

namespace sql_engine {

enum class PlanNodeType : uint8_t {
    SCAN,       // read from data source
    FILTER,     // WHERE / HAVING condition
    PROJECT,    // SELECT expression list
    JOIN,       // JOIN two sources
    AGGREGATE,  // GROUP BY + aggregate functions
    SORT,       // ORDER BY
    LIMIT,      // LIMIT + OFFSET
    DISTINCT,   // remove duplicates
    SET_OP,     // UNION / INTERSECT / EXCEPT
    DERIVED_SCAN,     // subquery in FROM clause (derived table)
    REMOTE_SCAN,      // fetch from remote backend via SQL
    MERGE_AGGREGATE,  // merge partial aggregates from N sources
    MERGE_SORT,       // merge N pre-sorted streams
    WINDOW,           // window function computation

    // DML plan nodes
    INSERT_PLAN,
    UPDATE_PLAN,
    DELETE_PLAN,
};

// Join type constants
static constexpr uint8_t JOIN_INNER = 0;
static constexpr uint8_t JOIN_LEFT  = 1;
static constexpr uint8_t JOIN_RIGHT = 2;
static constexpr uint8_t JOIN_FULL  = 3;
static constexpr uint8_t JOIN_CROSS = 4;

// Set operation type constants
static constexpr uint8_t SET_OP_UNION     = 0;
static constexpr uint8_t SET_OP_INTERSECT = 1;
static constexpr uint8_t SET_OP_EXCEPT    = 2;

struct PlanNode {
    PlanNodeType type;
    PlanNode* left = nullptr;    // primary child (or left of join/union)
    PlanNode* right = nullptr;   // right of join/union (null for unary ops)

    union {
        struct {
            const TableInfo* table;
        } scan;

        struct {
            const sql_parser::AstNode* expr;        // WHERE/HAVING expression AST
        } filter;

        struct {
            const sql_parser::AstNode** exprs;      // SELECT expression list (AST nodes)
            const sql_parser::AstNode** aliases;     // alias AST nodes (parallel array, nullable entries)
            uint16_t count;
        } project;

        struct {
            uint8_t join_type;          // INNER=0, LEFT=1, RIGHT=2, FULL=3, CROSS=4
            const sql_parser::AstNode* condition;   // ON expression AST (null for CROSS/NATURAL)
        } join;

        struct {
            const sql_parser::AstNode** group_by;   // GROUP BY expression list
            uint16_t group_count;
            const sql_parser::AstNode** agg_exprs;  // aggregate expressions (COUNT, SUM, etc.)
            uint16_t agg_count;
        } aggregate;

        struct {
            const sql_parser::AstNode** keys;       // ORDER BY key expressions
            uint8_t* directions;        // 0=ASC, 1=DESC (parallel array)
            uint16_t count;
        } sort;

        struct {
            int64_t count;
            int64_t offset;
        } limit;

        struct {
            uint8_t op;                 // 0=UNION, 1=INTERSECT, 2=EXCEPT
            bool all;                   // UNION ALL vs UNION
        } set_op;

        struct {
            PlanNode* inner_plan;       // the subquery's execution plan
            const char* alias;          // derived table alias (nullable)
            uint16_t alias_len;
            uint16_t column_count;      // number of columns from inner plan
            const TableInfo* synth_table; // synthetic table info for column resolution
        } derived_scan;

        struct {
            const char* backend_name;
            const char* remote_sql;
            uint16_t remote_sql_len;
            const TableInfo* table;       // expected result schema (for SELECT *)
            // Optional projection expressions used to derive result column
            // names when the remote SQL is not a passthrough SELECT *. When
            // non-null, build_column_names() prefers these over the table's
            // catalog columns. Required for aggregate / projected pushdown
            // to a single-shard backend; otherwise the catalog's table
            // columns mis-label the result.
            const sql_parser::AstNode** output_exprs;
            uint16_t output_expr_count;
        } remote_scan;

        // Merge operations for distributed aggregation
        // merge_op values: 0=SUM_OF_COUNTS, 1=SUM_OF_SUMS, 2=MIN_OF_MINS,
        //                  3=MAX_OF_MAXES, 4=AVG_FROM_SUM_COUNT
        struct {
            PlanNode** children;
            uint16_t child_count;
            uint8_t* merge_ops;       // parallel to agg columns
            uint16_t merge_op_count;
            uint16_t group_key_count; // number of leading group-by columns
            // Original output column expressions (for column naming)
            const sql_parser::AstNode** output_exprs;
            uint16_t output_expr_count;
        } merge_aggregate;

        struct {
            const sql_parser::AstNode** keys;
            uint8_t* directions;        // 0=ASC, 1=DESC
            uint16_t key_count;
            PlanNode** children;
            uint16_t child_count;
        } merge_sort;

        struct {
            const sql_parser::AstNode** window_exprs;    // window function expressions (NODE_WINDOW_FUNCTION)
            uint16_t window_count;
            // original SELECT expression list for pass-through
            const sql_parser::AstNode** select_exprs;
            const sql_parser::AstNode** select_aliases;
            uint16_t select_count;
        } window;

        // DML plan nodes
        struct {
            const TableInfo* table;
            const sql_parser::AstNode** columns;       // column names (nullable = all columns in order)
            uint16_t column_count;
            const sql_parser::AstNode** value_rows;    // array of NODE_VALUES_ROW pointers
            uint16_t row_count;
            PlanNode* select_source;       // INSERT ... SELECT (nullable)
        } insert_plan;

        struct {
            const TableInfo* table;
            const sql_parser::AstNode** set_columns;   // column name AST nodes
            const sql_parser::AstNode** set_exprs;     // new value expression AST nodes (parallel array)
            uint16_t set_count;
            const sql_parser::AstNode* where_expr;     // WHERE condition (nullable = update all)
            const sql_parser::AstNode* original_ast;   // non-null for multi-table UPDATE
        } update_plan;

        struct {
            const TableInfo* table;
            const sql_parser::AstNode* where_expr;     // WHERE condition (nullable = delete all)
            const sql_parser::AstNode* original_ast;   // non-null for multi-table DELETE
        } delete_plan;
    };
};

inline PlanNode* make_plan_node(sql_parser::Arena& arena, PlanNodeType type) {
    PlanNode* node = static_cast<PlanNode*>(arena.allocate(sizeof(PlanNode)));
    if (!node) return nullptr;
    // Zero-initialize then set type
    std::memset(node, 0, sizeof(PlanNode));
    node->type = type;
    return node;
}

} // namespace sql_engine

#endif // SQL_ENGINE_PLAN_NODE_H
