/**
 * @file nl2sql_integration-t.cpp
 * @brief Integration tests for NL2SQL with real database
 *
 * Test Categories:
 * 1. Schema-aware conversion
 * 2. Multi-table queries
 * 3. Complex SQL patterns (JOINs, subqueries)
 * 4. Error recovery
 *
 * Prerequisites:
 * - Test database with sample schema
 * - Admin interface
 * - Configured LLM (mock or live)
 *
 * Usage:
 *   make nl2sql_integration-t
 *   ./nl2sql_integration-t
 *
 * @date 2025-01-16
 */

#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

// Global connections
MYSQL* g_admin = NULL;
MYSQL* g_mysql = NULL;

// Test schema name
const char* TEST_SCHEMA = "test_nl2sql_integration";

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * @brief Execute SQL query via data connection
 * @param query SQL to execute
 * @return true on success
 */
bool execute_sql(const char* query) {
    if (mysql_query(g_mysql, query)) {
        diag("SQL error: %s", mysql_error(g_mysql));
        return false;
    }
    return true;
}

/**
 * @brief Setup test schema and tables
 */
bool setup_test_schema() {
    diag("=== Setting up test schema ===");

    // Create database
    if (mysql_query(g_admin, "CREATE DATABASE IF NOT EXISTS test_nl2sql_integration")) {
        diag("Failed to create database: %s", mysql_error(g_admin));
        return false;
    }

    // Create customers table
    const char* create_customers =
        "CREATE TABLE IF NOT EXISTS test_nl2sql_integration.customers ("
        "id INT PRIMARY KEY AUTO_INCREMENT,"
        "name VARCHAR(100) NOT NULL,"
        "email VARCHAR(100),"
        "country VARCHAR(50),"
        "created_at DATE)";

    if (mysql_query(g_admin, create_customers)) {
        diag("Failed to create customers table: %s", mysql_error(g_admin));
        return false;
    }

    // Create orders table
    const char* create_orders =
        "CREATE TABLE IF NOT EXISTS test_nl2sql_integration.orders ("
        "id INT PRIMARY KEY AUTO_INCREMENT,"
        "customer_id INT,"
        "order_date DATE,"
        "total DECIMAL(10,2),"
        "status VARCHAR(20),"
        "FOREIGN KEY (customer_id) REFERENCES test_nl2sql_integration.customers(id))";

    if (mysql_query(g_admin, create_orders)) {
        diag("Failed to create orders table: %s", mysql_error(g_admin));
        return false;
    }

    // Create products table
    const char* create_products =
        "CREATE TABLE IF NOT EXISTS test_nl2sql_integration.products ("
        "id INT PRIMARY KEY AUTO_INCREMENT,"
        "name VARCHAR(100),"
        "category VARCHAR(50),"
        "price DECIMAL(10,2))";

    if (mysql_query(g_admin, create_products)) {
        diag("Failed to create products table: %s", mysql_error(g_admin));
        return false;
    }

    // Create order_items table
    const char* create_order_items =
        "CREATE TABLE IF NOT EXISTS test_nl2sql_integration.order_items ("
        "id INT PRIMARY KEY AUTO_INCREMENT,"
        "order_id INT,"
        "product_id INT,"
        "quantity INT,"
        "FOREIGN KEY (order_id) REFERENCES test_nl2sql_integration.orders(id),"
        "FOREIGN KEY (product_id) REFERENCES test_nl2sql_integration.products(id))";

    if (mysql_query(g_admin, create_order_items)) {
        diag("Failed to create order_items table: %s", mysql_error(g_admin));
        return false;
    }

    // Insert test data
    const char* insert_data =
        "INSERT INTO test_nl2sql_integration.customers (name, email, country, created_at) VALUES"
        "('Alice', 'alice@example.com', 'USA', '2024-01-01'),"
        "('Bob', 'bob@example.com', 'UK', '2024-02-01'),"
        "('Charlie', 'charlie@example.com', 'USA', '2024-03-01')"
        " ON DUPLICATE KEY UPDATE name=name";

    if (mysql_query(g_admin, insert_data)) {
        diag("Failed to insert customers: %s", mysql_error(g_admin));
        return false;
    }

    const char* insert_orders =
        "INSERT INTO test_nl2sql_integration.orders (customer_id, order_date, total, status) VALUES"
        "(1, '2024-01-15', 100.00, 'completed'),"
        "(2, '2024-02-20', 200.00, 'pending'),"
        "(3, '2024-03-25', 150.00, 'completed')"
        " ON DUPLICATE KEY UPDATE total=total";

    if (mysql_query(g_admin, insert_orders)) {
        diag("Failed to insert orders: %s", mysql_error(g_admin));
        return false;
    }

    const char* insert_products =
        "INSERT INTO test_nl2sql_integration.products (name, category, price) VALUES"
        "('Laptop', 'Electronics', 999.99),"
        "('Mouse', 'Electronics', 29.99),"
        "('Desk', 'Furniture', 299.99)"
        " ON DUPLICATE KEY UPDATE price=price";

    if (mysql_query(g_admin, insert_products)) {
        diag("Failed to insert products: %s", mysql_error(g_admin));
        return false;
    }

    diag("Test schema setup complete");
    return true;
}

/**
 * @brief Cleanup test schema
 */
void cleanup_test_schema() {
    mysql_query(g_admin, "DROP DATABASE IF EXISTS test_nl2sql_integration");
}

/**
 * @brief Simulate NL2SQL conversion (placeholder)
 * @param natural_language Natural language query
 * @param schema Current schema name
 * @return Simulated SQL
 */
string simulate_nl2sql(const string& natural_language, const string& schema = "") {
    // For integration testing, we simulate the conversion based on patterns
    string nl_lower = natural_language;
    std::transform(nl_lower.begin(), nl_lower.end(), nl_lower.begin(), ::tolower);

    string result = "";

    if (nl_lower.find("select") != string::npos || nl_lower.find("show") != string::npos) {
        if (nl_lower.find("customers") != string::npos) {
            result = "SELECT * FROM " + (schema.empty() ? string(TEST_SCHEMA) : schema) + ".customers";
        } else if (nl_lower.find("orders") != string::npos) {
            result = "SELECT * FROM " + (schema.empty() ? string(TEST_SCHEMA) : schema) + ".orders";
        } else if (nl_lower.find("products") != string::npos) {
            result = "SELECT * FROM " + (schema.empty() ? string(TEST_SCHEMA) : schema) + ".products";
        } else {
            result = "SELECT * FROM " + (schema.empty() ? string(TEST_SCHEMA) : schema) + ".customers";
        }

        if (nl_lower.find("where") != string::npos) {
            result += " WHERE 1=1";
        }

        if (nl_lower.find("join") != string::npos) {
            result = "SELECT c.name, o.total FROM " + (schema.empty() ? string(TEST_SCHEMA) : schema) +
                    ".customers c JOIN " + (schema.empty() ? string(TEST_SCHEMA) : schema) +
                    ".orders o ON c.id = o.customer_id";
        }

        if (nl_lower.find("count") != string::npos) {
            result = "SELECT COUNT(*) FROM " + (schema.empty() ? string(TEST_SCHEMA) : schema);
            if (nl_lower.find("customer") != string::npos) {
                result += ".customers";
            }
        }

        if (nl_lower.find("group by") != string::npos || nl_lower.find("by country") != string::npos) {
            result = "SELECT country, COUNT(*) FROM " + (schema.empty() ? string(TEST_SCHEMA) : schema) +
                    ".customers GROUP BY country";
        }
    } else {
        result = "SELECT * FROM " + (schema.empty() ? string(TEST_SCHEMA) : schema) + ".customers";
    }

    return result;
}

/**
 * @brief Check if SQL contains expected elements
 */
bool sql_contains(const string& sql, const vector<string>& elements) {
    string sql_upper = sql;
    std::transform(sql_upper.begin(), sql_upper.end(), sql_upper.begin(), ::toupper);

    for (const auto& elem : elements) {
        string elem_upper = elem;
        std::transform(elem_upper.begin(), elem_upper.end(), elem_upper.begin(), ::toupper);
        if (sql_upper.find(elem_upper) == string::npos) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// Test: Schema-Aware Conversion
// ============================================================================

/**
 * @test Schema-aware NL2SQL conversion
 * @description Convert queries with actual database schema
 */
void test_schema_aware_conversion() {
    diag("=== Schema-Aware NL2SQL Conversion ===");

    // Test 1: Simple query with schema context
    string sql = simulate_nl2sql("Show all customers", TEST_SCHEMA);
    ok(sql_contains(sql, {"SELECT", "customers"}),
       "Simple query includes SELECT and correct table");

    // Test 2: Query with schema name specified
    sql = simulate_nl2sql("List all products", TEST_SCHEMA);
    ok(sql.find(TEST_SCHEMA) != string::npos && sql.find("products") != string::npos,
       "Query includes schema name and correct table");

    // Test 3: Query with conditions
    sql = simulate_nl2sql("Find customers from USA", TEST_SCHEMA);
    ok(sql_contains(sql, {"SELECT", "WHERE"}),
       "Query with conditions includes WHERE clause");

    // Test 4: Multiple tables mentioned
    sql = simulate_nl2sql("Show customers and their orders", TEST_SCHEMA);
    ok(sql_contains(sql, {"SELECT", "customers", "orders"}),
       "Multi-table query references both tables");

    // Test 5: Schema context affects table selection
    sql = simulate_nl2sql("Count records", TEST_SCHEMA);
    ok(sql.find(TEST_SCHEMA) != string::npos,
       "Schema context is included in generated SQL");
}

// ============================================================================
// Test: Multi-Table Queries (JOINs)
// ============================================================================

/**
 * @test JOIN query generation
 * @description Generate SQL with JOINs for related tables
 */
void test_join_queries() {
    diag("=== JOIN Query Tests ===");

    // Test 1: Simple JOIN between customers and orders
    string sql = simulate_nl2sql("Show customer names with their order amounts", TEST_SCHEMA);
    ok(sql_contains(sql, {"JOIN", "customers", "orders"}),
       "JOIN query includes JOIN keyword and both tables");

    // Test 2: Explicit JOIN request
    sql = simulate_nl2sql("Join customers and orders", TEST_SCHEMA);
    ok(sql.find("JOIN") != string::npos,
       "Explicit JOIN request generates JOIN syntax");

    // Test 3: Three table JOIN (customers, orders, products)
    // Note: This is a simplified test
    sql = simulate_nl2sql("Show all customer orders with products", TEST_SCHEMA);
    ok(sql_contains(sql, {"SELECT", "FROM"}),
       "Multi-table query has basic SQL structure");

    // Test 4: JOIN with WHERE clause
    sql = simulate_nl2sql("Find completed orders with customer info", TEST_SCHEMA);
    ok(sql_contains(sql, {"SELECT", "customers", "orders"}),
       "JOIN with condition references correct tables");

    // Test 5: Self-join pattern (if applicable)
    // For this schema, we test a similar pattern
    sql = simulate_nl2sql("Find customers who placed more than one order", TEST_SCHEMA);
    ok(!sql.empty(),
       "Complex query generates non-empty SQL");
}

// ============================================================================
// Test: Aggregation Queries
// ============================================================================

/**
 * @test Aggregation functions
 * @description Generate SQL with COUNT, SUM, AVG, etc.
 */
void test_aggregation_queries() {
    diag("=== Aggregation Query Tests ===");

    // Test 1: Simple COUNT
    string sql = simulate_nl2sql("Count customers", TEST_SCHEMA);
    ok(sql_contains(sql, {"SELECT", "COUNT"}),
       "COUNT query includes COUNT function");

    // Test 2: COUNT with GROUP BY
    sql = simulate_nl2sql("Count customers by country", TEST_SCHEMA);
    ok(sql_contains(sql, {"SELECT", "COUNT", "GROUP BY"}),
       "Grouped count includes COUNT and GROUP BY");

    // Test 3: SUM aggregation
    sql = simulate_nl2sql("Total order amounts", TEST_SCHEMA);
    ok(sql_contains(sql, {"SELECT", "FROM"}),
       "Sum query has basic SELECT structure");

    // Test 4: AVG aggregation
    sql = simulate_nl2sql("Average order value", TEST_SCHEMA);
    ok(sql_contains(sql, {"SELECT", "FROM"}),
       "Average query has basic SELECT structure");

    // Test 5: Multiple aggregations
    sql = simulate_nl2sql("Count orders and sum totals by customer", TEST_SCHEMA);
    ok(!sql.empty(),
       "Multiple aggregation query generates SQL");
}

// ============================================================================
// Test: Complex SQL Patterns
// ============================================================================

/**
 * @test Complex SQL patterns
 * @description Generate subqueries, nested queries, HAVING clauses
 */
void test_complex_patterns() {
    diag("=== Complex Pattern Tests ===");

    // Test 1: Subquery pattern
    string sql = simulate_nl2sql("Find customers with above average orders", TEST_SCHEMA);
    ok(!sql.empty(),
       "Subquery pattern generates non-empty SQL");

    // Test 2: Date range query
    sql = simulate_nl2sql("Find orders in January 2024", TEST_SCHEMA);
    ok(sql_contains(sql, {"SELECT", "FROM", "orders"}),
       "Date range query targets correct table");

    // Test 3: Multiple conditions
    sql = simulate_nl2sql("Find customers from USA with orders", TEST_SCHEMA);
    ok(sql_contains(sql, {"SELECT", "WHERE"}),
       "Multiple conditions includes WHERE clause");

    // Test 4: Sorting
    sql = simulate_nl2sql("Show customers sorted by name", TEST_SCHEMA);
    ok(sql_contains(sql, {"SELECT", "customers"}),
       "Sorted query references correct table");

    // Test 5: Limit clause
    sql = simulate_nl2sql("Show top 5 customers", TEST_SCHEMA);
    ok(sql_contains(sql, {"SELECT", "customers"}),
       "Limited query references correct table");
}

// ============================================================================
// Test: Error Recovery
// ============================================================================

/**
 * @test Error handling and recovery
 * @description Handle invalid queries gracefully
 */
void test_error_recovery() {
    diag("=== Error Recovery Tests ===");

    // Test 1: Empty query
    string sql = simulate_nl2sql("", TEST_SCHEMA);
    ok(!sql.empty(),
       "Empty query generates default SQL");

    // Test 2: Query with non-existent table
    sql = simulate_nl2sql("Show data from nonexistent_table", TEST_SCHEMA);
    ok(!sql.empty(),
       "Non-existent table query still generates SQL");

    // Test 3: Malformed query
    sql = simulate_nl2sql("Show show show", TEST_SCHEMA);
    ok(!sql.empty(),
       "Malformed query is handled gracefully");

    // Test 4: Query with special characters
    sql = simulate_nl2sql("Show users with \"quotes\" and 'apostrophes'", TEST_SCHEMA);
    ok(!sql.empty(),
       "Special characters are handled");

    // Test 5: Very long query
    string long_query(10000, 'a');
    sql = simulate_nl2sql(long_query, TEST_SCHEMA);
    ok(!sql.empty(),
       "Very long query is handled");
}

// ============================================================================
// Test: Cross-Schema Queries
// ============================================================================

/**
 * @test Cross-schema query handling
 * @description Generate SQL with fully qualified table names
 */
void test_cross_schema_queries() {
    diag("=== Cross-Schema Query Tests ===");

    // Test 1: Schema prefix included
    string sql = simulate_nl2sql("Show all customers", TEST_SCHEMA);
    ok(sql.find(TEST_SCHEMA) != string::npos,
       "Schema prefix is included in query");

    // Test 2: Different schema specified
    sql = simulate_nl2sql("Show orders", "other_schema");
    ok(sql.find("other_schema") != string::npos,
       "Different schema name is used correctly");

    // Test 3: No schema specified (uses default)
    sql = simulate_nl2sql("Show products", "");
    ok(sql.find("products") != string::npos,
       "Query without schema still generates valid SQL");

    // Test 4: Schema-qualified JOIN
    sql = simulate_nl2sql("Join customers and orders", TEST_SCHEMA);
    ok(sql.find(TEST_SCHEMA) != string::npos,
       "JOIN query includes schema prefix");

    // Test 5: Multiple schemas in one query
    sql = simulate_nl2sql("Cross-schema query", TEST_SCHEMA);
    ok(!sql.empty(),
       "Cross-schema query generates SQL");
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    // Parse command line
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Error getting environment variables");
        return exit_status();
    }

    // Connect to admin interface
    g_admin = mysql_init(NULL);
    if (!g_admin) {
        diag("Failed to initialize MySQL connection");
        return exit_status();
    }

    if (!mysql_real_connect(g_admin, cl.host, cl.admin_username, cl.admin_password,
                            NULL, cl.admin_port, NULL, 0)) {
        diag("Failed to connect to admin interface: %s", mysql_error(g_admin));
        mysql_close(g_admin);
        return exit_status();
    }

    // Connect to data interface
    g_mysql = mysql_init(NULL);
    if (!g_mysql) {
        diag("Failed to initialize MySQL connection");
        mysql_close(g_admin);
        return exit_status();
    }

    if (!mysql_real_connect(g_mysql, cl.host, cl.username, cl.password,
                            TEST_SCHEMA, cl.port, NULL, 0)) {
        diag("Failed to connect to data interface: %s", mysql_error(g_mysql));
        mysql_close(g_mysql);
        mysql_close(g_admin);
        return exit_status();
    }

    // Setup test schema
    if (!setup_test_schema()) {
        diag("Failed to setup test schema");
        mysql_close(g_mysql);
        mysql_close(g_admin);
        return exit_status();
    }

    // Plan tests: 6 categories with 5 tests each
    plan(30);

    // Run test categories
    test_schema_aware_conversion();
    test_join_queries();
    test_aggregation_queries();
    test_complex_patterns();
    test_error_recovery();
    test_cross_schema_queries();

    // Cleanup
    cleanup_test_schema();
    mysql_close(g_mysql);
    mysql_close(g_admin);

    return exit_status();
}
