/**
 * @file pgsql-query_rules_routing-t.cpp
 * @brief This test is for testing query routing to different hostgroups
 *  through 'query rules' for PostgreSQL. It aims to check that
 *  arbitrary query rules are properly matched and queries are executed in
 *  the target hostgroups for both 'text protocol' and 'extended query protocol'.
 *
 *  This test is the PostgreSQL equivalent of test_query_rules_routing-t.cpp
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <vector>
#include <utility>
#include <memory>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType {
    ADMIN,
    BACKEND
};

/**
 * @brief Create a new PostgreSQL connection.
 *
 * @param conn_type ADMIN for admin interface, BACKEND for proxy connection.
 * @param options Optional connection options string.
 * @param with_ssl Whether to use SSL.
 * @return PGConnPtr A smart pointer to PGconn.
 */
PGConnPtr createNewConnection(ConnType conn_type, const std::string& options = "", bool with_ssl = false) {
    const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
    int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
    const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

    std::stringstream ss;

    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

    if (options.empty() == false) {
        ss << " options='" << options << "'";
    }

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        diag("Connection failed to '%s': %s",
             (conn_type == BACKEND ? "Backend" : "Admin"),
             PQerrorMessage(conn));
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

/**
 * @brief For now a query rules test for destination hostgroup is going
 *   to consist into:
 *
 *   - A set of rules to apply.
 *   - A set of queries to exercise those rules.
 *   - The destination hostgroup in which the queries are supposed to end.
 */
using dst_hostgroup_test =
    std::pair<std::vector<std::string>, std::vector<std::pair<std::string, int>>>;

/**
 * @brief Test cases for query routing to different hostgroups.
 * Each test case contains:
 *   - Query rules to configure
 *   - Queries with their expected destination hostgroups
 */
std::vector<dst_hostgroup_test> dst_hostgroup_tests {
    {
        // Test 1: Basic read-write split
        // SELECT queries go to hostgroup 1 (reader)
        // All other queries go to hostgroup 0 (writer) via default
        {
            "INSERT INTO pgsql_query_rules (rule_id,active,match_pattern,destination_hostgroup,apply)"
            " VALUES (1,1,'^SELECT.*FOR UPDATE',0,1)",
            "INSERT INTO pgsql_query_rules (rule_id,active,match_pattern,destination_hostgroup,apply)"
            " VALUES (2,1,'^SELECT',1,1)"
        },
        {
            { "SELECT 1", 1 },
            { "SELECT * FROM pgsql_routing_test.test_table_0 WHERE id=1", 1 },
            { "SELECT * FROM pgsql_routing_test.test_table_0 WHERE id BETWEEN 1 AND 20", 1 },
            { "INSERT INTO pgsql_routing_test.test_table_0 (k) VALUES (2)", 0 },
            { "UPDATE pgsql_routing_test.test_table_0 SET pad='random' WHERE id=2", 0 },
            { "SELECT DISTINCT c FROM pgsql_routing_test.test_table_0 WHERE id BETWEEN 1 AND 10 ORDER BY c", 1 }
        }
    },
    {
        // Test 2: Table-based routing
        // Queries to test_table_0 go to hostgroup 1
        // Queries to test_table_1 go to hostgroup 0
        {
            "INSERT INTO pgsql_query_rules (rule_id,active,match_pattern,destination_hostgroup,apply)"
            " VALUES (1,1,'^SELECT.*FROM pgsql_routing_test.test_table_0.*',1,1)",
            "INSERT INTO pgsql_query_rules (rule_id,active,match_pattern,destination_hostgroup,apply)"
            " VALUES (2,1,'^SELECT.*FROM pgsql_routing_test.test_table_1.*',0,1)"
        },
        {
            { "UPDATE pgsql_routing_test.test_table_0 SET pad='random' WHERE id=2", 0 },
            { "SELECT DISTINCT c FROM pgsql_routing_test.test_table_0 WHERE id BETWEEN 1 AND 10 ORDER BY c", 1 },
            { "SELECT c FROM pgsql_routing_test.test_table_1 WHERE id BETWEEN 1 AND 10 ORDER BY c", 0 },
            { "INSERT INTO pgsql_routing_test.test_table_0 (k) VALUES (2)", 0 }
        }
    },
    {
        // Test 3: Mix of SELECT FOR UPDATE and regular SELECT
        {
            "INSERT INTO pgsql_query_rules (rule_id,active,match_pattern,destination_hostgroup,apply)"
            " VALUES (1,1,'^SELECT.*FOR UPDATE',0,1)",
            "INSERT INTO pgsql_query_rules (rule_id,active,match_pattern,destination_hostgroup,apply)"
            " VALUES (2,1,'^SELECT',1,1)"
        },
        {
            { "UPDATE pgsql_routing_test.test_table_0 SET pad='random' WHERE id=2", 0 },
            { "SELECT c FROM pgsql_routing_test.test_table_0 WHERE id=1", 1 },
            { "SELECT c FROM pgsql_routing_test.test_table_0 WHERE id BETWEEN 1 AND 20", 1 },
            { "SELECT SUM(k) c FROM pgsql_routing_test.test_table_0 WHERE id BETWEEN 1 AND 10", 1 }
        }
    }
};

/**
 * @brief Get the current query count for a specific hostgroup.
 *
 * @param admin A already opened PGconn connection to ProxySQL admin interface.
 * @param hostgroup_id The 'hostgroup_id' from which to get the query count.
 *
 * @return The number of queries that have been executed in that hostgroup id,
 *         or -1 on error.
 */
int get_hostgroup_query_count(PGconn* admin, const int hostgroup_id) {
    if (admin == NULL) {
        return -1;
    }

    std::stringstream ss;
    ss << "SELECT SUM(Queries) FROM stats.stats_pgsql_connection_pool WHERE hostgroup=" << hostgroup_id;

    PGresult* res = PQexec(admin, ss.str().c_str());
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        diag("Failed to get query count: %s", PQerrorMessage(admin));
        PQclear(res);
        return -1;
    }

    int query_count = -1;
    if (PQntuples(res) > 0 && PQgetvalue(res, 0, 0) != NULL) {
        query_count = atoi(PQgetvalue(res, 0, 0));
    }

    PQclear(res);
    return query_count;
}

/**
 * @brief Simple function that performs a text protocol query and discards the result.
 *
 * @param conn A already opened PGconn connection to ProxySQL.
 * @param query The query to be executed.
 *
 * @return true if the query succeeded, false otherwise.
 */
bool perform_text_protocol_query(PGconn* conn, const std::string& query) {
    PGresult* res = PQexec(conn, query.c_str());
    ExecStatusType status = PQresultStatus(res);

    bool success = (status == PGRES_TUPLES_OK || status == PGRES_COMMAND_OK);

    if (!success) {
        diag("Query '%s' failed: %s", query.c_str(), PQerrorMessage(conn));
    }

    PQclear(res);
    return success;
}

/**
 * @brief Simple function that performs an extended query protocol (prepared statement)
 * and discards the result.
 *
 * @param conn A already opened PGconn connection to ProxySQL.
 * @param query The query to be executed.
 * @param stmt_name The name for the prepared statement.
 *
 * @return true if the query succeeded, false otherwise.
 */
bool perform_extended_query_protocol(PGconn* conn, const std::string& query, const std::string& stmt_name) {
    // Prepare
    PGresult* res = PQprepare(conn, stmt_name.c_str(), query.c_str(), 0, nullptr);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        diag("Prepare failed for '%s': %s", query.c_str(), PQerrorMessage(conn));
        PQclear(res);
        return false;
    }
    PQclear(res);

    // Execute
    res = PQexecPrepared(conn, stmt_name.c_str(), 0, nullptr, nullptr, nullptr, 0);
    ExecStatusType status = PQresultStatus(res);
    bool success = (status == PGRES_TUPLES_OK || status == PGRES_COMMAND_OK);

    if (!success) {
        diag("Execute failed for '%s': %s", query.c_str(), PQerrorMessage(conn));
    }

    PQclear(res);

    // Cleanup - deallocate the prepared statement
    std::string dealloc_query = "DEALLOCATE " + stmt_name;
    res = PQexec(conn, dealloc_query.c_str());
    PQclear(res);

    return success;
}

/**
 * @brief Helper function for creating testing tables.
 *
 * @param backend A already opened PGconn connection through ProxySQL.
 *
 * @return true on success, false on failure.
 */
bool create_testing_tables(PGconn* backend) {
    if (backend == NULL) {
        return false;
    }

    // Create schema
    PGresult* res = PQexec(backend, "CREATE SCHEMA IF NOT EXISTS pgsql_routing_test");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        diag("Failed to create schema: %s", PQerrorMessage(backend));
        PQclear(res);
        return false;
    }
    PQclear(res);

    // Create tables
    for (int i = 0; i < 2; i++) {
        std::stringstream ss;

        // Drop table if exists
        ss << "DROP TABLE IF EXISTS pgsql_routing_test.test_table_" << i;
        res = PQexec(backend, ss.str().c_str());
        PQclear(res);

        // Create table
        ss.str("");
        ss << "CREATE TABLE pgsql_routing_test.test_table_" << i << " ("
           << "    id SERIAL PRIMARY KEY,"
           << "    k INTEGER NOT NULL DEFAULT 0,"
           << "    c VARCHAR(120) NOT NULL DEFAULT '',"
           << "    pad VARCHAR(60) NOT NULL DEFAULT ''"
           << ")";
        res = PQexec(backend, ss.str().c_str());
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            diag("Failed to create table: %s", PQerrorMessage(backend));
            PQclear(res);
            return false;
        }
        PQclear(res);

        // Insert test data
        ss.str("");
        ss << "INSERT INTO pgsql_routing_test.test_table_" << i
           << " (k, c, pad) VALUES (3427, 'foo', 'bar')";
        res = PQexec(backend, ss.str().c_str());
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            diag("Failed to insert data: %s", PQerrorMessage(backend));
            PQclear(res);
            return false;
        }
        PQclear(res);
    }

    return true;
}

/**
 * @brief Clear all query rules from the admin interface.
 *
 * @param admin A already opened PGconn connection to ProxySQL admin interface.
 */
void clear_query_rules(PGconn* admin) {
    PGresult* res = PQexec(admin, "DELETE FROM pgsql_query_rules");
    PQclear(res);

    res = PQexec(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
    PQclear(res);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

/**
 * @brief Insert query rules and load them to runtime.
 *
 * @param admin A already opened PGconn connection to ProxySQL admin interface.
 * @param rules The query rules to insert.
 *
 * @return true on success, false on failure.
 */
bool insert_query_rules(PGconn* admin, const std::vector<std::string>& rules) {
    for (const auto& rule : rules) {
        PGresult* res = PQexec(admin, rule.c_str());
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            diag("Failed to insert query rule: %s", PQerrorMessage(admin));
            PQclear(res);
            return false;
        }
        PQclear(res);
    }

    PGresult* res = PQexec(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        diag("Failed to load query rules: %s", PQerrorMessage(admin));
        PQclear(res);
        return false;
    }
    PQclear(res);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    return true;
}

int main(int argc, char** argv) {
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    plan(dst_hostgroup_tests.size());

    // Create admin connection
    PGConnPtr admin = createNewConnection(ADMIN);
    if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
        BAIL_OUT("Failed to connect to admin interface");
        return exit_status();
    }

    // Create backend connections for text and extended query protocol
    PGConnPtr backend_text = createNewConnection(BACKEND);
    PGConnPtr backend_extended = createNewConnection(BACKEND);

    if (!backend_text || PQstatus(backend_text.get()) != CONNECTION_OK) {
        BAIL_OUT("Failed to connect to backend (text protocol)");
        return exit_status();
    }

    if (!backend_extended || PQstatus(backend_extended.get()) != CONNECTION_OK) {
        BAIL_OUT("Failed to connect to backend (extended query protocol)");
        return exit_status();
    }

    // Create testing tables
    if (!create_testing_tables(backend_text.get())) {
        BAIL_OUT("Failed to create testing tables");
        return exit_status();
    }

    // Allow tables to be visible
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Run each test case
    for (size_t test_idx = 0; test_idx < dst_hostgroup_tests.size(); test_idx++) {
        const auto& test_case = dst_hostgroup_tests[test_idx];
        const auto& query_rules = test_case.first;
        const auto& queries_hids = test_case.second;

        // Clear existing rules
        clear_query_rules(admin.get());

        // Insert new rules
        if (!insert_query_rules(admin.get(), query_rules)) {
            ok(false, "Test %zu: Failed to insert query rules", test_idx + 1);
            continue;
        }

        // Execute queries and check hostgroup routing
        bool queries_properly_routed = true;
        std::vector<std::string> text_queries_failed_to_route;
        std::vector<std::string> extended_queries_failed_to_route;

        int stmt_counter = 0;

        for (const auto& query_hid : queries_hids) {
            const std::string& query = query_hid.first;
            int expected_hg = query_hid.second;

            // Test text protocol
            int cur_hid_queries = get_hostgroup_query_count(admin.get(), expected_hg);

            if (!perform_text_protocol_query(backend_text.get(), query)) {
                diag("Text protocol query failed: %s", query.c_str());
            }

            int new_hid_queries = get_hostgroup_query_count(admin.get(), expected_hg);

            if (new_hid_queries - cur_hid_queries != 1) {
                queries_properly_routed = false;
                text_queries_failed_to_route.push_back(query);
                diag("Text query '%s' routed incorrectly. Expected HG %d, query count diff: %d",
                     query.c_str(), expected_hg, new_hid_queries - cur_hid_queries);
            }

            // Test extended query protocol (prepared statements)
            cur_hid_queries = get_hostgroup_query_count(admin.get(), expected_hg);

            std::string stmt_name = "stmt_" + std::to_string(stmt_counter++);
            if (!perform_extended_query_protocol(backend_extended.get(), query, stmt_name)) {
                diag("Extended query protocol failed: %s", query.c_str());
            }

            new_hid_queries = get_hostgroup_query_count(admin.get(), expected_hg);

            // For prepared statements, we expect 2 queries (PREPARE + EXECUTE or similar)
            // The exact count depends on ProxySQL implementation
            if (new_hid_queries - cur_hid_queries < 1) {
                queries_properly_routed = false;
                extended_queries_failed_to_route.push_back(query);
                diag("Extended query '%s' routed incorrectly. Expected HG %d, query count diff: %d",
                     query.c_str(), expected_hg, new_hid_queries - cur_hid_queries);
            }
        }

        // Report failures
        if (!queries_properly_routed) {
            std::stringstream rules_ss;
            for (const auto& rule : query_rules) {
                rules_ss << rule << "\n";
            }

            diag("Test %zu with rules:\n%s\nFailed to route text queries:",
                 test_idx + 1, rules_ss.str().c_str());
            for (const auto& q : text_queries_failed_to_route) {
                diag("  - %s", q.c_str());
            }

            diag("Failed to route extended queries:");
            for (const auto& q : extended_queries_failed_to_route) {
                diag("  - %s", q.c_str());
            }
        }

        ok(queries_properly_routed,
           "Test %zu: Queries were properly routed to the target hostgroups",
           test_idx + 1);
    }

    // Cleanup
    clear_query_rules(admin.get());

    return exit_status();
}
