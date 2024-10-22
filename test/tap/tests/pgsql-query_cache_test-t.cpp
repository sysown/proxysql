/**
 * @file pgsql-query_cache_test-t.cpp
 * @brief This test validates the functionality and performance of PostgreSQL's query caching mechanism.
 *        It tests various scenarios including multi-threaded query execution, basic cache operations,
 *        data manipulation queries (INSERT, UPDATE, DELETE), and transaction behavior. The goal is to
 *        ensure that query results are cached, retrieved, and purged according to specified caching rules,
 *        while verifying cache-related metrics for correctness.
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

#define NUM_THREADS 3
#define PGSLEEP_QUERY "SELECT PG_SLEEP(1)"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

class TestMetrics {
public:
    std::map<std::string,int> before;
    std::map<std::string,int> after;

    void swap() { 
        before.swap(after); 
    }
};

TestMetrics metrics;

void printQueryCacheMetrics() {
	diag("Before: Query Cache Metrics");
	for (const auto& obj : metrics.before)
		diag("%s : %d", obj.first.c_str(), obj.second);
	diag("===========================");

	diag("After: Query Cache Metrics");
	for (const auto& obj : metrics.after)
		diag("%s : %d", obj.first.c_str(), obj.second);
	diag("===========================");
}

class Timer {
public:
    Timer() : lastTime(std::chrono::high_resolution_clock::now()) {}

    double elapsed() {
        auto currentTime = std::chrono::high_resolution_clock::now();
        double deltaTime = std::chrono::duration<double>(currentTime - lastTime).count();
        lastTime = currentTime;
        return deltaTime;
    }

private:
    std::chrono::time_point<std::chrono::high_resolution_clock> lastTime;
};

enum ConnType {
    ADMIN,
    BACKEND
};

PGConnPtr createNewConnection(ConnType conn_type, bool with_ssl) {
    std::stringstream ss;
    const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.admin_host;
    int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.admin_port;
    const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        diag("Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

bool executeQueries(PGconn* conn, const std::vector<std::string>& queries) {
    for (const auto& query : queries) {
        diag("Running: %s", query.c_str());
        PGresult* res = PQexec(conn, query.c_str());
        bool success = PQresultStatus(res) == PGRES_COMMAND_OK ||
            PQresultStatus(res) == PGRES_TUPLES_OK;
        if (!success) {
            diag("Failed to execute query '%s': %s",
                query.c_str(), PQerrorMessage(conn));
            PQclear(res);
            return false;
        }
        PQclear(res);
    }
    return true;
}

void run_pgsleep_thread(double* timer_result) {
    PGConnPtr pg_conn = createNewConnection(ConnType::BACKEND, false);

    if (!pg_conn) {
        *timer_result = -1.0;
        return;
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        // execute the query at 1.4 , 2.8 and 4.2 second
        // Running 3 queries we verify:
        // 1. the cache before the threshold
        // 2. the cache after the threshold
        // 3. that the cache has been refreshed
        usleep(1400000);  // Sleep for 1.4 seconds

        Timer stopwatch;
        if (!executeQueries(pg_conn.get(), { PGSLEEP_QUERY })) {
            *timer_result = -1.0;
            return;
        }
        *timer_result += stopwatch.elapsed();
    }
}

template<class BinaryOp>
bool checkMetricDelta(const std::string& metric_name, int expected, BinaryOp op) {
	if (metrics.before.find(metric_name) == metrics.before.end() ||
        metrics.after.find(metric_name) == metrics.after.end()) {
        BAIL_OUT("Metric '%s' not found", metric_name.c_str());
		return false;
	}

    int delta = metrics.after[metric_name] - metrics.before[metric_name];
    bool result = op(std::max(0, delta), expected);

    std::string bin_op_name = typeid(BinaryOp).name();
    bin_op_name = bin_op_name.substr(3, bin_op_name.size() - 6);

    ok(result, "Metric `%s` should be '%s' %d. Actual %d", metric_name.c_str(), bin_op_name.c_str(), expected, delta);
	return result;
}

std::map<std::string, int> getQueryCacheMertrics(PGconn* proxy_admin) {
	const char* query = "SELECT Variable_Name, Variable_Value FROM stats_pgsql_global WHERE Variable_Name LIKE 'Query_Cache%';";
    diag("Running: %s", query);
    PGresult* res = PQexec(proxy_admin, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        diag("Failed to execute query `%s`: %s", query, PQerrorMessage(proxy_admin));
        PQclear(res);
        return {};
    }

    std::map<std::string, int> metrics{};
    int nRows = PQntuples(res);
    for (int i = 0; i < nRows; i++) {
		const std::string& name = PQgetvalue(res, i, 0);
        metrics[name] = atoi(PQgetvalue(res, i, 1));
    }
    PQclear(res);
    return metrics;
}


void execute_multi_threaded_test(PGconn* admin_conn, PGconn* conn) {
    double timer_results[NUM_THREADS];
    std::vector<std::thread> mythreads(NUM_THREADS);

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_soft_ttl_pct'",
        "LOAD PGSQL VARIABLES TO RUNTIME",
        })) 
        return;

    if (!executeQueries(conn, { PGSLEEP_QUERY }))
        return;
    
    for (unsigned int i = 0; i < NUM_THREADS; i++) {
        mythreads[i] = std::thread(run_pgsleep_thread, &timer_results[i]);
    }

    for (auto& thread : mythreads) {
        thread.join();
    }

    for (unsigned int i = 0; i < NUM_THREADS; i++) {
        if (timer_results[i] == -1.0) {
            fprintf(stderr, "Error: one or more threads finished with errors in file %s, line %d\n", __FILE__, __LINE__);
            return;
        }
    }

    // Calculate the number of clients that took more than 1 second to execute the query
    int num_slow_clients = 0;
    for (unsigned int i = 0; i < NUM_THREADS; i++) {
        num_slow_clients += static_cast<int>(timer_results[i]);
    }

    int expected_num_slow_clients = 3;
    ok(num_slow_clients == expected_num_slow_clients,
        "3 clients should take 1 second to execute the query. "
        "Expected: '%d', Actual: '%d'", expected_num_slow_clients, num_slow_clients);

    executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=256 WHERE variable_name='pgsql-query_cache_size_MB'",
        "LOAD PGSQL VARIABLES TO RUNTIME" }
    );
}

void execute_multi_threaded_purge_test(PGconn* admin_conn, PGconn* conn) {
    double timer_results[NUM_THREADS];
    std::vector<std::thread> mythreads(NUM_THREADS);

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_soft_ttl_pct'",
        "UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_size_MB'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;

    if (!executeQueries(conn, { PGSLEEP_QUERY }))
        return;

    usleep(5000000);

    metrics.before = getQueryCacheMertrics(admin_conn);

    for (unsigned int i = 0; i < NUM_THREADS; i++) {
        mythreads[i] = std::thread(run_pgsleep_thread, &timer_results[i]);
    }

    for (auto& thread : mythreads) {
        thread.join();
    }

    for (unsigned int i = 0; i < NUM_THREADS; i++) {
        if (timer_results[i] == -1.0) {
            fprintf(stderr, "Error: one or more threads finished with errors in file %s, line %d\n", __FILE__, __LINE__);
            return;
        }
    }

    usleep(5000000);
    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    // difference query cache metrics
    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 9, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 9, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 9, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=4194304 WHERE variable_name='pgsql-threshold_resultset_size'",
        "UPDATE global_variables SET variable_value=256 WHERE variable_name='pgsql-query_cache_size_MB'",
        "LOAD PGSQL VARIABLES TO RUNTIME" 
    });
}

void execute_basic_test(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_soft_ttl_pct'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;

    metrics.before = getQueryCacheMertrics(admin_conn);

    if (!executeQueries(conn, { "SELECT 1" }))
        return;

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

	// difference query cache metrics
    checkMetricDelta<>("Query_Cache_Memory_bytes", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 1, std::equal_to<int>());

    metrics.swap();

    if (!executeQueries(conn, { "SELECT 1" }))
        return;

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    metrics.swap();

	usleep(4000000);

    if (!executeQueries(conn, { "SELECT 1" }))
        return;

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    checkMetricDelta<>("Query_Cache_Memory_bytes", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 1, std::equal_to<int>());

    metrics.swap();

    if (!executeQueries(admin_conn, {
        "UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_size_MB'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;

    usleep(5000000);

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 2, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=256 WHERE variable_name='pgsql-query_cache_size_MB'",
        "LOAD PGSQL VARIABLES TO RUNTIME",
        }))
        return;
}

void execute_data_manipulation_test(PGconn* admin_conn, PGconn* conn) {

    // Create query rules for INSERT, DELETE, and UPDATE statements
    if (!executeQueries(admin_conn, {
		"DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (3,1,'^INSERT',4000)",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (4,1,'^DELETE',4000)",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (5,1,'^UPDATE',4000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        }))
        return;

    // Create test table
    if (!executeQueries(conn, { "CREATE TABLE IF NOT EXISTS test_table(id INT PRIMARY KEY, name TEXT);" }))
        return;

    metrics.before = getQueryCacheMertrics(admin_conn);

    // INSERT
    if (!executeQueries(conn, { "INSERT INTO test_table(id, name) VALUES (1, 'test')" }))
        return;

    // DELETE
    if (!executeQueries(conn, { "DELETE FROM test_table WHERE id = 1" }))
        return;

    // UPDATE
    if (!executeQueries(conn, { "UPDATE test_table SET name = 'updated' WHERE id = 1" }))
        return;

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    // Validate that no cache entries were created for DML operations
    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 3, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    // Clean up test table
    if (!executeQueries(conn, { "DROP TABLE IF EXISTS test_table;" }))
        return;

	// Clean up query rules
    if (!executeQueries(admin_conn, {
       "DELETE FROM pgsql_query_rules",
       "LOAD PGSQL QUERY RULES TO RUNTIME"
        }))
        return;
}

void execute_threshold_resultset_size_test(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=1024 WHERE variable_name='pgsql-threshold_resultset_size'",
        "UPDATE global_variables SET variable_value=1 WHERE variable_name='pgsql-query_cache_size_MB'",
        "LOAD PGSQL VARIABLES TO RUNTIME",
        }))
        return;

    metrics.before = getQueryCacheMertrics(admin_conn);

    if (!executeQueries(conn, { "SELECT REPEAT('X', 8197)" }))
        return;

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    // difference query cache metrics
    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());


    if (!executeQueries(admin_conn, {
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME"
        }))
        return;

    metrics.swap();

    if (!executeQueries(conn, { "SELECT REPEAT('X', 8197)" }))
        return;

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    // difference query cache metrics
    checkMetricDelta<>("Query_Cache_Memory_bytes", 8197, std::greater<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 8197, std::greater<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 1, std::equal_to<int>());

    metrics.swap();

    if (!executeQueries(conn, { "SELECT REPEAT('X', 8197)" }))
        return;

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    // difference query cache metrics
    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 8197, std::greater<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=4194304 WHERE variable_name='pgsql-threshold_resultset_size'",
        "UPDATE global_variables SET variable_value=256 WHERE variable_name='pgsql-query_cache_size_MB'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;
}

void execute_multi_statement_test(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_soft_ttl_pct'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;

    metrics.before = getQueryCacheMertrics(admin_conn);

    if (!executeQueries(conn, { "SELECT 1; SELECT 2; SELECT 3;" }))
        return;

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    // difference query cache metrics
    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    metrics.swap();

    if (!executeQueries(conn, { "SELECT 1; SELECT 2; SELECT 3;" }))
        return;

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=256 WHERE variable_name='pgsql-query_cache_size_MB'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;
}

void execute_transaction_status_test(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',10000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_soft_ttl_pct'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;

    metrics.before = getQueryCacheMertrics(admin_conn);

    if (!executeQueries(conn, { "SELECT 1" }))
        return;

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    checkMetricDelta<>("Query_Cache_Memory_bytes", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 1, std::equal_to<int>());

    metrics.swap();

    if (!executeQueries(conn, { "SELECT 1" }))
        return;
    
    ok(PQtransactionStatus(conn) == PQTRANS_IDLE, "Connection is in IDLE state, Exp:%d : Act:%d", 
        PQTRANS_IDLE, PQtransactionStatus(conn));

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    metrics.swap();

    if (!executeQueries(conn, { "BEGIN" }))
        return;

    ok(PQtransactionStatus(conn) == PQTRANS_INTRANS, "Connection is in TRANSACTION STATE BEFORE CACHE HIT, Exp:%d : Act:%d",
        PQTRANS_INTRANS, PQtransactionStatus(conn));

    if (!executeQueries(conn, { "SELECT 1" }))
        return;

    ok(PQtransactionStatus(conn) == PQTRANS_INTRANS, "Connection is in TRANSACTION STATE AFTER CACHE HIT, Exp:%d : Act:%d",
        PQTRANS_INTRANS, PQtransactionStatus(conn));

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    if (!executeQueries(conn, { "ROLLBACK" }))
        return;

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=256 WHERE variable_name='pgsql-query_cache_size_MB'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;
}

void execute_query_cache_store_empty_result_test(PGconn* admin_conn, PGconn* conn) {

	if (!executeQueries(admin_conn, {
		"DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl,cache_empty_result) VALUES (2,1,'^SELECT',4000,0)",
		"LOAD PGSQL QUERY RULES TO RUNTIME",
		"UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_soft_ttl_pct'",
        "UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_stores_empty_result'",
		"LOAD PGSQL VARIABLES TO RUNTIME"
		}))
		return;

	metrics.before = getQueryCacheMertrics(admin_conn);

	if (!executeQueries(conn, {"SELECT 1 WHERE 1!=1"}))
		return;

	metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

	checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    metrics.swap();

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl,cache_empty_result) VALUES (3,1,'^SELECT',4000,1)",
        "LOAD PGSQL QUERY RULES TO RUNTIME"
        }))
        return;

	if (!executeQueries(conn, { "SELECT 1 WHERE 1!=1" }))
		return;

	metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

	checkMetricDelta<>("Query_Cache_Memory_bytes", 1, std::greater<int>());
	checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_count_SET", 1, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_bytes_IN", 1, std::greater<int>());
	checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_Entries", 1, std::equal_to<int>());

    metrics.swap();

	if (!executeQueries(conn, { "SELECT 1 WHERE 1!=1" }))
		return;

	metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    usleep(5000000);  // Sleep for 5 seconds

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (4,1,'^SELECT',4000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME"
        }))
        return;

    metrics.before = getQueryCacheMertrics(admin_conn);

    if (!executeQueries(conn, { "SELECT 1 WHERE 1!=1" }))
        return;

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    metrics.swap();

    if (!executeQueries(admin_conn, {
        "UPDATE global_variables SET variable_value=1 WHERE variable_name='pgsql-query_cache_stores_empty_result'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;

    if (!executeQueries(conn, { "SELECT 1 WHERE 1!=1" }))
        return;

    metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

    checkMetricDelta<>("Query_Cache_Memory_bytes", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 1, std::equal_to<int>());

	metrics.swap();

	if (!executeQueries(conn, { "SELECT 1 WHERE 1!=1" }))
		return;

	metrics.after = getQueryCacheMertrics(admin_conn);

    printQueryCacheMetrics();

	checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_count_GET_OK", 1, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_bytes_OUT", 1, std::greater<int>());
	checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
	checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());


	if (!executeQueries(admin_conn, {
		"DELETE FROM pgsql_query_rules",
		"LOAD PGSQL QUERY RULES TO RUNTIME",
		}))
		return;
}

std::vector<std::pair<std::string, void (*)(PGconn*, PGconn*)>> tests = {
	{ "Basic Test", execute_basic_test },
	{ "Data Manipulation Test", execute_data_manipulation_test },
	{ "Multi Statement Test", execute_multi_statement_test },
	{ "Threshold Resultset Size Test", execute_threshold_resultset_size_test },
	{ "Multi Threaded Test", execute_multi_threaded_test },
	{ "Multi Threaded Purge Test", execute_multi_threaded_purge_test },
	{ "Transaction Status Test", execute_transaction_status_test },
    { "Query Cache Store Empty Result Test", execute_query_cache_store_empty_result_test }
};

void execute_tests(bool with_ssl, bool diff_conn) {

    if (diff_conn == false) {
        PGConnPtr admin_conn = createNewConnection(ConnType::ADMIN, with_ssl);
        PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, with_ssl);

        if (!admin_conn || !backend_conn) {
            fprintf(stderr, "Error: failed to connect to the database in file %s, line %d\n", __FILE__, __LINE__);
            return;
        }

        if (!executeQueries(admin_conn.get(), { "PROXYSQL FLUSH PGSQL QUERY CACHE" }))
            return;

		for (const auto& test : tests) {
			diag(">>>> Running %s - Shared Connection: %s <<<<", test.first.c_str(), !diff_conn ? "True" : "False");
			test.second(admin_conn.get(), backend_conn.get());
            diag(">>>> Done <<<<");
		}
    } else {

        PGConnPtr admin_conn = createNewConnection(ConnType::ADMIN, with_ssl);
        if (!executeQueries(admin_conn.get(), { "PROXYSQL FLUSH PGSQL QUERY CACHE" }))
            return;

        for (const auto& test : tests) {
            diag(">>>> Running %s - Shared Connection: %s <<<<", test.first.c_str(), diff_conn ? "False" : "True");

            PGConnPtr admin_conn = createNewConnection(ConnType::ADMIN, with_ssl);
            PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, with_ssl);

            if (!admin_conn || !backend_conn) {
                fprintf(stderr, "Error: failed to connect to the database in file %s, line %d\n", __FILE__, __LINE__);
                return;
            }

            test.second(admin_conn.get(), backend_conn.get());
            diag(">>>> Done <<<<");
        }
    }
}

int main(int argc, char** argv) {

    plan(165*2); // Total number of tests planned

    if (cl.getEnv())
        return exit_status();

    execute_tests(false, false);
	execute_tests(false, true);

    return exit_status();
}
