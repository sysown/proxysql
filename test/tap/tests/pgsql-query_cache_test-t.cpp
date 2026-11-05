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
#include "noise_utils.h"
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

// 'extra' is appended to the conninfo, e.g. "options='-c TimeZone=UTC'".
PGConnPtr createNewConnection(ConnType conn_type, bool with_ssl, const char* extra = "") {
    std::stringstream ss;
    const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
    int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
    const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");
    ss << " " << extra;

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

bool prepareAndExec(PGconn* conn,
    const char* stmtName,
    const char* query,
    int nParams = 0,
    const Oid* paramTypes = nullptr,
    int nExecParams = 0,
    const char* const* execValues = nullptr)
{
    // Prepare
    diag("Preparing statement '%s': %s", stmtName, query);
    PGresult* res = PQprepare(conn, stmtName, query, nParams, paramTypes);
    if (!res) {
        diag("PQprepare returned NULL: %s", PQerrorMessage(conn));
        return false;
    }
    bool ok = PQresultStatus(res) == PGRES_COMMAND_OK;
    if (!ok) {
        diag("PQprepare failed for '%s': %s", stmtName, PQerrorMessage(conn));
        PQclear(res);
        return false;
    }
    PQclear(res);

    // Execute prepared
    diag("Executing prepared statement '%s'", stmtName);
    res = PQexecPrepared(conn, stmtName, nExecParams, execValues, /*paramLengths*/ nullptr,
        /*paramFormats*/ nullptr, /*resultFormat*/ 0);
    if (!res) {
        diag("PQexecPrepared returned NULL: %s", PQerrorMessage(conn));
        return false;
    }
    ok = PQresultStatus(res) == PGRES_TUPLES_OK || PQresultStatus(res) == PGRES_COMMAND_OK;
    if (!ok) {
        diag("PQexecPrepared failed for '%s': %s", stmtName, PQerrorMessage(conn));
        PQclear(res);
        return false;
    }
    PQclear(res);

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

std::map<std::string, int> getQueryCacheMetrics(PGconn* proxy_admin) {
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

    metrics.before = getQueryCacheMetrics(admin_conn);

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
    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.before = getQueryCacheMetrics(admin_conn);

    if (!executeQueries(conn, { "SELECT 1" }))
        return;

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.before = getQueryCacheMetrics(admin_conn);

    // INSERT
    if (!executeQueries(conn, { "INSERT INTO test_table(id, name) VALUES (1, 'test')" }))
        return;

    // DELETE
    if (!executeQueries(conn, { "DELETE FROM test_table WHERE id = 1" }))
        return;

    // UPDATE
    if (!executeQueries(conn, { "UPDATE test_table SET name = 'updated' WHERE id = 1" }))
        return;

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.before = getQueryCacheMetrics(admin_conn);

    if (!executeQueries(conn, { "SELECT REPEAT('X', 8197)" }))
        return;

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.before = getQueryCacheMetrics(admin_conn);

    if (!executeQueries(conn, { "SELECT 1; SELECT 2; SELECT 3;" }))
        return;

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.before = getQueryCacheMetrics(admin_conn);

    if (!executeQueries(conn, { "SELECT 1" }))
        return;

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.after = getQueryCacheMetrics(admin_conn);

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

	metrics.before = getQueryCacheMetrics(admin_conn);

	if (!executeQueries(conn, {"SELECT 1 WHERE 1!=1"}))
		return;

	metrics.after = getQueryCacheMetrics(admin_conn);

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

	metrics.after = getQueryCacheMetrics(admin_conn);

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

	metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.before = getQueryCacheMetrics(admin_conn);

    if (!executeQueries(conn, { "SELECT 1 WHERE 1!=1" }))
        return;

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    metrics.after = getQueryCacheMetrics(admin_conn);

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

	metrics.after = getQueryCacheMetrics(admin_conn);

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

void execute_query_cache_notice_test(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_soft_ttl_pct'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;

    const char* create_function_query =
        "CREATE OR REPLACE FUNCTION select_and_warn() RETURNS integer AS $$"
        "DECLARE "
        "    result integer; "
        "BEGIN "
        "    SELECT 1 INTO result; "
        "    RAISE WARNING 'This is a warning message'; "
        "    RETURN result; "
        "END; "
        "$$ LANGUAGE plpgsql;";

	if (!executeQueries(conn, { create_function_query }))
		return;

    metrics.before = getQueryCacheMetrics(admin_conn);

    if (!executeQueries(conn, { "SELECT select_and_warn()" }))
        return;

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    if (!executeQueries(conn, { "SELECT select_and_warn()" }))
        return;

    metrics.after = getQueryCacheMetrics(admin_conn);

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

    if (!executeQueries(conn, { "SELECT select_and_warn()" }))
        return;

    metrics.after = getQueryCacheMetrics(admin_conn);

    printQueryCacheMetrics();

    checkMetricDelta<>("Query_Cache_Memory_bytes", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_count_GET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 1, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 1, std::greater<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 1, std::equal_to<int>());


    executeQueries(conn, { "DROP FUNCTION IF EXISTS select_and_warn()" });

    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=256 WHERE variable_name='pgsql-query_cache_size_MB'",
        "LOAD PGSQL VARIABLES TO RUNTIME",
        }))
        return;
}

void execute_prepared_test(PGconn* admin_conn, PGconn* conn) {
    PGresult* version = PQexec(admin_conn,
        "SELECT variable_value FROM global_variables WHERE variable_name='admin-version'");
    int major = 0, minor = 0;
    if (PQresultStatus(version) != PGRES_TUPLES_OK || PQntuples(version) != 1 ||
        sscanf(PQgetvalue(version, 0, 0), "%d.%d", &major, &minor) != 2)
        BAIL_OUT("Cannot determine ProxySQL build tier from admin-version");
    PQclear(version);
    const bool extended_cache = major > 3 || (major == 3 && minor >= 1);
    const auto cache_growth = [extended_cache](int actual, int expected) {
        return extended_cache ? actual > expected : actual == expected;
    };
    // 1) Simple SELECT caching is available on every tier; extended caching
    // requires PROXYSQL31. Determine the server tier, not the TAP build flags.
    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_soft_ttl_pct'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        })) {
        return;
    }

    // Collect baseline metrics
    metrics.before = getQueryCacheMetrics(admin_conn);

    // 2) Separate preparation followed by Bind/Describe/Execute/Sync populates
    // the extended-protocol cache only on PROXYSQL31 builds.
    if (!prepareAndExec(conn, "ps_select_1", "SELECT 1")) {
        // attempt cleanup before returning
        executeQueries(admin_conn, { "DELETE FROM pgsql_query_rules", "LOAD PGSQL QUERY RULES TO RUNTIME" });
        return;
    }

    // Read metrics after extended-query run
    metrics.after = getQueryCacheMetrics(admin_conn);
    printQueryCacheMetrics();

    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, cache_growth);
    checkMetricDelta<>("Query_Cache_count_GET", extended_cache ? 1 : 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", extended_cache ? 1 : 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 0, cache_growth);
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", extended_cache ? 1 : 0, std::equal_to<int>());

    metrics.swap();

    executeQueries(conn, { "DEALLOCATE ps_select_1" });
    // 3) Re-prepare and execute identical SQL: client statement lifecycle
    // does not change the result key, so this execution hits on PROXYSQL31.
    if (!prepareAndExec(conn, "ps_select_1", "SELECT 1")) {
        // cleanup below
    }

    metrics.after = getQueryCacheMetrics(admin_conn);
    printQueryCacheMetrics();

    checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET", extended_cache ? 1 : 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_GET_OK", extended_cache ? 1 : 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_bytes_OUT", 0, cache_growth);
    checkMetricDelta<>("Query_Cache_Purged", 0, std::equal_to<int>());
    checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    metrics.swap();

    // 4) test that a simple (non-prepared) SELECT would create a cache entry here
    //    (verifies rule is active).
    
    if (!executeQueries(conn, { "SELECT 1" }))
        return;
    metrics.after = getQueryCacheMetrics(admin_conn);
    printQueryCacheMetrics();
    checkMetricDelta<>("Query_Cache_Entries", 1, std::equal_to<int>());
    metrics.swap();
    

    // 5) Cleanup: remove rules and restore variables as in basic test
    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=256 WHERE variable_name='pgsql-query_cache_size_MB'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        })) {
        return;
    }

    // 6) Deallocate prepared statement on connection (best-effort; ignore failure)
    executeQueries(conn, { "DEALLOCATE ps_select_1" });
}

// Escapes control and non-ASCII bytes, so a LATIN1 result does not reach the log raw.
static std::string show(const std::string& s) {
    std::string out;
    char buf[5];
    for (unsigned char ch : s) {
        if (ch >= 0x20 && ch < 0x7f) out += ch;
        else { snprintf(buf, sizeof(buf), "\\x%02x", ch); out += buf; }
    }
    return out;
}

// The single value a query returns, or the error text.
static std::string single_value(PGconn* conn, const char* query) {
    PGresult* res = PQexec(conn, query);
    std::string v = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) ?
        PQgetvalue(res, 0, 0) : PQerrorMessage(conn);
    PQclear(res);
    return v;
}

// Runs one SELECT under two values of a setting. The second value must get its own
// result, not the one cached under the first; the first must then still hit the cache.
static void check_setting_in_cache_key(PGconn* admin_conn, PGconn* conn, const char* set1,
    const char* set2, const char* query, const std::string& exp1, const std::string& exp2) {
    // A rejected SET would otherwise read as a cache failure in the checks below.
    const auto run = [&](const char* set) {
        if (!executeQueries(conn, { set })) return std::string("<SET failed>");
        return single_value(conn, query);
    };

    std::string v = run(set1);
    ok(v == exp1, "[%s] %s returns '%s'. Got '%s'", set1, query, show(exp1).c_str(), show(v).c_str());
    v = run(set2);
    ok(v == exp2, "[%s] %s is not served the result cached under [%s]. Expected '%s', got '%s'",
        set2, query, set1, show(exp2).c_str(), show(v).c_str());

    metrics.before = getQueryCacheMetrics(admin_conn);
    v = run(set1);
    metrics.after = getQueryCacheMetrics(admin_conn);
    ok(v == exp1, "[%s] again: %s returns '%s'. Got '%s'", set1, query, show(exp1).c_str(), show(v).c_str());
    checkMetricDelta<>("Query_Cache_count_GET_OK", 1, std::equal_to<int>());
    metrics.swap();
}

// The same SELECT text under two search_paths reads two different tables. The cache
// key must include search_path, or the second read gets the first schema's row.
void execute_search_path_test(PGconn* admin_conn, PGconn* conn) {
    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_soft_ttl_pct'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;

    if (!executeQueries(conn, {
        "DROP SCHEMA IF EXISTS qc_sp_a CASCADE",
        "DROP SCHEMA IF EXISTS qc_sp_b CASCADE",
        "CREATE SCHEMA qc_sp_a",
        "CREATE SCHEMA qc_sp_b",
        "CREATE TABLE qc_sp_a.t (v TEXT)",
        "CREATE TABLE qc_sp_b.t (v TEXT)",
        "INSERT INTO qc_sp_a.t VALUES ('a')",
        "INSERT INTO qc_sp_b.t VALUES ('b')"
        }))
        return;

    check_setting_in_cache_key(admin_conn, conn, "SET search_path TO qc_sp_a",
        "SET search_path TO qc_sp_b", "SELECT v FROM t", "a", "b");

    executeQueries(conn, {
        "SET search_path TO \"$user\", public",
        "DROP SCHEMA IF EXISTS qc_sp_a CASCADE",
        "DROP SCHEMA IF EXISTS qc_sp_b CASCADE"
        });
    executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "LOAD PGSQL QUERY RULES TO RUNTIME"
        });
}

// Each setting below changes the bytes a SELECT returns, so each must be part of the
// cache key. Every case ends on its first value, which is the PostgreSQL default.
void execute_result_settings_test(PGconn* admin_conn, PGconn* conn) {
    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_soft_ttl_pct'",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;

    struct Case { const char* set1; const char* set2; const char* query; const char* exp1; const char* exp2; };
    const Case cases[] = {
        // the server converts the result to the client's encoding: e-acute is 2 bytes in UTF8, 1 in LATIN1
        { "SET client_encoding TO UTF8", "SET client_encoding TO LATIN1",
          "SELECT chr(233)", "\xc3\xa9", "\xe9" },
        { "SET DateStyle TO 'ISO, MDY'", "SET DateStyle TO 'SQL, DMY'",
          "SELECT DATE '2026-11-05'", "2026-11-05", "05/11/2026" },
        { "SET IntervalStyle TO postgres", "SET IntervalStyle TO iso_8601",
          "SELECT INTERVAL '1 day 2 hours'", "1 day 02:00:00", "P1DT2H" },
        // with standard_conforming_strings off, \t in an ordinary literal is a TAB
        { "SET standard_conforming_strings TO on", "SET standard_conforming_strings TO off",
          "SELECT 'a\\tb'", "a\\tb", "a\tb" },
        { "SET TimeZone TO 'UTC'", "SET TimeZone TO 'Asia/Kolkata'",
          "SELECT TIMESTAMPTZ '2026-11-05 10:00:00+00'", "2026-11-05 10:00:00+00", "2026-11-05 15:30:00+05:30" },
        { "SET bytea_output TO hex", "SET bytea_output TO escape",
          "SELECT 'ab'::bytea", "\\x6162", "ab" },
        { "SET extra_float_digits TO 1", "SET extra_float_digits TO 0",
          "SELECT 0.1::float8 + 0.2::float8", "0.30000000000000004", "0.3" },
    };
    for (const auto& c : cases)
        check_setting_in_cache_key(admin_conn, conn, c.set1, c.set2, c.query, c.exp1, c.exp2);

    executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "LOAD PGSQL QUERY RULES TO RUNTIME"
        });
}

// Runs query on conn and checks both its value and how many cache hits it took.
static void check_value_hits(PGconn* admin_conn, PGconn* conn, const char* query,
    const std::string& expected, int hits, const char* what) {
    metrics.before = getQueryCacheMetrics(admin_conn);
    const std::string v = single_value(conn, query);
    metrics.after = getQueryCacheMetrics(admin_conn);
    ok(v == expected, "%s: %s returns '%s'. Got '%s'", what, query, show(expected).c_str(), show(v).c_str());
    checkMetricDelta<>("Query_Cache_count_GET_OK", hits, std::equal_to<int>());
    metrics.swap();
}

// Edge cases of the settings in the cache key: values sent at connect time, the ways a
// setting goes back to its default, transactions, SET aliases, and clients that differ
// from the start. Each case uses its own query text, so no case can hit another's entry.
void execute_settings_edge_test(PGconn* admin_conn, PGconn*) {
    if (!executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=0 WHERE variable_name='pgsql-query_cache_soft_ttl_pct'",
        "LOAD PGSQL VARIABLES TO RUNTIME",
        "PROXYSQL FLUSH PGSQL QUERY CACHE"
        }))
        return;

    const char* utc = "2026-11-05 10:00:00+00";
    const char* kol = "2026-11-05 15:30:00+05:30";
    const char* kol_opt = "options='-c TimeZone=Asia/Kolkata'";
    PGConnPtr plain = createNewConnection(ConnType::BACKEND, false);
    PGConnPtr start = createNewConnection(ConnType::BACKEND, false, kol_opt);
    PGConnPtr start2 = createNewConnection(ConnType::BACKEND, false, kol_opt);
    PGConnPtr c = createNewConnection(ConnType::BACKEND, false);
    if (!plain || !start || !start2 || !c)
        return;

    // TimeZone sent at connect time is part of the key, and is shared by clients that sent the same.
    const char* q1 = "SELECT TIMESTAMPTZ '2026-11-05 10:00:00+00' AS e1";
    check_value_hits(admin_conn, start.get(), q1, kol, 0, "connect-time TimeZone");
    check_value_hits(admin_conn, plain.get(), q1, utc, 0, "plain client after a connect-time TimeZone");
    check_value_hits(admin_conn, start2.get(), q1, kol, 1, "second client with the same connect-time TimeZone");

    // SET away from the connect-time value, then RESET back to it.
    executeQueries(start.get(), { "SET TimeZone TO 'UTC'" });
    check_value_hits(admin_conn, start.get(), q1, utc, 0, "SET away from the connect-time TimeZone");
    executeQueries(start.get(), { "RESET TimeZone" });
    check_value_hits(admin_conn, start.get(), q1, kol, 1, "RESET back to the connect-time TimeZone");

    // Every way back to the default reaches the plain client's key again.
    const char* q3 = "SELECT TIMESTAMPTZ '2026-11-05 10:00:00+00' AS e3";
    check_value_hits(admin_conn, plain.get(), q3, utc, 0, "plain client");
    for (const char* back : { "SET TimeZone TO DEFAULT", "RESET TimeZone", "RESET ALL", "DISCARD ALL" }) {
        executeQueries(c.get(), { "SET TimeZone TO 'Asia/Kolkata'", back });
        check_value_hits(admin_conn, c.get(), q3, utc, 1, back);
    }

    // A SET undone by ROLLBACK or ROLLBACK TO SAVEPOINT takes the key back with it.
    executeQueries(c.get(), { "BEGIN", "SET TimeZone TO 'Asia/Kolkata'", "ROLLBACK" });
    check_value_hits(admin_conn, c.get(), q3, utc, 1, "SET then ROLLBACK");
    executeQueries(c.get(), { "BEGIN", "SAVEPOINT s", "SET TimeZone TO 'Asia/Kolkata'", "ROLLBACK TO SAVEPOINT s" });
    check_value_hits(admin_conn, c.get(), q3, utc, 1, "SET then ROLLBACK TO SAVEPOINT, inside the transaction");
    executeQueries(c.get(), { "COMMIT" });

    // Other spellings of a tracked SET change the key too.
    const char* q5a = "SELECT TIMESTAMPTZ '2026-11-05 10:00:00+00' AS e5a";
    const char* q5b = "SELECT TIMESTAMPTZ '2026-11-05 10:00:00+00' AS e5b";
    const char* q5c = "SELECT chr(233) AS e5c";
    check_value_hits(admin_conn, plain.get(), q5a, utc, 0, "plain client");
    check_value_hits(admin_conn, plain.get(), q5b, utc, 0, "plain client");
    check_value_hits(admin_conn, plain.get(), q5c, "\xc3\xa9", 0, "plain client");
    {
        PGConnPtr a1 = createNewConnection(ConnType::BACKEND, false);
        PGConnPtr a2 = createNewConnection(ConnType::BACKEND, false);
        PGConnPtr a3 = createNewConnection(ConnType::BACKEND, false);
        executeQueries(a1.get(), { "SET TIME ZONE 'Asia/Kolkata'" });
        check_value_hits(admin_conn, a1.get(), q5a, kol, 0, "SET TIME ZONE");
        executeQueries(a2.get(), { "SET SESSION timezone = 'Asia/Kolkata'" });
        check_value_hits(admin_conn, a2.get(), q5b, kol, 0, "SET SESSION timezone =");
        executeQueries(a3.get(), { "SET NAMES 'LATIN1'" });
        check_value_hits(admin_conn, a3.get(), q5c, "\xe9", 0, "SET NAMES");
    }

    // Two clients that differ from their first query on.
    const char* q6 = "SELECT TIMESTAMPTZ '2026-11-05 10:00:00+00' AS e6";
    {
        PGConnPtr ny = createNewConnection(ConnType::BACKEND, false);
        PGConnPtr in = createNewConnection(ConnType::BACKEND, false);
        executeQueries(ny.get(), { "SET TimeZone TO 'America/New_York'" });
        executeQueries(in.get(), { "SET TimeZone TO 'Asia/Kolkata'" });
        check_value_hits(admin_conn, ny.get(), q6, "2026-11-05 05:00:00-05", 0, "New York client");
        check_value_hits(admin_conn, in.get(), q6, kol, 0, "Kolkata client");
        check_value_hits(admin_conn, plain.get(), q6, utc, 0, "plain client");
    }

    // Value-only check, where a cache miss is acceptable and only the result matters.
    const auto check_value = [](PGconn* conn, const char* query, const std::string& expected, const char* what) {
        const std::string v = single_value(conn, query);
        ok(v == expected, "%s: %s returns '%s'. Got '%s'", what, query, show(expected).c_str(), show(v).c_str());
    };

    // A setting in the startup packet itself (the client_encoding conninfo keyword), not via options.
    const char* s1 = "SELECT chr(233) AS s1";
    {
        PGConnPtr enc = createNewConnection(ConnType::BACKEND, false, "client_encoding=LATIN1");
        PGConnPtr enc2 = createNewConnection(ConnType::BACKEND, false, "client_encoding=LATIN1");
        check_value_hits(admin_conn, plain.get(), s1, "\xc3\xa9", 0, "plain client");
        check_value_hits(admin_conn, enc.get(), s1, "\xe9", 0, "startup client_encoding=LATIN1");
        check_value_hits(admin_conn, plain.get(), s1, "\xc3\xa9", 1, "plain client again");
        check_value_hits(admin_conn, enc2.get(), s1, "\xe9", 1, "second client with startup client_encoding=LATIN1");
    }

    // Settings above PGSQL_NAME_LAST_LOW_WM given at connect time.
    const char* s2a = "SELECT 'ab'::bytea AS s2a";
    const char* s2b = "SELECT 0.1::float8 + 0.2::float8 AS s2b";
    {
        PGConnPtr bo = createNewConnection(ConnType::BACKEND, false, "options='-c bytea_output=escape'");
        PGConnPtr fd = createNewConnection(ConnType::BACKEND, false, "options='-c extra_float_digits=0'");
        check_value_hits(admin_conn, plain.get(), s2a, "\\x6162", 0, "plain client");
        check_value_hits(admin_conn, bo.get(), s2a, "ab", 0, "connect-time bytea_output=escape");
        check_value_hits(admin_conn, plain.get(), s2a, "\\x6162", 1, "plain client again");
        check_value_hits(admin_conn, plain.get(), s2b, "0.30000000000000004", 0, "plain client");
        check_value_hits(admin_conn, fd.get(), s2b, "0.3", 0, "connect-time extra_float_digits=0");
        check_value_hits(admin_conn, plain.get(), s2b, "0.30000000000000004", 1, "plain client again");
    }

    // A setting above PGSQL_NAME_LAST_LOW_WM that was never set, set to its default, set and
    // then RESET. RESET with no connect-time value makes it "never set" again: plain's entry.
    const char* s3 = "SELECT 'ab'::bytea AS s3";
    {
        PGConnPtr x = createNewConnection(ConnType::BACKEND, false);
        PGConnPtr y = createNewConnection(ConnType::BACKEND, false);
        check_value_hits(admin_conn, plain.get(), s3, "\\x6162", 0, "plain client, bytea_output never set");
        executeQueries(x.get(), { "SET bytea_output TO hex" });
        check_value(x.get(), s3, "\\x6162", "bytea_output set to its default");
        executeQueries(y.get(), { "SET bytea_output TO escape" });
        check_value_hits(admin_conn, y.get(), s3, "ab", 0, "bytea_output set to escape");
        executeQueries(y.get(), { "RESET bytea_output" });
        check_value_hits(admin_conn, y.get(), s3, "\\x6162", 1, "bytea_output RESET with no connect-time value");
    }

    // The same value given at connect time or set later: both correct.
    const char* s5 = "SELECT TIMESTAMPTZ '2026-11-05 10:00:00+00' AS s5";
    {
        PGConnPtr z = createNewConnection(ConnType::BACKEND, false, "options='-c TimeZone=Asia/Tokyo'");
        PGConnPtr w = createNewConnection(ConnType::BACKEND, false);
        executeQueries(w.get(), { "SET TimeZone TO 'Asia/Tokyo'" });
        check_value(z.get(), s5, "2026-11-05 19:00:00+09", "connect-time TimeZone=Asia/Tokyo");
        check_value(w.get(), s5, "2026-11-05 19:00:00+09", "TimeZone set to Asia/Tokyo after connecting");
    }

    executeQueries(admin_conn, {
        "DELETE FROM pgsql_query_rules",
        "LOAD PGSQL QUERY RULES TO RUNTIME"
        });
}

std::vector<std::pair<std::string, void (*)(PGconn*, PGconn*)>> tests = {
	{ "Basic Test", execute_basic_test },
	{ "Data Manipulation Test", execute_data_manipulation_test },
	{ "Multi Statement Test", execute_multi_statement_test },
	{ "Threshold Resultset Size Test", execute_threshold_resultset_size_test },
	{ "Multi Threaded Test", execute_multi_threaded_test },
	{ "Multi Threaded Purge Test", execute_multi_threaded_purge_test },
	{ "Transaction Status Test", execute_transaction_status_test },
    { "Query Cache Store Empty Result Test", execute_query_cache_store_empty_result_test },
    { "Query Cache Store Notice Result Test", execute_query_cache_notice_test },
	{ "Prepared Statement Test", execute_prepared_test },
	{ "Search Path Test", execute_search_path_test },
	{ "Result Settings Test", execute_result_settings_test },
	{ "Settings Edge Test", execute_settings_edge_test },
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
    if (cl.getEnv())
        return exit_status();

	spawn_internal_noise(cl, internal_noise_mysql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}});
	spawn_internal_noise(cl, internal_noise_prometheus_poller);
	spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}});

	if (cl.use_noise) {
		plan(309*2 + 3);
	} else {
		plan(309*2);
	}

    execute_tests(false, false);
	execute_tests(false, true);

    return exit_status();
}
