/**
  * @file pgsql-query_cache_soft_ttl_pct-t.cpp
  * @brief This test verifies that query cache entries are refreshed upon reaching the soft TTL.
  * @details The test sets up a query rule with caching and configures the global variable
  * `pgsql-query_cache_soft_ttl_pct`. It then executes a query: "SELECT PG_SLEEP(1)",
  * and creates four threads to execute this same query once the soft TTL has been reached.
  * Finally, it checks that only one of the threads has hit the hostgroup by examining
  * the execution time of each thread and querying the "stats_pgsql_query_digest" table.
  */
#include <unistd.h>
#include <map>
#include <sstream>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

#define NUM_QUERIES	3
#define NUM_THREADS 8

double timer_results[NUM_THREADS];
const char* DUMMY_QUERY = "SELECT PG_SLEEP(1)";

CommandLine cl;

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

PGconn* createNewConnection(ConnType conn_type, bool with_ssl) {
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
        return nullptr;
    }
    return conn;
}

void runDummyQuery(double* timer_result) {
    std::unique_ptr<PGconn, decltype(&PQfinish)> pg_conn(createNewConnection(BACKEND, false), &PQfinish);
    if (!pg_conn) {
        *timer_result = -1.0;
        return;
    }

    for (int i = 0; i < NUM_QUERIES; i++) {
        // execute the query at 1.4 , 2.8 and 4.2 second
        // Running 3 queries we verify:
        // 1. the cache before the threshold
        // 2. the cache after the threshold
        // 3. that the cache has been refreshed
        usleep(1400000);  // Sleep for 1.4 seconds

        Timer stopwatch;
        PGresult* res = PQexec(pg_conn.get(), DUMMY_QUERY);
        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            diag("Failed to execute query `%s`: %s", DUMMY_QUERY, PQerrorMessage(pg_conn.get()));
            *timer_result = -1.0;
            PQclear(res);
            return;
        }
        *timer_result += stopwatch.elapsed();
        PQclear(res);
    }
}

const std::string STATS_QUERY_DIGEST =
"SELECT hostgroup, SUM(count_star) FROM stats_pgsql_query_digest "
"WHERE digest_text = 'SELECT PG_SLEEP(?)' GROUP BY hostgroup";

std::map<std::string, int> getDigestStatsDummyQuery(PGconn* proxy_admin) {
    diag("Running: %s", STATS_QUERY_DIGEST.c_str());
    PGresult* res = PQexec(proxy_admin, STATS_QUERY_DIGEST.c_str());

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        diag("Failed to execute query `%s`: %s", STATS_QUERY_DIGEST.c_str(), PQerrorMessage(proxy_admin));
        PQclear(res);
        return {};
    }

    std::map<std::string, int> stats{ {"cache", 0}, {"hostgroups", 0} }; // {hostgroup, count_star}
    int nRows = PQntuples(res);

    for (int i = 0; i < nRows; i++) {
        stats[atoi(PQgetvalue(res, i, 0)) == -1 ? "cache" : "hostgroups"] = atoi(PQgetvalue(res, i, 1));
    }

    diag("Queries hitting the cache:     %d", stats["cache"]);
    diag("Queries NOT hitting the cache: %d", stats["hostgroups"]);
    PQclear(res);
    return stats;
}

void executeTests(bool with_ssl) {
    std::unique_ptr<PGconn, decltype(&PQfinish)> pg_admin_conn(createNewConnection(ADMIN, with_ssl), &PQfinish);
    if (!pg_admin_conn) return;

    std::vector<std::string> admin_queries = {
        "DELETE FROM pgsql_query_rules",
        "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)",
        "LOAD PGSQL QUERY RULES TO RUNTIME",
        "UPDATE global_variables SET variable_value=50 WHERE variable_name='pgsql-query_cache_soft_ttl_pct'",
        "LOAD PGSQL VARIABLES TO RUNTIME",
    };

    for (const auto& query : admin_queries) {
        diag("Running: %s", query.c_str());
        PGresult* res = PQexec(pg_admin_conn.get(), query.c_str());
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            diag("Failed to execute query `%s`: %s", query.c_str(), PQerrorMessage(pg_admin_conn.get()));
            PQclear(res);
            return;
        }
        PQclear(res);
    }

    auto stats_before = getDigestStatsDummyQuery(pg_admin_conn.get());

    std::unique_ptr<PGconn, decltype(&PQfinish)> pg_conn(createNewConnection(BACKEND, with_ssl), &PQfinish);
    if (!pg_conn) return;

    diag("Running: %s", DUMMY_QUERY);
    PGresult* res = PQexec(pg_conn.get(), DUMMY_QUERY);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        diag("Failed to execute query `%s`: %s", DUMMY_QUERY, PQerrorMessage(pg_conn.get()));
        PQclear(res);
        return;
    }
    PQclear(res);

    std::vector<std::thread> mythreads(NUM_THREADS);
    for (unsigned int i = 0; i < NUM_THREADS; i++) {
        mythreads[i] = std::thread(runDummyQuery, &timer_results[i]);
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

    int expected_num_slow_clients = 1;
    ok(num_slow_clients == expected_num_slow_clients,
        "Only one client should take 1 second to execute the query. "
        "Expected: '%d', Actual: '%d'", expected_num_slow_clients, num_slow_clients);

    auto stats_after = getDigestStatsDummyQuery(pg_admin_conn.get());

    std::map<std::string, int> expected_stats{ {"cache", NUM_THREADS * NUM_QUERIES - 1}, {"hostgroups", 2} };
    ok(
        expected_stats["cache"] == stats_after["cache"] - stats_before["cache"],
        "Query cache should have been hit %d times. Number of hits - Expected: '%d', Actual: '%d'",
        expected_stats["cache"], expected_stats["cache"], stats_after["cache"] - stats_before["cache"]
    );
    ok(
        expected_stats["hostgroups"] == stats_after["hostgroups"] - stats_before["hostgroups"],
        "Hostgroups should have been hit %d times. Number of hits - Expected: '%d', Actual: '%d'",
        expected_stats["hostgroups"], expected_stats["hostgroups"],
        stats_after["hostgroups"] - stats_before["hostgroups"]
    );
}

int main(int argc, char** argv) {

    plan(3); // Total number of tests planned

    if (cl.getEnv())
        return exit_status();

    executeTests(false); // without SSL

    return exit_status();
}

