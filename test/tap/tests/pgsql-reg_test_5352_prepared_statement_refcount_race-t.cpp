// NOSONAR - TAP test files do not need to follow the same rules as production code
/**
 * @file pgsql-reg_test_5352_prepared_statement_refcount_race-t.cpp
 * @brief This TAP test reproduces and verifies the fix for the atomic refcount race condition
 *        in PgSQL_PreparedStatement.cpp where the purge thread could crash due to
 *        memory_order_relaxed not seeing concurrent refcount modifications.
 */


#include <sstream>
#include <thread>
#include <atomic>
#include <vector>
#include <memory>
#include <libpq-fe.h>
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

constexpr int NUM_WORKER_THREADS = 3;
constexpr int MAX_ITERATIONS = 2000;
constexpr int CREATE_PHASE = 1500;
constexpr int CACHE_LIMIT = 1024;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType {
	ADMIN,
	BACKEND
};

/**
 * Create a new PostgreSQL connection to ProxySQL
 */
PGConnPtr createNewConnection(ConnType conn_type, const std::string& options = "", bool with_ssl = false) {

	const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
	int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
	const char* username = (conn_type == BACKEND) ? cl.pgsql_root_username : cl.admin_username;
	const char* password = (conn_type == BACKEND) ? cl.pgsql_root_password : cl.admin_password;

	std::stringstream ss;

	ss << "host=" << host << " port=" << port;
	ss << " user=" << username << " password=" << password;
	ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

	if (options.empty() == false) {
		ss << " options='" << options << "'";
	}

	PGconn* conn = PQconnectdb(ss.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		fprintf(stderr, "Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
		PQfinish(conn);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

/**
 * Execute a prepared statement using libpq extended query protocol
 * PQprepare -> PQexecPrepared -> PQclear
 */
bool execute_prepared_stmt(PGConnPtr& conn_ptr, const std::string& stmt_name,
						   const std::string& query, const std::vector<const char*>& param_values = {}) {

	PGconn* conn = conn_ptr.get();
	// Parse (prepare the statement)
	PGresult* prep_res = PQprepare(conn, stmt_name.c_str(), query.c_str(),
								   static_cast<int>(param_values.size()), nullptr);
	if (PQresultStatus(prep_res) != PGRES_COMMAND_OK) {
		fprintf(stderr, "PQprepare failed for '%s': %s\n",
				stmt_name.c_str(), PQerrorMessage(conn));
		PQclear(prep_res);
		return false;
	}
	PQclear(prep_res);

	// Execute the prepared statement
	PGresult* exec_res = nullptr;
	if (!param_values.empty()) {
		std::vector<int> param_lengths;
		std::vector<int> param_formats;
		for (const char* val : param_values) {
			param_lengths.push_back(val ? static_cast<int>(strlen(val)) : 0);
			param_formats.push_back(0);  // text format
		}
		exec_res = PQexecPrepared(conn, stmt_name.c_str(),
								  static_cast<int>(param_values.size()),
								  param_values.data(),
								  param_lengths.data(),
								  param_formats.data(), 0);
	} else {
		exec_res = PQexecPrepared(conn, stmt_name.c_str(), 0, nullptr, nullptr, nullptr, 0);
	}

	bool success = (PQresultStatus(exec_res) == PGRES_TUPLES_OK ||
					PQresultStatus(exec_res) == PGRES_COMMAND_OK);
	if (!success) {
		fprintf(stderr, "PQexecPrepared failed for '%s': %s\n",
				stmt_name.c_str(), PQerrorMessage(conn));
	}
	PQclear(exec_res);

	return success;
}

/**
 * Close a prepared statement using DEALLOCATE
 */
bool close_prepared_stmt(PGConnPtr& conn_ptr, const std::string& stmt_name) {
	PGconn* conn = conn_ptr.get();
	std::string deallocate_query = "DEALLOCATE \"" + stmt_name + "\"";
	PGresult* res = PQexec(conn, deallocate_query.c_str());
	bool success = (PQresultStatus(res) == PGRES_COMMAND_OK);
	PQclear(res);
	return success;
}

/**
 * Close ALL prepared statements for this connection
 * This ensures ref_count_client drops to 0 for all statements
 */
bool close_all_prepared_stmts(PGConnPtr& conn_ptr) {
	PGconn* conn = conn_ptr.get();
	// DEALLOCATE ALL closes all prepared statements on this connection
	PGresult* res = PQexec(conn, "DEALLOCATE ALL");
	bool success = (PQresultStatus(res) == PGRES_COMMAND_OK);
	PQclear(res);
	return success;
}

/**
 * Worker thread that rapidly creates and closes prepared statements
 * This simulates the race condition where:
 * 1. Client thread increments ref_count_client
 * 2. Purge thread checks ref_count_client
 * 3. Without proper memory ordering, the read may see stale data
 */
void worker_thread(int thread_id, std::atomic<int>* ready_flag,
				   std::atomic<int>* stop_flag, std::atomic<int>* error_count) {
	// Wait for all threads to be ready
	while (ready_flag->load(std::memory_order_acquire) < NUM_WORKER_THREADS) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}

	auto conn = createNewConnection(BACKEND);

	if (!conn) {
		error_count->fetch_add(1, std::memory_order_relaxed);
		return;
	}

	int iterations = 0;

	// Phase 1: Create many statements WITHOUT closing to build up the cache
	// This ensures map_size > max_stmts_cache (1024)
	// IMPORTANT: Each statement must have a DIFFERENT query to avoid de-duplication

	while (!stop_flag->load(std::memory_order_acquire) && iterations < MAX_ITERATIONS) {
		iterations++;

		// Use unique statement names AND different queries
		// ProxySQL deduplicates by query hash, so we need different queries
		char stmt_name[64];
		char query[128];
		snprintf(stmt_name, sizeof(stmt_name), "test_stmt_t%d_i%d", thread_id, iterations);
		snprintf(query, sizeof(query), "SELECT 't%d-i%d'", thread_id, iterations);

		// Create and execute a prepared statement using extended query protocol
		if (!execute_prepared_stmt(conn, stmt_name, query, {})) {
			// Don't fail immediately - might have connection issues
		}

		// Phase 1: Don't close any statements - let the cache grow
		// Phase 2: After create_phase, close every statement to trigger refcount churn
		if (iterations > CREATE_PHASE) {
			close_prepared_stmt(conn, stmt_name);

			// Every 50 iterations in Phase 2, close ALL statements
			// This forces ref_count_client to 0 for all statements on this connection
			// and triggers the purge race condition
			if (iterations % 50 == 0) {
				close_all_prepared_stmts(conn);
			}
		}

		// Small delay to allow context switches (increases race window)
		if (iterations % 20 == 0) {
			std::this_thread::sleep_for(std::chrono::microseconds(100));
		}

		// Reconnect periodically to keep connection fresh
		if (iterations % 200 == 0) {
			conn = createNewConnection(BACKEND);
			if (!conn) {
				error_count->fetch_add(1, std::memory_order_relaxed);
				break;
			}
		}
	}

	diag("Thread %d completed %d iterations", thread_id, iterations);
}

/**
 * Execute an SQL query via libpq (simple query protocol)
 */
bool execute_simple_query(PGConnPtr& conn_ptr, const std::string& query) {
	PGconn* conn = conn_ptr.get();
	PGresult* res = PQexec(conn, query.c_str());
	bool success = (PQresultStatus(res) == PGRES_TUPLES_OK ||
					PQresultStatus(res) == PGRES_COMMAND_OK);
	if (!success) {
		fprintf(stderr, "Query failed '%s': %s\n", query.c_str(), PQerrorMessage(conn));
	}
	PQclear(res);
	return success;
}

/**
 * Test 1: Concurrent prepared statement creation/destruction
 * This reproduces the race condition where:
 * 1. Multiple threads create/close prepared statements rapidly via extended query protocol
 * 2. Purge thread runs concurrently (triggered by ref_count_client operations)
 * 3. Without memory_order_acquire, the assertion could fail
 */
bool test_concurrent_prepared_statements() {
	diag("=== Test 1: Concurrent Prepared Statements (Race Condition Test) ===");

	std::vector<std::thread> threads;
	std::atomic<int> ready_flag { 0 };
	std::atomic<int> stop_flag { 0 };
	std::atomic<int> error_count { 0 };

	// First, configure ProxySQL to lower the cache limit to trigger purges more frequently
	auto admin_conn = createNewConnection(ADMIN);
	if (!admin_conn) {
		diag("Failed to configure admin interface - using defaults");
		return false;
	} 

	// Set max_stmts_cache to 1024 (minimum value to trigger frequent purges)
	// This ensures that after 1024+ unique statements, purges will be triggered
	if (execute_simple_query(admin_conn,
			"SET pgsql-max_stmts_cache=1024")) {
		execute_simple_query(admin_conn, "LOAD PGSQL VARIABLES TO RUNTIME");
		diag("Configured pgsql-max_stmts_cache = 1024 for testing");
	}

	// Get initial prepared statement stats
	PGresult* res = PQexec(admin_conn.get(),
		"SELECT COUNT(*) as stmt_count, "
		"SUM(ref_count_client) as total_ref_client, "
		"SUM(ref_count_server) as total_ref_server "
		"FROM stats_pgsql_prepared_statements_info");
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		const char* count = PQgetvalue(res, 0, 0);
		const char* ref_client = PQgetvalue(res, 0, 1);
		const char* ref_server = PQgetvalue(res, 0, 2);
		diag("Initial prepared statement stats:");
		diag("  Total statements: %s", count);
		diag("  Total ref_count_client: %s", ref_client);
		diag("  Total ref_count_server: %s", ref_server);
	}
	PQclear(res);

	// Create a backend connection to ProxySQL 
	auto backend_conn = createNewConnection(BACKEND);
	if (!backend_conn) {
		diag("FAIL: Could not create check connection - possible crash!");
		return false;
	}

	diag("Starting %d worker threads to stress test prepared statement refcounts", NUM_WORKER_THREADS);

	// Launch worker threads
	for (int i = 0; i < NUM_WORKER_THREADS; i++) {
		threads.emplace_back(worker_thread, i, &ready_flag, &stop_flag, &error_count);
		ready_flag.fetch_add(1, std::memory_order_release);
	}

	// Let threads run for a while
	// The race condition should manifest within this time if the bug exists
	// Extended duration to ensure purge has time to trigger multiple times
	std::this_thread::sleep_for(std::chrono::seconds(45));

	// Signal threads to stop
	stop_flag.store(1, std::memory_order_release);

	// Wait for all threads to complete
	for (auto& t : threads) {
		t.join();
	}

	diag("All worker threads completed. Error count: %d", error_count.load(std::memory_order_relaxed));

	// Verify that purges actually happened by checking prepared statement stats
	diag("=== Verifying purge behavior ===");

	// First, just get the count
	res = PQexec(admin_conn.get(), "SELECT COUNT(*) FROM stats_pgsql_prepared_statements_info");

	int stmt_count = 0;
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		const char* count = PQgetvalue(res, 0, 0);
		stmt_count = atoi(count);
		diag("Final statement count: %d", stmt_count);
	} else {
		diag("FAIL: Could not query prepared statement stats: %s", PQerrorMessage(admin_conn.get()));
		return false;
	}
	PQclear(res);

	// try to get more details
	res = PQexec(admin_conn.get(),
		"SELECT SUM(ref_count_client) as total_ref_client, "
		"SUM(ref_count_server) as total_ref_server "
		"FROM stats_pgsql_prepared_statements_info");

	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		const char* total_client = PQgetvalue(res, 0, 0);
		const char* total_server = PQgetvalue(res, 0, 1);
		diag("  Total ref_count_client: %s", total_client);
		diag("  Total ref_count_server: %s", total_server);
	} else {
		diag("FAIL: Could not get detailed stats: %s", PQerrorMessage(admin_conn.get()));
		return false;
	}
	PQclear(res);
	

	// Verify purge mechanism by creating enough statements to exceed cache limit
	// This forces a purge to trigger, verifying purge logic works correctly
	diag("=== Purge Verification: Active Cache Limit Enforcement ===");
	bool purge_verified = false;

	int stmt_count_before = 0;
	res = PQexec(admin_conn.get(), "SELECT COUNT(*) FROM stats_pgsql_prepared_statements_info");
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		stmt_count_before = atoi(PQgetvalue(res, 0, 0));
	}
	PQclear(res);

	diag("Cache limit (pgsql-max_stmts_cache): %d", CACHE_LIMIT);
	diag("Statements before purge test: %d", stmt_count_before);

	// Calculate how many statements to create to exceed cache limit by ~20%
	// This ensures we trigger a purge even if some statements are deduplicated
	int needed = CACHE_LIMIT + 200 - stmt_count_before;
	if (needed < 200) needed = 200; // Create at least 200 statements
	diag("Creating %d new statements to exceed cache limit and trigger purge...", needed);

	// Create unique statements with different queries to force cache to exceed limit
	// This triggers purge mechanism
	int created = 0;
	for (int i = 0; i < needed; i++) {
		char stmt_name[64];
		char query[128];
		snprintf(stmt_name, sizeof(stmt_name), "verify_stmt_%d", i);
		snprintf(query, sizeof(query), "SELECT %d::int,'unique_%d'", i, i);

		if (execute_prepared_stmt(backend_conn, stmt_name, query, {})) {
			created++;
		}
	}

	// The purge mechanism has a 1-second minimum interval between attempts
	// (see PgSQL_PreparedStatement.cpp: ref_count_client___purge_stmts_if_needed).
	// Close the verification connection to drop ref_count_client to 0 for all
	// statements we just created, making them eligible for purge.
	backend_conn.reset();

	// Wait for the purge interval to elapse
	std::this_thread::sleep_for(std::chrono::seconds(3));

	// Open a new connection and trigger a refcount change so the purge fires
	backend_conn = createNewConnection(BACKEND);
	if (!backend_conn) {
		diag("FAIL: Could not create purge-trigger backend connection");
		return false;
	}
	if (!execute_prepared_stmt(backend_conn, "purge_trigger", "SELECT 'trigger_purge'", {})) {
		diag("FAIL: Could not execute purge-trigger prepared statement");
		return false;
	}
	if (!close_prepared_stmt(backend_conn, "purge_trigger")) {
		diag("FAIL: Could not deallocate purge-trigger prepared statement");
		return false;
	}

	// Check how many statements remain after forcing a purge
	int stmt_count_after = 0;
	res = PQexec(admin_conn.get(), "SELECT COUNT(*) FROM stats_pgsql_prepared_statements_info");
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		stmt_count_after = atoi(PQgetvalue(res, 0, 0));
		int purged = stmt_count_before + created - stmt_count_after;

		diag("Cache limit enforcement test results:");
		diag("  Statements before test: %d", stmt_count_before);
		diag("  New statements created: %d", created);
		diag("  Statements after test: %d", stmt_count_after);
		diag("  Statements purged: %d", purged);

		// Verify purge occurred:
		// 1. Final count is at/below cache limit (enforcement worked)
		// 2. At least some statements were purged (mechanism activated)
		if (stmt_count_after <= CACHE_LIMIT) {
			diag("PASS: Cache limit ENFORCED - final count (%d) <= limit (%d)",
				stmt_count_after, CACHE_LIMIT);
			purge_verified = true;
		} else {
			diag("WARN: Cache limit NOT enforced - final count (%d) exceeds limit (%d)",
				stmt_count_after, CACHE_LIMIT);
			purge_verified = false;
		}

		if (purged > 0) {
			diag("PASS: Purge mechanism ACTIVATED - %d statements purged", purged);
		} else {
			diag("INFO: No statements were purged (count may not have exceeded limit during test)");
		}
	} else {
		diag("FAIL: Could not query statement count after creating verification statements: %s",
				PQerrorMessage(admin_conn.get()));
		return false;
	}
	PQclear(res);
	

	ok(purge_verified, "Purge mechanism is WORKING");

	if (error_count.load(std::memory_order_relaxed) > 0) {
		diag("FAIL: Some worker threads encountered errors");
		return false;
	}

	diag("PASS: Concurrent prepared statement test completed without crashes");
	return true;
}

/**
 * Test 2: Verify prepared statement refcount tracking via admin interface
 */
bool test_refcount_tracking() {
	diag("=== Test 2: Verify Prepared Statement Refcount Tracking ===");

	auto admin_conn = createNewConnection(ADMIN);
	if (!admin_conn) {
		diag("Failed to connect to admin interface");
		return false;
	}

	// Create some prepared statements
	auto conn = createNewConnection(BACKEND);

	if (!conn) {
		return false;
	}

	// Create 10 prepared statements
	for (int i = 0; i < 10; i++) {
		char stmt_name[64];
		snprintf(stmt_name, sizeof(stmt_name), "track_stmt_%d", i);
		std::string param_val = std::to_string(i);
		const char* param = param_val.c_str();
		execute_prepared_stmt(conn, stmt_name, "SELECT $1::int,'1024x968'", { param }); // unique query
	}

	// Check the prepared statement stats
	PGresult* res = PQexec(admin_conn.get(),
		"SELECT COUNT(*), SUM(ref_count_client), SUM(ref_count_server) "
		"FROM stats_pgsql_prepared_statements_info");

	int before_ref_client_count = 0;

	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		const char* count = PQgetvalue(res, 0, 0);
		const char* ref_client = PQgetvalue(res, 0, 1);
		const char* ref_server = PQgetvalue(res, 0, 2);

		before_ref_client_count = atoi(ref_client);
		diag("Prepared statement stats: count=%s, ref_count_client=%s, ref_count_server=%s",
			count, ref_client, ref_server);
	}
	PQclear(res);

	conn.reset(); // Close the connection, should drop ref_count_client to 0

	std::this_thread::sleep_for(std::chrono::seconds(2)); // Wait for stats to update

	int after_ref_client_count = 0;
	// Check stats after closing client connection
	res = PQexec(admin_conn.get(),
		"SELECT SUM(ref_count_client) FROM stats_pgsql_prepared_statements_info");
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		const char* ref_client = PQgetvalue(res, 0, 0);
		after_ref_client_count = atoi(ref_client);
	}
	PQclear(res);

	ok(before_ref_client_count - after_ref_client_count == 10, "ref_count_client after disconnect:%d", after_ref_client_count);
	return true;
}

int main(int argc, char** argv) {
	plan(4);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// Test 1: Concurrent access (reproduces the race condition)
	bool test1_passed = test_concurrent_prepared_statements();
	ok(test1_passed, "Test 1: Concurrent prepared statements (race condition reproduction)");

	// Test 2: Verify refcount tracking
	bool test2_passed = test_refcount_tracking();
	ok(test2_passed, "Test 2: Verify prepared statement refcount tracking");

	return exit_status();
}
