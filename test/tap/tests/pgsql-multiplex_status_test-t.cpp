/**
 * @file pgsql-multiplex_status_test-t.cpp
 * @brief TAP test verifying ProxySQL session status flags that control multiplexing behavior.
 * 
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
#include "json.hpp"

typedef unsigned int Oid;
using nlohmann::json;

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType {
    ADMIN,
    BACKEND
};

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
        fprintf(stderr, "Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

// Fatal error if query fails
void check_result(PGresult* res, PGconn* conn) {
    ExecStatusType st = PQresultStatus(res);
    if (st != PGRES_TUPLES_OK && st != PGRES_COMMAND_OK) {
        diag("FATAL: %s",PQerrorMessage(conn));
        PQclear(res);
		throw std::runtime_error("Query execution failed");
    }
}

void executeQuery(PGconn* conn, const std::string& query) {
    diag("Executing: %s", query.c_str());
    PGresult* res = PQexec(conn, query.c_str());
	check_result(res, conn);
    PQclear(res);
}

// Forward declaration for the new has_lock signature
bool has_lock(PGconn* conn, const std::string& locktype, const std::string& mode, Oid reloid = 0, bool granted = true);

// Get OID for a relation by name
Oid get_rel_oid(PGconn* conn, const std::string& relname) {
    std::string q = "SELECT oid FROM pg_class WHERE relname = '" + relname + "';";
    PGresult* res = PQexec(conn, q.c_str());
    check_result(res, conn);
    if (PQntuples(res) == 0) {
        PQclear(res);
        throw std::runtime_error("Relation " + relname + " not found");
    }
    Oid oid = std::stoul(PQgetvalue(res, 0, 0));
    PQclear(res);
    return oid;
}

// Return true if a lock matching criteria exists (with optional relation OID)
bool has_lock(PGconn* conn,
    const std::string& locktype,
    const std::string& mode,
    Oid reloid,
    bool granted)
{
    std::string q =
        "SELECT count(*) FROM pg_locks WHERE pid = pg_backend_pid() "
        "AND locktype = '" + locktype + "' "
        "AND mode = '" + mode + "' "
        "AND granted = " + (granted ? "true" : "false");

    // Add relation filter if valid OID is provided and locktype is relation or tuple
    if (reloid != 0 && (locktype == "relation" || locktype == "tuple")) {
        q += " AND relation = " + std::to_string(reloid);
    }
    q += ";";

    PGresult* res = PQexec(conn, q.c_str());
    check_result(res, conn);
    int count = std::stoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    return count > 0;
}

bool get_proxysql_lock_status(PGconn* conn, const std::string& type) {
    try {
        PGresult* res = PQexec(conn, "PROXYSQL INTERNAL SESSION;");
        check_result(res, conn);
        const std::string json_str = PQgetvalue(res, 0, 0);
        PQclear(res);
        const json& j = json::parse(json_str);

        if (!j.contains("backends") || !j["backends"].is_array() || j["backends"].empty()) {
            return false;
        }

        const auto& backend = j["backends"][0];
        if (!backend.contains("conn") || !backend["conn"].contains("status")) {
            return false;
        }

        const auto& status = backend["conn"]["status"];
        if (!status.contains(type) || !status[type].is_boolean()) {
            return false;
        }

        return status[type].get<bool>();
    }
    catch (...) {
        return false;
    }
}

bool get_proxysql_is_multiplex_disabled(PGconn* conn) {
    try {
        PGresult* res = PQexec(conn, "PROXYSQL INTERNAL SESSION;");
        check_result(res, conn);
        const std::string json_str = PQgetvalue(res, 0, 0);
        PQclear(res);
        const json& j = json::parse(json_str);

        if (!j.contains("backends") || !j["backends"].is_array() || j["backends"].empty()) {
            return false;
        }

        const auto& backend = j["backends"][0];
        if (!backend.contains("conn") || !backend["conn"].contains("MultiplexDisabled")) {
            return false;
        }

        const auto& multiplex = backend["conn"]["MultiplexDisabled"];
        if (!multiplex.is_boolean()) {
            return false;
        }

        return multiplex.get<bool>();
    }
    catch (...) {
        return false;
    }
}

// 1. Table lock modes
void test_table_locks(Oid test_table_oid) {
    const char* modes[] = {
        "ACCESS SHARE",
        "ROW SHARE",
        "ROW EXCLUSIVE",
        "SHARE UPDATE EXCLUSIVE",
        "SHARE",
        "SHARE ROW EXCLUSIVE",
        "EXCLUSIVE",
        "ACCESS EXCLUSIVE"
    };

    PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, "", false);
    if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
        diag("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    try {
        PGconn* conn = backend_conn.get();
        for (int i = 0; i < 8; ++i) {
            std::string mode_sql = modes[i];
            std::string mode_pg = modes[i];
            // Remove space for pg_locks.mode matching (e.g. "AccessShareLock")
            std::string mode_lock = mode_sql;
            for (auto& c : mode_lock) if (c == ' ') c = '\0';
            // map to the exact mode name used internally:
            // AccessShareLock, RowShareLock, RowExclusiveLock, ShareUpdateExclusiveLock,
            // ShareLock, ShareRowExclusiveLock, ExclusiveLock, AccessExclusiveLock
            static std::string names[] = {
                "AccessShareLock",
                "RowShareLock",
                "RowExclusiveLock",
                "ShareUpdateExclusiveLock",
                "ShareLock",
                "ShareRowExclusiveLock",
                "ExclusiveLock",
                "AccessExclusiveLock"
            };
            executeQuery(conn, "BEGIN;");
            ok(!has_lock(conn, "relation", names[i], test_table_oid),
                ("No " + std::string(names[i]) + " before LOCK TABLE").c_str());
            ok(!get_proxysql_lock_status(conn, "lock_tables"), "No 'lock_tables' in ProxySQL before LOCK TABLE");
            executeQuery(conn, ("LOCK TABLE test_table IN " + mode_sql + " MODE;").c_str());
            ok(has_lock(conn, "relation", names[i], test_table_oid),
                (names[i] + " acquired via LOCK TABLE " + mode_sql).c_str());
            ok(get_proxysql_lock_status(conn, "lock_tables"), "'lock_tables' in ProxySQL after LOCK TABLE");
            executeQuery(conn, "COMMIT;");
            ok(!has_lock(conn, "relation", names[i], test_table_oid),
                (names[i] + " released after COMMIT").c_str());
            ok(!get_proxysql_lock_status(conn, "lock_tables"), "No 'lock_tables' in ProxySQL after COMMIT");
        }
    }
    catch (const std::exception& e) {
        diag("Exception during table locks test: %s", e.what());
        ok(false, "Table locks test failed");
    }
}

// 2. Advisory locks
void test_advisory_locks() {
    PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, "", false);
    if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
        diag("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    try {
        PGconn* conn = backend_conn.get();
        // Session advisory
        ok(!get_proxysql_lock_status(conn, "advisory_lock"), "No 'advisory_lock' in ProxySQL");
        executeQuery(conn, "SELECT pg_advisory_lock(111);");
        ok(has_lock(conn, "advisory", "ExclusiveLock"),
            "Session advisory lock 111 acquired");
        ok(get_proxysql_lock_status(conn, "advisory_lock"), "'advisory_lock' in ProxySQL After SELECT pg_advisory_lock(111)");
        executeQuery(conn, "SELECT pg_advisory_unlock(111);");
        ok(!has_lock(conn, "advisory", "ExclusiveLock"),
            "Session advisory lock 111 released");
        ok(get_proxysql_lock_status(conn, "advisory_lock"), "'advisory_lock' in ProxySQL After SELECT pg_advisory_unlock(111)");
        executeQuery(conn, "SELECT pg_advisory_unlock_all();");
        ok(!has_lock(conn, "advisory", "ExclusiveLock"),
            "Session advisory all locks released");
        ok(!get_proxysql_lock_status(conn, "advisory_lock"), "No 'advisory_lock' in ProxySQL After SELECT pg_advisory_unlock_all()");

		// Session advisory 2
        executeQuery(conn, "SELECT pg_advisory_lock(222);");
        ok(has_lock(conn, "advisory", "ExclusiveLock"),
            "Session advisory lock 222 acquired");
        ok(get_proxysql_lock_status(conn, "advisory_lock"), "'advisory_lock' in ProxySQL After SELECT pg_advisory_lock(222)");
        executeQuery(conn, "DISCARD ALL;");
        ok(!has_lock(conn, "advisory", "ExclusiveLock"),
            "Session advisory all locks released");
        ok(!get_proxysql_lock_status(conn, "advisory_lock"), "No 'advisory_lock' in ProxySQL After DISCARD ALL");


        // Xact advisory
        ok(!get_proxysql_lock_status(conn, "advisory_xact_lock"), "No 'advisory_xact_lock' in ProxySQL");
        executeQuery(conn, "BEGIN;");
        executeQuery(conn, "SELECT pg_advisory_xact_lock(222);");
        ok(has_lock(conn, "advisory", "ExclusiveLock"),
            "Xact advisory lock 222 acquired");
        ok(get_proxysql_lock_status(conn, "advisory_xact_lock"), "'advisory_xact_lock' in ProxySQL After SELECT pg_advisory_xact_lock(222)");
        executeQuery(conn, "COMMIT;");
        ok(!has_lock(conn, "advisory", "ExclusiveLock"),
            "Xact advisory lock 222 released after COMMIT");
        ok(!get_proxysql_lock_status(conn, "advisory_xact_lock"), "No 'advisory_xact_lock' in ProxySQL After COMMIT");
    }
    catch (const std::exception& e) {
        diag("Exception during advisory locks test: %s", e.what());
        ok(false, "Advisory locks test failed");
    }
}

// 3. Advisory lock cleanup on session close
void test_advisory_session_cleanup() {

    try {
        {
            PGConnPtr conn = createNewConnection(ConnType::BACKEND, "", false);
            if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
                diag("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
				throw std::runtime_error("Failed to connect for advisory session cleanup test");
            }
            executeQuery(conn.get(), "SELECT pg_advisory_lock(333);");
            ok(has_lock(conn.get(), "advisory", "ExclusiveLock"),
                "Session advisory lock 333 acquired");
			ok(get_proxysql_lock_status(conn.get(), "advisory_lock"), "'advisory_lock' in ProxySQL after SELECT pg_advisory_lock(333)");
        }
        {
            // reconnect and count any lingering advisory locks for this PID
            PGConnPtr conn2 = createNewConnection(ConnType::BACKEND, "", false);
            if (!conn2 || PQstatus(conn2.get()) != CONNECTION_OK) {
                diag("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
				throw std::runtime_error("Failed to reconnect for advisory session cleanup test");
            }
            PGresult* r = PQexec(conn2.get(),
                "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND granted AND pid=pg_backend_pid();");
            check_result(r, conn2.get());
            int cnt = std::stoi(PQgetvalue(r, 0, 0));
            PQclear(r);
            ok(cnt == 0,
                "Session advisory lock 333 auto-released on disconnect");
			ok(!get_proxysql_lock_status(conn2.get(), "advisory_lock"), "No 'advisory_lock' in ProxySQL after session disconnect");
        }
    }
    catch (const std::exception& e) {
        diag("Exception during advisory session cleanup test: %s", e.what());
        ok(false, "Advisory session cleanup test failed");
    }
}

// 4. Temp table lock tracking
void test_temp_table() {
    PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, "", false);
    if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
        diag("Error: failed to connect for temp table test");
        return;
    }

    try {
        PGconn* conn = backend_conn.get();

        ok(!get_proxysql_lock_status(conn, "temporary_table"), "No 'temporary_table' in ProxySQL before CREATE TEMP TABLE");
        executeQuery(conn, "CREATE TEMP TABLE temp_test(id INT);");
        ok(get_proxysql_lock_status(conn, "temporary_table"), "'temporary_table' in ProxySQL after CREATE TEMP TABLE");

        executeQuery(conn, "DROP TABLE temp_test;");
        ok(get_proxysql_lock_status(conn, "temporary_table"), "'temporary_table' still present after DROP TEMP TABLE");

        executeQuery(conn, "DISCARD TEMP;");
        ok(!get_proxysql_lock_status(conn, "temporary_table"), "'temporary_table' cleared after DISCARD TEMP");

        // Second case: test DISCARD TEMPORARY
        executeQuery(conn, "CREATE TEMP TABLE temp_test2(id INT);");
        ok(get_proxysql_lock_status(conn, "temporary_table"), "'temporary_table' in ProxySQL after second CREATE TEMP TABLE");

        executeQuery(conn, "DISCARD TEMPORARY;");
        ok(!get_proxysql_lock_status(conn, "temporary_table"), "'temporary_table' cleared after DISCARD TEMPORARY");
    }
    catch (const std::exception& e) {
        diag("Exception during temp table lock test: %s", e.what());
        ok(false, "Temp table lock test failed");
    }
}

// 5. Sequence tracking
void test_sequence() {
    PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, "", false);
    if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
        diag("Error: failed to connect for sequence lock test");
        return;
    }

    try {
        PGconn* conn = backend_conn.get();

        ok(!get_proxysql_lock_status(conn, "has_sequences"), "No 'has_sequences' in ProxySQL before CREATE SEQUENCE");

        executeQuery(conn, "CREATE SEQUENCE test_seq;");
        ok(get_proxysql_lock_status(conn, "has_sequences"), "'has_sequences' in ProxySQL after CREATE SEQUENCE");

        executeQuery(conn, "DROP SEQUENCE test_seq;");
        ok(get_proxysql_lock_status(conn, "has_sequences"), "'has_sequences' still present after DROP SEQUENCE");

        executeQuery(conn, "DISCARD SEQUENCES;");
        ok(!get_proxysql_lock_status(conn, "has_sequences"), "'has_sequences' cleared after DISCARD SEQUENCES");
    }
    catch (const std::exception& e) {
        diag("Exception during sequence lock test: %s", e.what());
        ok(false, "Sequence lock test failed");
    }
}

// 6. Query Rules - Multiplex
void test_query_rules_multiplex() {
    PGConnPtr admin_conn = createNewConnection(ConnType::ADMIN, "", false);
    if (!admin_conn || PQstatus(admin_conn.get()) != CONNECTION_OK) {
        diag("Error: failed to connect to admin for query rules - multiplex test");
        return;
    }

    PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, "", false);
    if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
        diag("Error: failed to connect to backend for query rules - multiplex test");
        return;
    }

    try {
        PGconn* admin = admin_conn.get();
        PGconn* backend = backend_conn.get();
        // Clean up any existing rules
        executeQuery(admin, "DELETE FROM pgsql_query_rules WHERE rule_id > 1000;");
        // Add rules to enable/disable multiplexing for SELECT queries
        executeQuery(admin,
            "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, apply, multiplex) "
            "VALUES (1001, 1, '^SELECT 9998', 1, 0);");
        executeQuery(admin,
            "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, apply, multiplex) "
            "VALUES (1002, 1, '^SELECT 9999', 1, 1);");
        executeQuery(admin, "LOAD PGSQL QUERY RULES TO RUNTIME;");

		executeQuery(backend, "SELECT 9998");

		ok(get_proxysql_is_multiplex_disabled(backend), "'multiplex' disabled for 'SELECT 9998'");

        executeQuery(backend, "SELECT 9999");

        ok(!get_proxysql_is_multiplex_disabled(backend), "'multiplex' enabled for 'SELECT 9999'");

        // Clean up: remove the rule
        executeQuery(admin, "DELETE FROM pgsql_query_rules WHERE rule_id > 1000;");
        executeQuery(admin, "LOAD PGSQL QUERY RULES TO RUNTIME;");
    }
    catch (const std::exception& e) {
        diag("Exception during query rules - multiplex test: %s", e.what());
        ok(false, "Query rules - multiplex test failed");
    }
}

int main(int argc, char** argv) {

    if (cl.getEnv())
        return exit_status();

    plan(80);
    
    PGConnPtr conn = createNewConnection(ConnType::BACKEND, "", false);
    if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
        BAIL_OUT("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return exit_status();
    }

    // Setup: create TEMP table in main
    executeQuery(conn.get(), "DROP TABLE IF EXISTS test_table;");
    executeQuery(conn.get(), "CREATE TABLE test_table (id SERIAL PRIMARY KEY, value TEXT);");

    // Get OID of test_table
    Oid test_table_oid = get_rel_oid(conn.get(), "test_table");
    diag("test_table OID: %u", test_table_oid);

    test_table_locks(test_table_oid);
    test_advisory_locks();
    test_advisory_session_cleanup();
	test_temp_table();
	test_sequence();
    test_query_rules_multiplex();
    executeQuery(conn.get(), "DROP TABLE test_table;");
    return exit_status();
}
