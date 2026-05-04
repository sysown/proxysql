/**
 * @file pgsql-transaction_variable_state_tracking-t.cpp
 * @brief TAP test validating PostgreSQL session parameter behavior in transactions.
 * Tests rollback/commit/savepoint behavior for session variables to ensure state consistency.
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <sys/select.h>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using PGResultPtr = std::unique_ptr<PGresult, decltype(&PQclear)>;

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

struct TestCase {
    std::string name;
    std::function<bool()> test_fn;
    bool should_fail;
};

struct TestVariable {
    std::string name;
    std::vector<std::string> test_values;
};

std::vector<TestCase> tests;

PGResultPtr executeQuery(PGconn* conn, const std::string& query) {
    diag("Executing: %s", query.c_str());
    PGresult* res = PQexec(conn, query.c_str());
    if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK) {
        diag("Query failed: %s", PQerrorMessage(conn));
    }
    return PGResultPtr(res, &PQclear);
}

std::string getVariable(PGconn* conn, const std::string& var) {
    auto res = executeQuery(conn, ("SHOW " + var));
    const std::string& val = std::string(PQgetvalue(res.get(), 0, 0));
    diag(">> '%s' = '%s'", var.c_str(), val.c_str());
    return val;
}

void reset_variable(PGconn* conn, const std::string& var, const std::string& original) {
    executeQuery(conn, "SET " + var + " = " + original);
}

void add_test(const std::string& name, std::function<bool()> fn, bool should_fail = false) {
    tests.push_back({ name, fn, should_fail });
}

void run_tests() {
    
    for (const auto& test : tests) {
        bool result = false;

        try {
            result = test.test_fn();
            if (test.should_fail) result = !result;
        }
        catch (const std::exception& e) {
            result = false;
        }

		ok(result, "Test:%s should %s", test.name.c_str(), test.should_fail ? "FAIL" : "PASS");
    }
}

// Common test scenarios
bool test_transaction_rollback(const TestVariable& var) {
    auto conn = createNewConnection(ConnType::BACKEND, "", false);
    const auto original = getVariable(conn.get(), var.name);

    bool success = true;

    for (const auto& val : var.test_values) {
        executeQuery(conn.get(), "BEGIN");
        executeQuery(conn.get(), "SET " + var.name + " = " + val);
        executeQuery(conn.get(), "ROLLBACK");

        success = getVariable(conn.get(), var.name) == original;
        if (!success)
            break;
    }

    return success;
}

bool test_transaction_abort(const TestVariable& var) {
    auto conn = createNewConnection(ConnType::BACKEND, "", false);
    const auto original = getVariable(conn.get(), var.name);

    bool success = true;

    for (const auto& val : var.test_values) {
        executeQuery(conn.get(), "START TRANSACTION");
        executeQuery(conn.get(), "SET " + var.name + " = " + val);
        executeQuery(conn.get(), "ABORT");

        success = getVariable(conn.get(), var.name) == original;
        if (!success)
            break;
    }
    return success;
}

bool test_savepoint_rollback(const TestVariable& var) {
    auto conn = createNewConnection(ConnType::BACKEND, "", false);
    const auto original = getVariable(conn.get(), var.name);

    bool success = true;

    for (const auto& val : var.test_values) {
        executeQuery(conn.get(), "BEGIN");
        executeQuery(conn.get(), "SAVEPOINT sp1");
        executeQuery(conn.get(), "SET " + var.name + " = " + val);
        executeQuery(conn.get(), "ROLLBACK TO sp1");
        executeQuery(conn.get(), "COMMIT");

        success = getVariable(conn.get(), var.name) == original;
        if (!success)
            break;
    }
    return success;
}

bool test_transaction_commit(const TestVariable& var, const std::map<std::string, std::string>& original_values) {
    auto conn = createNewConnection(ConnType::BACKEND, "", false);
    
    bool success = true;
    
    for (const auto& val : var.test_values) {
        executeQuery(conn.get(), "BEGIN");
        executeQuery(conn.get(), "SET " + var.name + " = " + val);
        executeQuery(conn.get(), "COMMIT");

        success = getVariable(conn.get(), var.name) == val;
        if (!success)
            break;
    }
    reset_variable(conn.get(), var.name, original_values.at(var.name));
    return success;
}

bool test_savepoint_commit(const TestVariable& var, const std::map<std::string, std::string>& original_values) {
    auto conn = createNewConnection(ConnType::BACKEND, "", false);
    bool success = true;

    for (const auto& val : var.test_values) {
        executeQuery(conn.get(), "BEGIN");
        executeQuery(conn.get(), "SAVEPOINT sp1");
        executeQuery(conn.get(), "SET " + var.name + " = " + val);
        executeQuery(conn.get(), "RELEASE SAVEPOINT sp1");
        executeQuery(conn.get(), "COMMIT");

        success = getVariable(conn.get(), var.name) == val;
        if (!success)
            break;
    }
    reset_variable(conn.get(), var.name, original_values.at(var.name));
    return success;
}

bool test_savepoint_release_commit(const TestVariable& var, const std::map<std::string, std::string>& original_values) {
    auto conn = createNewConnection(ConnType::BACKEND, "", false);
    const auto original = getVariable(conn.get(), var.name);
    executeQuery(conn.get(), "BEGIN");
    executeQuery(conn.get(), "SET " + var.name + " = " + var.test_values[0]);
    executeQuery(conn.get(), "SAVEPOINT sp1");
    executeQuery(conn.get(), "SET " + var.name + " = " + var.test_values[1]);
    executeQuery(conn.get(), "RELEASE SAVEPOINT sp1");
    executeQuery(conn.get(), "COMMIT");
    const bool success = getVariable(conn.get(), var.name) == var.test_values[1];
    reset_variable(conn.get(), var.name, original_values.at(var.name));
    return success;
}

bool has_warnings = false;

void notice_processor(void* arg, const char* message) {
    diag("NOTICE: %s", message);
	has_warnings = true;
}

bool test_transaction_rollback_and_chain(const TestVariable& var) {
    auto conn = createNewConnection(ConnType::BACKEND, "", false);
    PQsetNoticeProcessor(conn.get(), notice_processor, NULL);

    const auto original = getVariable(conn.get(), var.name);

    bool success = true;

    for (const auto& val : var.test_values) {

        executeQuery(conn.get(), "START TRANSACTION");
        executeQuery(conn.get(), "SET " + var.name + " = " + val);
        executeQuery(conn.get(), "ROLLBACK AND CHAIN");

		char tran_stat = PQtransactionStatus(conn.get());

        if (tran_stat != PQTRANS_INTRANS) {
            diag("Expected transaction status INTRANS after ROLLBACK AND CHAIN, got %d", tran_stat);
            success = false;
            break;
		}

        success = getVariable(conn.get(), var.name) == original;
        if (success) {
            executeQuery(conn.get(), "ROLLBACK");
            tran_stat = PQtransactionStatus(conn.get());
            if (tran_stat != PQTRANS_IDLE) {
                diag("Expected transaction status IDLE after ROLLBACK, got %d", tran_stat);
                success = false;
                break;
            }

            if (has_warnings == false)
                success = getVariable(conn.get(), var.name) == original;
            else
                success = false;
        }
        if (!success)
            break;
    }

    return success;
}

int main(int argc, char** argv) {

    if (cl.getEnv())
        return exit_status();

    std::map<std::string, std::string> original_values;
    std::map<std::string, TestVariable> tracked_vars = {
        {"client_encoding", {"client_encoding", {"LATIN1", "UTF8"}}},
        {"datestyle", {"datestyle", {"ISO, MDY", "SQL, DMY"}}},
        {"intervalstyle", {"intervalstyle", {"postgres", "iso_8601"}}},
        {"standard_conforming_strings", {"standard_conforming_strings", {"on", "off"}}},
        {"timezone", {"timezone", {"UTC", "PST8PDT"}}},
        {"bytea_output", {"bytea_output", {"hex", "escape"}}},
        {"enable_mergejoin", {"enable_mergejoin", {"on", "off"}}},
        {"enable_bitmapscan", {"enable_bitmapscan", {"on", "off"}}},
        {"enable_hashjoin", {"enable_hashjoin", {"on", "off"}}},
        {"enable_indexscan", {"enable_indexscan", {"on", "off"}}},
        {"enable_nestloop", {"enable_nestloop", {"on", "off"}}},
        {"enable_seqscan", {"enable_seqscan", {"on", "off"}}},
        {"enable_sort", {"enable_sort", {"on", "off"}}},
        {"escape_string_warning", {"escape_string_warning", {"on", "off"}}},
        {"synchronous_commit", {"synchronous_commit", {"on", "off"}}},
        {"extra_float_digits", {"extra_float_digits", {"0", "3"}}},
        {"client_min_messages", {"client_min_messages", {"notice", "warning"}}}
    };


    PGConnPtr conn = createNewConnection(ConnType::BACKEND, "", false);
    if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
        BAIL_OUT("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return exit_status();
    }

    // Store original values
    for (const auto& [name, var] : tracked_vars) {
        original_values[name] = getVariable(conn.get(), name);
    }


    // Add generic tests
    add_test("Commit without transaction should fail", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        PGresult* res = PQexec(conn.get(), "COMMIT");
        const bool failed = PQresultStatus(res) != PGRES_COMMAND_OK;
        PQclear(res);
        return failed;
        }, true);

    // Add variable-specific tests using containers
    for (const auto& [name, var] : tracked_vars) {
        add_test("Rollback reverts " + var.name, [var]() {
            return test_transaction_rollback(var);
            });

		add_test("Abort reverts " + var.name, [var]() {
            return test_transaction_abort(var);
			});

        add_test("Commit persists " + var.name, [&]() {
            return test_transaction_commit(var, original_values);
            });

        add_test("Savepoint rollback for " + var.name, [var]() {
            return test_savepoint_rollback(var);
            });

        add_test("Savepoint commit for " + var.name, [&]() {
            return test_savepoint_commit(var, original_values);
            });

		add_test("Rollback and chain for " + var.name, [var]() {
			return test_transaction_rollback_and_chain(var);
			});

        // Multi-value savepoint test
        if (var.test_values.size() > 1) {
           add_test("Multi-value savepoint for " + var.name, [&]() {
                return test_savepoint_release_commit(var, original_values);
                });
        }
    }

    // Add complex scenario tests
    add_test("Nested BEGIN with rollback", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        const auto original_tz = getVariable(conn.get(), "timezone");

        executeQuery(conn.get(), "BEGIN");
        executeQuery(conn.get(), "SET timezone = 'UTC'");
        executeQuery(conn.get(), "BEGIN");  // Second BEGIN
        executeQuery(conn.get(), "SET timezone = 'PST8PDT'");
        executeQuery(conn.get(), "ROLLBACK");

        const bool success = getVariable(conn.get(), "timezone") == original_tz;
        return success;
        });

    add_test("Mixed variables in transaction", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        bool success = true;

        executeQuery(conn.get(), "BEGIN");
        for (const auto& [name, var] : tracked_vars) {
            executeQuery(conn.get(), "SET " + var.name + " = " + var.test_values[0]);
        }
        executeQuery(conn.get(), "ROLLBACK");

        for (const auto& [name, var] : tracked_vars) {
            success = (getVariable(conn.get(), var.name) == original_values.at(var.name));
        }
        return success;
        });

    add_test("Mixed variables in transaction (ROLLBACK AND CHAIN)", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        bool success = true;

        executeQuery(conn.get(), "BEGIN");
        for (const auto& [name, var] : tracked_vars) {
            executeQuery(conn.get(), "SET " + var.name + " = " + var.test_values[0]);
        }
        executeQuery(conn.get(), "ROLLBACK AND CHAIN");

        for (const auto& [name, var] : tracked_vars) {
            success = (getVariable(conn.get(), var.name) == original_values.at(var.name));
        }
        return success;
        });

    // Test: ROLLBACK AND CHAIN with savepoints - verifies savepoint snapshots are cleaned
    add_test("ROLLBACK AND CHAIN with savepoints", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);

        const auto original = getVariable(conn.get(), "DateStyle");

        // Start transaction and set initial value
        executeQuery(conn.get(), "BEGIN");
        executeQuery(conn.get(), "SET DateStyle = 'Postgres, DMY'");

        // Create savepoints (these create snapshots in transaction_state)
        executeQuery(conn.get(), "SAVEPOINT sp1");
        executeQuery(conn.get(), "SET DateStyle = 'SQL, DMY'");
        executeQuery(conn.get(), "SAVEPOINT sp2");
        executeQuery(conn.get(), "SET DateStyle = 'ISO, MDY'");

        // ROLLBACK AND CHAIN should clear all savepoint snapshots
        executeQuery(conn.get(), "ROLLBACK AND CHAIN");

        // Verify we're still in a transaction
        char tran_stat = PQtransactionStatus(conn.get());
        if (tran_stat != PQTRANS_INTRANS) {
            diag("Expected INTRANS after ROLLBACK AND CHAIN, got %d", tran_stat);
            executeQuery(conn.get(), "ROLLBACK");
            return false;
        }

        // Verify DateStyle was reset to original (before BEGIN)
        bool datestyle_ok = (getVariable(conn.get(), "DateStyle") == original);

        // Now test that we can create new savepoints (this would fail if stale snapshots remained)
        executeQuery(conn.get(), "SAVEPOINT sp_after_chain");
        executeQuery(conn.get(), "SET DateStyle = 'Postgres, DMY'");

        // Rollback to savepoint
        executeQuery(conn.get(), "ROLLBACK TO SAVEPOINT sp_after_chain");

        // Final cleanup
        executeQuery(conn.get(), "ROLLBACK");

        return datestyle_ok;
    });

    add_test("Prepared ROLLBACK statement", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);

        executeQuery(conn.get(), "SET client_encoding = 'LATIN1'");
        const auto original = getVariable(conn.get(), "client_encoding");

        executeQuery(conn.get(), "BEGIN");
        executeQuery(conn.get(), "SET client_encoding = 'UTF8'");

        {
            diag(">>> Create Prepared Statement [stmt_client_encoding]: ROLLBACK");
            PGResultPtr res(PQprepare(conn.get(), "stmt_client_encoding", "ROLLBACK", 0, NULL), &PQclear);
            if (PQresultStatus(res.get()) != PGRES_COMMAND_OK) {
                diag("Prepare failed: %s", PQerrorMessage(conn.get()));
                return false;
            }
        }

        bool success = getVariable(conn.get(), "client_encoding") == "UTF8";

        if (!success) {
            diag("client_encoding not set to UTF8 as expected");
            return false;
		}

        {
            diag(">>> Executing Prepared Statement [stmt_client_encoding]: ROLLBACK");
			PGResultPtr res(PQexecPrepared(conn.get(), "stmt_client_encoding", 0, NULL, NULL, NULL, 0), &PQclear);
            if (PQresultStatus(res.get()) != PGRES_COMMAND_OK) {
                diag("Execute failed: %s", PQerrorMessage(conn.get()));
                return false;
            }
        }

        success = getVariable(conn.get(), "client_encoding") == original;
        if (!success) {
            diag("client_encoding not restored after ROLLBACK");
            return false;
        }

        return success;
	});

    add_test("Prepared ROLLBACK statement 2", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);

        executeQuery(conn.get(), "SET standard_conforming_strings = off");
        const auto original = getVariable(conn.get(), "standard_conforming_strings");

        executeQuery(conn.get(), "BEGIN");
        executeQuery(conn.get(), "SET standard_conforming_strings = on");

        {
            diag(">>> Create Prepared Statement [stmt_standard_conforming_strings]: ROLLBACK");
            PGResultPtr res(PQprepare(conn.get(), "stmt_standard_conforming_strings", "ROLLBACK", 0, NULL), &PQclear);
            if (PQresultStatus(res.get()) != PGRES_COMMAND_OK) {
                diag("Prepare failed: %s", PQerrorMessage(conn.get()));
                return false;
            }
        }

        bool success = getVariable(conn.get(), "standard_conforming_strings") == "on";

        if (!success) {
            diag("standard_conforming_strings not set to 'on' as expected");
            return false;
        }

        {
            diag(">>> Executing Prepared Statement [stmt_standard_conforming_strings]: ROLLBACK");
            PGResultPtr res(PQexecPrepared(conn.get(), "stmt_standard_conforming_strings", 0, NULL, NULL, NULL, 0), &PQclear);
            if (PQresultStatus(res.get()) != PGRES_COMMAND_OK) {
                diag("Execute failed: %s", PQerrorMessage(conn.get()));
                return false;
            }
        }

        success = getVariable(conn.get(), "standard_conforming_strings") == original;
        if (!success) {
            diag("standard_conforming_strings not restored after ROLLBACK");
            return false;
        }

        return success;
        });

    add_test("Prepared ROLLBACK TO SAVEPOINT statement", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        const auto original = getVariable(conn.get(), "client_encoding");

        executeQuery(conn.get(), "BEGIN");
        executeQuery(conn.get(), "SET client_encoding = 'UTF8'");
        executeQuery(conn.get(), "SAVEPOINT sp1");
        executeQuery(conn.get(), "SET client_encoding = 'LATIN1'");

        {
			diag(">>> Create Prepared Statement [stmt_rollback_sp]: ROLLBACK TO SAVEPOINT sp1");
            PGResultPtr res(PQprepare(conn.get(), "stmt_rollback_sp", "ROLLBACK TO SAVEPOINT sp1", 0, NULL), &PQclear);
            if (PQresultStatus(res.get()) != PGRES_COMMAND_OK) {
                diag("Prepare failed: %s", PQerrorMessage(conn.get()));
                return false;
            }
        }

        // Before executing prepared rollback, client_encoding should be 'LATIN1'
        bool success = getVariable(conn.get(), "client_encoding") == "LATIN1";
        if (!success) {
            diag("client_encoding not changed to 'LATIN1' before rollback");
            return false;
        }

        {
			diag(">>> Executing Prepared Statement [stmt_rollback_sp]: ROLLBACK TO SAVEPOINT sp1");
            PGResultPtr res(PQexecPrepared(conn.get(), "stmt_rollback_sp", 0, NULL, NULL, NULL, 0), &PQclear);
            if (PQresultStatus(res.get()) != PGRES_COMMAND_OK) {
                diag("Execute failed: %s", PQerrorMessage(conn.get()));
                return false;
            }
        }

        success = getVariable(conn.get(), "client_encoding") == original;
        if (!success) {
            diag("client_encoding not restored after ROLLBACK TO SAVEPOINT");
            return false;
        }

        return true;
        });
    
    add_test("Prepared ROLLBACK TO SAVEPOINT statement 2", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        const auto original = getVariable(conn.get(), "standard_conforming_strings");

        executeQuery(conn.get(), "BEGIN");
        executeQuery(conn.get(), "SET standard_conforming_strings = on");
        executeQuery(conn.get(), "SAVEPOINT sp1");
        executeQuery(conn.get(), "SET standard_conforming_strings = off");

        {
            diag(">>> Create Prepared Statement [stmt_rollback_sp2]: ROLLBACK TO SAVEPOINT sp1");
            PGResultPtr res(PQprepare(conn.get(), "stmt_rollback_sp2", "ROLLBACK TO SAVEPOINT sp1", 0, NULL), &PQclear);
            if (PQresultStatus(res.get()) != PGRES_COMMAND_OK) {
                diag("Prepare failed: %s", PQerrorMessage(conn.get()));
                return false;
            }
        }

        // Before executing prepared rollback, client_encoding should be 'off'
        bool success = getVariable(conn.get(), "standard_conforming_strings") == "off";
        if (!success) {
            diag("standard_conforming_strings not changed to 'off' before rollback");
            return false;
        }

        {
            diag(">>> Executing Prepared Statement [stmt_rollback_sp2]: ROLLBACK TO SAVEPOINT sp1");
            PGResultPtr res(PQexecPrepared(conn.get(), "stmt_rollback_sp2", 0, NULL, NULL, NULL, 0), &PQclear);
            if (PQresultStatus(res.get()) != PGRES_COMMAND_OK) {
                diag("Execute failed: %s", PQerrorMessage(conn.get()));
                return false;
            }
        }

        success = getVariable(conn.get(), "standard_conforming_strings") == original;
        if (!success) {
            diag("standard_conforming_strings not restored after ROLLBACK TO SAVEPOINT");
            return false;
        }
   
        return true;
        });

    // ============================================================================
    // Variable Sync Verification Tests for Simple and Pipeline Mode
    // ============================================================================

    // Test: Verify SET variable sync in SIMPLE query mode
    // This test confirms that when SET is executed in simple query mode,
    // the variable is properly synced to the backend
    add_test("Variable sync: SET in simple query mode", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        // Get original value
        const auto original = getVariable(conn.get(), "DateStyle");
        diag("Original DateStyle: %s", original.c_str());

        // Set a specific value in simple query mode
        const std::string test_value = "Postgres, DMY";
        PGresult* set_res = PQexec(conn.get(), ("SET DateStyle = '" + test_value + "'").c_str());
        bool set_ok = (PQresultStatus(set_res) == PGRES_COMMAND_OK);
        PQclear(set_res);

        if (!set_ok) {
            diag("SET failed: %s", PQerrorMessage(conn.get()));
            return false;
        }

        // Verify client-side value is set
        const auto client_val = getVariable(conn.get(), "DateStyle");
        diag("Client DateStyle after SET: %s", client_val.c_str());

        // Verify value was actually set (not still original)
        bool client_set = (client_val.find(test_value.substr(0, 7)) != std::string::npos);
        if (!client_set) {
            diag("Client value was not set correctly. Got '%s', expected '%s'",
                 client_val.c_str(), test_value.c_str());
            return false;
        }

        // Execute a query to trigger backend sync and verify backend has the value
        // The backend should have the same value if sync worked
        PGresult* sel_res = PQexec(conn.get(), "SELECT 1");
        PQclear(sel_res);

        const auto after_query = getVariable(conn.get(), "DateStyle");
        diag("DateStyle after query: %s", after_query.c_str());

        // Cleanup
        PGresult* cleanup_res2 = PQexec(conn.get(), ("SET DateStyle = '" + original + "'").c_str());
        PQclear(cleanup_res2);

        // In simple mode, SET should be immediately effective
        bool synced = (after_query.find(test_value.substr(0, 7)) != std::string::npos);
        if (!synced) {
            diag("Variable not synced to backend! Got '%s'", after_query.c_str());
        }

        return synced;
    });

    // Test: Verify SET variable sync in PIPELINE mode
    // This test confirms that when SET is executed in pipeline mode,
    // the variable is properly synced to the backend via extended query protocol
    add_test("Variable sync: SET in pipeline mode", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        // Get original value
        const auto original = getVariable(conn.get(), "DateStyle");
        diag("Original DateStyle: %s", original.c_str());

        // Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Set a specific value using extended query protocol
        const std::string test_value = "SQL, DMY";
        std::string set_query = "SET DateStyle = '" + test_value + "'";

        // Send SET via pipeline (extended query protocol)
        if (PQsendQueryParams(conn.get(), set_query.c_str(), 0, NULL, NULL, NULL, NULL, 0) != 1) {
            diag("Failed to send SET in pipeline");
            PQexitPipelineMode(conn.get());
            return false;
        }

        // Send a SELECT to verify the value
        if (PQsendQueryParams(conn.get(), "SHOW DateStyle", 0, NULL, NULL, NULL, NULL, 0) != 1) {
            diag("Failed to send SHOW in pipeline");
            PQexitPipelineMode(conn.get());
            return false;
        }

        // Sync
        if (PQpipelineSync(conn.get()) != 1) {
            diag("PQpipelineSync failed");
            PQexitPipelineMode(conn.get());
            return false;
        }

        // Consume results
        int count = 0;
        int set_success = 0;
        int show_received = 0;
        std::string show_value;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 3) {  // SET result + SHOW result + sync
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed");
                PQexitPipelineMode(conn.get());
                return false;
            }

            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    set_success++;
                    diag("SET succeeded in pipeline");
                } else if (status == PGRES_TUPLES_OK) {
                    show_received++;
                    if (PQntuples(res) > 0) {
                        show_value = PQgetvalue(res, 0, 0);
                        diag("SHOW returned: %s", show_value.c_str());
                    }
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }

            if (count >= 3) break;

            if (!PQisBusy(conn.get())) continue;

            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // Cleanup
        PGresult* cleanup_res = PQexec(conn.get(), ("SET DateStyle = '" + original + "'").c_str());
        PQclear(cleanup_res);

        // Verify results
        if (set_success == 0) {
            diag("SET did not succeed in pipeline");
            return false;
        }
        if (show_received == 0) {
            diag("SHOW did not return value in pipeline");
            return false;
        }

        // Check if the value was properly synced
        bool value_synced = (show_value.find(test_value.substr(0, 3)) != std::string::npos);
        if (!value_synced) {
            diag("Value not synced in pipeline! Got '%s', expected '%s'",
                 show_value.c_str(), test_value.c_str());
        }

        return value_synced;
    });

    // ============================================================================
    // Pipeline Mode Tests for SET Variable Tracking
    // ============================================================================

    // Test: BEGIN + SET + COMMIT in pipeline mode
    add_test("BEGIN + SET + COMMIT in pipeline mode", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        // Get original value and choose DIFFERENT value
        const auto original = getVariable(conn.get(), "datestyle");
        const std::string new_value = (original.find("ISO") != std::string::npos) ?
                                      "SQL, DMY" : "Postgres, MDY";
        diag("BEGIN+SET+COMMIT: original='%s', will SET to='%s'",
             original.c_str(), new_value.c_str());

        // Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Send BEGIN, SET with DIFFERENT value, COMMIT in pipeline
        PQsendQueryParams(conn.get(), "BEGIN", 0, NULL, NULL, NULL, NULL, 0);
        std::string set_query = "SET datestyle = '" + new_value + "'";
        PQsendQueryParams(conn.get(), set_query.c_str(), 0, NULL, NULL, NULL, NULL, 0);
        PQsendQueryParams(conn.get(), "COMMIT", 0, NULL, NULL, NULL, NULL, 0);
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results - using proper pattern to avoid blocking
        int count = 0;
        int cmdCount = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 4) {  // 3 commands + 1 sync
            if (PQconsumeInput(conn.get()) == 0) break;

            // Gate PQgetResult() on PQisBusy() to avoid blocking
            if (PQisBusy(conn.get())) {
                fd_set input_mask;
                FD_ZERO(&input_mask);
                FD_SET(sock, &input_mask);
                struct timeval timeout = {5, 0};
                select(sock + 1, &input_mask, NULL, NULL, &timeout);
                continue;
            }

            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) cmdCount++;
                if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }

            if (count >= 4) break;
        }

        PQexitPipelineMode(conn.get());

        // Verify SET persisted after COMMIT (value should be different from original)
        const auto newVal = getVariable(conn.get(), "datestyle");
        bool value_changed = (newVal.find(new_value) != std::string::npos) &&
                             (newVal != original);

        // Cleanup - restore original
        executeQuery(conn.get(), "SET datestyle = '" + original + "'");

        return value_changed && cmdCount >= 3;
    });

    // Test: BEGIN + SET + ROLLBACK in pipeline mode
    add_test("BEGIN + SET + ROLLBACK in pipeline mode", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        // Get original value and choose DIFFERENT value
        const auto original = getVariable(conn.get(), "timezone");
        const std::string new_value = (original.find("UTC") != std::string::npos) ?
                                      "PST8PDT" : "UTC";
        diag("BEGIN+SET+ROLLBACK: original='%s', will SET to='%s'",
             original.c_str(), new_value.c_str());

        // Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Send BEGIN, SET with DIFFERENT value, ROLLBACK in pipeline
        PQsendQueryParams(conn.get(), "BEGIN", 0, NULL, NULL, NULL, NULL, 0);
        std::string set_query = "SET timezone = '" + new_value + "'";
        PQsendQueryParams(conn.get(), set_query.c_str(), 0, NULL, NULL, NULL, NULL, 0);
        PQsendQueryParams(conn.get(), "ROLLBACK", 0, NULL, NULL, NULL, NULL, 0);
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results
        int count = 0;
        int cmdCount = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 4) {
            if (PQconsumeInput(conn.get()) == 0) break;

            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) cmdCount++;
                if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }

            if (count >= 4) break;

            // Only wait if libpq reports it's busy waiting for more data
            if (!PQisBusy(conn.get())) continue;

            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // Verify ROLLBACK reverted the SET (value should be back to original, not the new value)
        const auto newVal = getVariable(conn.get(), "timezone");
        bool reverted = (newVal == original) && (newVal != new_value);

        return reverted && cmdCount >= 3;
    });

    // Test: Multiple variables in transaction in pipeline mode
    add_test("Multiple variables in transaction in pipeline", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        // Get original values and choose DIFFERENT values
        const auto orig_datestyle = getVariable(conn.get(), "datestyle");
        const auto orig_timezone = getVariable(conn.get(), "timezone");
        const auto orig_bytea = getVariable(conn.get(), "bytea_output");

        // Choose DIFFERENT values from original
        const std::string new_datestyle = (orig_datestyle.find("ISO") != std::string::npos) ?
                                          "Postgres, MDY" : "ISO, DMY";
        const std::string new_timezone = (orig_timezone.find("UTC") != std::string::npos) ?
                                         "EST5EDT" : "UTC";
        const std::string new_bytea = (orig_bytea == "hex") ? "escape" : "hex";

        diag("Multi-var: datestyle orig='%s'->'%s', timezone orig='%s'->'%s', bytea orig='%s'->'%s'",
             orig_datestyle.c_str(), new_datestyle.c_str(),
             orig_timezone.c_str(), new_timezone.c_str(),
             orig_bytea.c_str(), new_bytea.c_str());

        // Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Send BEGIN + multiple SETs (with DIFFERENT values) + COMMIT
        PQsendQueryParams(conn.get(), "BEGIN", 0, NULL, NULL, NULL, NULL, 0);
        std::string set_datestyle = "SET datestyle = '" + new_datestyle + "'";
        std::string set_timezone = "SET timezone = '" + new_timezone + "'";
        std::string set_bytea = "SET bytea_output = '" + new_bytea + "'";
        PQsendQueryParams(conn.get(), set_datestyle.c_str(), 0, NULL, NULL, NULL, NULL, 0);
        PQsendQueryParams(conn.get(), set_timezone.c_str(), 0, NULL, NULL, NULL, NULL, 0);
        PQsendQueryParams(conn.get(), set_bytea.c_str(), 0, NULL, NULL, NULL, NULL, 0);
        PQsendQueryParams(conn.get(), "COMMIT", 0, NULL, NULL, NULL, NULL, 0);
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results
        int count = 0;
        int cmdCount = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 6) {  // 5 commands + 1 sync
            if (PQconsumeInput(conn.get()) == 0) break;

            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) cmdCount++;
                if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }

            if (count >= 6) break;

            // Only wait if libpq reports it's busy waiting for more data
            if (!PQisBusy(conn.get())) continue;

            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // Verify all SETs persisted (values should be the new ones, different from original)
        bool success = true;
        const auto final_datestyle = getVariable(conn.get(), "datestyle");
        const auto final_timezone = getVariable(conn.get(), "timezone");
        const auto final_bytea = getVariable(conn.get(), "bytea_output");

        success &= (final_datestyle.find(new_datestyle) != std::string::npos) && (final_datestyle != orig_datestyle);
        success &= (final_timezone == new_timezone) && (final_timezone != orig_timezone);
        success &= (final_bytea == new_bytea) && (final_bytea != orig_bytea);

        diag("Final values: datestyle='%s' (changed:%s), timezone='%s' (changed:%s), bytea='%s' (changed:%s)",
             final_datestyle.c_str(), (final_datestyle != orig_datestyle) ? "yes" : "no",
             final_timezone.c_str(), (final_timezone != orig_timezone) ? "yes" : "no",
             final_bytea.c_str(), (final_bytea != orig_bytea) ? "yes" : "no");

        // Cleanup
        executeQuery(conn.get(), "SET datestyle = '" + orig_datestyle + "'");
        executeQuery(conn.get(), "SET timezone = '" + orig_timezone + "'");
        executeQuery(conn.get(), "SET bytea_output = '" + orig_bytea + "'");

        return success && cmdCount >= 5;
    });

    // Test: SAVEPOINT with SET in pipeline mode
    add_test("SAVEPOINT with SET in pipeline mode", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        // Get original and choose DIFFERENT values for testing
        const auto original = getVariable(conn.get(), "extra_float_digits");
        // Choose values that are different from original AND different from each other
        const std::string value1 = (original == "0") ? "2" : "0";  // First SET value
        const std::string value2 = (value1 == "2") ? "3" : "2";     // Second SET value (different from value1)

        diag("SAVEPOINT test: original='%s', value1='%s', value2='%s'",
             original.c_str(), value1.c_str(), value2.c_str());

        // Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Send: BEGIN, SET (value1), SAVEPOINT, SET (value2), ROLLBACK TO SAVEPOINT, COMMIT
        // After ROLLBACK TO SAVEPOINT, value should be value1
        // After COMMIT, value should remain value1
        PQsendQueryParams(conn.get(), "BEGIN", 0, NULL, NULL, NULL, NULL, 0);
        std::string set1 = "SET extra_float_digits = " + value1;
        std::string set2 = "SET extra_float_digits = " + value2;
        PQsendQueryParams(conn.get(), set1.c_str(), 0, NULL, NULL, NULL, NULL, 0);
        PQsendQueryParams(conn.get(), "SAVEPOINT sp1", 0, NULL, NULL, NULL, NULL, 0);
        PQsendQueryParams(conn.get(), set2.c_str(), 0, NULL, NULL, NULL, NULL, 0);
        PQsendQueryParams(conn.get(), "ROLLBACK TO SAVEPOINT sp1", 0, NULL, NULL, NULL, NULL, 0);
        PQsendQueryParams(conn.get(), "COMMIT", 0, NULL, NULL, NULL, NULL, 0);
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results
        int count = 0;
        int cmdCount = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 7) {  // 6 commands + 1 sync
            if (PQconsumeInput(conn.get()) == 0) break;

            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) cmdCount++;
                if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }

            if (count >= 7) break;

            // Only wait if libpq reports it's busy waiting for more data
            if (!PQisBusy(conn.get())) continue;

            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // After ROLLBACK TO SAVEPOINT, value should be value1 (first SET), not value2 (second SET)
        // After COMMIT, the first SET persists
        const auto newVal = getVariable(conn.get(), "extra_float_digits");
        bool success = (newVal == value1) && (newVal != original) && (newVal != value2);

        diag("After savepoint rollback: value='%s' (expected='%s', original='%s', value2='%s')",
             newVal.c_str(), value1.c_str(), original.c_str(), value2.c_str());

        // Cleanup
        executeQuery(conn.get(), "SET extra_float_digits = " + original);

        return success && cmdCount >= 6;
    });

    // ============================================================================
    // SET Failure Tests in Pipeline Mode
    // ============================================================================

    // Test: SET failure with invalid value in pipeline - verify error handling
    add_test("SET failure - invalid value in pipeline", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        // Get original value
        const auto original = getVariable(conn.get(), "datestyle");

        // Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Send SET with invalid value
        PQsendQueryParams(conn.get(), "SET datestyle = 'INVALID_STYLE_VALUE'", 0, NULL, NULL, NULL, NULL, 0);
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results
        int count = 0;
        bool got_error = false;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 2) {
            if (PQconsumeInput(conn.get()) == 0) break;

            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_FATAL_ERROR) {
                    got_error = true;
                    diag("Got expected error for invalid datestyle");
                }
                if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }

            if (count >= 2) break;

            // Only wait if libpq reports it's busy waiting for more data
            if (!PQisBusy(conn.get())) continue;

            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // Verify value unchanged (still original)
        const auto afterVal = getVariable(conn.get(), "datestyle");
        bool unchanged = (afterVal == original);

        diag("After invalid SET: value='%s', original='%s', unchanged=%s",
             afterVal.c_str(), original.c_str(), unchanged ? "yes" : "no");

        return got_error && unchanged;
    });

    // Test: SET failure - multiple SETs with one invalid, verify state consistency
    add_test("SET failure - state consistency after partial failure", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        // Get original values and choose DIFFERENT valid values
        const auto orig_datestyle = getVariable(conn.get(), "datestyle");
        const auto orig_timezone = getVariable(conn.get(), "timezone");

        const std::string new_datestyle = (orig_datestyle.find("ISO") != std::string::npos) ?
                                          "Postgres, MDY" : "ISO, DMY";
        const std::string new_timezone = (orig_timezone.find("UTC") != std::string::npos) ?
                                         "PST8PDT" : "UTC";

        diag("Partial failure test: datestyle orig='%s'->'%s', timezone orig='%s'->'%s'",
             orig_datestyle.c_str(), new_datestyle.c_str(),
             orig_timezone.c_str(), new_timezone.c_str());

        // Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Send: valid SET, invalid SET, valid SET
        std::string set1 = "SET datestyle = '" + new_datestyle + "'";
        std::string set3 = "SET timezone = '" + new_timezone + "'";
        PQsendQueryParams(conn.get(), set1.c_str(), 0, NULL, NULL, NULL, NULL, 0);
        PQsendQueryParams(conn.get(), "SET invalid_variable = 'value'", 0, NULL, NULL, NULL, NULL, 0);
        PQsendQueryParams(conn.get(), set3.c_str(), 0, NULL, NULL, NULL, NULL, 0);
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results
        int count = 0;
        int error_count = 0;
        int success_count = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 4) {  // 3 commands + 1 sync
            if (PQconsumeInput(conn.get()) == 0) break;

            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    success_count++;
                } else if (status == PGRES_FATAL_ERROR) {
                    error_count++;
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }

            if (count >= 4) break;

            // Only wait if libpq reports it's busy waiting for more data
            if (!PQisBusy(conn.get())) continue;

            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // After error, connection should still be usable
        const auto final_datestyle = getVariable(conn.get(), "datestyle");
        const auto final_timezone = getVariable(conn.get(), "timezone");

        // At least first SET should have succeeded, middle should fail
        diag("Results: successes=%d, errors=%d, final datestyle='%s', final timezone='%s'",
             success_count, error_count, final_datestyle.c_str(), final_timezone.c_str());

        // Verify connection still works
        PGresult* test_res = PQexec(conn.get(), "SELECT 1");
        bool connection_ok = (PQresultStatus(test_res) == PGRES_TUPLES_OK);
        PQclear(test_res);

        // Cleanup
        executeQuery(conn.get(), "SET datestyle = '" + orig_datestyle + "'");
        executeQuery(conn.get(), "SET timezone = '" + orig_timezone + "'");

        // Expect at least 1 error (the invalid variable), and connection should still work
        return (error_count >= 1) && connection_ok;
    });

    // ============================================================================
    // Mixed Mode Transition Tests (Simple Query <-> Pipeline)
    // ============================================================================

    // Test: Simple query BEGIN -> Pipeline SET -> Simple query ROLLBACK
    add_test("Mixed mode: Simple BEGIN -> Pipeline SET -> Simple ROLLBACK", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "timezone");
        const std::string new_value = (original.find("UTC") != std::string::npos) ?
                                      "PST8PDT" : "UTC";

        diag("Original timezone: '%s', will SET to: '%s'", original.c_str(), new_value.c_str());

        // Step 1: Simple query BEGIN - verify it succeeded
        PGresult* begin_res = PQexec(conn.get(), "BEGIN");
        if (PQresultStatus(begin_res) != PGRES_COMMAND_OK) {
            diag("BEGIN failed: %s", PQerrorMessage(conn.get()));
            PQclear(begin_res);
            return false;
        }
        PQclear(begin_res);
        diag("Step 1: BEGIN succeeded");

        // Step 2: Enter pipeline mode and SET
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            PQexec(conn.get(), "ROLLBACK");  // Cleanup
            return false;
        }

        std::string set_query = "SET timezone = '" + new_value + "'";
        if (PQsendQueryParams(conn.get(), set_query.c_str(), 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send SET query");
            PQexitPipelineMode(conn.get());
            PQexec(conn.get(), "ROLLBACK");  // Cleanup
            return false;
        }
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results - track errors
        int count = 0;
        int cmd_success = 0;
        int errors = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 2) {
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed: %s", PQerrorMessage(conn.get()));
                PQexitPipelineMode(conn.get());
                PQexec(conn.get(), "ROLLBACK");
                return false;
            }
            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    cmd_success++;
                } else if (status == PGRES_FATAL_ERROR) {
                    errors++;
                    diag("Command failed in pipeline: %s", PQresultErrorMessage(res));
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 2) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // Verify SET succeeded
        if (errors > 0 || cmd_success < 1) {
            diag("SET command failed or not completed. successes=%d, errors=%d", cmd_success, errors);
            PQexec(conn.get(), "ROLLBACK");  // Cleanup
            return false;
        }
        diag("Step 2: Pipeline SET succeeded");

        // Step 3: Simple query ROLLBACK
        PGresult* rollback_res = PQexec(conn.get(), "ROLLBACK");
        if (PQresultStatus(rollback_res) != PGRES_COMMAND_OK) {
            diag("ROLLBACK failed: %s", PQerrorMessage(conn.get()));
            PQclear(rollback_res);
            return false;
        }
        PQclear(rollback_res);
        diag("Step 3: ROLLBACK succeeded");

        // Verify ROLLBACK reverted the SET
        const auto final_val = getVariable(conn.get(), "timezone");
        diag("Final timezone after ROLLBACK: '%s', expected: '%s'", final_val.c_str(), original.c_str());
        bool reverted = (final_val == original);

        return reverted;
    });

    // Test: Pipeline BEGIN -> Simple query SET -> Pipeline COMMIT
    add_test("Mixed mode: Pipeline BEGIN -> Simple SET -> Pipeline COMMIT", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "datestyle");
        const std::string new_value = (original.find("ISO") != std::string::npos) ?
                                      "SQL, DMY" : "ISO, MDY";

        // Step 1: Enter pipeline mode and BEGIN
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        PQsendQueryParams(conn.get(), "BEGIN", 0, NULL, NULL, NULL, NULL, 0);
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume BEGIN result
        int count = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 2) {
            if (PQconsumeInput(conn.get()) == 0) break;
            while ((res = PQgetResult(conn.get())) != NULL) {
                if (PQresultStatus(res) == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 2) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // Step 2: Simple query SET
        executeQuery(conn.get(), "SET datestyle = '" + new_value + "'");

        // Step 3: Re-enter pipeline mode and COMMIT
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        PQsendQueryParams(conn.get(), "COMMIT", 0, NULL, NULL, NULL, NULL, 0);
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume COMMIT result
        count = 0;
        while (count < 2) {
            if (PQconsumeInput(conn.get()) == 0) break;
            while ((res = PQgetResult(conn.get())) != NULL) {
                if (PQresultStatus(res) == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 2) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // Verify COMMIT persisted the SET
        const auto final_val = getVariable(conn.get(), "datestyle");
        bool persisted = (final_val.find(new_value) != std::string::npos) && (final_val != original);

        // Cleanup: always restore original setting before returning connection to pool
        executeQuery(conn.get(), "SET datestyle = '" + original + "'");

        return persisted;
    });

    // Test: Simple query transaction -> enter pipeline -> continue transaction
    add_test("Mixed mode: Simple transaction -> Pipeline continuation", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "timezone");
        const std::string value1 = (original.find("UTC") != std::string::npos) ?
                                   "PST8PDT" : "UTC";
        const std::string value2 = (value1 == "UTC") ? "EST5EDT" : "UTC";

        diag("Original: '%s', value1: '%s', value2: '%s'", original.c_str(), value1.c_str(), value2.c_str());

        // Step 1: Simple query BEGIN and first SET
        PGresult* begin_res = PQexec(conn.get(), "BEGIN");
        if (PQresultStatus(begin_res) != PGRES_COMMAND_OK) {
            diag("BEGIN failed");
            PQclear(begin_res);
            return false;
        }
        PQclear(begin_res);

        PGresult* set1_res = PQexec(conn.get(), ("SET timezone = '" + value1 + "'").c_str());
        if (PQresultStatus(set1_res) != PGRES_COMMAND_OK) {
            diag("First SET failed");
            PQclear(set1_res);
            PQexec(conn.get(), "ROLLBACK");
            return false;
        }
        PQclear(set1_res);
        diag("Step 1: BEGIN and first SET succeeded");

        // Step 2: Enter pipeline mode for second SET and COMMIT
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            PQexec(conn.get(), "ROLLBACK");
            return false;
        }

        std::string set_query = "SET timezone = '" + value2 + "'";
        if (PQsendQueryParams(conn.get(), set_query.c_str(), 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), "COMMIT", 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send queries");
            PQexitPipelineMode(conn.get());
            PQexec(conn.get(), "ROLLBACK");
            return false;
        }
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results
        int count = 0;
        int set2_success = 0;
        int commit_success = 0;
        int errors = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 3) {
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed");
                PQexitPipelineMode(conn.get());
                return false;
            }
            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    if (set2_success == 0 && commit_success == 0) {
                        set2_success++;
                        diag("Second SET succeeded");
                    } else {
                        commit_success++;
                        diag("COMMIT succeeded");
                    }
                } else if (status == PGRES_FATAL_ERROR) {
                    errors++;
                    diag("Command failed: %s", PQresultErrorMessage(res));
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 3) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        if (errors > 0) {
            diag("Errors in pipeline: %d", errors);
            return false;
        }
        if (set2_success < 1 || commit_success < 1) {
            diag("Missing results: SET2=%d, COMMIT=%d", set2_success, commit_success);
            return false;
        }

        // Verify final value is value2 (second SET persisted)
        const auto final_val = getVariable(conn.get(), "timezone");
        diag("Final value: '%s', expected: '%s'", final_val.c_str(), value2.c_str());
        bool success = (final_val == value2);

        // Cleanup: always restore original setting before returning connection to pool
        executeQuery(conn.get(), "SET timezone = '" + original + "'");

        return success;
    });

    // Test: Pipeline transaction -> exit pipeline -> simple query ROLLBACK
    add_test("Mixed mode: Pipeline start -> Simple ROLLBACK", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "datestyle");
        const std::string new_value = (original.find("ISO") != std::string::npos) ?
                                      "SQL, DMY" : "ISO, MDY";

        diag("Original: '%s', will SET to: '%s'", original.c_str(), new_value.c_str());

        // Step 1: Enter pipeline mode, BEGIN, SET, then exit
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        std::string set_query = "SET datestyle = '" + new_value + "'";
        if (PQsendQueryParams(conn.get(), "BEGIN", 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), set_query.c_str(), 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send queries");
            PQexitPipelineMode(conn.get());
            return false;
        }
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results
        int count = 0;
        int begin_success = 0;
        int set_success = 0;
        int errors = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 3) {
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed");
                PQexitPipelineMode(conn.get());
                return false;
            }
            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    if (begin_success == 0) {
                        begin_success++;
                        diag("BEGIN succeeded");
                    } else {
                        set_success++;
                        diag("SET succeeded");
                    }
                } else if (status == PGRES_FATAL_ERROR) {
                    errors++;
                    diag("Command failed: %s", PQresultErrorMessage(res));
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 3) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        if (errors > 0) {
            diag("Errors in pipeline: %d", errors);
            return false;
        }
        if (begin_success < 1 || set_success < 1) {
            diag("Missing results: BEGIN=%d, SET=%d", begin_success, set_success);
            return false;
        }

        // Step 2: Simple query ROLLBACK
        PGresult* rollback_res = PQexec(conn.get(), "ROLLBACK");
        if (PQresultStatus(rollback_res) != PGRES_COMMAND_OK) {
            diag("ROLLBACK failed: %s", PQerrorMessage(conn.get()));
            PQclear(rollback_res);
            return false;
        }
        PQclear(rollback_res);
        diag("Step 2: ROLLBACK succeeded");

        // Verify ROLLBACK reverted the SET
        const auto final_val = getVariable(conn.get(), "datestyle");
        bool reverted = (final_val == original);

        return reverted;
    });

    // ============================================================================
    // Complex Pipeline Scenarios
    // ============================================================================

    // Test: Multiple pipeline sync points within transaction
    add_test("Pipeline: Multiple sync points in transaction", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "timezone");
        const std::string value1 = (original.find("UTC") != std::string::npos) ?
                                   "PST8PDT" : "UTC";
        const std::string value2 = (value1 == "UTC") ? "EST5EDT" : "UTC";

        diag("Original: '%s', value1: '%s', value2: '%s'", original.c_str(), value1.c_str(), value2.c_str());

        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // First batch: BEGIN + SET
        std::string set1 = "SET timezone = '" + value1 + "'";
        if (PQsendQueryParams(conn.get(), "BEGIN", 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), set1.c_str(), 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send first batch");
            PQexitPipelineMode(conn.get());
            return false;
        }
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume first sync point
        int count = 0;
        int batch1_ok = 0;
        int errors = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 3) {
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed in batch 1");
                PQexitPipelineMode(conn.get());
                return false;
            }
            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    batch1_ok++;
                } else if (status == PGRES_FATAL_ERROR) {
                    errors++;
                    diag("Batch 1 error: %s", PQresultErrorMessage(res));
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 3) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        // Check first batch succeeded
        if (errors > 0 || batch1_ok < 2) {
            diag("Batch 1 failed: ok=%d, errors=%d", batch1_ok, errors);
            PQexitPipelineMode(conn.get());
            return false;
        }
        diag("Batch 1 succeeded (BEGIN + SET)");

        // Second batch: SET + COMMIT
        std::string set2 = "SET timezone = '" + value2 + "'";
        if (PQsendQueryParams(conn.get(), set2.c_str(), 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), "COMMIT", 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send second batch");
            PQexitPipelineMode(conn.get());
            return false;
        }
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume second sync point
        count = 0;
        int batch2_ok = 0;
        errors = 0;
        while (count < 3) {
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed in batch 2");
                PQexitPipelineMode(conn.get());
                return false;
            }
            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    batch2_ok++;
                } else if (status == PGRES_FATAL_ERROR) {
                    errors++;
                    diag("Batch 2 error: %s", PQresultErrorMessage(res));
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 3) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        if (errors > 0 || batch2_ok < 2) {
            diag("Batch 2 failed: ok=%d, errors=%d", batch2_ok, errors);
            return false;
        }
        diag("Batch 2 succeeded (SET + COMMIT)");

        // Verify final value is value2
        const auto final_val = getVariable(conn.get(), "timezone");
        diag("Final value: '%s', expected: '%s'", final_val.c_str(), value2.c_str());
        bool success = (final_val == value2);

        // Cleanup: always restore original setting before returning connection to pool
        if (!success) {
            diag("Wrong final value");
        }
        executeQuery(conn.get(), "SET timezone = '" + original + "'");

        return success;
    });

    // Test: Pipeline error recovery with transaction
    add_test("Pipeline: Error recovery with ROLLBACK", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "datestyle");
        diag("Original datestyle: '%s'", original.c_str());

        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Send BEGIN, invalid SET, ROLLBACK
        if (PQsendQueryParams(conn.get(), "BEGIN", 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), "SET datestyle = 'INVALID_VALUE'", 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), "ROLLBACK", 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send queries");
            PQexitPipelineMode(conn.get());
            return false;
        }
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results
        int count = 0;
        int error_count = 0;
        int success_count = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 4) {
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed");
                PQexitPipelineMode(conn.get());
                return false;
            }
            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    success_count++;
                } else if (status == PGRES_FATAL_ERROR) {
                    error_count++;
                    diag("Expected error: %s", PQresultErrorMessage(res));
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 4) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        diag("Pipeline completed: successes=%d, errors=%d", success_count, error_count);

        if (error_count < 1) {
            diag("Expected at least 1 error, got %d", error_count);
            return false;
        }

        // Verify value unchanged
        const auto final_val = getVariable(conn.get(), "datestyle");
        diag("Final value: '%s', expected original: '%s'", final_val.c_str(), original.c_str());
        bool unchanged = (final_val == original);

        return unchanged;
    });

    // ============================================================================
    // Connection Lifecycle Tests
    // ============================================================================

    // Test: Startup parameter sync with connection reuse
    // Verifies that when a pooled connection is reused, ProxySQL syncs parameters
    // from the new client's startup options to match the backend
    add_test("Connection lifecycle: Startup parameter sync check", [&]() {
        const int SEED_COUNT = 5;   // Connections to seed pool with markers
        const int CHECK_COUNT = 10; // Connections to verify sync
        int synced_count = 0;
        int reused_count = 0;
        std::string original_val;

        // Step 1: Get original value and seed pool with marked connections
        {
            auto conn = createNewConnection(ConnType::BACKEND, "", false);
            if (!conn) {
                diag("Failed to create initial connection");
                return false;
            }
            original_val = getVariable(conn.get(), "extra_float_digits");
            diag("Original extra_float_digits value: %s", original_val.c_str());
        }

        diag("Seeding pool with %d connections having marker value '3'", SEED_COUNT);
        for (int i = 0; i < SEED_COUNT; i++) {
            auto conn = createNewConnection(ConnType::BACKEND, "", false);
            if (!conn) continue;

            // Set marker value 3 (high value, different from default -15 to 3 range)
            PGresult* set_res = PQexec(conn.get(), "SET extra_float_digits = 3");
            if (PQresultStatus(set_res) == PGRES_COMMAND_OK) {
                // Verify it was set
                const auto val = getVariable(conn.get(), "extra_float_digits");
                if (val == "3") {
                    diag("Seeded connection %d with marker '3'", i);
                }
            }
            PQclear(set_res);
            // Connection closes, returns to pool with marker value '3'
        }

        // Small delay for pool processing
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Step 2: Create connections with startup parameter -15 (different from marker '3')
        // If sync works, the connection should have '-15' not '3'
        diag("Creating %d connections with startup option extra_float_digits=-15", CHECK_COUNT);

        for (int i = 0; i < CHECK_COUNT; i++) {
            // Create connection with startup parameter -15
            // Using options='-c extra_float_digits=-15' to set at connection startup
            auto conn = createNewConnection(ConnType::BACKEND, "-c extra_float_digits=-15", false);
            if (!conn) {
                diag("Connection %d: Failed to create", i);
                continue;
            }

            // Get the value - this should trigger sync if connection was reused
            const auto val = getVariable(conn.get(), "extra_float_digits");
            diag("Connection %d: extra_float_digits='%s'", i, val.c_str());

            // Check if we got a reused connection (has marker '3' before sync)
            // After SHOW triggers sync, it should be '-15'
            if (val == "-15") {
                synced_count++;
                diag("Connection %d: Sync working correctly (got expected -15)", i);
            } else if (val == "3") {
                // This shouldn't happen if sync is working - SHOW should have triggered sync
                reused_count++;
                diag("Connection %d: WARNING - Got marker '3' instead of '-15', sync may not be working", i);
            } else {
                diag("Connection %d: Got value '%s' (expected '-15')", i, val.c_str());
            }

            // Run a query to verify connection works
            PGresult* res = PQexec(conn.get(), "SELECT 1");
            if (PQresultStatus(res) != PGRES_TUPLES_OK) {
                diag("Connection %d: Query failed", i);
            }
            PQclear(res);
        }

        diag("Results: %d connections with correct sync, %d with marker still present",
             synced_count, reused_count);

        // Test passes if all checked connections have the synced value
        // It's OK if we didn't get any reused connections (pool may not have returned them)
        // But if we created connections, they should all be synced correctly
        bool passed = (synced_count == CHECK_COUNT);

        if (!passed) {
            diag("FAIL: Expected %d synced connections, got %d", CHECK_COUNT, synced_count);
        }

        // Cleanup: restore original value
        {
            auto conn = createNewConnection(ConnType::BACKEND, "", false);
            if (conn) {
                PGresult* cleanup_res = PQexec(conn.get(),
                    ("SET extra_float_digits = " + original_val).c_str());
                PQclear(cleanup_res);
            }
        }

        return passed;
    });

    // Test: No inherited transactions
    add_test("Connection lifecycle: No inherited transactions", [&]() {
        const int CYCLES = 10;

        for (int i = 0; i < CYCLES; i++) {
            // Create connection, start transaction, close without commit
            {
                auto conn = createNewConnection(ConnType::BACKEND, "", false);
                if (!conn) return false;

                PGresult* begin_res = PQexec(conn.get(), "BEGIN");
                if (PQresultStatus(begin_res) != PGRES_COMMAND_OK) {
                    PQclear(begin_res);
                    return false;
                }
                PQclear(begin_res);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(50));

            // New connection should NOT be in transaction
            {
                auto conn = createNewConnection(ConnType::BACKEND, "", false);
                if (!conn) return false;

                // Use PQtransactionStatus() instead of pg_current_xact_id_if_assigned()
                // because BEGIN alone doesn't force an XID assignment
                bool in_transaction = (PQtransactionStatus(conn.get()) != PQTRANS_IDLE);

                if (in_transaction) {
                    diag("Cycle %d: Inherited transaction!", i);
                    PQexec(conn.get(), "ROLLBACK");
                    return false;
                }
            }
        }

        return true;
    });

    // ============================================================================
    // Detailed Parameter Value Verification Tests
    // ============================================================================

    // Test: Verify SET value visible immediately, persists after COMMIT
    add_test("Value verification: SET visible immediately and persists after COMMIT", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "datestyle");
        const std::string new_value = (original.find("ISO") != std::string::npos) ?
                                      "SQL, DMY" : "ISO, MDY";

        // Before transaction
        diag("Step 1 - Before BEGIN: datestyle = '%s'", original.c_str());

        // Start transaction
        executeQuery(conn.get(), "BEGIN");
        const auto after_begin = getVariable(conn.get(), "datestyle");
        diag("Step 2 - After BEGIN: datestyle = '%s'", after_begin.c_str());

        // SET new value
        executeQuery(conn.get(), "SET datestyle = '" + new_value + "'");
        const auto after_set = getVariable(conn.get(), "datestyle");
        diag("Step 3 - After SET datestyle = '%s': datestyle = '%s'", new_value.c_str(), after_set.c_str());

        // COMMIT
        executeQuery(conn.get(), "COMMIT");
        const auto after_commit = getVariable(conn.get(), "datestyle");
        diag("Step 4 - After COMMIT: datestyle = '%s'", after_commit.c_str());

        // Cleanup
        if (after_commit != original) {
            executeQuery(conn.get(), "SET datestyle = '" + original + "'");
        }

        // Verify: after_set should be new_value, after_commit should also be new_value
        bool set_visible = (after_set.find(new_value) != std::string::npos) && (after_set != original);
        bool commit_persisted = (after_commit.find(new_value) != std::string::npos) && (after_commit != original);

        return set_visible && commit_persisted;
    });

    // Test: Verify ROLLBACK reverts to original value
    add_test("Value verification: ROLLBACK reverts to original", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "timezone");
        const std::string new_value = (original.find("UTC") != std::string::npos) ?
                                      "PST8PDT" : "UTC";

        // Before transaction
        diag("Step 1 - Before BEGIN: timezone = '%s'", original.c_str());

        // Start transaction
        executeQuery(conn.get(), "BEGIN");

        // SET new value
        executeQuery(conn.get(), "SET timezone = '" + new_value + "'");
        const auto after_set = getVariable(conn.get(), "timezone");
        diag("Step 2 - After SET timezone = '%s': timezone = '%s'", new_value.c_str(), after_set.c_str());

        // ROLLBACK
        executeQuery(conn.get(), "ROLLBACK");
        const auto after_rollback = getVariable(conn.get(), "timezone");
        diag("Step 3 - After ROLLBACK: timezone = '%s'", after_rollback.c_str());

        // Verify: after_set should be new_value, after_rollback should be original
        bool set_changed = (after_set == new_value);
        bool rollback_reverted = (after_rollback == original);

        return set_changed && rollback_reverted;
    });

    // Test: Verify multiple SETs then ROLLBACK reverts to original (not intermediate)
    add_test("Value verification: Multiple SETs then ROLLBACK reverts to original", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "extra_float_digits");

        // Choose two different values
        const std::string value1 = (original == "0") ? "1" : "0";
        const std::string value2 = (value1 == "0") ? "2" : "0";

        diag("Step 1 - Original: extra_float_digits = '%s'", original.c_str());
        diag("Will SET to '%s', then to '%s', then ROLLBACK", value1.c_str(), value2.c_str());

        // Start transaction
        executeQuery(conn.get(), "BEGIN");

        // First SET
        executeQuery(conn.get(), "SET extra_float_digits = " + value1);
        const auto after_set1 = getVariable(conn.get(), "extra_float_digits");
        diag("Step 2 - After SET extra_float_digits = %s: value = '%s'", value1.c_str(), after_set1.c_str());

        // Second SET
        executeQuery(conn.get(), "SET extra_float_digits = " + value2);
        const auto after_set2 = getVariable(conn.get(), "extra_float_digits");
        diag("Step 3 - After SET extra_float_digits = %s: value = '%s'", value2.c_str(), after_set2.c_str());

        // ROLLBACK
        executeQuery(conn.get(), "ROLLBACK");
        const auto after_rollback = getVariable(conn.get(), "extra_float_digits");
        diag("Step 4 - After ROLLBACK: value = '%s' (expected original: '%s')", after_rollback.c_str(), original.c_str());

        // Verify: after_rollback should be original, not value1 or value2
        return (after_rollback == original);
    });

    // Test: Error in middle of transaction then ROLLBACK
    add_test("Value verification: Error in transaction then ROLLBACK", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "datestyle");
        const std::string new_value = (original.find("ISO") != std::string::npos) ?
                                      "SQL, DMY" : "ISO, MDY";

        diag("Step 1 - Original: datestyle = '%s'", original.c_str());

        // Start transaction
        executeQuery(conn.get(), "BEGIN");

        // SET valid value
        executeQuery(conn.get(), "SET datestyle = '" + new_value + "'");
        const auto after_set = getVariable(conn.get(), "datestyle");
        diag("Step 2 - After valid SET: datestyle = '%s'", after_set.c_str());

        // Try invalid SET (this will fail)
        PGresult* invalid_res = PQexec(conn.get(), "SET datestyle = 'INVALID_VALUE'");
        bool invalid_failed = (PQresultStatus(invalid_res) != PGRES_COMMAND_OK);
        PQclear(invalid_res);
        diag("Step 3 - Invalid SET failed as expected: %s", invalid_failed ? "yes" : "no");

        // Check value after error (should still be new_value)
        const auto after_error = getVariable(conn.get(), "datestyle");
        diag("Step 4 - After error: datestyle = '%s'", after_error.c_str());

        // ROLLBACK
        executeQuery(conn.get(), "ROLLBACK");
        const auto after_rollback = getVariable(conn.get(), "datestyle");
        diag("Step 5 - After ROLLBACK: datestyle = '%s'", after_rollback.c_str());

        // Cleanup if needed
        if (after_rollback != original) {
            executeQuery(conn.get(), "SET datestyle = '" + original + "'");
        }

        // Verify: invalid should have failed, value after error should be new_value, after rollback should be original
        return invalid_failed && (after_error.find(new_value) != std::string::npos) && (after_rollback == original);
    });

    // Test: Pipeline mode detailed value verification
    add_test("Value verification: Pipeline mode SET then ROLLBACK", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "timezone");
        const std::string new_value = (original.find("UTC") != std::string::npos) ?
                                      "PST8PDT" : "UTC";

        diag("Step 1 - Original: timezone = '%s'", original.c_str());

        // Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Send BEGIN, SET, ROLLBACK in pipeline
        PQsendQueryParams(conn.get(), "BEGIN", 0, NULL, NULL, NULL, NULL, 0);
        std::string set_query = "SET timezone = '" + new_value + "'";
        PQsendQueryParams(conn.get(), set_query.c_str(), 0, NULL, NULL, NULL, NULL, 0);
        PQsendQueryParams(conn.get(), "ROLLBACK", 0, NULL, NULL, NULL, NULL, 0);
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results
        int count = 0;
        int cmdCount = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 4) {
            if (PQconsumeInput(conn.get()) == 0) break;
            while ((res = PQgetResult(conn.get())) != NULL) {
                if (PQresultStatus(res) == PGRES_COMMAND_OK) cmdCount++;
                if (PQresultStatus(res) == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 4) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // Verify ROLLBACK reverted the SET
        const auto final_val = getVariable(conn.get(), "timezone");
        diag("Step 2 - After pipeline BEGIN/SET/ROLLBACK: timezone = '%s'", final_val.c_str());

        return (final_val == original) && (cmdCount >= 3);
    });

    // ============================================================================
    // Pipeline Mode SHOW Value Verification Tests (values read within pipeline)
    // ============================================================================

    // Test: Pipeline SHOW value after SET (without exiting pipeline)
    add_test("Pipeline: SHOW value after SET within pipeline", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "timezone");
        const std::string new_value = (original.find("UTC") != std::string::npos) ?
                                      "PST8PDT" : "UTC";

        diag("Step 1 - Original timezone (before pipeline): '%s'", original.c_str());
        diag("Will SET to '%s' and verify via SHOW within pipeline", new_value.c_str());

        // Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Send: SET, SHOW timezone (all in pipeline)
        std::string set_query = "SET timezone = '" + new_value + "'";
        if (PQsendQueryParams(conn.get(), set_query.c_str(), 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), "SHOW timezone", 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send queries");
            PQexitPipelineMode(conn.get());
            return false;
        }
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results and capture SHOW result
        int count = 0;
        int set_success = 0;
        int show_received = 0;
        int errors = 0;
        std::string show_value;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 3) {  // SET + SHOW + SYNC
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed: %s", PQerrorMessage(conn.get()));
                PQexitPipelineMode(conn.get());
                return false;
            }
            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    // SET succeeded
                    set_success++;
                    diag("SET command succeeded");
                } else if (status == PGRES_TUPLES_OK) {
                    // This is the SHOW result
                    if (PQntuples(res) > 0) {
                        show_value = PQgetvalue(res, 0, 0);
                        show_received++;
                        diag("SHOW result within pipeline: '%s'", show_value.c_str());
                    }
                } else if (status == PGRES_FATAL_ERROR) {
                    errors++;
                    diag("Command failed: %s", PQresultErrorMessage(res));
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 3) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // Verify all steps succeeded
        if (errors > 0) {
            diag("Errors occurred in pipeline: %d", errors);
            executeQuery(conn.get(), "SET timezone = '" + original + "'");
            return false;
        }
        if (set_success < 1) {
            diag("SET command did not succeed");
            executeQuery(conn.get(), "SET timezone = '" + original + "'");
            return false;
        }
        if (show_received < 1) {
            diag("SHOW result not received");
            executeQuery(conn.get(), "SET timezone = '" + original + "'");
            return false;
        }

        // Cleanup
        executeQuery(conn.get(), "SET timezone = '" + original + "'");

        // Verify: SHOW within pipeline should return new_value
        diag("Step 2 - SHOW within pipeline returned: '%s', expected: '%s'", show_value.c_str(), new_value.c_str());
        bool show_correct = (show_value == new_value);

        return show_correct;
    });

    // Test: Pipeline transaction SHOW value after SET, before COMMIT
    add_test("Pipeline: SHOW value before COMMIT within pipeline", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "datestyle");
        const std::string new_value = (original.find("ISO") != std::string::npos) ?
                                      "SQL, DMY" : "ISO, MDY";

        diag("Step 1 - Original datestyle (before pipeline): '%s'", original.c_str());
        diag("Will BEGIN, SET, SHOW, COMMIT all within pipeline");

        // Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Send: BEGIN, SET, SHOW, COMMIT (all in pipeline)
        std::string set_query = "SET datestyle = '" + new_value + "'";
        if (PQsendQueryParams(conn.get(), "BEGIN", 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), set_query.c_str(), 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), "SHOW datestyle", 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), "COMMIT", 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send queries");
            PQexitPipelineMode(conn.get());
            return false;
        }
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results and capture SHOW result
        int count = 0;
        int begin_success = 0;
        int set_success = 0;
        int show_received = 0;
        int commit_success = 0;
        int errors = 0;
        std::string show_value_before_commit;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 5) {  // BEGIN + SET + SHOW + COMMIT + SYNC
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed: %s", PQerrorMessage(conn.get()));
                PQexitPipelineMode(conn.get());
                return false;
            }
            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    // Track which command succeeded based on order
                    // Commands sent: BEGIN, SET, COMMIT (SHOW is TUPLES_OK)
                    if (begin_success == 0) {
                        begin_success++;
                        diag("BEGIN succeeded");
                    } else if (set_success == 0) {
                        set_success++;
                        diag("SET succeeded");
                    } else {
                        commit_success++;
                        diag("COMMIT succeeded");
                    }
                } else if (status == PGRES_TUPLES_OK) {
                    // This is the SHOW result (before COMMIT)
                    if (PQntuples(res) > 0) {
                        show_value_before_commit = PQgetvalue(res, 0, 0);
                        show_received++;
                        diag("SHOW datestyle before COMMIT: '%s'", show_value_before_commit.c_str());
                    }
                } else if (status == PGRES_FATAL_ERROR) {
                    errors++;
                    diag("Command failed: %s", PQresultErrorMessage(res));
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 5) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // Check for errors
        if (errors > 0) {
            diag("Errors occurred in pipeline: %d", errors);
            executeQuery(conn.get(), "SET datestyle = '" + original + "'");
            return false;
        }
        if (begin_success < 1 || set_success < 1 || show_received < 1 || commit_success < 1) {
            diag("Missing results: BEGIN=%d, SET=%d, SHOW=%d, COMMIT=%d",
                 begin_success, set_success, show_received, commit_success);
            executeQuery(conn.get(), "SET datestyle = '" + original + "'");
            return false;
        }

        // Verify via simple query that value persisted
        const auto final_val = getVariable(conn.get(), "datestyle");
        diag("Step 2 - Value after COMMIT (simple query): '%s'", final_val.c_str());

        // Cleanup
        if (final_val != original) {
            executeQuery(conn.get(), "SET datestyle = '" + original + "'");
        }

        // Verify: SHOW before commit should be new_value, final should be new_value
        bool show_correct = (show_value_before_commit.find(new_value) != std::string::npos);
        bool final_correct = (final_val.find(new_value) != std::string::npos);

        return show_correct && final_correct;
    });

    // Test: Pipeline SHOW value after ROLLBACK within pipeline
    add_test("Pipeline: SHOW value after ROLLBACK within pipeline", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "timezone");
        const std::string new_value = (original.find("UTC") != std::string::npos) ?
                                      "PST8PDT" : "UTC";

        diag("Step 1 - Original timezone (before pipeline): '%s'", original.c_str());
        diag("Will BEGIN, SET, ROLLBACK, SHOW all within pipeline");

        // Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Send: BEGIN, SET, ROLLBACK, SHOW (all in pipeline)
        std::string set_query = "SET timezone = '" + new_value + "'";
        if (PQsendQueryParams(conn.get(), "BEGIN", 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), set_query.c_str(), 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), "ROLLBACK", 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), "SHOW timezone", 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send queries");
            PQexitPipelineMode(conn.get());
            return false;
        }
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results and capture SHOW result
        int count = 0;
        int cmd_ok_count = 0;
        int show_received = 0;
        int errors = 0;
        std::string show_value_after_rollback;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 5) {  // BEGIN + SET + ROLLBACK + SHOW + SYNC
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed: %s", PQerrorMessage(conn.get()));
                PQexitPipelineMode(conn.get());
                return false;
            }
            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    cmd_ok_count++;
                } else if (status == PGRES_TUPLES_OK) {
                    // This is the SHOW result (after ROLLBACK)
                    if (PQntuples(res) > 0) {
                        show_value_after_rollback = PQgetvalue(res, 0, 0);
                        show_received++;
                        diag("SHOW timezone after ROLLBACK: '%s'", show_value_after_rollback.c_str());
                    }
                } else if (status == PGRES_FATAL_ERROR) {
                    errors++;
                    diag("Command failed: %s", PQresultErrorMessage(res));
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 5) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        if (errors > 0) {
            diag("Errors occurred in pipeline: %d", errors);
            return false;
        }
        if (cmd_ok_count < 3) {  // BEGIN, SET, ROLLBACK should all succeed
            diag("Not all commands succeeded. cmd_ok=%d, expected=3", cmd_ok_count);
            return false;
        }
        if (show_received < 1) {
            diag("SHOW result not received");
            return false;
        }

        // Verify via simple query that value reverted
        const auto final_val = getVariable(conn.get(), "timezone");
        diag("Step 2 - Value after ROLLBACK (simple query): '%s'", final_val.c_str());

        // Verify: SHOW after rollback should be original, final should be original
        bool show_correct = (show_value_after_rollback == original);
        bool final_correct = (final_val == original);

        return show_correct && final_correct;
    });

    // Test: Pipeline SAVEPOINT SHOW values within pipeline
    add_test("Pipeline: SHOW values at SAVEPOINT within pipeline", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "extra_float_digits");
        // Ensure value1 != value2 != original
        const std::string value1 = (original == "0") ? "1" : "0";
        const std::string value2 = "2";  // Always different from value1 and original

        diag("Step 1 - Original extra_float_digits: '%s'", original.c_str());
        diag("Will SET to '%s', SAVEPOINT, SET to '%s', SHOW all within pipeline", value1.c_str(), value2.c_str());

        // Verify values are distinct
        if (value1 == value2 || value1 == original || value2 == original) {
            diag("Test logic error: values not distinct. orig=%s, v1=%s, v2=%s",
                 original.c_str(), value1.c_str(), value2.c_str());
            return false;
        }

        // Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Send: BEGIN, SET value1, SAVEPOINT, SET value2, SHOW
        std::string set1 = "SET extra_float_digits = " + value1;
        std::string set2 = "SET extra_float_digits = " + value2;
        if (PQsendQueryParams(conn.get(), "BEGIN", 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), set1.c_str(), 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), "SAVEPOINT sp1", 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), set2.c_str(), 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), "SHOW extra_float_digits", 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), "COMMIT", 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send queries");
            PQexitPipelineMode(conn.get());
            return false;
        }
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results and capture SHOW result
        int count = 0;
        int cmd_ok_count = 0;
        int show_received = 0;
        int errors = 0;
        std::string show_value_after_savepoint;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 7) {  // BEGIN + SET + SAVEPOINT + SET + SHOW + COMMIT + SYNC
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed: %s", PQerrorMessage(conn.get()));
                PQexitPipelineMode(conn.get());
                return false;
            }
            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    cmd_ok_count++;
                } else if (status == PGRES_TUPLES_OK) {
                    // This is the SHOW result (after savepoint SET)
                    if (PQntuples(res) > 0) {
                        show_value_after_savepoint = PQgetvalue(res, 0, 0);
                        show_received++;
                        diag("SHOW extra_float_digits after savepoint SET: '%s'", show_value_after_savepoint.c_str());
                    }
                } else if (status == PGRES_FATAL_ERROR) {
                    errors++;
                    diag("Command failed: %s", PQresultErrorMessage(res));
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 7) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        if (errors > 0) {
            diag("Errors occurred in pipeline: %d", errors);
            executeQuery(conn.get(), "SET extra_float_digits = " + original);
            return false;
        }
        if (cmd_ok_count < 5) {  // BEGIN, SET, SAVEPOINT, SET, COMMIT
            diag("Not all commands succeeded. cmd_ok=%d, expected=5", cmd_ok_count);
            executeQuery(conn.get(), "SET extra_float_digits = " + original);
            return false;
        }
        if (show_received < 1) {
            diag("SHOW result not received");
            executeQuery(conn.get(), "SET extra_float_digits = " + original);
            return false;
        }

        // Cleanup
        if (show_value_after_savepoint != original) {
            executeQuery(conn.get(), "SET extra_float_digits = " + original);
        }

        // Verify: SHOW after savepoint SET should be value2 (second SET)
        bool show_correct = (show_value_after_savepoint == value2);
        if (!show_correct) {
            diag("SHOW returned wrong value. Got '%s', expected '%s'",
                 show_value_after_savepoint.c_str(), value2.c_str());
        }

        return show_correct;
    });

    // Test: Compare simple query vs pipeline SHOW values
    add_test("Pipeline: Compare simple vs pipeline SHOW values", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        const auto original = getVariable(conn.get(), "bytea_output");
        const std::string new_value = (original == "hex") ? "escape" : "hex";

        diag("Step 1 - Original bytea_output (simple query): '%s'", original.c_str());

        // First, SET via simple query
        PGresult* set_res = PQexec(conn.get(), ("SET bytea_output = '" + new_value + "'").c_str());
        if (PQresultStatus(set_res) != PGRES_COMMAND_OK) {
            diag("Simple query SET failed: %s", PQerrorMessage(conn.get()));
            PQclear(set_res);
            return false;
        }
        PQclear(set_res);

        const auto simple_show = getVariable(conn.get(), "bytea_output");
        diag("Step 2 - After SET, simple query SHOW: '%s'", simple_show.c_str());

        if (simple_show != new_value) {
            diag("Simple query SHOW returned wrong value. Got '%s', expected '%s'",
                 simple_show.c_str(), new_value.c_str());
            executeQuery(conn.get(), "SET bytea_output = '" + original + "'");
            return false;
        }

        // Reset to original
        executeQuery(conn.get(), "SET bytea_output = '" + original + "'");

        // Now do same thing in pipeline
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        std::string set_query = "SET bytea_output = '" + new_value + "'";
        if (PQsendQueryParams(conn.get(), set_query.c_str(), 0, NULL, NULL, NULL, NULL, 0) == 0 ||
            PQsendQueryParams(conn.get(), "SHOW bytea_output", 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send queries");
            PQexitPipelineMode(conn.get());
            return false;
        }
        PQpipelineSync(conn.get());
        PQflush(conn.get());

        // Consume results
        int count = 0;
        int set_success = 0;
        int show_received = 0;
        int errors = 0;
        std::string pipeline_show;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 3) {
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed: %s", PQerrorMessage(conn.get()));
                PQexitPipelineMode(conn.get());
                return false;
            }
            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    set_success++;
                } else if (status == PGRES_TUPLES_OK) {
                    if (PQntuples(res) > 0) {
                        pipeline_show = PQgetvalue(res, 0, 0);
                        show_received++;
                    }
                } else if (status == PGRES_FATAL_ERROR) {
                    errors++;
                    diag("Command failed: %s", PQresultErrorMessage(res));
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 3) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        if (errors > 0) {
            diag("Errors in pipeline: %d", errors);
            executeQuery(conn.get(), "SET bytea_output = '" + original + "'");
            return false;
        }
        if (set_success < 1) {
            diag("SET did not succeed in pipeline");
            executeQuery(conn.get(), "SET bytea_output = '" + original + "'");
            return false;
        }
        if (show_received < 1) {
            diag("SHOW result not received in pipeline");
            executeQuery(conn.get(), "SET bytea_output = '" + original + "'");
            return false;
        }

        diag("Step 3 - Pipeline SHOW value: '%s'", pipeline_show.c_str());

        // Cleanup
        executeQuery(conn.get(), "SET bytea_output = '" + original + "'");

        // Verify pipeline returned correct value
        if (pipeline_show != new_value) {
            diag("Pipeline SHOW returned wrong value. Got '%s', expected '%s'",
                 pipeline_show.c_str(), new_value.c_str());
            return false;
        }

        // Verify: Both simple and pipeline should show the same new_value
        bool simple_correct = (simple_show == new_value);
        bool pipeline_correct = (pipeline_show == new_value);
        bool values_match = (simple_show == pipeline_show);

        diag("Comparison - Simple: '%s', Pipeline: '%s', Match: %s",
             simple_show.c_str(), pipeline_show.c_str(), values_match ? "yes" : "no");

        return simple_correct && pipeline_correct && values_match;
    });

    // ============================================================================
    // RESET Pipeline Mode Tests - Verify pipeline invariant fix
    // ============================================================================

    // Test: RESET ALL in pipeline mode should be rejected and pipeline reset
    // This tests the fix for: When RESET is rejected, reset_extended_query_frame()
    // must be called to prevent subsequent messages from being processed incorrectly
    add_test("Pipeline: RESET ALL rejected with proper pipeline reset", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        // Step 1: Set a variable to create marker state
        executeQuery(conn.get(), "SET DateStyle = 'Postgres, DMY'");
        std::string marker_val = getVariable(conn.get(), "DateStyle");
        diag("Marker value set: '%s'", marker_val.c_str());

        // Step 2: Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Step 3: Send RESET ALL (may be rejected due to startup mismatch)
        if (PQsendQueryParams(conn.get(), "RESET ALL", 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send RESET ALL");
            PQexitPipelineMode(conn.get());
            return false;
        }

        // Step 4: Send a subsequent query - this tests the pipeline reset fix
        if (PQsendQueryParams(conn.get(), "SELECT 1 as test_col", 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send SELECT 1");
            PQexitPipelineMode(conn.get());
            return false;
        }

        // Step 5: Sync
        if (PQpipelineSync(conn.get()) != 1) {
            diag("PQpipelineSync failed");
            PQexitPipelineMode(conn.get());
            return false;
        }

        // Step 6: Consume results with proper loop (like working tests)
        int count = 0;
        int errors = 0;
        int select_ok = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 3) {
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed: %s", PQerrorMessage(conn.get()));
                PQexitPipelineMode(conn.get());
                return false;
            }
            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_TUPLES_OK) {
                    select_ok++;
                    diag("SELECT 1 returned: %s", PQgetvalue(res, 0, 0));
                } else if (status == PGRES_FATAL_ERROR) {
                    errors++;
                    diag("Command failed (expected for RESET ALL): %s", PQresultErrorMessage(res));
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 3) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // Cleanup
        executeQuery(conn.get(), "SET DateStyle = 'ISO, MDY'");

        // Test passes if:
        // 1. RESET failed (errors > 0) - the error was returned
        // 2. SELECT was NOT executed (select_ok == 0) - frame was reset/discarded
        diag("Results: errors=%d, select_ok=%d", errors, select_ok);
        return (errors > 0 && select_ok == 0);
    });

    // Test: RESET single variable in pipeline mode
    add_test("Pipeline: RESET single variable with pipeline reset", [&]() {
        auto conn = createNewConnection(ConnType::BACKEND, "", false);
        if (!conn) return false;

        // Step 1: Set a marker value
        executeQuery(conn.get(), "SET DateStyle = 'SQL, DMY'");

        // Step 2: Enter pipeline mode
        if (PQenterPipelineMode(conn.get()) != 1) {
            diag("Failed to enter pipeline mode");
            return false;
        }

        // Step 3: Send RESET DateStyle
        if (PQsendQueryParams(conn.get(), "RESET DateStyle", 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send RESET DateStyle");
            PQexitPipelineMode(conn.get());
            return false;
        }

        // Step 4: Send subsequent query
        if (PQsendQueryParams(conn.get(), "SELECT 2 as test_col", 0, NULL, NULL, NULL, NULL, 0) == 0) {
            diag("Failed to send SELECT 2");
            PQexitPipelineMode(conn.get());
            return false;
        }

        // Step 5: Sync
        if (PQpipelineSync(conn.get()) != 1) {
            diag("PQpipelineSync failed");
            PQexitPipelineMode(conn.get());
            return false;
        }

        // Step 6: Consume results with proper loop
        int count = 0;
        int errors = 0;
        int select_ok = 0;
        int reset_ok = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 3) {
            if (PQconsumeInput(conn.get()) == 0) {
                diag("PQconsumeInput failed: %s", PQerrorMessage(conn.get()));
                PQexitPipelineMode(conn.get());
                return false;
            }
            while ((res = PQgetResult(conn.get())) != NULL) {
                ExecStatusType status = PQresultStatus(res);
                if (status == PGRES_COMMAND_OK) {
                    reset_ok++;
                    diag("RESET DateStyle succeeded");
                } else if (status == PGRES_TUPLES_OK) {
                    select_ok++;
                    diag("SELECT 2 returned: %s", PQgetvalue(res, 0, 0));
                } else if (status == PGRES_FATAL_ERROR) {
                    errors++;
                    diag("Command failed: %s", PQresultErrorMessage(res));
                } else if (status == PGRES_PIPELINE_SYNC) {
                    PQclear(res);
                    count++;
                    break;
                }
                PQclear(res);
                count++;
            }
            if (count >= 3) break;
            if (!PQisBusy(conn.get())) continue;
            fd_set input_mask;
            FD_ZERO(&input_mask);
            FD_SET(sock, &input_mask);
            struct timeval timeout = {5, 0};
            select(sock + 1, &input_mask, NULL, NULL, &timeout);
        }

        PQexitPipelineMode(conn.get());

        // Cleanup
        executeQuery(conn.get(), "SET DateStyle = 'ISO, MDY'");

        // Test logic:
        // If RESET failed (errors > 0), SELECT should be discarded (select_ok == 0) - frame was reset
        // If RESET succeeded (reset_ok > 0), SELECT should also succeed (select_ok > 0) - normal operation
        diag("Results: reset_ok=%d, errors=%d, select_ok=%d", reset_ok, errors, select_ok);
        if (errors > 0) {
            // RESET was rejected - frame should be reset, SELECT discarded
            return (select_ok == 0);
        } else if (reset_ok > 0) {
            // RESET succeeded - pipeline should continue normally
            return (select_ok > 0);
        }
        return false;  // Neither success nor error - unexpected
    });

    int total_tests = 0;

    total_tests = tests.size();
    plan(total_tests);

    run_tests();

    return exit_status();
}
