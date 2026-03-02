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
        {"allow_in_place_tablespaces", {"allow_in_place_tablespaces", {"on", "off"}}},
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

        // Consume results
        int count = 0;
        int cmdCount = 0;
        int sock = PQsocket(conn.get());
        PGresult* res;

        while (count < 4) {  // 3 commands + 1 sync
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

    int total_tests = 0;

    total_tests = tests.size();
    plan(total_tests);

    run_tests();

    return exit_status();
}
