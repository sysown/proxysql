/**
 * @file pgsql-reg_test_5273_bind_parameter_format-t.cpp
 * @brief Comprehensive test suite for PostgreSQL BIND message parameter format handling
 * 
 * This test verifies the fix for PostgreSQL Extended Query Protocol BIND message
 * parameter format handling according to PostgreSQL protocol specification:
 * - num_param_formats = 0: All parameters use default format (text)
 * - num_param_formats = 1: Single format applies to ALL parameters
 * - num_param_formats = num_params: Each parameter gets explicit format
 */

#include <string>
#include <sstream>
#include <vector>
#include "libpq-fe.h"
#include "pg_lite_client.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

// CommandLine is defined elsewhere, we'll declare it extern
CommandLine cl;

int test_count = 1;

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

bool executeQueries(PGconn* conn, const std::vector<std::string>& queries) {
    auto fnResultType = [](const char* query) -> int {
        const char* fs = strchr(query, ' ');
        // NOSONAR: strlen is safe here as we control the input
        size_t qtlen = strlen(query); // NOSONAR
        if (fs != NULL) {
            qtlen = (fs - query) + 1;
        }
        char buf[qtlen];
        memcpy(buf, query, qtlen - 1);
        buf[qtlen - 1] = 0;

        if (strncasecmp(buf, "SELECT", sizeof("SELECT") - 1) == 0) {
            return PGRES_TUPLES_OK;
        }
        else if (strncasecmp(buf, "COPY", sizeof("COPY") - 1) == 0) {
            return PGRES_COPY_OUT;
        }

        return PGRES_COMMAND_OK;
        };


    for (const auto& query : queries) {
        diag("Running: %s", query.c_str());
        PGresult* res = PQexec(conn, query.c_str());
        bool success = PQresultStatus(res) == fnResultType(query.c_str());
        if (!success) {
            fprintf(stderr, "Failed to execute query '%s': %s\n",
                query.c_str(), PQerrorMessage(conn));
            PQclear(res);
            return false;
        }
        PQclear(res);
    }
    return true;
}

// Connection creation helper
std::shared_ptr<PgConnection> create_connection() {
    auto conn = std::make_shared<PgConnection>(5000);
    try {
        conn->connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
    } catch (const PgException& e) {
        diag("Connection failed: %s", e.what());
        return nullptr;
    }
    return conn;
}

std::vector<uint8_t> stringToBytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

// ===== Test Case Implementations =====
void test_zero_param_formats() {
    diag("Test %d: Zero parameter formats (default text)", test_count++);
    auto conn = create_connection();
    if (!conn) return;

    try {
        // Prepare statement with 4 parameters
        conn->prepareStatement("stmt_zero_fmt",
            "SELECT $1::int, $2::text, $3::bool, $4::bytea",
            true);
        
        // Bind with zero parameter formats (all text by default)
        std::vector<PgConnection::Param> params = {
            {"123", 0},           // text format
            {"hello", 0},         // text format  
            {"true", 0},          // text format
            {"\\xDEADBEEF", 0}    // text format (hex string)
        };
        
        conn->bindStatement("stmt_zero_fmt", "", params, {}, false);
        conn->describePortal("", false);

        // Execute
        conn->executePortal("", 0, true);
        
        // Read result
        auto result = conn->readResult();
        ok(result != nullptr, "Result received");
        if (result) {
            ok(result->rowCount() == 1, "One row returned");
            ok(result->columnCount() == 4, "Four columns returned");
            
            // Verify values
            if (result->rowCount() > 0 && result->columnCount() >= 4) {
                auto val1 = result->getValue(0, 0);
                auto val2 = result->getValue(0, 1);
                auto val3 = result->getValue(0, 2);
                auto val4 = result->getValue(0, 3);
                
                bool ok1 = std::holds_alternative<std::string>(val1) && 
                          std::get<std::string>(val1) == "123";
                bool ok2 = std::holds_alternative<std::string>(val2) && 
                          std::get<std::string>(val2) == "hello";
                bool ok3 = std::holds_alternative<std::string>(val3) && 
                          std::get<std::string>(val3) == "t";
                // PostgreSQL returns hex in lowercase
                bool ok4 = std::holds_alternative<std::string>(val4) && 
                          (std::get<std::string>(val4) == "\\xdeadbeef" ||
                           std::get<std::string>(val4).find("deadbeef") != std::string::npos);
                
                ok(ok1, "Integer value correct");
                ok(ok2, "Text value correct");
                ok(ok3, "Boolean value correct");
                ok(ok4, "Binary value correct (hex representation)");
            }
        }
        
        // Cleanup
        conn->closeStatement("stmt_zero_fmt", true);
        
    } catch (const PgException& e) {
        ok(false, "Zero parameter formats test failed: %s", e.what());
    }
}

void test_single_param_format_for_all() {
    diag("Test %d: Single parameter format for all parameters", test_count++);
    auto conn = create_connection();
    if (!conn) return;

    try {
        // Prepare statement with 4 parameters
        conn->prepareStatement("stmt_single_fmt",
            "SELECT $1::int, $2::text, $3::bool, $4::bytea",
            true);
        
        // Bind with single parameter format (all text)
        std::vector<PgConnection::Param> params = {
            {"456", 0},           // text format
            {"world", 0},         // text format  
            {"false", 0},         // text format
            {"\\xCAFEBABE", 0}    // text format (hex string)
        };
        
        // Use new bindStatementSingleFormat method
        conn->bindStatementSingleFormat("stmt_single_fmt", "", params, 0, {}, false);
        conn->describePortal("", false);

        // Execute
        conn->executePortal("", 0, true);
        
        // Read result
        auto result = conn->readResult();
        ok(result != nullptr, "Result received");
        if (result) {
            ok(result->rowCount() == 1, "One row returned");
            
            // Verify values
            if (result->rowCount() > 0 && result->columnCount() >= 4) {
                auto val1 = result->getValue(0, 0);
                auto val2 = result->getValue(0, 1);
                auto val3 = result->getValue(0, 2);
                auto val4 = result->getValue(0, 3);
                
                bool ok1 = std::holds_alternative<std::string>(val1) && 
                          std::get<std::string>(val1) == "456";
                bool ok2 = std::holds_alternative<std::string>(val2) && 
                          std::get<std::string>(val2) == "world";
                bool ok3 = std::holds_alternative<std::string>(val3) && 
                          std::get<std::string>(val3) == "f";
                bool ok4 = std::holds_alternative<std::string>(val4) && 
                          (std::get<std::string>(val4) == "\\xcafebabe" ||
                           std::get<std::string>(val4).find("cafebabe") != std::string::npos);
                
                ok(ok1, "Integer value correct with single format");
                ok(ok2, "Text value correct with single format");
                ok(ok3, "Boolean value correct with single format");
                ok(ok4, "Binary value correct with single format");
            }
        }
        
        // Cleanup
        conn->closeStatement("stmt_single_fmt", true);
        
    } catch (const PgException& e) {
        ok(false, "Single parameter format test failed: %s", e.what());
    }
}

void test_single_binary_format_for_all() {
    diag("Test %d: Single binary format for all parameters", test_count++);
    auto conn = create_connection();
    if (!conn) return;

    try {
        // Prepare statement with 3 parameters (bytea doesn't work well with binary int)
        conn->prepareStatement("stmt_single_bin",
            "SELECT $1::int, $2::text, $3::bool",
            true);
        
        // Bind with single binary format
        std::vector<PgConnection::Param> params = {
            {789, 1},                   // binary integer
            {stringToBytes("binary"), 1}, // binary text
            {std::vector<uint8_t>{1}, 1}  // binary boolean (true)
        };
        
        // Use bindStatementEx with single format
        std::vector<int16_t> paramFormats = {1}; // single binary format
        conn->bindStatementEx("stmt_single_bin", "", params, paramFormats, {}, false);
        conn->describePortal("", false);

        // Execute
        conn->executePortal("", 0, true);
        
        // Read result
        auto result = conn->readResult();
        ok(result != nullptr, "Result received for binary format");
        if (result) {
            ok(result->rowCount() == 1, "One row returned for binary format");
            
            // Verify values - they will be returned in text format unless we specify result formats
            if (result->rowCount() > 0 && result->columnCount() >= 3) {
                auto val1 = result->getValue(0, 0);
                auto val2 = result->getValue(0, 1);
                auto val3 = result->getValue(0, 2);
                
                // Results come back as text by default
                bool ok1 = std::holds_alternative<std::string>(val1) && 
                          std::get<std::string>(val1) == "789";
                bool ok2 = std::holds_alternative<std::string>(val2) && 
                          std::get<std::string>(val2) == "binary";
                bool ok3 = std::holds_alternative<std::string>(val3) && 
                          std::get<std::string>(val3) == "t";
                
                ok(ok1, "Binary integer parsed correctly");
                ok(ok2, "Binary text parsed correctly");
                ok(ok3, "Binary boolean parsed correctly");
            }
        }
        
        // Cleanup
        conn->closeStatement("stmt_single_bin", true);
        
    } catch (const PgException& e) {
        ok(false, "Single binary format test failed: %s", e.what());
    }
}

void test_mixed_param_formats() {
    diag("Test %d: Explicit format per parameter", test_count++);
    auto conn = create_connection();
    if (!conn) return;

    try {
        // Prepare statement
        conn->prepareStatement("stmt_mixed_fmt",
            "SELECT $1::int, $2::text, $3::bool",
            true);
        
        // Bind with mixed formats
        std::vector<PgConnection::Param> params = {
            {999, 1},                    // binary integer
            {"mixed", 0},                // text string
            {std::vector<uint8_t>{0}, 1} // binary boolean (false)
        };
        
        // Use bindStatementEx with explicit format array
        std::vector<int16_t> paramFormats = {1, 0, 1};
        conn->bindStatementEx("stmt_mixed_fmt", "", params, paramFormats, {}, false);
        conn->describePortal("", false);

        // Execute
        conn->executePortal("", 0, true);
        
        // Read result
        auto result = conn->readResult();
        ok(result != nullptr, "Result received for mixed formats");
        if (result) {
            ok(result->rowCount() == 1, "One row returned for mixed formats");
            
            // Verify values
            if (result->rowCount() > 0 && result->columnCount() >= 3) {
                auto val1 = result->getValue(0, 0);
                auto val2 = result->getValue(0, 1);
                auto val3 = result->getValue(0, 2);
                
                bool ok1 = std::holds_alternative<std::string>(val1) && 
                          std::get<std::string>(val1) == "999";
                bool ok2 = std::holds_alternative<std::string>(val2) && 
                          std::get<std::string>(val2) == "mixed";
                bool ok3 = std::holds_alternative<std::string>(val3) && 
                          std::get<std::string>(val3) == "f";
                
                ok(ok1, "Binary integer (mixed format) parsed correctly");
                ok(ok2, "Text string (mixed format) parsed correctly");
                ok(ok3, "Binary boolean (mixed format) parsed correctly");
            }
        }
        
        // Cleanup
        conn->closeStatement("stmt_mixed_fmt", true);
        
    } catch (const PgException& e) {
        ok(false, "Mixed parameter formats test failed: %s", e.what());
    }
}

void test_insert_with_zero_formats() {
    diag("Test %d: INSERT with zero parameter formats", test_count++);
    auto conn = create_connection();
    if (!conn) return;

    try {
        // Create test table
        conn->execute("DROP TABLE IF EXISTS test_insert_formats_1");
        conn->waitForReady();

        conn->execute("CREATE TABLE test_insert_formats_1 ("
                     "id SERIAL PRIMARY KEY, "
                     "int_val INTEGER, "
                     "text_val TEXT, "
                     "bool_val BOOLEAN, "
                     "bytea_val BYTEA)");
        conn->waitForReady();
        
        // Prepare INSERT statement
        conn->prepareStatement("insert_zero_fmt",
            "INSERT INTO test_insert_formats_1 (int_val, text_val, bool_val, bytea_val) "
            "VALUES ($1, $2, $3, $4)",
            false);
        
        // Bind with zero parameter formats (all text)
        std::vector<PgConnection::Param> params = {
            {"1000", 0},
            {"insert_test", 0},
            {"true", 0},
            {"\\x11223344", 0}
        };
        
        conn->bindStatement("insert_zero_fmt", "", params, {}, false);

        // Execute INSERT
        conn->executePortal("", 0, true);
        
        // Read result
        char type;
        std::vector<uint8_t> buffer;
        conn->readMessage(type, buffer);
        ok(type == PgConnection::PARSE_COMPLETE, "PARSE command completed");

        conn->readMessage(type, buffer);
        ok(type == PgConnection::BIND_COMPLETE, "BIND command completed");

        conn->readMessage(type, buffer);
        ok(type == PgConnection::COMMAND_COMPLETE, "Binary INSERT command completed");

        conn->readMessage(type, buffer);
        ok(type == PgConnection::READY_FOR_QUERY, "READY FOR QUERY");
        
        // Verify data was actually inserted
        conn->execute("SELECT int_val, text_val, bool_val, bytea_val FROM test_insert_formats_1");
        auto result = conn->readResult();
        ok(result != nullptr, "SELECT result received after INSERT");
        if (result) {
            ok(result->rowCount() == 1, "One row inserted");
            
            if (result->rowCount() > 0 && result->columnCount() >= 4) {
                auto val1 = result->getValue(0, 0);
                auto val2 = result->getValue(0, 1);
                auto val3 = result->getValue(0, 2);
                auto val4 = result->getValue(0, 3);
                
                bool ok1 = std::holds_alternative<std::string>(val1) && 
                          std::get<std::string>(val1) == "1000";
                bool ok2 = std::holds_alternative<std::string>(val2) && 
                          std::get<std::string>(val2) == "insert_test";
                bool ok3 = std::holds_alternative<std::string>(val3) && 
                          std::get<std::string>(val3) == "t";
                bool ok4 = std::holds_alternative<std::string>(val4) && 
                          (std::get<std::string>(val4) == "\\x11223344" ||
                           std::get<std::string>(val4).find("11223344") != std::string::npos);
                
                ok(ok1, "INSERT integer value correct");
                ok(ok2, "INSERT text value correct");
                ok(ok3, "INSERT boolean value correct");
                ok(ok4, "INSERT binary value correct");
            }
        }
        
        // Cleanup
        conn->closeStatement("insert_zero_fmt", true);
        
    } catch (const PgException& e) {
        ok(false, "INSERT with zero formats test failed: %s", e.what());
    }
}

void test_insert_with_single_binary_format() {
    diag("Test %d: INSERT with single binary format", test_count++);
    auto conn = create_connection();
    if (!conn) return;

    try {
        // Create test table
        conn->execute("DROP TABLE IF EXISTS test_insert_formats_2");
        conn->waitForReady();

        conn->execute("CREATE TABLE test_insert_formats_2 ("
                     "id SERIAL PRIMARY KEY, "
                     "int_val INTEGER, "
                     "text_val TEXT)");
        conn->waitForReady();

        // Prepare INSERT statement
        conn->prepareStatement("insert_single_bin",
            "INSERT INTO test_insert_formats_2 (int_val, text_val) VALUES ($1, $2)",
            false);

        // Bind with single binary format
        std::vector<PgConnection::Param> params = {
            {2000, 1},                    // binary integer
            {stringToBytes("binary_insert"), 1} // binary text
        };
        
        std::vector<int16_t> paramFormats = {1}; // single binary format
        conn->bindStatementEx("insert_single_bin", "", params, paramFormats, {}, false);

        // Execute INSERT
        conn->executePortal("", 0, true);
        
        // Read result
        char type;
        std::vector<uint8_t> buffer;
        conn->readMessage(type, buffer);
        ok(type == PgConnection::PARSE_COMPLETE, "PARSE command completed");

        conn->readMessage(type, buffer);
        ok(type == PgConnection::BIND_COMPLETE, "BIND command completed");

        conn->readMessage(type, buffer);
        ok(type == PgConnection::COMMAND_COMPLETE, "Binary INSERT command completed");

        conn->readMessage(type, buffer);
        ok(type == PgConnection::READY_FOR_QUERY, "READY FOR QUERY");
        
        // Verify data
        conn->execute("SELECT int_val, text_val FROM test_insert_formats_2");
        auto result = conn->readResult();
        ok(result != nullptr, "SELECT result received after binary INSERT");
        if (result) {
            ok(result->rowCount() == 1, "One row inserted with binary format");
            
            if (result->rowCount() > 0 && result->columnCount() >= 2) {
                auto val1 = result->getValue(0, 0);
                auto val2 = result->getValue(0, 1);
                
                bool ok1 = std::holds_alternative<std::string>(val1) && 
                          std::get<std::string>(val1) == "2000";
                bool ok2 = std::holds_alternative<std::string>(val2) && 
                          std::get<std::string>(val2) == "binary_insert";
                
                ok(ok1, "Binary INSERT integer value correct");
                ok(ok2, "Binary INSERT text value correct");
            }
        }
        
        // Cleanup
        conn->closeStatement("insert_single_bin", true);
        
    } catch (const PgException& e) {
        ok(false, "INSERT with single binary format test failed: %s", e.what());
    }
}

void test_null_parameter_handling() {
    diag("Test %d: NULL parameter handling with formats", test_count++);
    auto conn = create_connection();
    if (!conn) return;

    try {
        // Prepare statement
        conn->prepareStatement("stmt_null_test",
            "SELECT $1::int, $2::text, $3::bool",
            true);
        
        // Bind with NULL parameters
        std::vector<PgConnection::Param> params = {
            {123, 0},                    // integer
            {std::monostate{}, 0},  // NULL text (default constructed)
            {std::vector<uint8_t>{1}, 1} // binary boolean
        };
        params[1].value = std::monostate{}; // Explicit NULL
        
        // Use single format
        conn->bindStatementSingleFormat("stmt_null_test", "", params, 1, {}, false);
        conn->describePortal("", false);

        // Execute
        conn->executePortal("", 0, true);
        
        // Read result
        auto result = conn->readResult();
        ok(result != nullptr, "Result received with NULL parameters");
        if (result) {
            ok(result->rowCount() == 1, "One row returned with NULL");
            
            if (result->rowCount() > 0 && result->columnCount() >= 3) {
                auto val1 = result->getValue(0, 0);
                auto val2 = result->getValue(0, 1);
                auto val3 = result->getValue(0, 2);
                
                bool ok1 = std::holds_alternative<std::string>(val1) && 
                          std::get<std::string>(val1) == "123";
                bool ok2 = result->isNull(0, 1); // Should be NULL
                bool ok3 = std::holds_alternative<std::string>(val3) && 
                          std::get<std::string>(val3) == "t";
                
                ok(ok1, "Non-NULL integer value correct");
                ok(ok2, "NULL parameter handled correctly");
                ok(ok3, "Binary boolean with NULL in middle handled");
            }
        }
        
        // Cleanup
        conn->closeStatement("stmt_null_test", true);
        
    } catch (const PgException& e) {
        ok(false, "NULL parameter handling test failed: %s", e.what());
    }
}

int main() {
    plan(46); // Total number of checks we'll perform

    if (cl.getEnv())
        return exit_status();

    auto admin_conn = createNewConnection(ConnType::ADMIN, "", false);

    if (!admin_conn || PQstatus(admin_conn.get()) != CONNECTION_OK) {
        BAIL_OUT("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return exit_status();
    }


    if (executeQueries(admin_conn.get(), { "SET pgsql-authentication_method=1",
                                           "LOAD PGSQL VARIABLES TO RUNTIME" }) == false) {
        BAIL_OUT("Error: failed to set pgsql-authentication_method=1 in file %s, line %d", __FILE__, __LINE__);
        return exit_status();
    }
    
    // Run tests
    test_zero_param_formats();
    test_single_param_format_for_all();
    test_single_binary_format_for_all();
    test_mixed_param_formats();
    test_insert_with_zero_formats();
    test_insert_with_single_binary_format();
    test_null_parameter_handling();
    
    return exit_status();
}