/**
 * @file pgsql-copy_to_test-t.cpp
 * @brief Tests COPY TO functionality in ProxySQL
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

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType {
    ADMIN,
    BACKEND
};

PGConnPtr createNewConnection(ConnType conn_type, bool with_ssl) {
    
    const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
    int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
    const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

    std::stringstream ss;

    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

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
        size_t qtlen = strlen(query);
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
            fprintf(stderr, "Failed to execute query '%s': %s",
                query.c_str(), PQerrorMessage(conn));
            PQclear(res);
            return false;
        }
        PQclear(res);
    }
    return true;
}

size_t recvCopyData(PGconn* conn, char** output) {

    char* buffer = NULL;
    int bytesRead;
    size_t totalBytes = 0;
    size_t outputBuffCapacity = 1024;
    char* outputBuff = (char*)malloc(outputBuffCapacity); 

    if (!outputBuff) {
        fprintf(stderr, "Out of memory. %ld", outputBuffCapacity);
        return 0;
    }

    while ((bytesRead = PQgetCopyData(conn, &buffer, 0)) > 0) {
        if (totalBytes + bytesRead >= outputBuffCapacity) {
            outputBuffCapacity *= 2;
            if (outputBuffCapacity <= totalBytes + bytesRead)
                outputBuffCapacity = totalBytes + bytesRead + 1;

            char *tempBuff = (char*)realloc(outputBuff, outputBuffCapacity);
            if (!tempBuff) {
                fprintf(stderr, "Out of memory. %ld", outputBuffCapacity);
                free(outputBuff);
                PQfreemem(buffer);
                return 0;
            }
            outputBuff = tempBuff;
        }
        memcpy(outputBuff + totalBytes, buffer, bytesRead);
        totalBytes += bytesRead;
        PQfreemem(buffer);
        buffer = NULL;
    }
    outputBuff[totalBytes] = '\0';  // Null-terminate the output string

    ok(bytesRead == -1, "COPY OUT data retrieved successfully");

    // Verify no more results are pending
    PGresult *res = PQgetResult(conn);
    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
        ok(true, "Expected Command OK");
    } else {
        ok(false, "Expected Command OK");
        free(outputBuff);
        PQclear(res);
        return 0;
    }
    PQclear(res);

    if (PQgetResult(conn) == NULL) {
        ok(true, "Expected no more results after COPY OUT");
    } else {
        ok(false, "Expected no more results after COPY OUT");
        free(outputBuff);
        return 0;
    }

    if (output && totalBytes > 0)
        *output = outputBuff;
	else {
		free(outputBuff);
	}
    return totalBytes;
}

bool setupTestTable(PGconn* conn) {
	return executeQueries(conn, { 
        "DROP TABLE IF EXISTS copy_test",
		"CREATE TABLE copy_test (id SERIAL PRIMARY KEY, name TEXT, value INT, active BOOLEAN, created_at TIMESTAMP)"
	});
}

void testDataIntegrity(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(conn, { "INSERT INTO copy_test (name, value, active, created_at) VALUES ('Alice', 42, TRUE, NOW())" }))
        return;

    // Test COPY OUT
	if (!executeQueries(conn, { "COPY copy_test TO STDOUT" }))
		return;

    // Read data from COPY OUT
	char* output = NULL;
    if (recvCopyData(conn, &output) == 0)
        return;

    // Check output matches inserted values
    ok(strstr(output, "1\tAlice\t42\tt\t") != NULL, "Data integrity check");
    free(output);
}

void testCopyOutWithHeader(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(conn, { "INSERT INTO copy_test (name, value, active, created_at) VALUES ('Eve', 35, FALSE, NOW())" }))
        return;

    // Test COPY OUT
    if (!executeQueries(conn, { "COPY copy_test TO STDOUT WITH (FORMAT TEXT, HEADER)" }))
        return;

    // Read data from COPY OUT
    char* output = NULL;
    if (recvCopyData(conn, &output) == 0)
        return;

    // Check output includes the header
    ok(strstr(output, "id\tname\tvalue\tactive\tcreated_at") != NULL,
        "Expected header in COPY OUT output");
    free(output);
}

void testCopyOutLargeBinary(PGconn* admin_conn, PGconn* conn) {
    if (!executeQueries(admin_conn, { 
        "SET pgsql-threshold_resultset_size=536870911",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;
    
    if (!executeQueries(conn, { 
        "DROP TABLE IF EXISTS copy_test_large",
        "CREATE TABLE copy_test_large (id SERIAL PRIMARY KEY, data BYTEA)" 
        }))
        return;
    
    // Insert a large binary object
    constexpr unsigned int data_len = 1024 * 1024;
    char* largeData = (char*)malloc(data_len + 1); // 1MB
    memset(largeData, 'A', data_len);
    largeData[data_len] = '\0';

    // Escape the large data string to ensure safety
    char* escapedData = PQescapeLiteral(conn, largeData, data_len);

    if (escapedData == NULL) {
        // Handle escaping error, if needed
        fprintf(stderr, "Escaping error: %s\n", PQerrorMessage(conn));
        free(largeData);
        return;
    }

    // Create query string with escaped data embedded
    std::string query = "INSERT INTO copy_test_large (data) VALUES (" + std::string(escapedData) + ")";
    
    // Free resources
    PQfreemem(escapedData);
    free(largeData);

    if (!executeQueries(conn, { query.c_str() } ))
        return;

    // Test COPY OUT
    if (!executeQueries(conn, { "COPY copy_test_large TO STDOUT" }))
        return;

    // Read data from COPY OUT
    size_t bytesRecv = recvCopyData(conn, NULL);

    // Verify that binary data is read
    ok(bytesRecv > 0, "Expected non-zero binary output");
    
    if (!executeQueries(conn, {
        "DROP TABLE IF EXISTS copy_test_large"
    }))
        return;
}

void testTransactionHandling(PGconn* admin_conn, PGconn* conn) {

    // Use a transaction
    if (!executeQueries(conn, {
        "BEGIN",
        "INSERT INTO copy_test (name, value, active, created_at) VALUES ('Frank', 29, TRUE, NOW())",
        "ROLLBACK"
        }))
        return;

    // Test COPY OUT
    if (!executeQueries(conn, { "COPY copy_test TO STDOUT" }))
        return;

    // Read data from COPY OUT
    size_t bytesRecv = recvCopyData(conn, NULL);

    // Verify no data is present due to rollback
    ok(bytesRecv == 0, "Expected zero output after rollback");
}

void testErrorHandling(PGconn* admin_conn, PGconn* conn) {
    // Attempt to copy from a non-existent table
    PGresult *res = PQexec(conn, "COPY non_existent_table TO STDOUT");
    ok(PQresultStatus(res) != PGRES_COPY_OUT, "Expected COPY to fail on non-existent table");
    PQclear(res);
}

void testLargeDataVolume(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(admin_conn, {
      "SET pgsql-threshold_resultset_size=536870911",
      "LOAD PGSQL VARIABLES TO RUNTIME",
        }))
        return;

    // Insert a large number of rows
    for (int i = 0; i < 1000; i++) {
        char query[256];
        sprintf(query, "INSERT INTO copy_test (name, value, active, created_at) VALUES ('User%d', %d, %s, NOW())",
            i, i * 10, (i % 2 == 0) ? "TRUE" : "FALSE");
        if (!executeQueries(conn, {
            query
            }))
            return;
    }

    // Test COPY OUT
    if (!executeQueries(conn, { "COPY copy_test TO STDOUT" }))
        return;

    // Read data from COPY OUT
    size_t bytesRecv = recvCopyData(conn, NULL);

    // Verify output matches number of inserted rows
    ok(bytesRecv > 0, "Expected non-zero output for large data volume");
}

void testTransactionStatus(PGconn* admin_conn, PGconn* conn) {

    // Test COPY OUT
    if (!executeQueries(conn, {
        "BEGIN",
        "COPY copy_test TO STDOUT" }))
        return;

    // Read data from COPY OUT
    recvCopyData(conn, NULL);

    ok(PQtransactionStatus(conn) == PQTRANS_INTRANS, "Expected In Transaction Status");

    if (!executeQueries(conn, { "ROLLBACK" }))
        return;
}

void testThresholdResultsetSize(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(admin_conn, {
        "SET pgsql-poll_timeout=2000",
        "SET pgsql-threshold_resultset_size=1024",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;

    {
        auto startTime = std::chrono::high_resolution_clock::now();
        if (!executeQueries(conn, { "COPY (SELECT REPEAT('X', 1000)) TO STDOUT" }))
            return;
        // Read data from COPY OUT
        size_t bytesRecv = recvCopyData(conn, NULL);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
        ok(duration < 10, "Threshold check should not be triggered. Duration:%ld, Total Bytes Received:%ld", duration, bytesRecv);
    }
    {
        auto startTime = std::chrono::high_resolution_clock::now();
        if (!executeQueries(conn, { "COPY (SELECT REPEAT('X', 9999)) TO STDOUT" }))
            return;
        // Read data from COPY OUT
        size_t bytesRecv = recvCopyData(conn, NULL);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
        ok(duration >= 2000, "Threshold check should be triggered. Duration:%ld, Total Bytes Received:%ld", duration, bytesRecv);
    }
}

void testMultistatementWithCopy(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(conn, { "INSERT INTO copy_test(name, value) VALUES ('Alice', 10), ('Bob', 20)" }))
        return;

    // Multistatement query: First a SELECT, then COPY TO STDOUT
    if (PQsendQuery(conn, "SELECT * FROM copy_test; COPY copy_test TO STDOUT") == 0) {
        fprintf(stderr, "Error sending query: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return;
    }
    
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }

    // Check first result (SELECT statement)
    PGresult* res = PQgetResult(conn);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "SELECT failed\n");
        PQclear(res);
        return;
    }

    int rows = PQntuples(res);
    ok(rows == 2, "Expected 2 rows from SELECT");

    // Check the data returned by SELECT
    char* name1 = PQgetvalue(res, 0, 1);
    char* value1 = PQgetvalue(res, 0, 2);
    ok(strcmp(name1, "Alice") == 0, "Expected 'Alice' in first row");
    ok(atoi(value1) == 10, "Expected value 10 in first row");

    char* name2 = PQgetvalue(res, 1, 1);
    char* value2 = PQgetvalue(res, 1, 2);
    ok(strcmp(name2, "Bob") == 0, "Expected 'Bob' in second row");
    ok(atoi(value2) == 20, "Expected value 20 in second row");

    PQclear(res); // Clear SELECT result

    // Check second result (COPY TO STDOUT)
    res = PQgetResult(conn);
    if (PQresultStatus(res) != PGRES_COPY_OUT) {
        fprintf(stderr, "COPY OUT failed\n");
        PQclear(res);
        return;
    }

    // Read data from COPY OUT
    char* buffer = NULL;
    int bytesRead;
    size_t totalBytes = 0;
    char output[1024] = { 0 };

    while ((bytesRead = PQgetCopyData(conn, &buffer, 0)) > 0) {
        memcpy(output + totalBytes, buffer, bytesRead);
        totalBytes += bytesRead;
        PQfreemem(buffer);
        buffer = NULL;
    }

    output[totalBytes] = '\0'; // Null-terminate output for easier checking

    // Expected output format: "id\tname\tvalue\n1\tAlice\t10\n2\tBob\t20\n"
    ok(strstr(output, "1\tAlice\t10") != NULL, "Expected '1\tAlice\t10' in COPY OUT output");
    ok(strstr(output, "2\tBob\t20") != NULL, "Expected '2\tBob\t20' in COPY OUT output");

    // Finish COPY operation
    PQclear(res);

    // Verify no more results are pending
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "Expected Command OK");
    PQclear(res);
    ok(PQgetResult(conn) == NULL, "Expected no more results after COPY OUT");
}

std::vector<std::pair<std::string, void (*)(PGconn*, PGconn*)>> tests = {
    { "Data Intergrity Test", testDataIntegrity },
    { "Copy Out With Header Test", testCopyOutWithHeader },
    { "Copy Out With Large Data Test", testCopyOutLargeBinary },
    { "Transaction Handling Test", testTransactionHandling },
    { "Error Handling Test", testErrorHandling },
	{ "Large Data Volume Test", testLargeDataVolume },
    { "Transaction Status Test", testTransactionStatus },
    { "Threshold Result Size Test", testThresholdResultsetSize },
    { "Multi Statement With Copy Test", testMultistatementWithCopy }
};

void execute_tests(bool with_ssl, bool diff_conn) {

    PGConnPtr admin_conn_1 = createNewConnection(ConnType::ADMIN, with_ssl);

    if (!executeQueries(admin_conn_1.get(), {
       "DELETE FROM pgsql_query_rules",
       "LOAD PGSQL QUERY RULES TO RUNTIME"
        }))
        return;

    if (diff_conn == false) {
        PGConnPtr admin_conn = createNewConnection(ConnType::ADMIN, with_ssl);
        PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, with_ssl);

        if (!admin_conn || !backend_conn) {
            BAIL_OUT("Error: failed to connect to the database in file %s, line %d\n", __FILE__, __LINE__);
            return;
        }

        for (const auto& test : tests) {
            if (!setupTestTable(backend_conn.get())) 
                return;
            diag(">>>> Running %s - Shared Connection: %s <<<<", test.first.c_str(), !diff_conn ? "True" : "False");
            test.second(admin_conn.get(), backend_conn.get());
            diag(">>>> Done <<<<");
        }
    }
    else {
        for (const auto& test : tests) {
            diag(">>>> Running %s - Shared Connection: %s <<<<", test.first.c_str(), diff_conn ? "False" : "True");

            PGConnPtr admin_conn = createNewConnection(ConnType::ADMIN, with_ssl);
            PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, with_ssl);

            if (!admin_conn || !backend_conn) {
                BAIL_OUT("Error: failed to connect to the database in file %s, line %d\n", __FILE__, __LINE__);
                return;
            }
            if (!setupTestTable(backend_conn.get()))
                return;
            test.second(admin_conn.get(), backend_conn.get());
            diag(">>>> Done <<<<");
        }
    }
}

int main(int argc, char** argv) {

    plan(42 * 2); // Total number of tests planned

    if (cl.getEnv())
        return exit_status();

    execute_tests(true, false);
    execute_tests(false, false);

    return exit_status();
}
