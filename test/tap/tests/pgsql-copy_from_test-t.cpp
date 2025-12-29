/**
 * @file pgsql-copy_from_test-t.cpp
 * @brief Tests COPY FROM functionality in ProxySQL
 */

#include <unistd.h>
#include <arpa/inet.h>
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
			if (strstr(query, "FROM") && (strstr(query, "STDIN") || strstr(query, "STDOUT"))) {
				return PGRES_COPY_IN;
            }
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

bool sendCopyData(PGconn* conn, const char* data, int size, bool last) {

    if (data != nullptr && size > 0) {
        if (PQputCopyData(conn, data, size) != 1) {
            fprintf(stderr, "Failed to send data: %s", PQerrorMessage(conn));
            return false;
        }
    }
    if (last) {
        if (PQputCopyEnd(conn, NULL) != 1) {
            fprintf(stderr, "Failed to send end of data: %s", PQerrorMessage(conn));
            return false;
        }
    }
    return true;
}

void splitString(std::vector<std::string>& split_str, const std::string& str) {
    std::stringstream ss(str);
    std::string token;

    while (std::getline(ss, token, '\t')) {
        // Remove the newline character at the end if present
        if (!token.empty() && token.back() == '\n') {
            token.pop_back();
        }
        split_str.push_back(token);
    }
}

// Helper function to convert a 32-bit integer to network byte order
void write_int32(uint8_t* dest, int32_t value) {
    dest[0] = (value >> 24) & 0xFF;
    dest[1] = (value >> 16) & 0xFF;
    dest[2] = (value >> 8) & 0xFF;
    dest[3] = value & 0xFF;
}

// Helper function to convert a 16-bit integer to network byte order
void write_int16(uint8_t* dest, int16_t value) {
    dest[0] = (value >> 8) & 0xFF;
    dest[1] = value & 0xFF;
}

bool encodeNumericBinary(uint8_t* out, const char* numStr) {
    int16_t numDigits = 0, weight = 0, sign = 0x0000, scale = 0;
    int16_t digits[64] = { 0 }; // Temporary storage for up to 64 4-digit groups
    size_t digitCount = 0;

    // Handle negative numbers
    const char* numericPart = numStr;
    if (numStr[0] == '-') {
        sign = 0x4000; // Negative sign
        numericPart++; // Skip the negative sign
    }

    // Split the number into integer and fractional parts
    const char* dotPos = strchr(numericPart, '.');
    size_t intPartLen = dotPos ? (size_t)(dotPos - numericPart) : strlen(numericPart);
    size_t fracPartLen = dotPos ? strlen(dotPos + 1) : 0;

    // Combine integer and fractional parts into a single string of digits
    char combined[128] = { 0 };
    strncpy(combined, numericPart, intPartLen);
    if (fracPartLen > 0) {
        strncat(combined, dotPos + 1, fracPartLen);
    }

    // Remove leading zeros
    while (combined[0] == '0' && combined[1] != '\0') {
        memmove(combined, combined + 1, strlen(combined));
    }

    // Pad the combined string length to a multiple of 4 for grouping
    size_t combinedLen = strlen(combined);
    size_t paddedLen = (combinedLen + 3) & ~3; // Round up to next multiple of 4
    for (size_t i = combinedLen; i < paddedLen; ++i) {
        combined[i] = '0'; // Pad with zeros
    }

    // Parse the padded string into 4-digit groups
    for (size_t i = 0; i < paddedLen; i += 4) {
        char group[5] = { 0 }; // Temporary buffer for a group of up to 4 digits
        strncpy(group, combined + i, 4);
        digits[digitCount++] = htons((int16_t)atoi(group)); // Convert group to 16-bit integer
    }


    numDigits = (int16_t)(digitCount == 1 && combined[0] == '0') ? 0 : digitCount;

    // Calculate weight
    weight = (int16_t)((intPartLen + 3) / 4 - 1);

    // Scale (number of fractional digits)
    scale = (int16_t)fracPartLen;

    // Pack the binary data
    write_int16(out, numDigits);          // numDigits
    out += sizeof(int16_t);
    write_int16(out, weight);             // weight
    out += sizeof(int16_t);
    write_int16(out, htons(sign));        // sign (converted to network byte order)
    out += sizeof(int16_t);
    write_int16(out, scale);              // scale
    out += sizeof(int16_t);
    memcpy(out, digits, numDigits * sizeof(int16_t)); // digit groups

	return numDigits;
}

// Helper function to check if a year is a leap year
int isLeapYear(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

// Function to calculate days from 2000-01-01
int calculateDaysFromEpoch(int year, int month, int day) {
    // Days in each month (non-leap year)
    const int daysInMonth[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    // Calculate days for previous years
    int days = 0;
    for (int y = 2000; y < year; ++y) {
        days += isLeapYear(y) ? 366 : 365;
    }
    for (int y = 1999; y > year; --y) {
        days -= isLeapYear(y) ? 366 : 365;
    }

    // Add days for previous months in the current year
    for (int m = 1; m < month; ++m) {
        days += daysInMonth[m - 1];
        if (m == 2 && isLeapYear(year)) {
            days += 1; // February in a leap year
        }
    }

    // Add/subtract the current month's days
    if (year >= 2000) {
        days += day - 1;
    }
    else {
        days -= daysInMonth[month - 1] - day + 1;
        if (month == 2 && isLeapYear(year)) {
            days -= 1; // Adjust for leap year February
        }
    }

    return days;
}

// Function to encode a date into PostgreSQL binary format
uint32_t encodeDateBinary(const char* dateStr) {
    int year, month, day;

    // Parse the date string (expected format: YYYY-MM-DD)
    if (sscanf(dateStr, "%d-%d-%d", &year, &month, &day) != 3) {
        fprintf(stderr, "Invalid date format. Use YYYY-MM-DD.\n");
        exit(EXIT_FAILURE);
    }

    // Calculate the number of days since 2000-01-01
    int days = calculateDaysFromEpoch(year, month, day);

    // Convert to big-endian (network byte order)
    return htonl(days);
}

int is_string_in_result(PGresult* result, const char* target_str) {
    int rows = PQntuples(result);
    int cols = PQnfields(result);

    // Iterate through all rows and columns
    for (int i = 0; i < rows; i++) {
        int match_count = 0;
        char full_row_str[1024] = { 0 }; // Buffer to reconstruct full row string

        // Reconstruct the row string (with tab and newline separators)
        for (int j = 0; j < cols; j++) {
            char* val = PQgetvalue(result, i, j);
            strcat(full_row_str, val);
            if (j < cols - 1) {
                strcat(full_row_str, "\t");
            }
        }
        strcat(full_row_str, "\n");

        // Compare reconstructed row string with target
        if (strcmp(full_row_str, target_str) == 0) {
            return 1; // Found a match
        }
    }
    return 0; // No match found
}

bool check_logs_for_command(std::fstream& f_proxysql_log, const std::string& command_regex) {
    const auto& [_, cmd_lines] { get_matching_lines(f_proxysql_log, command_regex) };
	return cmd_lines.empty() ? false : true;
}

bool setupTestTable(PGconn* conn) {
	return executeQueries(conn, { 
        "DROP TABLE IF EXISTS copy_in_test",
		"CREATE TABLE copy_in_test (column1 INT,column2 TEXT,column3 NUMERIC(10, 2),column4 BOOLEAN,column5 DATE)"
	});
}

std::vector<const char*> test_data = { "1\tHello\t123.45\tt\t2024-01-01\n",
									   "2\tWorld\t678.90\tf\t2024-02-15\n",
									   "3\tTest\t0.00\tt\t2023-12-25\n",
									   //"4\tSample\t-42.42\tf\t2024-11-27\n" 
                                       "4\tSample\t142.42\tf\t2024-11-27\n"
};

typedef enum {
    INT,
    TEXT,
    NUMERIC,
    BOOLEAN,
    DATE
} column_type_t;

const column_type_t columns_type[] = {
    INT,
    TEXT,
    NUMERIC,
    BOOLEAN,
    DATE
};

/**
 * @brief Tests the COPY IN functionality using STDIN in TEXT format.
 *
 * This function executes a COPY IN command to insert data into a PostgreSQL table
 * using the STDIN method in TEXT format. It verifies the success of the data transmission
 * and checks the logs for specific commands to ensure the session mode switches correctly.
 *
 * @param admin_conn A pointer to the admin PGconn connection.
 * @param conn A pointer to the PGconn connection used for the COPY IN operation.
 * @param f_proxysql_log A reference to the fstream object for ProxySQL logs.
 */
void testSTDIN_TEXT_FORMAT(PGconn* admin_conn, PGconn* conn, std::fstream& f_proxysql_log) {
    if (!executeQueries(conn, {"COPY /*dummy comment*/ copy_in_test(column1,column2,column3,column4,column5) /*dummy comment*/  FROM /*dummy comment*/ STDIN /*dummy comment*/ (FORMAT TEXT) /*dummy comment*/ "}))
        return;

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\].* Switching to Fast Forward mode \\(Session Type:0x06\\)"), "Session Switched to fast forward mode");

    bool success = true;

    for (unsigned int i = 0; i < test_data.size(); i++) {
        const char* data = test_data[i];
        bool last = (i == (test_data.size() - 1));
        if (!sendCopyData(conn, data, strlen(data), last)) {
            success = false;
            break;
        }
    }

    ok(success, "Copy data transmission should be successful");

    PGresult* res = PQgetResult(conn);

    ok((PQresultStatus(res) == PGRES_COMMAND_OK), "Rows successfully inserted. %s", PQerrorMessage(conn));

    const char* row_count_str = PQcmdTuples(res);
    const int row_count = atoi(row_count_str);

    ok(row_count == test_data.size(), "Total rows inserted: %d. Expected: %ld", row_count, test_data.size());
    PQclear(res);

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\] Switching back to Normal mode \\(Session Type:0x06\\).*"), "Switching back to Normal mode");
}

/**
 * @brief Tests the COPY IN functionality using BINARY formats.
 *
 * This function performs the following steps:
 * 1. Executes a COPY command to start the COPY IN process.
 * 2. Checks the logs to ensure the session has switched to fast forward mode.
 * 3. Sends the binary header for the COPY IN process.
 * 4. Iterates over the test data, encoding each row according to its column type.
 * 5. Sends the encoded row data to the PostgreSQL server.
 * 6. Verifies that the data transmission was successful.
 * 7. Checks the result to ensure rows were successfully inserted.
 * 8. Verifies the number of rows inserted matches the expected count.
 * 9. Checks the logs to ensure the session has switched back to normal mode.
 *
 * @param admin_conn The connection to the admin database.
 * @param conn The connection to the target database.
 * @param f_proxysql_log The log file stream for ProxySQL logs.
 */
void testSTDIN_TEXT_BINARY(PGconn* admin_conn, PGconn* conn, std::fstream& f_proxysql_log) {
    if (!executeQueries(conn, { "COPY copy_in_test(column1,column2,column3,column4,column5) FROM STDIN (FORMAT BINARY)" }))
        return;

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\].* Switching to Fast Forward mode \\(Session Type:0x06\\)"), "Session Switched to fast forward mode");

    bool success = true;

    // Send binary header
    const char binary_signature[] = "PGCOPY\n\377\r\n\0";
    int32_t flags = 0;
    int32_t header_extension_length = 0;

    char header[19];
    memcpy(header, binary_signature, sizeof(binary_signature) - 1);
    memcpy(header + 11, &flags, sizeof(flags));
    memcpy(header + 15, &header_extension_length, sizeof(header_extension_length));

    uint8_t row[1024];
    int offset = 0;

    for (unsigned int i = 0; i < test_data.size(); i++) {
        if (i == 0) {
            memcpy(row, header, sizeof(header));
            offset = sizeof(header);
        } else {
            offset = 0;
        }

        std::vector<std::string> row_data;
        splitString(row_data, test_data[i]);

        const int16_t num_fields = row_data.size();
        // write column count
        write_int16(row + offset, num_fields);
        offset += sizeof(num_fields);

        for (unsigned int j = 0; j < row_data.size(); j++) {
            const std::string& data = row_data[j];
            if (columns_type[j] == INT) {
                write_int32(row + offset, sizeof(int32_t));
                offset += sizeof(int32_t);

                int32_t value = atoi(data.c_str());
                // write actual data
                memcpy(row + offset, &value, sizeof(value));
                offset += sizeof(value);
            } else if (columns_type[j] == DATE) {
                write_int32(row + offset, sizeof(int32_t));
                offset += sizeof(int32_t);

                uint32_t date = encodeDateBinary(data.c_str());
                // write actual data
                memcpy(row + offset, &date, sizeof(date));
                offset += sizeof(date);
            } else if (columns_type[j] == TEXT || columns_type[j] == BOOLEAN) {
                // write field length
                write_int32(row + offset, data.size());
                offset += sizeof(int32_t);

                // write actual data
                memcpy(row + offset, data.c_str(), data.size());
                offset += data.size();
            } else if (columns_type[j] == NUMERIC) {
                uint8_t* prev_pos = (row + offset);
                offset += sizeof(int32_t);
                bool has_digits = encodeNumericBinary(row + offset, data.c_str());
                if (has_digits) {
                    write_int32(prev_pos, 12);
                    offset += 12;
                } else {
                    write_int32(prev_pos, 8);
                    offset += 8;
                }
            }
        }

        bool last = (i == (test_data.size() - 1));

        if (last) {
            write_int16(row + offset, -1);
            offset += sizeof(int16_t);
        }
        if (!sendCopyData(conn, reinterpret_cast<const char*>(row), offset, last)) {
            success = false;
            break;
        }
    }

    ok(success, "Copy data transmission should be successful");

    PGresult* res = PQgetResult(conn);

    ok((PQresultStatus(res) == PGRES_COMMAND_OK), "Rows successfully inserted. %s", PQerrorMessage(conn));

    const char* row_count_str = PQcmdTuples(res);
    const int row_count = atoi(row_count_str);

    ok(row_count == test_data.size(), "Total rows inserted: %d. Expected: %ld", row_count, test_data.size());
    PQclear(res);

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\] Switching back to Normal mode \\(Session Type:0x06\\).*"), "Switching back to Normal mode");
}

/**
 * @brief Tests the behavior of COPY FROM STDIN with an error scenario.
 *
 * This function attempts to execute a COPY FROM STDIN command on a non-existent table,
 * expecting it to fail. It then checks the ProxySQL logs to ensure that the session
 * switches to fast forward mode and then back to normal mode.
 *
 * @param admin_conn A pointer to the admin PGconn connection.
 * @param conn A pointer to the PGconn connection.
 * @param f_proxysql_log A reference to the fstream object for ProxySQL logs.
 */
void testSTDIN_ERROR(PGconn* admin_conn, PGconn* conn, std::fstream& f_proxysql_log) {

    ok(executeQueries(conn, { "COPY non_existent_table FROM STDIN (FORMAT TEXT)" }) == false, "Query should fail. %s", PQerrorMessage(conn));
    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\].* Switching to Fast Forward mode \\(Session Type:0x06\\)"), "Session Switched to fast forward mode");
    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\] Switching back to Normal mode \\(Session Type:0x06\\).*"), "Switching back to Normal mode");
}

/**
 * @brief Tests the COPY IN functionality within a transaction.
 *
 * This function initiates a transaction, performs a COPY IN operation to insert data into the 
 * 'copy_in_test' table, and verifies the success of the operation. It also checks the session 
 * mode transitions and ensures the connection remains in the transaction state throughout the process.
 *
 * @param admin_conn Pointer to the admin connection.
 * @param conn Pointer to the backend connection.
 * @param f_proxysql_log Reference to the ProxySQL log file stream.
 */
void testSTDIN_TRANSACTION(PGconn* admin_conn, PGconn* conn, std::fstream& f_proxysql_log) {

    if (!executeQueries(conn, { "BEGIN;" }))
        return;

    ok(PQtransactionStatus(conn) == PQTRANS_INTRANS, "Connection should be in Transaction State");

    if (!executeQueries(conn, { "COPY copy_in_test(column1,column2,column3,column4,column5) FROM STDIN (FORMAT TEXT)" }))
        return;

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\].* Switching to Fast Forward mode \\(Session Type:0x06\\)"), "Session Switched to fast forward mode");

    bool success = true;

    for (unsigned int i = 0; i < test_data.size(); i++) {
        const char* data = test_data[i];
        bool last = (i == (test_data.size() - 1));
        if (sendCopyData(conn, data, strlen(data), last) == false) {
            success = false;
            break;
        }
    }

    ok(success, "Copy data transmission should be successful");

    PGresult* res = PQgetResult(conn);

    ok((PQresultStatus(res) == PGRES_COMMAND_OK), "Rows successfully inserted. %s", PQerrorMessage(conn));

    const char* row_count_str = PQcmdTuples(res);
    const int row_count = atoi(row_count_str);

    ok(row_count == test_data.size(), "Total rows inserted: %d. Expected: %ld", row_count, test_data.size());
    PQclear(res);

    PQclear(PQgetResult(conn));

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\] Switching back to Normal mode \\(Session Type:0x06\\).*"), "Switching back to Normal mode");
    ok(PQtransactionStatus(conn) == PQTRANS_INTRANS, "Connection should be in Transaction State");

    if (!executeQueries(conn, { "ROLLBACK;" }))
        return;
}


/**
 * @brief Tests the behavior of a transaction when a COPY FROM STDIN command fails.
 *
 * This function initiates a transaction, attempts to execute a COPY FROM STDIN command
 * on a non-existent table, and verifies that the connection transitions to an error state.
 * It also checks the ProxySQL logs to ensure that the session switches to fast forward mode
 * and then back to normal mode.
 *
 * @param admin_conn Pointer to the admin connection.
 * @param conn Pointer to the backend connection.
 * @param f_proxysql_log Reference to the ProxySQL log file stream.
 */
void testSTDIN_TRANSACTION_ERROR(PGconn* admin_conn, PGconn* conn, std::fstream& f_proxysql_log) {

	if (!executeQueries(conn, { "BEGIN;" })) 		
        return;

    ok(PQtransactionStatus(conn) == PQTRANS_INTRANS, "Connection should be in Transaction State");
    ok(executeQueries(conn, { "COPY non_existent_table FROM STDIN (FORMAT TEXT)" }) == false, "Query should fail. %s", PQerrorMessage(conn));
    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\].* Switching to Fast Forward mode \\(Session Type:0x06\\)"), "Session Switched to fast forward mode");
    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\] Switching back to Normal mode \\(Session Type:0x06\\).*"), "Switching back to Normal mode");
	ok(PQtransactionStatus(conn) == PQTRANS_INERROR, "Connection should be in Error Transaction State");

	if (!executeQueries(conn, { "ROLLBACK;" }))
		return;
}

/**
 * @brief Tests the COPY IN and COPY OUT functionality using a file.
 *
 * This function first tests the COPY IN functionality using text format.
 * It then performs a COPY OUT operation to a file, verifies that the session
 * does not switch to fast forward mode, truncates the table, and performs a
 * COPY IN operation from the file. Finally, it verifies that all test data
 * entries are successfully copied into the database.
 *
 * @param admin_conn The connection to the admin database.
 * @param conn The connection to the target database.
 * @param f_proxysql_log The log file stream for ProxySQL logs.
 */
void testSTDIN_FILE(PGconn* admin_conn, PGconn* conn, std::fstream& f_proxysql_log) {
    testSTDIN_TEXT_FORMAT(admin_conn, conn, f_proxysql_log);

    if (!executeQueries(conn, { "COPY copy_in_test(column1,column2,column3,column4,column5) TO '/tmp/copy_in_test.txt' (FORMAT TEXT)" }))
        return;

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\].* Switching to Fast Forward mode \\(Session Type:0x06\\)") == false, "Session should NOT Switch to fast forward mode");

    if (!executeQueries(conn, { "TRUNCATE TABLE copy_in_test" }))
        return;

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\].* Switching to Fast Forward mode \\(Session Type:0x06\\)") == false, "Session should NOT Switch to fast forward mode");

    if (!executeQueries(conn, { "COPY copy_in_test(column1,column2,column3,column4,column5) FROM '/tmp/copy_in_test.txt' (FORMAT TEXT)" }))
        return;

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\].* Switching to Fast Forward mode \\(Session Type:0x06\\)") == false, "Session should NOT Switch to fast forward mode");

    PGresult* res = PQexec(conn, "SELECT column1,column2,column3,column4,column5 FROM copy_in_test");

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Query failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return;
    }

    // Verify each test data entry
    bool all_found = true;
    for (const char* data : test_data) {
        if (!is_string_in_result(res, data)) {
            all_found = false;
            break;
        }
    }

    ok(all_found == true, "All test data successfully verified in the database!");

    // Cleanup
    PQclear(res);
}

/**
 * @brief Test COPY FROM STDIN functionality with a multistatement query.
 *
 * This function sends a multistatement query to the PostgreSQL server, which includes a SELECT statement
 * followed by a COPY FROM STDIN statement. It then verifies the results of the SELECT statement, sends
 * data to be copied into the table, and verifies that the data was successfully inserted.
 *
 * @param admin_conn Pointer to the admin connection.
 * @param conn Pointer to the PostgreSQL connection.
 * @param f_proxysql_log Reference to the ProxySQL log file stream.
 */
void testSTDIN_MULTISTATEMENT(PGconn* admin_conn, PGconn* conn, std::fstream& f_proxysql_log) {
    // Multistatement query: First a SELECT, then COPY TO STDIN
    const char* query = "SELECT 1; COPY copy_in_test(column1,column2,column3,column4,column5) FROM STDIN (FORMAT TEXT);";
    if (PQsendQuery(conn, query) == 0) {
        fprintf(stderr, "Error sending query: %s\n", PQerrorMessage(conn));
        return;
    }

    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\].* Switching to Fast Forward mode \\(Session Type:0x06\\)"), "Session Switched to fast forward mode");

    // Check first result (SELECT statement)
    PGresult* res = PQgetResult(conn);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "SELECT failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return;
    }

    int rows = PQntuples(res);
    ok(rows == 1, "Expected 1 row from SELECT. Actual: %d", rows);

    // Check the data returned by SELECT
    char* value = PQgetvalue(res, 0, 0);
    ok(atoi(value) == 1, "Expected value 1 in first row");
    PQclear(res); // Clear result

    // Check second result (COPY FROM STDIN)
    res = PQgetResult(conn);
    if (PQresultStatus(res) != PGRES_COPY_IN) {
        fprintf(stderr, "COPY IN failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return;
    }

    bool success = true;
    for (unsigned int i = 0; i < test_data.size(); i++) {
        const char* data = test_data[i];
        bool last = (i == (test_data.size() - 1));
        if (!sendCopyData(conn, data, strlen(data), last)) {
            success = false;
            break;
        }
    }

    ok(success, "Copy data transmission should be successful");
    PQclear(res); // Clear result

    res = PQgetResult(conn);
    ok((PQresultStatus(res) == PGRES_COMMAND_OK), "Rows successfully inserted. %s", PQerrorMessage(conn));

    const char* row_count_str = PQcmdTuples(res);
    int row_count = atoi(row_count_str);
    ok(row_count == test_data.size(), "Total rows inserted: %d. Expected: %ld", row_count, test_data.size());
    PQclear(res);

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\] Switching back to Normal mode \\(Session Type:0x06\\).*"), "Switching back to Normal mode");

    // Cleanup
    PQclear(PQgetResult(conn));
}

/**
 * @brief Tests the COPY IN functionality with permanent fast forward mode.
 *
 * This function performs the following steps:
 * 1. Updates the pgsql_users table to enable fast forward mode.
 * 2. Loads the updated pgsql_users to runtime.
 * 3. Creates a new backend connection.
 * 4. Executes a COPY command to start copying data from STDIN.
 * 5. Verifies that the session does not switch to fast forward mode.
 * 6. Sends the test data to the backend connection.
 * 7. Verifies that the data transmission is successful.
 * 8. Checks that the rows are successfully inserted.
 * 9. Verifies that the session does not switch back to normal mode.
 * 10. Cleans up the result.
 *
 * @param admin_conn The connection to the admin database.
 * @param conn The connection to the backend database.
 * @param f_proxysql_log The log file stream for ProxySQL logs.
 */
void testSTDIN_PERMANENT_FAST_FORWARD(PGconn* admin_conn, PGconn* conn, std::fstream& f_proxysql_log) {
    if (!executeQueries(admin_conn, {
        "UPDATE pgsql_users SET fast_forward = 1",
        "LOAD PGSQL USERS TO RUNTIME"
    })) {
        return;
    }

    PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, false);

    if (!executeQueries(backend_conn.get(), {"COPY copy_in_test(column1,column2,column3,column4,column5) FROM STDIN (FORMAT TEXT)"})) {
        return;
    }

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\].* Switching to Fast Forward mode \\(Session Type:0x06\\)") == false, "Session should NOT Switch to fast forward mode");

    bool success = true;

    for (unsigned int i = 0; i < test_data.size(); i++) {
        const char* data = test_data[i];
        bool last = (i == (test_data.size() - 1));
        if (sendCopyData(backend_conn.get(), data, strlen(data), last) == false) {
            success = false;
            break;
        }
    }

    ok(success == true, "Copy data transmission should be successful");

    PGresult* res = PQgetResult(backend_conn.get());

    ok((PQresultStatus(res) == PGRES_COMMAND_OK), "Rows successfully inserted. %s", PQerrorMessage(backend_conn.get()));

    const char* row_count_str = PQcmdTuples(res);
    const int row_count = atoi(row_count_str);

    ok(row_count == test_data.size(), "Total rows inserted: %d. Expected: %ld", row_count, test_data.size());
    PQclear(res);

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\] Switching back to Normal mode \\(Session Type:0x06\\).*") == false, "Should NOT Switch back to Normal mode");

    // Cleanup
    PQclear(PQgetResult(backend_conn.get()));
}

/**
 * @brief Tests the COPY IN functionality using STDOUT in TEXT format.
 *
 * This function executes a COPY IN command to insert data into a PostgreSQL table
 * using the STDOUT method in TEXT format. It verifies the success of the data transmission
 * and checks the logs for specific commands to ensure the session mode switches correctly.
 *
 * @param admin_conn A pointer to the admin PGconn connection.
 * @param conn A pointer to the PGconn connection used for the COPY IN operation.
 * @param f_proxysql_log A reference to the fstream object for ProxySQL logs.
 */
void testSTDOUT_TEXT_FORMAT(PGconn* admin_conn, PGconn* conn, std::fstream& f_proxysql_log) {
    if (!executeQueries(conn, { "COPY copy_in_test(column1,column2,column3,column4,column5) FROM STDOUT" }))
        return;

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\].* Switching to Fast Forward mode \\(Session Type:0x06\\)"), "Session Switched to fast forward mode");

    bool success = true;

    for (unsigned int i = 0; i < test_data.size(); i++) {
        const char* data = test_data[i];
        bool last = (i == (test_data.size() - 1));
        if (!sendCopyData(conn, data, strlen(data), last)) {
            success = false;
            break;
        }
    }

    ok(success, "Copy data transmission should be successful");

    PGresult* res = PQgetResult(conn);

    ok((PQresultStatus(res) == PGRES_COMMAND_OK), "Rows successfully inserted. %s", PQerrorMessage(conn));

    const char* row_count_str = PQcmdTuples(res);
    const int row_count = atoi(row_count_str);

    ok(row_count == test_data.size(), "Total rows inserted: %d. Expected: %ld", row_count, test_data.size());
    PQclear(res);

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\] Switching back to Normal mode \\(Session Type:0x06\\).*"), "Switching back to Normal mode");
}

std::vector<std::pair<std::string, void (*)(PGconn*, PGconn*, std::fstream& f_proxysql_log)>> tests = {
    { "COPY ... FROM STDIN Text Format", testSTDIN_TEXT_FORMAT },
    { "COPY ... FROM STDIN Binary Format", testSTDIN_TEXT_BINARY },
    { "COPY ... FROM STDIN Error", testSTDIN_ERROR },
    { "COPY ... FROM STDIN Transaction", testSTDIN_TRANSACTION },
    { "COPY ... FROM STDIN Transaction Error", testSTDIN_TRANSACTION_ERROR },
    { "COPY ... FROM STDIN File", testSTDIN_FILE },
    { "COPY ... FROM STDIN Multistatement", testSTDIN_MULTISTATEMENT },
    { "COPY ... FROM STDOUT Text Format", testSTDOUT_TEXT_FORMAT },
	{ "COPY ... FROM STDIN Permanent Fast Forward", testSTDIN_PERMANENT_FAST_FORWARD }
};

void execute_tests(bool with_ssl, bool diff_conn) {

    PGConnPtr admin_conn_1 = createNewConnection(ConnType::ADMIN, with_ssl);

    if (!executeQueries(admin_conn_1.get(), {
           "DELETE FROM pgsql_query_rules",
           "LOAD PGSQL QUERY RULES TO RUNTIME",
           "UPDATE pgsql_users SET fast_forward=0" ,
           "LOAD PGSQL USERS TO RUNTIME"
        }))
        return;

    std::string f_path{ get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log" };
    std::fstream f_proxysql_log{};

    int of_err = open_file_and_seek_end(f_path, f_proxysql_log);
    if (of_err != EXIT_SUCCESS) {
        return;
    }

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
            test.second(admin_conn.get(), backend_conn.get(), f_proxysql_log);
            f_proxysql_log.clear(f_proxysql_log.rdstate() & ~std::ios_base::failbit);
            f_proxysql_log.seekg(f_proxysql_log.tellg());
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

            test.second(admin_conn.get(), backend_conn.get(), f_proxysql_log);
            f_proxysql_log.clear(f_proxysql_log.rdstate() & ~std::ios_base::failbit);
            f_proxysql_log.seekg(f_proxysql_log.tellg());
            diag(">>>> Done <<<<");
        }
    }

    f_proxysql_log.close();
}

int main(int argc, char** argv) {

    plan(51 * 2); // Total number of tests planned

    if (cl.getEnv())
        return exit_status();

    execute_tests(true, false);
    execute_tests(false, false);

    return exit_status();
}
