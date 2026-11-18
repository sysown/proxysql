/**
 * @file pgsql-copy_from_test-t.cpp
 * @brief Tests COPY FROM functionality in ProxySQL
 */

#include <unistd.h>
#include <poll.h>
#include <ctime>
#include <vector>
#include <arpa/inet.h>
#include <string>
#include <string_view>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <thread>
#include "libpq-fe.h"
#include "command_line.h"
#include "noise_utils.h"
#include "tap.h"
#include "utils.h"
#include "pgsql_native_tier.h"

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
        // Skip leading whitespace and /* ... */ comments to find the first keyword
        const char* p = query;
        while (*p) {
            if (isspace(static_cast<unsigned char>(*p))) { p++; continue; }
            if (p[0] == '/' && p[1] == '*') {
                p += 2;
                while (*p && !(p[0] == '*' && p[1] == '/')) p++;
                if (*p) p += 2;
                continue;
            }
            break;
        }

        if (strncasecmp(p, "SELECT", 6) == 0) {
            return PGRES_TUPLES_OK;
        }
        else if (strncasecmp(p, "COPY", 4) == 0) {
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

int encodeNumericBinary(uint8_t* out, const char* numStr) {
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
    if (intPartLen >= sizeof(combined) || fracPartLen > sizeof(combined) - 1 - intPartLen) {
        return -1;
    }
    size_t copy_len = intPartLen;
    memcpy(combined, numericPart, copy_len);
    combined[copy_len] = 0;
    if (fracPartLen > 0) {
		size_t combined_len = copy_len;
        size_t copy_len_frac = fracPartLen;
        memcpy(combined + combined_len, dotPos + 1, copy_len_frac);
        combined[combined_len + copy_len_frac] = 0;
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
        memcpy(group, combined + i, 4);
        group[4] = 0;
        digits[digitCount++] = static_cast<int16_t>(htons(static_cast<uint16_t>(atoi(group)))); // Convert group to 16-bit integer
    }


    numDigits = static_cast<int16_t>((digitCount == 1 && combined[0] == '0') ? 0 : digitCount);

    // Calculate weight
    weight = (int16_t)((intPartLen + 3) / 4 - 1);

    // Scale (number of fractional digits)
    scale = (int16_t)fracPartLen;

    // Pack the binary data
    write_int16(out, numDigits);          // numDigits
    out += sizeof(int16_t);
    write_int16(out, weight);             // weight
    out += sizeof(int16_t);
    write_int16(out, static_cast<int16_t>(htons(sign)));        // sign (converted to network byte order)
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
		size_t current_len = 0;
		for (int j = 0; j < cols; j++) {
			char* val = PQgetvalue(result, i, j);
			size_t space_left = sizeof(full_row_str) - current_len;
            if (space_left == 0) {
                break;
            }
            int nwritten = snprintf(full_row_str + current_len, space_left, "%s%s", val, (j < cols - 1) ? "\t" : "");
			if (nwritten < 0 || (size_t)nwritten >= space_left) {
				break;
			}
			current_len += nwritten;
		}
		size_t space_left = sizeof(full_row_str) - current_len;
        if (space_left > 1) {
            snprintf(full_row_str + current_len, space_left, "\n");
        }

        // Compare reconstructed row string with target
        if (strcmp(full_row_str, target_str) == 0) {
            return 1; // Found a match
        }
    }
    return 0; // No match found
}

bool check_logs_for_command(std::fstream& f_proxysql_log, const std::string& command_regex) {
    // ProxySQL's log writes for 'Switching {to Fast Forward,back to Normal} mode'
    // happen asynchronously relative to the SQL that triggers them, so a single
    // scan right after the SQL completes is racy. wait_for_log_match() retries
    // with a short timeout, clearing EOF between scans; on hit it returns
    // immediately, so assertions against a line that is already present pay no
    // extra latency. Negative assertions (check_logs_for_command(...) == false)
    // also benefit: they now wait up to the timeout to confirm absence, avoiding
    // a false pass when the line would have arrived a few hundred ms later.
    return wait_for_log_match(f_proxysql_log, command_regex);
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

bool encodeBinaryField(uint8_t* row, int& offset, column_type_t type, const std::string& data) {
    switch (type) {
        case INT: {
            write_int32(row + offset, sizeof(int32_t));
            offset += sizeof(int32_t);
            const int32_t value = atoi(data.c_str());
            write_int32(row + offset, value);
            offset += sizeof(value);
            return true;
        }
        case DATE: {
            write_int32(row + offset, sizeof(int32_t));
            offset += sizeof(int32_t);
            const uint32_t date = encodeDateBinary(data.c_str());
            memcpy(row + offset, &date, sizeof(date));
            offset += sizeof(date);
            return true;
        }
        case TEXT:
            write_int32(row + offset, data.size());
            offset += sizeof(int32_t);
            memcpy(row + offset, data.c_str(), data.size());
            offset += data.size();
            return true;
        case BOOLEAN: {
            bool value;
            if (data == "true" || data == "t") {
                value = true;
            } else if (data == "false" || data == "f") {
                value = false;
            } else {
                fprintf(stderr, "Invalid boolean value for binary COPY: %s\n", data.c_str());
                return false;
            }
            write_int32(row + offset, 1);
            offset += sizeof(int32_t);
            row[offset++] = value ? 1 : 0;
            return true;
        }
        case NUMERIC: {
            uint8_t* length_pos = row + offset;
            offset += sizeof(int32_t);
            const int digit_count = encodeNumericBinary(row + offset, data.c_str());
            if (digit_count < 0) {
                fprintf(stderr, "Numeric value is too long for the binary COPY test buffer: %s\n", data.c_str());
                return false;
            }
            const int32_t payload_length = digit_count > 0 ? 12 : 8;
            write_int32(length_pos, payload_length);
            offset += payload_length;
            return true;
        }
    }
    return false;
}

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
			if (!encodeBinaryField(row, offset, columns_type[j], row_data[j])) {
				success = false;
				break;
			}
        }
		if (!success) {
			break;
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
    if (!success) {
        return;
    }

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

/**
 * @brief Tests that COPY commands with leading SQL comments still trigger fast-forward mode.
 *
 * When digest is available, leading comments are stripped, so the strncasecmp
 * prefix check sees "COPY ..." and allows the RE2 match to proceed. This test
 * verifies that comment-prefixed COPY commands are not incorrectly rejected by
 * the fast-reject optimization.
 *
 * @param admin_conn A pointer to the admin PGconn connection.
 * @param conn A pointer to the PGconn connection.
 * @param f_proxysql_log A reference to the fstream object for ProxySQL logs.
 */
void testCopyWithLeadingComments(PGconn* admin_conn, PGconn* conn, std::fstream& f_proxysql_log) {
    if (!executeQueries(conn, {"/* leading comment */ COPY copy_in_test(column1,column2,column3,column4,column5) FROM STDIN (FORMAT TEXT)"}))
        return;

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\].* Switching to Fast Forward mode \\(Session Type:0x06\\)"),
        "COPY with leading comments should trigger fast forward mode");

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

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\] Switching back to Normal mode \\(Session Type:0x06\\).*"),
        "Switching back to Normal mode");
}

/**
 * @brief Tests that SELECT containing COPY keywords in a string literal works correctly.
 *
 * With digest ON, string literals are normalized to '?', so the regex never sees
 * COPY keywords. With digest OFF, the regex may match COPY inside a string literal.
 * This test verifies that the query still executes correctly in either case.
 *
 * @param admin_conn A pointer to the admin PGconn connection.
 * @param conn A pointer to the PGconn connection.
 * @param f_proxysql_log A reference to the fstream object for ProxySQL logs.
 */
void testSelectWithCopyInStringLiteral(PGconn* admin_conn, PGconn* conn, std::fstream& f_proxysql_log) {
    PGresult* res = PQexec(conn, "SELECT 'COPY x FROM STDIN'");
    ok(PQresultStatus(res) == PGRES_TUPLES_OK, "SELECT with COPY in string literal should return TUPLES_OK. %s", PQerrorMessage(conn));

    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int rows = PQntuples(res);
        ok(rows == 1, "Expected 1 row. Actual: %d", rows);
        char* value = PQgetvalue(res, 0, 0);
        ok(strcmp(value, "COPY x FROM STDIN") == 0, "Expected 'COPY x FROM STDIN'. Actual: '%s'", value);
    } else {
        ok(0, "Skipped row count check - query failed");
        ok(0, "Skipped value check - query failed");
    }
    PQclear(res);
}

std::vector<std::pair<std::string, void (*)(PGconn*, PGconn*, std::fstream& f_proxysql_log)>> tests = {
    { "SELECT with COPY in string literal", testSelectWithCopyInStringLiteral },
    { "COPY with leading comments", testCopyWithLeadingComments },
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

/**
 * COPY over a TLS-encrypted BACKEND connection. Everything above encrypts the
 * CLIENT leg only. Fast forward borrows the backend's TLS and must hand it back;
 * when it did not, the next query never reached the backend -- in this session,
 * or in whichever one later took the connection from the pool.
 */
static const int TLS_BACKEND_TESTS = 11;

struct TlsSrvRow { std::string hostname, port, max_connections, comment; };

// Admin takes no bound parameters, so quote by doubling. A hostname or comment
// holding an apostrophe would otherwise build a broken INSERT and leave
// hostgroup 0 empty after the DELETE.
static std::string tlsQuote(const std::string& v) {
    std::string out("'");
    for (char c : v) {
        if (c == '\'') out += '\'';
        out += c;
    }
    out += '\'';
    return out;
}

static std::string tlsQueryOneValue(PGconn* c, const std::string& q) {
    PGresult* res = PQexec(c, q.c_str());
    std::string out;
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0))
        out = PQgetvalue(res, 0, 0);
    PQclear(res);
    return out;
}

// Gives up after timeout_s. The defect under test strands the query, so a plain
// PQexec would block until the harness kills the whole test.
static std::string tlsQueryWithin(PGconn* c, const std::string& q, int timeout_s) {
    if (PQsendQuery(c, q.c_str()) != 1) {
        diag("PQsendQuery failed: %s", PQerrorMessage(c));
        return "";
    }
    const time_t deadline = time(NULL) + timeout_s;
    while (PQisBusy(c)) {
        if (time(NULL) >= deadline) {
            diag("no reply to '%s' within %d seconds -- the backend connection is wedged", q.c_str(), timeout_s);
            return "";
        }
        struct pollfd pfd = { PQsocket(c), POLLIN, 0 };
        if (poll(&pfd, 1, 500) > 0 && PQconsumeInput(c) != 1) {
            diag("PQconsumeInput failed: %s", PQerrorMessage(c));
            return "";
        }
    }
    std::string out;
    bool got = false;
    PGresult* res;
    while ((res = PQgetResult(c)) != nullptr) {
        if (!got && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0)) {
            out = PQgetvalue(res, 0, 0);
            got = true;
        }
        PQclear(res);
    }
    return out;
}

static std::vector<TlsSrvRow> tlsReadServers(PGconn* admin) {
    std::vector<TlsSrvRow> rows;
    PGresult* res = PQexec(admin,
        "SELECT hostname, port, max_connections, COALESCE(comment,'') FROM pgsql_servers WHERE hostgroup_id=0");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        for (int i = 0; i < PQntuples(res); i++)
            rows.push_back(TlsSrvRow { PQgetvalue(res,i,0), PQgetvalue(res,i,1),
                                       PQgetvalue(res,i,2), PQgetvalue(res,i,3) });
    }
    PQclear(res);
    return rows;
}

// Deleting the servers drops the pool, so the next query opens a fresh
// connection under the use_ssl setting we want. Updating the row in place does
// not: the pooled connection survives and every assertion below would run over
// plaintext. Only the columns this test needs are carried across; the harness
// reloads the whole config from disk before every test, so the rest cannot leak.
static bool tlsReloadServers(PGconn* admin, const std::vector<TlsSrvRow>& rows, int use_ssl) {
    if (rows.empty()) return false;
    std::vector<std::string> q { "DELETE FROM pgsql_servers WHERE hostgroup_id=0", "LOAD PGSQL SERVERS TO RUNTIME" };
    for (const auto& r : rows) {
        q.push_back("INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment)"
            " VALUES (0," + tlsQuote(r.hostname) + "," + r.port + ","
            + (r.max_connections.empty() ? std::string("1000") : r.max_connections) + ","
            + std::to_string(use_ssl) + "," + tlsQuote(r.comment) + ")");
    }
    q.push_back("LOAD PGSQL SERVERS TO RUNTIME");
    if (!executeQueries(admin, q)) return false;
    usleep(300000);
    return true;
}

// Asks the backend whether this session's connection is encrypted.
// pg_backend_pid() is intercepted, so match on the text of this very query.
static bool tlsBackendLegIsEncrypted(PGconn* client) {
    return tlsQueryOneValue(client,
        "SELECT s.ssl FROM pg_stat_ssl s JOIN pg_stat_activity a ON s.pid = a.pid"
        " WHERE a.state = 'active' AND a.query LIKE '%copytls_self_marker%' LIMIT 1") == "t";
}

// A plaintext connection can still be handed out briefly after the reload, and
// then every assertion below passes while testing nothing.
static bool tlsWaitForEncryptedBackend() {
    for (int attempt = 0; attempt < 20; attempt++) {
        PGConnPtr probe = createNewConnection(ConnType::BACKEND, false);
        if (probe && tlsBackendLegIsEncrypted(probe.get())) return true;
        usleep(500000);
    }
    diag("no encrypted backend connection appeared after the reload");
    return false;
}

static bool tlsCopyIn(PGconn* c, const std::string& table, const std::string& payload) {
    PGresult* res = PQexec(c, ("COPY " + table + " FROM STDIN").c_str());
    if (PQresultStatus(res) != PGRES_COPY_IN) {
        diag("COPY IN did not start: %s", PQerrorMessage(c));
        PQclear(res);
        return false;
    }
    PQclear(res);
    if (PQputCopyData(c, payload.data(), (int)payload.size()) != 1) return false;
    if (PQputCopyEnd(c, nullptr) != 1) return false;
    res = PQgetResult(c);
    bool ok_ = (res != nullptr && PQresultStatus(res) == PGRES_COMMAND_OK);
    if (!ok_) diag("COPY IN did not complete: %s", PQerrorMessage(c));
    PQclear(res);
    while ((res = PQgetResult(c)) != nullptr) PQclear(res);
    return ok_;
}

static std::string tlsCopyOut(PGconn* c, const std::string& sql, bool* ok_) {
    std::string out;
    *ok_ = false;
    PGresult* res = PQexec(c, sql.c_str());
    if (PQresultStatus(res) != PGRES_COPY_OUT) {
        diag("COPY OUT did not start: %s", PQerrorMessage(c));
        PQclear(res);
        return out;
    }
    PQclear(res);
    char* buf = nullptr;
    int n;
    while ((n = PQgetCopyData(c, &buf, 0)) > 0) { out.append(buf, n); PQfreemem(buf); buf = nullptr; }
    if (n == -2) { diag("COPY OUT failed mid-stream: %s", PQerrorMessage(c)); return out; }
    res = PQgetResult(c);
    *ok_ = (res != nullptr && PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    while ((res = PQgetResult(c)) != nullptr) PQclear(res);
    return out;
}

void testCopyOverTlsBackend() {
    diag(">>>> Running COPY over a TLS-encrypted backend connection <<<<");
    const std::string tbl = "pgsql_copy_tls_" + std::to_string(getpid());
    const char* payload = "1\tone\n2\ttwo\n3\tthree\n";
    const char* copy_out_sql = "COPY (SELECT g, 'row'||g FROM generate_series(1,5) g) TO STDOUT";

    PGConnPtr admin = createNewConnection(ConnType::ADMIN, false);
    if (!admin) { BAIL_OUT("Error: failed to connect to admin in file %s, line %d\n", __FILE__, __LINE__); return; }

    // The permanent fast forward case above leaves fast_forward=1 and relies on the
    // next pass to clear it. A forwarded session never switches back to normal
    // mode, which is the transition under test, so clear it here.
    if (!executeQueries(admin.get(), { "UPDATE pgsql_users SET fast_forward=0", "LOAD PGSQL USERS TO RUNTIME" }))
        return;

    const std::vector<TlsSrvRow> saved = tlsReadServers(admin.get());
    if (saved.empty()) { BAIL_OUT("no servers in hostgroup 0 to work with"); return; }

    ok(tlsReloadServers(admin.get(), saved, 1), "backend servers set to use_ssl=1 and pool flushed");
    const bool tls_ready = tlsWaitForEncryptedBackend();

    std::string out;
    bool copy_out_ok = false, copy_in_ok = false, tls = false, still_usable = false;
    {
        PGConnPtr conn = createNewConnection(ConnType::BACKEND, false);
        if (!conn) { BAIL_OUT("client connection failed"); return; }
        executeQueries(conn.get(), { "DROP TABLE IF EXISTS " + tbl, "CREATE TABLE " + tbl + " (id int, name text)" });
        tls = tls_ready && tlsBackendLegIsEncrypted(conn.get());
        out = tlsCopyOut(conn.get(), copy_out_sql, &copy_out_ok);
        copy_in_ok = tlsCopyIn(conn.get(), tbl, payload);
        // When the TLS was not handed back, this query went into a buffer nobody
        // drained and the session waited for a reply forever.
        still_usable = (tlsQueryWithin(conn.get(), "SELECT 42", 20) == "42");
    }

    // The bulk-load shape: connect, COPY, disconnect. Nothing there notices a
    // broken connection; the next unrelated session gets it from the pool.
    bool loader_pool_ok = false;
    {
        PGConnPtr loader = createNewConnection(ConnType::BACKEND, false);
        if (loader) tlsCopyIn(loader.get(), tbl, payload);
    }
    {
        PGConnPtr conn = createNewConnection(ConnType::BACKEND, false);
        if (conn) loader_pool_ok = (tlsQueryWithin(conn.get(), "SELECT 7", 20) == "7");
    }

    ok(tls, "the COPY really ran over an encrypted backend connection");
    ok(copy_out_ok && !out.empty(), "COPY TO STDOUT completed (%zu bytes)", out.size());
    ok(copy_in_ok, "COPY FROM STDIN completed");
    ok(still_usable, "the session still works after a COPY over a TLS backend connection");
    ok(loader_pool_ok, "a later session works on the connection a COPY-and-disconnect left pooled");

    // A second COPY on the same session exercises adopt -> release -> adopt.
    bool second_copy_ok = false;
    {
        PGConnPtr conn = createNewConnection(ConnType::BACKEND, false);
        if (conn) {
            bool a = tlsCopyIn(conn.get(), tbl, payload);
            bool b = tlsCopyIn(conn.get(), tbl, payload);
            second_copy_ok = a && b && (tlsQueryWithin(conn.get(), "SELECT 5", 20) == "5");
        }
    }
    ok(second_copy_ok, "two COPYs on one session, then a query, all succeed");

    // A payload big enough to need many SSL_write cycles through the memory BIOs.
    // A partial write leaves ciphertext buffered, which is the state release has to
    // notice rather than hand the connection back to the pool holding it.
    bool bulk_ok = false;
    {
        std::string big;
        big.reserve(600 * 1024);
        for (int i = 0; big.size() < 512 * 1024; i++)
            big += std::to_string(i) + "\tpadding-so-the-row-is-not-tiny-" + std::to_string(i) + "\n";
        PGConnPtr conn = createNewConnection(ConnType::BACKEND, false);
        if (conn) {
            bool a = tlsCopyIn(conn.get(), tbl, big);
            bulk_ok = a && (tlsQueryWithin(conn.get(), "SELECT 9", 20) == "9");
        }
    }
    ok(bulk_ok, "a half-megabyte COPY over TLS completes and leaves the session usable");

    // Both legs encrypted at once: the client leg has its own TLS, and the relay
    // must not confuse it with the backend's.
    bool both_legs_ok = false;
    {
        PGConnPtr conn = createNewConnection(ConnType::BACKEND, true);
        if (conn) {
            bool a = tlsCopyIn(conn.get(), tbl, payload);
            both_legs_ok = a && (tlsQueryWithin(conn.get(), "SELECT 11", 20) == "11");
        }
    }
    ok(both_legs_ok, "COPY works with the client leg encrypted as well as the backend");

    // Permanent fast forward reaches the other two places the backend TLS is
    // borrowed: attach_connection() when a pooled connection joins a session that
    // is already forwarding, and the connect path when a new one is opened for it.
    // The COPY cases above only ever exercise the switch into fast forward.
    bool perm_ff_ok = false, perm_ff_pool_ok = false;
    if (executeQueries(admin.get(), { "UPDATE pgsql_users SET fast_forward=1", "LOAD PGSQL USERS TO RUNTIME" })) {
        // Drop the pool so the first session has to open a connection while the
        // session is already in fast forward.
        tlsReloadServers(admin.get(), saved, 1);
        {
            PGConnPtr conn = createNewConnection(ConnType::BACKEND, false);
            if (conn) perm_ff_ok = (tlsQueryWithin(conn.get(), "SELECT 13", 20) == "13");
        }
        // Now one that takes the pooled connection instead of opening its own.
        {
            PGConnPtr conn = createNewConnection(ConnType::BACKEND, false);
            if (conn) perm_ff_pool_ok = (tlsQueryWithin(conn.get(), "SELECT 17", 20) == "17");
        }
        executeQueries(admin.get(), { "UPDATE pgsql_users SET fast_forward=0", "LOAD PGSQL USERS TO RUNTIME" });
    }
    ok(perm_ff_ok, "a forwarded session works on a TLS backend connection it opened itself");
    ok(perm_ff_pool_ok, "a forwarded session works on a TLS backend connection taken from the pool");

    {
        PGConnPtr conn = createNewConnection(ConnType::BACKEND, false);
        if (conn) executeQueries(conn.get(), { "DROP TABLE IF EXISTS " + tbl });
    }
    // Only to leave the pool usable for anything after this; the harness reloads
    // the config from disk before the next test, so exact fidelity is not needed.
    if (!tlsReloadServers(admin.get(), saved, 0)) {
        diag("WARNING: could not restore the original pgsql_servers rows for hostgroup 0");
    }
    diag(">>>> Done <<<<");
}

/**
 * Regression #6628: a backend that answers during COPY FROM STDIN must reach the client and leave the
 * connection usable.
 *
 * During a COPY FROM STDIN ProxySQL relays raw bytes, and the backend may answer while client data is
 * still queued for it: a NOTICE, or an error that ends the COPY early (a bad row, a cancel). ProxySQL
 * used to close the session then ("Data at both ends of a PgSQL data stream"). Once such answers were
 * let through, an early end could leave a CopyData message half sent: going back to normal mode
 * dropped the rest of it, and the backend read the client's next query as that rest. The query then
 * hung, or the backend failed with "invalid frontend message type".
 *
 * The cases stream 256 KB CopyData messages, so that one is likely to be half sent when the backend
 * answers, then:
 *  - a row raises an error: the client must get it (P0001). Also with the error on the very first row,
 *    and with 4 MB messages;
 *  - the backend is held on its first row and the COPY is cancelled, or runs into statement_timeout:
 *    the client must get 57014;
 *  - the client gives up with a CopyFail while its data is still queued: it must get 57014;
 *  - the backend is killed: the client must get an error at once, and a new session work;
 *  - every message has a row that raises a NOTICE: each must reach the client, and the COPY complete.
 * After an error the connection must keep working, for a simple query and for a pipeline of extended
 * queries (which the native protocol sends as one batch), and a full COPY on it must deliver every row.
 * Inside a transaction the next query must fail with 25P02, which only the same backend can answer, and
 * work after ROLLBACK. Each case runs over plain and TLS client connections, with a plain and then a TLS
 * backend connection, over the libpq and the native backend protocol (native only where the build has it).
 * Where the build has the fast forward traffic observer (FFTO), an error, a cancel in a transaction and the
 * NOTICEs run again with it on: it reads every message ProxySQL relays, including the reply held back
 * until a half-sent message is finished.
 */
namespace early_end {

static const std::string TBL = "copy_early_end_" + std::to_string(getpid());
static const std::string SEQ = TBL + "_rows";
static const std::string FN = TBL + "_trg";
static const std::string LOCK_KEY = std::to_string(880000000LL + getpid());
// Rows as small as a bulk load's keep the backend slower than the client, so client data stays queued.
static const std::string ROW = "x\t" + std::string(61, 'y') + "\n";
static const size_t MSG_BYTES = 256 * 1024;
static const size_t BIG_MSG_BYTES = 4 << 20;
static const int RESULT_TIMEOUT_S = 60;
static const int QUERY_TIMEOUT_S = 10;
// A client whose backend was killed gets the error within this.
static const double ERROR_MAX_S = 5.0;
// Per backend protocol: 2 backend modes x (2 + 2 client modes x 25 checks, see run()); with FFTO on, 9
// checks per client mode.
static const int TESTS_PER_PROTOCOL = 2 * (2 + 2 * 25);
static const int FFTO_TESTS_PER_PROTOCOL = 2 * (2 + 2 * 9);

using Clock = std::chrono::steady_clock;

static std::string make_msg(const std::string& first_row, size_t bytes = MSG_BYTES) {
    std::string m = first_row;
    while (m.size() + ROW.size() <= bytes) m += ROW;
    return m;
}

static void wait_socket(int fd, bool for_write, int ms) {
    struct pollfd pfd = { fd, (short)(POLLIN | (for_write ? POLLOUT : 0)), 0 };
    poll(&pfd, 1, ms);
}

// Sends what libpq holds, reading meanwhile: the server may be blocked sending to us.
static bool flush_all(PGconn* c, Clock::time_point stop) {
    int f;
    while ((f = PQflush(c)) == 1) {
        if (Clock::now() > stop || PQsocket(c) < 0) return false;
        wait_socket(PQsocket(c), true, 50);
        if (PQconsumeInput(c) == 0) return false;
    }
    return f == 0;
}

// Queues msg for 'seconds', a message at a time once libpq has sent the previous ones. Returns how many.
static long stream_for(PGconn* c, const std::string& msg, int seconds) {
    const auto stop = Clock::now() + std::chrono::seconds(seconds);
    long n = 0;
    while (Clock::now() < stop && flush_all(c, stop)) {
        if (PQconsumeInput(c) == 0 || PQputCopyData(c, msg.data(), (int)msg.size()) != 1) break;
        n++;
    }
    return n;
}

// Reads results until the command is done. Returns "" on success, "ERR <sqlstate>" on an error,
// "COPY_IN" when a COPY FROM STDIN starts, or "timeout". *val gets the first value of a row result.
static std::string collect(PGconn* c, int timeout_s, std::string* val = nullptr) {
    const auto stop = Clock::now() + std::chrono::seconds(timeout_s);
    std::string out;
    for (;;) {
        if (!flush_all(c, stop)) return Clock::now() > stop ? "timeout" : "ERR connection lost";
        PQconsumeInput(c);
        while (PQisBusy(c) == 0) {
            PGresult* r = PQgetResult(c);
            if (r == nullptr) return out;
            const ExecStatusType st = PQresultStatus(r);
            if (st == PGRES_COPY_IN) {
                PQclear(r);
                return "COPY_IN";
            }
            if (st == PGRES_FATAL_ERROR) {
                const char* s = PQresultErrorField(r, PG_DIAG_SQLSTATE);
                out = std::string("ERR ") + (s ? s : "(no SQLSTATE)");
            } else if (st == PGRES_TUPLES_OK && val && PQntuples(r) > 0) {
                *val = PQgetvalue(r, 0, 0);
            }
            PQclear(r);
        }
        if (PQsocket(c) < 0 || PQstatus(c) == CONNECTION_BAD) return "ERR connection lost";
        if (Clock::now() > stop) return "timeout";
        wait_socket(PQsocket(c), false, 50);
    }
}

// Every query in the cases goes through here, with a time limit: a broken build leaves a backend out of
// step, and ProxySQL may hand it to the next session, where a blocking PQexec() would wait forever.
static std::string query(PGconn* c, const std::string& q) {
    PQsetnonblocking(c, 1);
    if (PQsendQuery(c, q.c_str()) != 1) return std::string("ERR send: ") + PQerrorMessage(c);
    std::string v;
    const std::string st = collect(c, QUERY_TIMEOUT_S, &v);
    return st.empty() ? v : st;
}

static bool start_copy(PGconn* c) {
    const std::string st = query(c, "COPY " + TBL + " FROM STDIN");
    if (st != "COPY_IN") diag("COPY did not start: %s", st.c_str());
    return st == "COPY_IN";
}

// errormsg != nullptr sends a CopyFail instead of a CopyDone.
static std::string end_copy(PGconn* c, const char* errormsg = nullptr) {
    const auto stop = Clock::now() + std::chrono::seconds(RESULT_TIMEOUT_S);
    int r;
    while ((r = PQputCopyEnd(c, errormsg)) == 0) {
        if (!flush_all(c, stop)) return Clock::now() > stop ? "timeout" : "ERR connection lost";
    }
    if (r < 0) return std::string("ERR copy end: ") + PQerrorMessage(c);
    return collect(c, RESULT_TIMEOUT_S);
}

static void count_notice(void* arg, const char* message) {
    if (strstr(message, "copy notice")) ++*static_cast<long*>(arg);
}

// Two pipelined extended queries and a Sync: the native protocol sends them as one batch. Returns their
// values joined by ',', or what went wrong.
static std::string pipeline_pair(PGconn* c) {
    PQsetnonblocking(c, 1);
    const char* one[1] = { "1" };
    const char* two[1] = { "2" };
    if (PQenterPipelineMode(c) != 1 || PQsendQueryParams(c, "SELECT $1::int", 1, nullptr, one, nullptr, nullptr, 0) != 1
        || PQsendQueryParams(c, "SELECT $1::int", 1, nullptr, two, nullptr, nullptr, 0) != 1 || PQpipelineSync(c) != 1)
        return std::string("ERR pipeline: ") + PQerrorMessage(c);
    const auto stop = Clock::now() + std::chrono::seconds(QUERY_TIMEOUT_S);
    std::string out;
    for (;;) {
        if (!flush_all(c, stop)) return Clock::now() > stop ? "timeout" : "ERR connection lost";
        PQconsumeInput(c);
        int nulls = 0;
        while (PQisBusy(c) == 0 && nulls < 2) {
            PGresult* r = PQgetResult(c);
            if (r == nullptr) { nulls++; continue; }
            nulls = 0;
            const ExecStatusType st = PQresultStatus(r);
            if (st == PGRES_PIPELINE_SYNC) {
                PQclear(r);
                if (PQexitPipelineMode(c) != 1) return std::string("ERR exit pipeline: ") + PQerrorMessage(c);
                return out;
            }
            if (st == PGRES_TUPLES_OK && PQntuples(r) == 1) {
                out += (out.empty() ? "" : ",") + std::string(PQgetvalue(r, 0, 0));
            } else {
                const char* e = PQresultErrorField(r, PG_DIAG_SQLSTATE);
                out += (out.empty() ? "" : ",") + std::string("ERR ") + (e ? e : PQresStatus(st));
            }
            PQclear(r);
        }
        if (PQsocket(c) < 0 || PQstatus(c) == CONNECTION_BAD) return "ERR connection lost";
        if (Clock::now() > stop) return "timeout";
        wait_socket(PQsocket(c), false, 50);
    }
}

// "1|1,2" when a simple query and a batch of extended queries both work on c.
static std::string works(PGconn* c) {
    const std::string v = query(c, "SELECT 1");
    return v + "|" + pipeline_pair(c);
}
static const char* WORKS = "1|1,2";

// The backend running this test's COPY ("" when none does).
static std::string copy_pid(PGconn* be) {
    return tlsQueryOneValue(be, "SELECT pid FROM pg_stat_activity WHERE query LIKE 'COPY " + TBL + "%' AND state='active' LIMIT 1");
}

static PGConnPtr open_direct_backend() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_server_host << " port=" << cl.pgsql_server_port << " user=" << cl.pgsql_server_username
       << " password=" << cl.pgsql_server_password << " dbname=postgres sslmode=disable";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

// The rows the trigger has counted since the last reset.
static std::string counted(PGconn* setup) {
    return query(setup, "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM " + SEQ);
}

// How the backend ends the COPY early.
enum class End { ERROR_ROW, ERROR_FIRST_ROW, CANCEL, STATEMENT_TIMEOUT, COPY_FAIL, BACKEND_KILLED };

// The backend ends the COPY early. Checks: 1 for the error, then 1 that the connection works (a new one
// after BACKEND_KILLED), or 2 in a transaction (25P02, then working after ROLLBACK); plus 1 for a full
// COPY on the same connection when 'then_full_copy'.
static void early_end_case(const std::string& phase, bool client_tls, End how, bool txn, PGconn* setup, PGconn* be,
    size_t msg_bytes = MSG_BYTES, bool then_full_copy = false) {
    static const char* names[] = { "error row", "error on the first row", "cancel", "statement_timeout",
                                   "CopyFail from the client", "backend killed" };
    const bool held = (how == End::CANCEL || how == End::STATEMENT_TIMEOUT);
    const std::string what = phase + (client_tls ? ", client TLS, " : ", client plain, ") + names[(int)how]
        + (msg_bytes != MSG_BYTES ? ", " + std::to_string(msg_bytes >> 20) + " MB messages" : "")
        + (txn ? " in a transaction" : "");
    const std::string expect = (how == End::ERROR_ROW || how == End::ERROR_FIRST_ROW) ? "ERR P0001" : "ERR 57014";
    PGConnPtr c = createNewConnection(ConnType::BACKEND, client_tls);
    PGConnPtr holder(nullptr, &PQfinish);
    if (held) {
        holder = createNewConnection(ConnType::BACKEND, false);
        if (!query(holder.get(), "BEGIN").empty() || !query(holder.get(), "SELECT pg_advisory_xact_lock(" + LOCK_KEY + ")").empty())
            diag("%s: could not hold the backend", what.c_str());
    }
    std::string got = "COPY did not start", pid;
    double took = -1;
    const bool begun = !txn || (query(c.get(), "BEGIN").empty()
        && (how != End::STATEMENT_TIMEOUT || query(c.get(), "SET LOCAL statement_timeout = '1s'").empty()));
    if (PQstatus(c.get()) == CONNECTION_OK && begun && start_copy(c.get())) {
        const std::string msg = make_msg("", msg_bytes);
        if (held) PQputCopyData(c.get(), "S\ts\n", 4);
        if (how == End::ERROR_FIRST_ROW) PQputCopyData(c.get(), "E\te\n", 4);
        const long before = how == End::ERROR_FIRST_ROW ? 0 : stream_for(c.get(), msg, held ? 3 : 1);
        long after = 0;
        const auto t0 = Clock::now();
        switch (how) {
        case End::ERROR_ROW:
            PQputCopyData(c.get(), "E\te\n", 4);
            break;
        case End::CANCEL: {
            char err[256] = "";
            PGcancel* cn = PQgetCancel(c.get());
            if (cn == nullptr || PQcancel(cn, err, sizeof(err)) == 0) diag("%s: PQcancel failed: %s", what.c_str(), err);
            if (cn) PQfreeCancel(cn);
            break;
        }
        case End::BACKEND_KILLED:
            pid = copy_pid(be);
            if (!pid.empty()) tlsQueryOneValue(be, "SELECT pg_terminate_backend(" + pid + ")");
            break;
        default:
            break;
        }
        if (how != End::COPY_FAIL && how != End::BACKEND_KILLED) after = stream_for(c.get(), msg, 2);
        if (holder) query(holder.get(), "COMMIT");
        got = end_copy(c.get(), how == End::COPY_FAIL ? "client gave up" : nullptr);
        took = std::chrono::duration<double>(Clock::now() - t0).count();
        diag("%s: streamed %ld messages before the early end, %ld after", what.c_str(), before, after);
    } else if (holder) {
        query(holder.get(), "COMMIT");
    }
    if (how == End::BACKEND_KILLED) {
        ok(!pid.empty() && got.rfind("ERR", 0) == 0 && took < ERROR_MAX_S, "%s: the client gets an error at once"
            " (got '%s' in %.1f s, backend pid %s)", what.c_str(), got.c_str(), took, pid.empty() ? "not found" : pid.c_str());
        PGConnPtr n = createNewConnection(ConnType::BACKEND, client_tls);
        const std::string v = n ? works(n.get()) : "no connection";
        ok(v == WORKS, "%s: a new session works (got '%s')", what.c_str(), v.c_str());
        return;
    }
    ok(got == expect, "%s: the client gets the backend's error (expected %s, got %s)",
        what.c_str(), expect.c_str(), got.c_str());
    if (txn) {
        const std::string next = query(c.get(), "SELECT 1");
        ok(next == "ERR 25P02", "%s: the next query fails as the transaction is aborted on the same backend"
            " (expected ERR 25P02, got %s)", what.c_str(), next.c_str());
        const std::string rb = query(c.get(), "ROLLBACK");
        const std::string v = works(c.get());
        ok(rb.empty() && v == WORKS, "%s: after ROLLBACK the connection works (ROLLBACK '%s', got '%s')",
            what.c_str(), rb.c_str(), v.c_str());
    } else {
        const std::string v = works(c.get());
        ok(v == WORKS, "%s: the connection still works (got '%s')", what.c_str(), v.c_str());
    }
    if (then_full_copy) {
        const std::string msg = make_msg("");
        const long rows = 4 * (long)std::count(msg.begin(), msg.end(), '\n');
        query(setup, "SELECT setval('" + SEQ + "', 1, false)");
        std::string full = "COPY did not start";
        if (start_copy(c.get())) {
            for (int i = 0; i < 4; i++) PQputCopyData(c.get(), msg.data(), (int)msg.size());
            full = end_copy(c.get());
        }
        const std::string n = counted(setup);
        ok(full.empty() && n == std::to_string(rows), "%s: a full COPY on the same connection then delivers every row"
            " (COPY '%s', sent %ld, counted %s)", what.c_str(), full.c_str(), rows, n.c_str());
    }
}

// Every message has a row that raises a NOTICE while the client keeps streaming. 3 checks.
static void notice_case(const std::string& phase, bool client_tls, PGconn* setup) {
    const std::string what = phase + (client_tls ? ", client TLS" : ", client plain") + ", NOTICE in every message";
    long notices = 0;
    PGConnPtr c = createNewConnection(ConnType::BACKEND, client_tls);
    PQsetNoticeProcessor(c.get(), count_notice, &notices);
    query(setup, "SELECT setval('" + SEQ + "', 1, false)");
    const std::string msg = make_msg("N\tn\n");
    const long rows_per_msg = std::count(msg.begin(), msg.end(), '\n');
    long sent = 0;
    std::string got = "COPY did not start";
    if (PQstatus(c.get()) == CONNECTION_OK && start_copy(c.get())) {
        sent = stream_for(c.get(), msg, 3);
        got = end_copy(c.get());
    }
    const std::string n = counted(setup);
    ok(got.empty() && notices == sent, "%s: the COPY completes and each of its %ld NOTICEs reaches the client"
        " (COPY '%s', NOTICEs %ld)", what.c_str(), sent, got.c_str(), notices);
    ok(n == std::to_string(sent * rows_per_msg), "%s: the backend received every row: sent %ld, counted %s",
        what.c_str(), sent * rows_per_msg, n.c_str());
    const std::string v = works(c.get());
    ok(v == WORKS, "%s: the connection still works (got '%s')", what.c_str(), v.c_str());
}

static void run(PGconn* admin, bool native_supported, bool ffto) {
    diag(">>>> Running a backend answer during COPY FROM STDIN%s <<<<", ffto ? ", FFTO on" : "");
    if (ffto && !executeQueries(admin, { "SET pgsql-ffto_enabled='true'", "LOAD PGSQL VARIABLES TO RUNTIME" })) return;
    const std::vector<TlsSrvRow> saved = tlsReadServers(admin);
    if (saved.empty()) { BAIL_OUT("no servers in hostgroup 0 to work with"); return; }
    const std::string saved_native = tlsQueryOneValue(admin,
        "SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
    PGConnPtr be = open_direct_backend();
    if (PQstatus(be.get()) != CONNECTION_OK) { BAIL_OUT("direct backend connection failed: %s", PQerrorMessage(be.get())); return; }

    // The sink keeps nothing: a trigger counts each row in a sequence and drops it. Row 'S' waits for the
    // advisory lock, row 'E' raises an error, row 'N' a NOTICE.
    if (!executeQueries(admin, { "UPDATE pgsql_users SET fast_forward=0", "LOAD PGSQL USERS TO RUNTIME" })) return;
    PGConnPtr setup = createNewConnection(ConnType::BACKEND, false);
    if (!setup || !executeQueries(setup.get(), {
            "DROP TABLE IF EXISTS " + TBL,
            "DROP SEQUENCE IF EXISTS " + SEQ,
            "CREATE TABLE " + TBL + " (a text, b text)",
            "CREATE SEQUENCE " + SEQ,
            "CREATE OR REPLACE FUNCTION " + FN + "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN"
                " IF NEW.a = 'S' THEN PERFORM pg_advisory_lock(" + LOCK_KEY + "); PERFORM pg_advisory_unlock(" + LOCK_KEY + "); END IF;"
                " IF NEW.a = 'E' THEN RAISE EXCEPTION 'copy early end'; END IF;"
                " IF NEW.a = 'N' THEN RAISE NOTICE 'copy notice'; END IF;"
                " PERFORM nextval('" + SEQ + "'); RETURN NULL; END $$",
            "CREATE TRIGGER " + FN + " BEFORE INSERT ON " + TBL + " FOR EACH ROW EXECUTE FUNCTION " + FN + "()" })) {
        BAIL_OUT("could not create the COPY sink");
        return;
    }

    const std::vector<std::string> protocols = native_supported
        ? std::vector<std::string> { "libpq", "native" } : std::vector<std::string> { "libpq" };
    for (const std::string& protocol : protocols) {
        if (native_supported)
            executeQueries(admin, { "SET pgsql-use_native_backend_protocol='" + std::string(protocol == "native" ? "true" : "false") + "'",
                "LOAD PGSQL VARIABLES TO RUNTIME" });
        for (int use_ssl : { 0, 1 }) {
            const std::string phase = protocol + (use_ssl ? ", backend TLS" : ", backend plain") + (ffto ? ", FFTO on" : "");
            diag("---- %s ----", phase.c_str());
            ok(tlsReloadServers(admin, saved, use_ssl), "%s: servers set to use_ssl=%d and the pool flushed", phase.c_str(), use_ssl);
            // pg_backend_pid() is answered by ProxySQL itself: find this backend by the text of the query.
            PGConnPtr probe = createNewConnection(ConnType::BACKEND, false);
            const std::string leg = probe ? tlsQueryOneValue(probe.get(),
                "SELECT s.ssl FROM pg_stat_ssl s JOIN pg_stat_activity a ON s.pid = a.pid"
                " WHERE a.state = 'active' AND a.query LIKE '%copy_early_end_leg_marker%' LIMIT 1") : "";
            ok(leg == (use_ssl ? "t" : "f"), "%s: the backend connection is %s (pg_stat_ssl says '%s')",
                phase.c_str(), use_ssl ? "encrypted" : "plain", leg.c_str());
            if (ffto) {
                // 9 checks per client mode.
                for (bool client_tls : { false, true }) {
                    early_end_case(phase, client_tls, End::ERROR_ROW, false, setup.get(), be.get(), MSG_BYTES, true);
                    early_end_case(phase, client_tls, End::CANCEL, true, setup.get(), be.get());
                    notice_case(phase, client_tls, setup.get());
                }
                continue;
            }
            // 25 checks per client mode.
            for (bool client_tls : { false, true }) {
                early_end_case(phase, client_tls, End::ERROR_ROW, false, setup.get(), be.get(), MSG_BYTES, true);
                early_end_case(phase, client_tls, End::ERROR_ROW, true, setup.get(), be.get());
                early_end_case(phase, client_tls, End::ERROR_FIRST_ROW, false, setup.get(), be.get());
                early_end_case(phase, client_tls, End::ERROR_ROW, false, setup.get(), be.get(), BIG_MSG_BYTES);
                early_end_case(phase, client_tls, End::CANCEL, false, setup.get(), be.get());
                early_end_case(phase, client_tls, End::CANCEL, true, setup.get(), be.get());
                early_end_case(phase, client_tls, End::STATEMENT_TIMEOUT, true, setup.get(), be.get());
                early_end_case(phase, client_tls, End::COPY_FAIL, false, setup.get(), be.get());
                early_end_case(phase, client_tls, End::BACKEND_KILLED, false, setup.get(), be.get());
                notice_case(phase, client_tls, setup.get());
            }
        }
    }

    if (native_supported && !saved_native.empty())
        executeQueries(admin, { "SET pgsql-use_native_backend_protocol='" + saved_native + "'", "LOAD PGSQL VARIABLES TO RUNTIME" });
    if (ffto) executeQueries(admin, { "SET pgsql-ffto_enabled='false'", "LOAD PGSQL VARIABLES TO RUNTIME" });
    // As in testCopyOverTlsBackend(): the harness reloads the config from disk before the next test.
    if (!tlsReloadServers(admin, saved, 0))
        diag("WARNING: could not restore the original pgsql_servers rows for hostgroup 0");
    query(setup.get(), "DROP TABLE IF EXISTS " + TBL);
    query(setup.get(), "DROP FUNCTION IF EXISTS " + FN + "()");
    query(setup.get(), "DROP SEQUENCE IF EXISTS " + SEQ);
    diag(">>>> Done <<<<");
}

} // namespace early_end

/**
 * More of COPY FROM STDIN, for each backend protocol:
 *  - a WHERE clause: only the matching rows are stored, and the command tag says how many;
 *  - the query digests count each COPY, the one with a WHERE clause under its own digest;
 *  - 8 sessions, half of them over TLS, each COPY rows of their own at the same time: every row of each
 *    must arrive, and every session keep working.
 */
namespace more {

static const std::string TBL = "copy_more_from";
static const int PAR_SESSIONS = 8;
static const int PAR_ROWS = 20000;
// Per backend protocol: 2 WHERE (plain and TLS client), 1 digest, 1 parallel.
static const int TESTS_PER_PROTOCOL = 4;

// Runs a COPY FROM STDIN of 'data'. Returns the command tag's row count, or "ERR ..." / "" on failure.
static std::string copy_in(PGconn* c, const std::string& sql, const std::string& data) {
    PGresult* r = PQexec(c, sql.c_str());
    const bool started = PQresultStatus(r) == PGRES_COPY_IN;
    PQclear(r);
    if (!started) return std::string("ERR start: ") + PQerrorMessage(c);
    if (PQputCopyData(c, data.data(), (int)data.size()) != 1 || PQputCopyEnd(c, nullptr) != 1)
        return std::string("ERR send: ") + PQerrorMessage(c);
    std::string out;
    while ((r = PQgetResult(c)) != nullptr) {
        if (out.empty()) out = PQresultStatus(r) == PGRES_COMMAND_OK ? PQcmdTuples(r) : std::string("ERR ") + PQerrorMessage(c);
        PQclear(r);
    }
    return out;
}

static std::string numbers(int from, int to, const std::string& prefix = "") {
    std::string d;
    for (int i = from; i <= to; i++) d += prefix + std::to_string(i) + "\n";
    return d;
}

static void run_protocol(PGconn* admin, const std::string& protocol) {
    PGConnPtr c = createNewConnection(ConnType::BACKEND, false);
    if (!c || !executeQueries(c.get(), { "DROP TABLE IF EXISTS " + TBL, "CREATE TABLE " + TBL + " (id int, a int)" })) {
        BAIL_OUT("could not create %s", TBL.c_str());
        return;
    }

    for (bool client_tls : { false, true }) {
        PGConnPtr w = createNewConnection(ConnType::BACKEND, client_tls);
        std::string tag = "no connection", n;
        if (w && executeQueries(w.get(), { "TRUNCATE " + TBL })) {
            tag = copy_in(w.get(), "COPY " + TBL + " (a) FROM STDIN WHERE a > 5", numbers(1, 10));
            n = tlsQueryOneValue(w.get(), "SELECT count(*) FROM " + TBL + " WHERE a > 5");
            n += "/" + tlsQueryOneValue(w.get(), "SELECT count(*) FROM " + TBL);
        }
        ok(tag == "5" && n == "5/5", "%s, client %s: COPY FROM STDIN WHERE stores only the matching rows"
            " (tag 'COPY %s', matching/stored rows %s)", protocol.c_str(), client_tls ? "TLS" : "plain", tag.c_str(), n.c_str());
    }

    // The last pass of execute_tests() leaves the digests off.
    executeQueries(admin, { "SET pgsql-query_digests='true'", "LOAD PGSQL VARIABLES TO RUNTIME",
        "SELECT * FROM stats_pgsql_query_digest_reset" });
    for (int i = 0; i < 3; i++) copy_in(c.get(), "COPY " + TBL + " (a) FROM STDIN", numbers(1, 10));
    copy_in(c.get(), "COPY " + TBL + " (a) FROM STDIN WHERE a > 5", numbers(1, 10));
    std::string plain, where;
    for (int i = 0; i < 30 && !(plain == "3" && where == "1"); i++) {
        plain = tlsQueryOneValue(admin, "SELECT COALESCE(SUM(count_star),0) FROM stats_pgsql_query_digest"
            " WHERE digest_text LIKE 'COPY " + TBL + "%' AND digest_text NOT LIKE '%WHERE%'");
        where = tlsQueryOneValue(admin, "SELECT COALESCE(SUM(count_star),0) FROM stats_pgsql_query_digest"
            " WHERE digest_text LIKE 'COPY " + TBL + "%WHERE%'");
        if (!(plain == "3" && where == "1")) usleep(100000);
    }
    ok(plain == "3" && where == "1", "%s: the query digests count each COPY FROM STDIN (plain %s of 3, with WHERE %s of 1)",
        protocol.c_str(), plain.c_str(), where.c_str());

    executeQueries(c.get(), { "TRUNCATE " + TBL });
    std::vector<std::string> tags(PAR_SESSIONS), after(PAR_SESSIONS);
    std::vector<std::thread> threads;
    for (int t = 0; t < PAR_SESSIONS; t++) {
        threads.emplace_back([&, t]() {
            PGConnPtr p = createNewConnection(ConnType::BACKEND, t % 2 == 1);
            if (!p) { tags[t] = "no connection"; return; }
            tags[t] = copy_in(p.get(), "COPY " + TBL + " (id, a) FROM STDIN", numbers(1, PAR_ROWS, std::to_string(t) + "\t"));
            after[t] = tlsQueryOneValue(p.get(), "SELECT 1");
        });
    }
    for (auto& th : threads) th.join();
    bool all = true;
    std::string report;
    for (int t = 0; t < PAR_SESSIONS; t++) {
        const std::string n = tlsQueryOneValue(c.get(), "SELECT count(*) FROM " + TBL + " WHERE id = " + std::to_string(t));
        const bool good = tags[t] == std::to_string(PAR_ROWS) && n == tags[t] && after[t] == "1";
        all = all && good;
        if (!good) report += " session " + std::to_string(t) + ": tag '" + tags[t] + "', stored " + n + ", then '" + after[t] + "';";
    }
    ok(all, "%s: %d sessions COPY FROM STDIN at once, each %d rows: every row arrives and every session works%s",
        protocol.c_str(), PAR_SESSIONS, PAR_ROWS, report.c_str());

    executeQueries(c.get(), { "DROP TABLE IF EXISTS " + TBL });
}

} // namespace more

void execute_tests(bool with_ssl, bool diff_conn, bool query_digests = true) {

    PGConnPtr admin_conn_1 = createNewConnection(ConnType::ADMIN, with_ssl);

    if (!executeQueries(admin_conn_1.get(), {
           "DELETE FROM pgsql_query_rules",
           "LOAD PGSQL QUERY RULES TO RUNTIME",
           "UPDATE pgsql_users SET fast_forward=0" ,
           "LOAD PGSQL USERS TO RUNTIME",
           query_digests ? "SET pgsql-query_digests='true'" : "SET pgsql-query_digests='false'",
           "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;

    diag(">>>> query_digests=%s <<<<", query_digests ? "true" : "false");

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
    if (cl.getEnv())
        return exit_status();

	spawn_internal_noise(cl, internal_noise_mysql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}});
	spawn_internal_noise(cl, internal_noise_prometheus_poller);
	spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}});

	PGConnPtr admin = createNewConnection(ConnType::ADMIN, false);
	if (!admin) { BAIL_OUT("Error: failed to connect to admin in file %s, line %d\n", __FILE__, __LINE__); return exit_status(); }
	const bool native_supported = pgsql_native_supported(admin.get());
	const std::vector<std::string> protocols = native_supported
		? std::vector<std::string> { "libpq", "native" } : std::vector<std::string> { "libpq" };
	const bool ffto_supported = tlsQueryOneValue(admin.get(),
		"SELECT count(*) FROM global_variables WHERE variable_name='pgsql-ffto_enabled'") == "1";
	const int per_protocol = 59 * 4 + TLS_BACKEND_TESTS + more::TESTS_PER_PROTOCOL;
	const int early_end_tests = (int)protocols.size()
		* (early_end::TESTS_PER_PROTOCOL + (ffto_supported ? early_end::FFTO_TESTS_PER_PROTOCOL : 0));

	if (cl.use_noise) {
		plan((int)protocols.size() * per_protocol + 3 + early_end_tests);
	} else {
		plan((int)protocols.size() * per_protocol + early_end_tests);
	}

	const std::string saved_native = tlsQueryOneValue(admin.get(),
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
	const std::vector<TlsSrvRow> servers = tlsReadServers(admin.get());
	for (const std::string& protocol : protocols) {
		diag("==== backend protocol: %s ====", protocol.c_str());
		// Reloading the servers drops the pooled connections, so the next ones use the protocol set here.
		if (native_supported && !(executeQueries(admin.get(), { "SET pgsql-use_native_backend_protocol='"
				+ std::string(protocol == "native" ? "true" : "false") + "'", "LOAD PGSQL VARIABLES TO RUNTIME" })
				&& tlsReloadServers(admin.get(), servers, 0)))
			BAIL_OUT("could not switch the backend protocol to %s", protocol.c_str());

		// query_digests ON: strncasecmp fast-reject path active
		execute_tests(true, false, true);
		execute_tests(false, false, true);
		// query_digests OFF: falls back to full RE2 match
		execute_tests(true, false, false);
		execute_tests(false, false, false);

		// It changes pgsql_servers.use_ssl and restores it.
		testCopyOverTlsBackend();
		more::run_protocol(admin.get(), protocol);
	}
	if (native_supported && !saved_native.empty())
		executeQueries(admin.get(), { "SET pgsql-use_native_backend_protocol='" + saved_native + "'", "LOAD PGSQL VARIABLES TO RUNTIME" });

	// Runs last: it changes pgsql_servers.use_ssl and the backend protocol, and restores them.
    early_end::run(admin.get(), native_supported, false);
    if (ffto_supported) early_end::run(admin.get(), native_supported, true);

    return exit_status();
}
