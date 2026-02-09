/**
 * @file pgsql-connection_parameters_test-t-t.cpp
 * @brief This TAP test validates if connection parameters are correctly handled by ProxySQL.
 * 
 * Note:
 *  - Using libpq to test ProxySQL's handling of undocumented parameters isn't possible, as libpq enforces a strict subset of PostgreSQL 
 *    connection parameters as per the official documentation, rejecting any undocumented parameters. However, actual 
 *    PostgreSQL servers accept additional parameters (e.g., extra_float_digits) and apply them at the connection/session level. 
 *    To test this behavior, a raw socket is used to connect to a ProxySQL server and send custom built messages to communicate
 *    with ProxySQL. It currently works with plain text password authentication, without ssl support.
 *    
 *  - Failure due to an invalid parameter returned by the PostgreSQL server, differs from ProxySQL's behavior.
 *    PostgreSQL returns an error during the connection handshake phase, whereas in ProxySQL, the connection succeeds, 
 *    but the error is encountered when executing a query. 
 *    This is behaviour is intentional, as newer PostgreSQL versions may introduce new parameters that ProxySQL is not yet aware of.
 * 
 * 
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

PGConnPtr createNewConnection(ConnType conn_type, const std::string& parameters = "", bool with_ssl = false) {
    
    const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
    int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
    const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

    std::stringstream ss;

    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

	if (parameters.empty() == false) {
		ss << " " << parameters;
	}

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection failed to '%s': %s\n", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
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
            fprintf(stderr, "Failed to execute query '%s': %s\n",
                query.c_str(), PQerrorMessage(conn));
            PQclear(res);
            return false;
        }
        PQclear(res);
    }
    return true;
}

struct parameter {
	std::string name;
	std::string value;
};

struct parameter_test {
    std::vector<parameter> set_admin_vars;  // Admin variables to set
    std::vector<parameter> conn_params;     // Parameters in startup message
    std::vector<std::string> conn_options;    // Options (-c flags) in startup
    std::vector<std::string> set_commands;    // SET commands after connection
    std::vector<std::string> expected;      // Expected SHOW values
    bool reset_after;                       // Whether to RESET parameters
    bool expect_failure;                    // If connection/query should fail
};

/**
 * @struct MyPGresult
 * @brief Represents the result of a PostgreSQL query.
 *
 * This structure holds the columns, rows, status, and error message of a PostgreSQL query result.
 */
struct MyPGresult {
    std::vector<std::string> columns; ///< Column names of the result set.
    std::vector<std::vector<std::string>> rows; ///< Rows of the result set.
    std::string status; ///< Status of the query execution.
    std::string error; ///< Error message if the query failed.
};

struct PgSQLResponse {
    char type; ///< Type of the response message.
    int32_t length; ///< Length of the response message.
    std::vector<char> data; ///< Data of the response message.
};

void add_param(std::vector<char>& msg, std::string_view key, std::string_view value) {
    msg.insert(msg.end(), key.begin(), key.end());
    msg.push_back('\0');
    msg.insert(msg.end(), value.begin(), value.end());
    msg.push_back('\0');
}

// Function to receive data from socket
bool recv_data(int sock, void* buffer, size_t len) {

    if (recv(sock, buffer, len, 0) <= 0) {
        fprintf(stderr, "Error receiving data\n");
		return false;
    }
	return true;
}

// Function to send data over socket
bool send_data(int sock, const void* data, size_t len) {
    if (send(sock, data, len, 0) != len) {
        fprintf(stderr, "Error sending data\n");
        return false;
    }
	return true;
}

/**
 * @brief Builds a startup message for PostgreSQL connection.
 *
 * This function constructs a startup message for PostgreSQL connection using the provided
 * connection parameters. 
 *
 * @param parameters A vector of key-value pairs representing the connection parameters.
 * @return A vector of characters representing the constructed startup message.
 */
std::vector<char> build_startup_message(const std::vector<parameter>& parameters) {
    // Build startup message
    std::vector<char> startup_body;
    int32_t protocol = htonl(0x00030000);  // Protocol 3.0
    startup_body.insert(startup_body.end(), (char*)&protocol, (char*)&protocol + 4);

    // Add connection parameters
    for (const auto& param : parameters) {
        add_param(startup_body, param.name, param.value);
    }
    startup_body.push_back('\0');

    // Prepend message length
    std::vector<char> startup_msg;
    int32_t len = htonl(startup_body.size() + 4);
    startup_msg.insert(startup_msg.end(), (char*)&len, (char*)&len + 4);
    startup_msg.insert(startup_msg.end(), startup_body.begin(), startup_body.end());

    return startup_msg;
}

/**
 * @brief Builds a password message for PostgreSQL authentication.
 *
 * This function constructs a password message to be sent to the PostgreSQL server
 * during the authentication process. 
 *
 * @param password The password to be included in the message.
 * @return A vector of characters representing the constructed password message.
 */
std::vector<char> build_password_message(std::string_view password) {
    std::vector<char> password_message;
    int pass_msg_len = htonl(password.size() + 1 + 4);
    password_message.push_back('p');
    password_message.insert(password_message.end(), (char*)&pass_msg_len, (char*)&pass_msg_len + 4);
    password_message.insert(password_message.end(), password.begin(), password.end());
    password_message.push_back('\0');
    return password_message;
}

/**
 * @brief Connects to a PostgreSQL server.
 *
 * This function establishes a connection to a PostgreSQL server using the provided
 * host and port number.
 *
 * @param host The hostname or IP address of the PostgreSQL server.
 * @param port The port number of the PostgreSQL server.
 * @return The socket file descriptor for the connection.
 */
int connect_server(const std::string& host, int port) {
    int sock;
    struct sockaddr_in server;

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        return 1;
    }

    // Configure server address
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(host.c_str());

    // Connect to PostgreSQL server
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        fprintf(stderr, "Connection failed\n");
        return -1;
    }
    return sock;
}

/**
 * @brief Sends a startup message to the PostgreSQL server.
 *
 * This function constructs and sends a startup message to the PostgreSQL server
 * using the provided socket and connection parameters.
 *
 * @param sock The socket file descriptor for the connection.
 * @param params A vector of key-value pairs representing the connection parameters.
 */
void send_startup_message(int sock, const std::vector<std::pair<std::string, std::string>>& params) {

    int param_count = params.size();

    char msg[512];
    int offset = 0;
    uint32_t length = 4 + 4;

    for (int i = 0; i < param_count; i++) {
        length += params[i].first.size() + 1 + params[i].second.size() + 1;
    }
    length += 1;

    uint32_t length_nbo = htonl(length);
    uint32_t protocol = htonl(196608);

    memcpy(msg + offset, &length_nbo, 4);
    offset += 4;
    memcpy(msg + offset, &protocol, 4);
    offset += 4;

    for (int i = 0; i < param_count; i++) {
        strcpy(msg + offset, params[i].first.c_str());
        offset += params[i].first.size() + 1;
        strcpy(msg + offset, params[i].second.c_str());
        offset += params[i].second.size() + 1;
    }
    msg[offset++] = '\0';

    send(sock, msg, offset, 0);
}

/**
 * @brief Parses an error message from a PostgreSQL response payload.
 *
 * This function extracts and returns the error message from a given PostgreSQL response payload.
 *
 * @param payload A vector of characters representing the PostgreSQL response payload.
 * @return A string containing the extracted error message.
 */
std::string parse_error(const std::vector<char>& payload) {
    const char* data = payload.data();
    size_t pos = 0;
    std::string message;

    while (pos < payload.size()) {
        if (data[pos] == '\0') break;
        char field_type = data[pos++];

        std::string field_value;
        while (pos < payload.size() && data[pos] != '\0') {
            field_value += data[pos++];
        }
        pos++;

        if (field_type == 'M') message = field_value;
    }
    return message;
}

/**
 * @brief Handles cleartext password authentication for PostgreSQL.
 *
 * This function processes the cleartext password authentication request from the PostgreSQL server.
 *
 * @param sock The socket file descriptor for the connection.
 * @param password The password to be sent for authentication.
 * @return True if authentication is successful, false otherwise.
 */
bool handle_cleartext_auth(int sock, std::string_view password) {

    char response[1024];
    if (recv_data(sock, response, 9) == false) { // Read first 8 bytes (message type + length + auth type)
        fprintf(stderr, "Error: failed to receive authentication message in file %s, line %d\n", __FILE__, __LINE__);
        return false;
    }

    if (response[0] != 'R') {
        fprintf(stderr, "Unexpected authentication response\n");
        return false;
    }

    uint32_t auth_type;
    memcpy(&auth_type, response + 5, 4);
    auth_type = ntohl(auth_type);

    if (auth_type == 3) { // AuthenticationCleartextPassword
        diag("Server requests cleartext password authentication\n");

        std::vector<char> password_msg = build_password_message(password);

        // Send PasswordMessage
        if (send_data(sock, password_msg.data(), password_msg.size()) == false) {
            fprintf(stderr, "Error: failed to send password message in file %s, line %d\n", __FILE__, __LINE__);
            return false;
        }

        // Receive AuthenticationOK or Failure
        if (recv_data(sock, response, 5) == false) {
            fprintf(stderr, "Error: failed to receive authentication response in file %s, line %d\n", __FILE__, __LINE__);
            return false;
        }

        if (response[0] == 'E') {
			uint32_t err_msg_len = ntohl(*reinterpret_cast<uint32_t*>(response + 1));
			if (recv_data(sock, response, err_msg_len - 4) == false) {
				fprintf(stderr, "Error: failed to receive error message in file %s, line %d\n", __FILE__, __LINE__);
				return false;
			}

            const std::vector<char> payload (response, response + err_msg_len - 4);
            std::string error_message = parse_error(payload);
            fprintf(stderr, "%s\n", error_message.c_str());
            return false;
        }
        else if (response[0] != 'R') {
            fprintf(stderr, "Unexpected authentication response\n");
            return false;
        }

        if (recv_data(sock, response, 4) == false) {
            fprintf(stderr, "Error: failed to receive error message in file %s, line %d\n", __FILE__, __LINE__);
            return false;
        }

        memcpy(&auth_type, response, 4);
        auth_type = ntohl(auth_type);

        if (auth_type != 0) {
            diag("Authentication failed!\n");
            return false;
        }

        std::vector<PgSQLResponse> msg_list;

        while (true) {
            int bytes_received = recv(sock, response, sizeof(response), MSG_DONTWAIT);
            if (bytes_received == 0) {
                fprintf(stderr, "Error: Connection closed in file %s, line %d\n", __FILE__, __LINE__);
                return false;
            }

            if (bytes_received == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                fprintf(stderr, "Error: Connection closed or error occurred in file %s, line %d\n", __FILE__, __LINE__);
                return false;
            }

            size_t offset = 0;
            while (offset < static_cast<size_t>(bytes_received)) {
                char messageType = response[offset];
                int32_t messageLength;

                if (offset + 5 > static_cast<size_t>(bytes_received)) {
                    fprintf(stderr, "Incomplete message header received\n");
                    return false;
                }

                memcpy(&messageLength, response + offset + 1, 4);
                messageLength = ntohl(messageLength);

                if (offset + messageLength > static_cast<size_t>(bytes_received)) {
                    fprintf(stderr, "Incomplete message body received.\n");
                    return false;
                }

                PgSQLResponse msg;
                msg.type = messageType;
                msg.length = messageLength;
                msg.data.assign(response + offset + 5, response + offset + messageLength + 1);
                msg_list.emplace_back(std::move(msg));
                offset += messageLength + 1;
            }
        }

        if (msg_list.back().type == 'E') {
			const std::vector<char> payload = msg_list.back().data;
            std::string error_message = parse_error(payload);
            fprintf(stderr, "%s\n", error_message.c_str());
            return false;
        } else if (msg_list.back().type != 'Z') {
            fprintf(stderr, "Unexpected message type %c\n", msg_list.back().type);
            return false;
        }

    } else {
        diag("Unexpected authentication method: %d\n", auth_type);
        return false;
    }
    diag("Authentication successful!\n");
    return true;
}

/**
 * @brief Executes a query on the PostgreSQL server.
 *
 * This function sends a query to the PostgreSQL server and processes the response.
 *
 * @param sock The socket file descriptor for the connection.
 * @param query The SQL query to be executed.
 * @return A unique pointer to a MyPGresult structure containing the query result.
 */
std::unique_ptr<MyPGresult> execute_query(int sock, const std::string& query) {
    std::vector<char> msg;

    // Build query message
    msg.push_back('Q');
    uint32_t length = htonl(query.size() + 5); // 1 byte for Q + 4 for length + query + null
    msg.insert(msg.end(), reinterpret_cast<char*>(&length), reinterpret_cast<char*>(&length) + 4);
    msg.insert(msg.end(), query.begin(), query.end());
    msg.push_back('\0');

    // Send Query message
    if (send_data(sock, msg.data(), msg.size()) == false) {
        fprintf(stderr, "Error: failed to send query in file %s, line %d\n", __FILE__, __LINE__);
        return nullptr;
    }

    std::unique_ptr<MyPGresult> result(new MyPGresult);

    while (true) {
        char msg_type;
        if (recv_data(sock, reinterpret_cast<char*>(&msg_type), 1) == false) {
            fprintf(stderr, "Error: failed to receive message in file %s, line %d\n", __FILE__, __LINE__);
            return nullptr;
        }

        uint32_t msg_length;
        if (recv_data(sock, reinterpret_cast<char*>(&msg_length), 4) == false) {
            fprintf(stderr, "Error: failed to receive message length in file %s, line %d\n", __FILE__, __LINE__);
            return nullptr;
        }

        msg_length = ntohl(msg_length);

        std::vector<char> payload(msg_length - 4);
        if (msg_length > 4) {
            if (recv_data(sock, payload.data(), msg_length - 4) == false) {
                fprintf(stderr, "Error: failed to receive message payload in file %s, line %d\n", __FILE__, __LINE__);
                return nullptr;
            }
        }

        switch (msg_type) {
        case 'T': { // Row Description
            const char* data = payload.data();
            uint16_t num_columns;
            memcpy(&num_columns, data, 2);
            num_columns = ntohs(num_columns);

            size_t pos = 2;
            result->columns.reserve(num_columns);
            for (int i = 0; i < num_columns; i++) {
                std::string col_name(data + pos);
                pos += col_name.length() + 1 + 22; // Skip field metadata
                result->columns.push_back(col_name);
            }
            break;
        }

        case 'D': { // Data Row
            const char* data = payload.data();
            uint16_t num_fields;
            memcpy(&num_fields, data, 2);
            num_fields = ntohs(num_fields);

            std::vector<std::string> row;
            size_t pos = 2;
            for (int i = 0; i < num_fields; i++) {
                int32_t field_len;
                memcpy(&field_len, data + pos, 4);
                pos += 4;
                field_len = ntohl(field_len);

                if (field_len == -1) {
                    row.push_back("NULL");
                }
                else {
                    row.emplace_back(data + pos, field_len);
                    pos += field_len;
                }
            }
            result->rows.push_back(row);
            break;
        }

        case 'C': // Command Complete
            result->status = std::string(payload.data(), payload.size());
            break;

        case 'E': // Error
            result->error = parse_error(payload);
            // Consume remaining messages
            while (msg_type != 'Z') {
                if (recv_data(sock, &msg_type, 1) == false) {
                    fprintf(stderr, "Error: failed to receive message in file %s, line %d\n", __FILE__, __LINE__);
                    return nullptr;
                }
                if (recv_data(sock, reinterpret_cast<char*>(&msg_length), 4) == false) {
                    fprintf(stderr, "Error: failed to receive message length in file %s, line %d\n", __FILE__, __LINE__);
                    return nullptr;
                }

                msg_length = ntohl(msg_length);
                if (msg_length > 4) {
                    std::vector<char> temp(msg_length - 4);
                    if (recv_data(sock, temp.data(), msg_length - 4) == false) {
                        fprintf(stderr, "Error: failed to receive message payload in file %s, line %d\n", __FILE__, __LINE__);
                        return nullptr;
                    }
                }
            }
            return std::move(result);

        case 'Z': // Ready for Query
            return std::move(result);

        default:
            break;
        }
    }
    return nullptr;
}

const char* escape_string_backslash_spaces(const char* input) {
    const char* c;
    int input_len = 0;
    int escape_count = 0;

    for (c = input; *c != '\0'; c++) {
        if ((*c == ' ')) {
            escape_count += 3;
        }
        else if ((*c == '\\')) {
            escape_count += 2;
        }
        input_len++;
    }

    if (escape_count == 0)
        return input;

    char* output = (char*)malloc(input_len + escape_count + 1);
    char* p = output;

    for (c = input; *c != '\0'; c++) {
        if ((*c == ' ')) {
            memcpy(p, "\\\\", 2);
            p += 2;
        }
        else if (*c == '\\') {
            *(p++) = '\\';
        }
        *(p++) = *c;
    }
    *(p++) = '\0';
    return output;
}

bool test_parameters(PGconn* admin_conn, const parameter_test& test) {
    char buffer[512];
    bool ret = false;
    for (const auto& parameter : test.set_admin_vars) {
        snprintf(buffer, sizeof(buffer), "SET %s='%s'", parameter.name.c_str(), parameter.value.c_str());

		if (executeQueries(admin_conn, { buffer, "LOAD PGSQL VARIABLES TO RUNTIME" }) == false) {
			diag("Error: failed to set admin variable in file %s, line %d", __FILE__, __LINE__);
			return false;
		}
    }

    int sock = connect_server(cl.pgsql_host, cl.pgsql_port);
    if (sock == -1) {
        diag("Error: failed to connect to the server in file %s, line %d", __FILE__, __LINE__);
        return false;
    }

    // Build startup message
    std::vector<parameter> parameters = {
        { "user", cl.pgsql_username },
    };

	parameters.reserve(test.conn_params.size() + test.conn_options.size() + 1);

	for (const auto& param : test.conn_params) {
        if (param.value.empty() == true) continue;
		parameters.push_back(param);
	}

	if (test.conn_options.empty() == false) {
        std::string options_value;

        for (size_t i = 0; i < test.conn_options.size(); i++) {

            options_value += " -c " + test.conn_params[i].name;
            options_value += "=";

            const char* value = test.conn_options[i].c_str();
			const char* escaped_value = escape_string_backslash_spaces(value);
			options_value += escaped_value;

            if (value != escaped_value)
			    free((void*)escaped_value);
		}

		parameters.push_back({ "options", options_value });
	}

    // print parameters
	for (const auto& param : parameters) {
		diag("Parameter: %s = %s\n", param.name.c_str(), param.value.c_str());
	}

    std::vector<char> startup_msg = build_startup_message(parameters);

    // Send StartupMessage
    if (send_data(sock, startup_msg.data(), startup_msg.size()) == false) {
        diag("Error: failed to send startup message in file %s, line %d", __FILE__, __LINE__);
        goto cleanup;
    }

    // Receive AuthenticationRequest
    if (handle_cleartext_auth(sock, cl.pgsql_password) == false) {
        if (test.expect_failure) {
            ok(true, "Authentication should fail");
            ret = true;
        } else {
            diag("Error: failed to handle cleartext authentication in file %s, line %d", __FILE__, __LINE__);
        }
        goto cleanup;
    }

    for (size_t i = 0; i < test.set_commands.size(); i++) {
        snprintf(buffer, sizeof(buffer), "SET %s='%s'", test.conn_params[i].name.c_str(), test.set_commands[i].c_str());
        diag("Executing: %s\n", buffer);
        auto result = execute_query(sock, buffer);

		if (result == nullptr) {
			diag("Error: failed to execute query in file %s, line %d", __FILE__, __LINE__);
            goto cleanup;
		}

        if (result->error.empty() == false) {
            ok(test.expect_failure, "Query '%s' should fail. %s", buffer, result->error.c_str());
        }
    }

    if (test.reset_after) {
		for (const auto& param : test.conn_params) {
			std::string reset_cmd = "RESET " + param.name;
            diag("Executing: %s\n", reset_cmd.c_str());
            auto result = execute_query(sock, reset_cmd);
			if (result == nullptr) {
				diag("Error: failed to reset parameter in file %s, line %d", __FILE__, __LINE__);
                goto cleanup;
			}
			if (result->error.empty() == false) {
                ok(test.expect_failure, "Query '%s' should fail. %s", reset_cmd.c_str(), result->error.c_str());
            }
		}
    }

    for (int i = 0; i < test.conn_params.size(); i++) {
        const auto& param = test.conn_params[i];
		std::string show_cmd = "SHOW " + param.name;
        diag("Executing: %s\n", show_cmd.c_str());
        auto result = execute_query(sock, show_cmd);
		if (result == nullptr) {
			diag("Error: failed to execute query in file %s, line %d", __FILE__, __LINE__);
            goto cleanup;
		}
		if (test.expect_failure == false && result->error.empty()) {
			ok(result->rows.size() == 1, "Number of rows should be 1");
			ok(result->rows[0][0] == test.expected[i], "Parameter '%s' value should be '%s'. Actual: '%s'",
                param.name.c_str(), test.expected[i].c_str(), result->rows[0][0].c_str());
		} else {
            ok(test.expect_failure, "Query '%s' should fail. %s", show_cmd.c_str(), result->error.c_str());
		}
	}
	ret = true;
cleanup:
    close(sock);

    return ret;
}

std::vector<parameter_test> test_cases = {
    // check if connection parameters validation is working correctly
    {   {},
        {{"sslmode", "test"}},
        {},
        {},
        {""},
        false,
        true
    },
	// check if session parameter validation is working correctly
    {   {},
        {{"extra_float_digits", "20"}},
        {},
        {},
        {""},
        false,
        true
    },
    // check if options parameters validation is working correctly
    {   {},
        {{"extra_float_digits", "1"}},
        {"19"},
        {},
        {""},
        false,
        true
    },
    {   {},
        {{"ENABLE_HASHJOIN", "off"}, {"enable_seqscan", "on"}},
        {"on", "off"},
        {},
        {"off", "on"},
        false,
        false
    },
    {   
        {},
        {{"extra_float_digits", "1"}},
        {"2"},
        {},
        {"1"},
        false,
        false
    },
    {
        {},
        {{"enable_hashjoin", "off"}, {"enable_seqscan", "on"}},
        {"on", "off"},
        {"on", "off"},
        {"off", "on"},
        true,
        false
    },
    {
        {{"pgsql-default_datestyle", "ISO, MDY"}},
        {{"datestyle", ""}},
        {},
        {"Postgres"},
        {"Postgres, MDY"},
        false,  // Reset both
        false
    },
    {
        {{"pgsql-default_datestyle", "ISO, MDY"}},
        {{"datestyle", ""}},
        {},
        {"Postgres"},
        {"ISO, MDY"},
        true,  // Reset both
        false
    },
    {
        {},
        {{"escape_string_warning", "on"}, {"standard_conforming_strings", "on"}},
		{},
		{"off", "off"},
        {"off", "off"},
        false,
        false
    },
	{
		{},
		{{"client_encoding", "UTF8"}},
		{"LATIN1"},
		{},
		{"UTF8"},
		false,
		false
	},
	{
		{},
		{{"client_encoding", "UTF8"}},
		{"LATIN1"},
		{"LATIN1"},
		{"LATIN1"},
		false,
		false
	},
    {
        {{"pgsql-default_client_encoding", "utf8"}},
        {{"client_encoding", "UTF8"}},
        {"LATIN1"},
        {"LATIN1"},
        {"UTF8"},
        true,
        false
    },
    {
        {},
        {{"invalid_param", "invalid"}},
        {},
        {},
        {"invalid"},
        false,
        true
    }
};

constexpr int MAX_REG_ITERATION_PER_THREAD = 5;
constexpr int MAX_REG_THREAD = 2;

void test_invalid_param_reg_4919_thread() {
    auto admin_conn = createNewConnection(ConnType::ADMIN, "", false);

    if (!admin_conn || PQstatus(admin_conn.get()) != CONNECTION_OK) {
        diag("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    parameter_test invalid_param_test = test_cases.back();

    for (int i = 0; i < MAX_REG_ITERATION_PER_THREAD; i++) {
        if (test_parameters(admin_conn.get(), invalid_param_test) == false) {
            diag("Error: failed to test parameters in file %s, line %d", __FILE__, __LINE__);
			return;
        }
    }
}

int main(int argc, char** argv) {

    int test_count = 0;

	for (const auto& test_case : test_cases) {

        if (test_case.expect_failure) {
            int case_count = 1;

            if (test_case.set_commands.empty() == false)
                case_count++;
            if (test_case.reset_after)
                case_count++;

            test_count += test_case.conn_params.size() * case_count;
        } else
            test_count += test_case.conn_params.size() * 2;
	}

    // Regression test for Issue#4919 (https://github.com/sysown/proxysql/issues/4919)
	int test_count_regression = 0;

    const auto& test_case = test_cases.back();

    if (test_case.expect_failure) {
        int case_count = 1;

        if (test_case.set_commands.empty() == false)
            case_count++;
        if (test_case.reset_after)
            case_count++;

        test_count_regression += test_case.conn_params.size() * case_count;
    }
    else
        test_count_regression += test_case.conn_params.size() * 2;

	test_count_regression *= MAX_REG_ITERATION_PER_THREAD * MAX_REG_THREAD;
    test_count_regression += 1; // execute "select 1" to check if proxysql is alive
	// Regression test for Issue#4919
    test_count += test_count_regression;

    plan(test_count);

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

    for (const auto& test_case : test_cases) {

        if (test_parameters(admin_conn.get(), test_case) == false) {
            diag("Error: failed to test parameters in file %s, line %d", __FILE__, __LINE__);
            return exit_status();
        }
    }

    // Regression test for Issue#4919 (https://github.com/sysown/proxysql/issues/4919)
    std::vector<std::thread> threads;
  
    for (int i = 0; i < MAX_REG_THREAD; ++i) {
        threads.emplace_back(test_invalid_param_reg_4919_thread);
    }

    for (auto& t : threads) {
        t.join();
    }

    auto result = executeQueries(admin_conn.get(), {"SELECT 1"});

	ok(result, "ProxySQL should be alive");
    // Regression test for Issue#4919

    return exit_status();
}
