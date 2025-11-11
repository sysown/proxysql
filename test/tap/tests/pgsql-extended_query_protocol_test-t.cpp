// NOSONAR - TAP test files do not need to follow the same rules as production code
/**
 * @file pgsql-extended_query_protocol_test-t.cpp
 * @brief This TAP test suite verifies the correct handling of PostgreSQL's Extended Query Protocol 
 * through ProxySQL. It includes comprehensive tests for Parse, Bind, Execute, Describe, and Close message flows,
 * ensuring compliance with protocol semantics and robustness under edge cases.
 */

#include <fcntl.h>
#include <cerrno>
#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include "libpq-fe.h"
#include "pg_lite_client.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

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

std::fstream f_proxysql_log{};

bool check_logs_for_command(const std::string& command_regex) {
	const auto& [_, cmd_lines] { get_matching_lines(f_proxysql_log, command_regex) };
	return cmd_lines.empty() ? false : true;
}

std::shared_ptr<PgConnection> create_connection() {
	auto conn = std::make_shared<PgConnection>(5000);
	try {
		conn->connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
	}
	catch (const PgException& e) {
		diag("Connection failed: %s", e.what());
		return nullptr;
	}
	return conn;
}

bool has_immediate_response(int sock) {
	if (sock < 0) return false;

	// Save current socket flags
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1) return false;

	// Set non-blocking mode
	if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
		return false;
	}

	// Try to read one byte (without removing from buffer)
	char dummy;
	ssize_t n = recv(sock, &dummy, 1, MSG_PEEK | MSG_DONTWAIT);

	// Restore original flags
	fcntl(sock, F_SETFL, flags);

	if (n > 0) {
		return true;  // Data available
	}
	else if (n == 0) {
		return true;  // Connection closed
	}
	else {
		// Check if error was due to no data
		return (errno != EAGAIN && errno != EWOULDBLOCK);
	}
}

/*bool no_immediate_response(int sock) {
	fd_set read_fds;
	FD_ZERO(&read_fds);
	FD_SET(sock, &read_fds);

	timeval timeout{};
	timeout.tv_sec = 0;
	timeout.tv_usec = 100000; // 100ms timeout

	return select(sock + 1, &read_fds, nullptr, nullptr, &timeout) == 0;
}*/


void test_parse_without_sync() {
	diag("Test %d: Parse without sync should not respond", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Get raw socket for timeout check
		int sock = conn->getSocket();

		// Prepare without sync
		conn->prepareStatement("test_stmt", "SELECT 1", false);

		// Check for immediate response (should timeout)
		ok(!has_immediate_response(sock), "No response after parse without sync");

		// Now sync and verify completion
		conn->sendSync();

		char type;
		bool got_ready = 0;
		int parse_count = 0;
		int other_count = 0;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);
			if (type == PgConnection::PARSE_COMPLETE) {
				parse_count++;
			} else if (type == PgConnection::READY_FOR_QUERY) {
				got_ready = true;
			} else {
				other_count++;
			}
		}

		ok(parse_count == 1, "Received parse complete after sync (%d/1)", parse_count);
		ok(got_ready, "Received ready packet after sync");
		ok(other_count == 0, "No other messages received after sync (%d)", other_count);
	} 
	catch (const PgException& e) {
		ok(false, "Parse without sync test failed with errpr: %s", e.what());
	}
}

void test_parse_with_sync() {
	diag("Test %d: Parse with sync should respond immediately", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("test_stmt", "SELECT 1", true);
		ok(true, "Parse completes with sync enabled");
	}
	catch (const PgException& e) {
		ok(false, "Parse with sync test failed with error: %s", e.what());
	}
}

void test_parse_use_same_stmt_name() {
	diag("Test %d: Parse using same statement name", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {

		char type;
		std::vector<uint8_t> buffer;

		{
			conn->prepareStatement("test_stmt_multi", "SELECT $1::int", false);
			conn->describeStatement("test_stmt_multi", false);
			conn->sendSync();

			// Read the parse complete for the first statement
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARSE_COMPLETE, "Received parse complete for first parse");

			// Read the describe complete for the first statement
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARAMETER_DESCRIPTION, "Received parameter description for first parse");

			// Read parameter description
			BufferReader reader(buffer);
			int num_params = reader.readInt16();
			ok(num_params == 1, "Received 1 parameter description for first parse");
			// Read parameter type OID
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Parameter type OID is 23 (int)");

			conn->waitForReady();
		}

		{
			conn->prepareStatement("test_stmt_multi", "SELECT $1::text", false);
			conn->sendSync();

			conn->readMessage(type, buffer);
			ok(type == PgConnection::ERROR_RESPONSE,
				"Received error response for second parse with same name");

			std::string errormsg;
			std::string errorcode;

			if (type == PgConnection::ERROR_RESPONSE) {
				BufferReader reader(buffer);
				char field;
				while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
					if (field == 'M') errormsg = reader.readString();
					else if (field == 'C') errorcode = reader.readString();
					else reader.readString();
				}
			}

			ok(errorcode == "42P05", "Received ERRCODE_DUPLICATE_PSTATEMENT Error:%s", errormsg.c_str());
			// Now read the ready for query
			conn->readMessage(type, buffer);
			ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query after multiple parse");
		}

		{
			conn->describeStatement("test_stmt_multi", false);
			conn->sendSync();

			// Read the describe complete for the second statement
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARAMETER_DESCRIPTION, "Received parameter description for second parse");
			// Read parameter description
			BufferReader reader(buffer);
			int num_params = reader.readInt16();
			ok(num_params == 1, "Received 1 parameter description for second parse");
			// Read parameter type OID
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Parameter type OID is 23 (int)");

			conn->waitForReady();
		}

		{
			conn->closeStatement("test_stmt_multi", false);
			conn->sendSync();

			// Read the close complete for the statement
			conn->readMessage(type, buffer);
			ok(type == PgConnection::CLOSE_COMPLETE, "Received close complete for statement");
			// Now read the ready for query
			conn->readMessage(type, buffer);
			ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query after close statement");
		}

		{
			conn->prepareStatement("test_stmt_multi", "SELECT $1::text", false);
			conn->describeStatement("test_stmt_multi", false);
			conn->sendSync();

			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARSE_COMPLETE, "Received parse complete for second parse with same name");

			// Read the describe complete for the second statement
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARAMETER_DESCRIPTION, "Received parameter description for second parse with same name");
			// Read parameter description
			BufferReader reader(buffer);
			int num_params = reader.readInt16();
			ok(num_params == 1, "Received 1 parameter description for second parse with same name");
			// Read parameter type OID
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 25, "Parameter type OID is 25 (text)");
			conn->waitForReady();
		}
	}
	catch (const PgException& e) {
		ok(false, "Parse using same statement name failed with error: %s", e.what());
	}
}

void test_parse_use_unnamed_stmt() {
	diag("Test %d: Parse using unnamed statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {

		char type;
		std::vector<uint8_t> buffer;

		{
			conn->prepareStatement("", "SELECT $1::int", false);
			conn->describeStatement("", false);
			conn->sendSync();

			// Read the parse complete for the first statement
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARSE_COMPLETE, "Received parse complete for first parse");

			// Read the describe complete for the first statement
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARAMETER_DESCRIPTION, "Received parameter description for first parse");

			// Read parameter description
			BufferReader reader(buffer);
			int num_params = reader.readInt16();
			ok(num_params == 1, "Received 1 parameter description for first parse");
			// Read parameter type OID
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Parameter type OID is 23 (int)");

			conn->waitForReady();
		}

		{
			conn->prepareStatement("", "SELECT $1::text", false);
			conn->describeStatement("", false);
			conn->sendSync();

			// Read the parse complete for the first statement
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARSE_COMPLETE, "Received parse complete for second parse");

			// Read the describe complete for the first statement
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARAMETER_DESCRIPTION, "Received parameter description for second parse");

			// Read parameter description
			BufferReader reader(buffer);
			int num_params = reader.readInt16();
			ok(num_params == 1, "Received 1 parameter description for first parse");
			// Read parameter type OID
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 25, "Parameter type OID is 25 (text)");

			conn->waitForReady();
		}
	}
	catch (const PgException& e) {
		ok(false, "Parse using unnamed statement with error: %s", e.what());
	}
}

void test_malformed_packet() {
	diag("Test %d: Malformed parse packet", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send garbage instead of parse message
		std::vector<uint8_t> garbage{ 0xDE, 0xAD, 0xBE, 0xEF };
		conn->sendMessage('P', garbage);

		// Should get error response
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received error response for malformed packet");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "08P01", "Received ERRCODE_PROTOCOL_VIOLATION Error:%s", errormsg.c_str());
	
		conn->readMessage(type, buffer);
		ok(false, "Session should be terminated by server");
	}
	catch (const PgException& e) {
		ok(true, "Session should be terminated error: %s", e.what());
	}
}

void test_empty_query() {
	diag("Test %d: Empty query string", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("empty_stmt", "", true);
		ok(true, "Empty query should succeed");
	}
	catch (const PgException& e) {
		ok(false, "Empty query string failed with error: %s", e.what());
	}
}

void test_multiple_parse() {
	diag("Test %d: Multiple parse without sync", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send multiple parse commands
		conn->prepareStatement("stmt1", "SELECT 1", false);
		conn->prepareStatement("stmt2", "SELECT 2", false);
		conn->prepareStatement("stmt3", "SELECT 3", false);

		// Send single sync
		conn->sendSync();

		// Should get 3 parse complete messages
		char type;
		bool got_ready = false;
		int parse_count = 0;
		int other_count = 0;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);

			if (type == PgConnection::PARSE_COMPLETE) {
				parse_count++;
			} else if (type == PgConnection::READY_FOR_QUERY) {
				got_ready = true;
			} else {
				other_count++;
			}
		}

		ok(parse_count == 3, "Received all parse completes (%d/3)", parse_count);
		ok(got_ready, "Received ready packet after multiple parse");
		ok(other_count == 0, "No other messages received after multiple parse (%d)", other_count);
	}
	catch (const PgException& e) {
		ok(false, "Multiple parse test faile with error: %s", e.what());
	}
}

void test_only_sync() {
	diag("Test %d: Sending only sync", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send single sync
		conn->sendSync();

		// Should get 3 parse complete messages
		char type;
		bool got_ready = false;
		int other_count = 0;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);

			if (type == PgConnection::READY_FOR_QUERY) {
				got_ready = true;
			} else {
				other_count++;
			}
		}

		ok(got_ready, "Received ready packet after sync");
		ok(other_count == 0, "No other messages received after sync (%d)", other_count);
	}
	catch (const PgException& e) {
		ok(false, "Sending only sync test failed with error: %s", e.what());
	}
}

void test_empty_stmt() {
	diag("Test %d: Empty statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("", "SELECT 1", true);
		ok(true, "Empty statmement should succeed");
	} catch (const PgException& e) {
		ok(false, "Empty stmt failed with error: %s", e.what());
	}
}

void test_prepare_statement_mix() {
	diag("Test %d: Prepare statement + Simple Query", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("test_stmt_mix", "SELECT 1", false);
		conn->sendQuery("SELECT 2");
		
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received parse complete for prepared statement");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received row description for query");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received row data for query");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received command completion for query");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query");

		// Now send sync
		conn->sendSync();

		// Should get ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query after sync");
	}
	catch (const PgException& e) {
		ok(false, "Prepare statement + Simple Query failed with error: %s", e.what());
	}
}

void test_extended_query_prepared_describe_execute_simple_query_without_sync() {
	diag("Test %d: Extended Query (Prepare, Describe, Execute) + Simple Query without sync", test_count++);
	auto conn = create_connection();
	if (!conn) return;
	try {
		// Prepare without sync
		conn->prepareStatement("test_stmt_eq", "SELECT $1::int + 1", false);
		conn->describeStatement("test_stmt_eq", false);
		PgConnection::Param param = { "41", 0 };
		conn->bindStatement("test_stmt_eq", "", { param }, { 0 }, false);
		conn->executePortal("", 0, false);
		// Now send simple query without sync
		conn->sendQuery("SELECT 2");
		// Finally send sync
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received parse complete for prepared statement");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARAMETER_DESCRIPTION, "Received parameter description for prepared statement");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received row description for prepared statement");
		{
			BufferReader reader(buffer);
			// Read row description
			int fieldCount = reader.readInt16();
			ok(fieldCount == 1, "Row description has 1 field (%d/1)", fieldCount);
			// Read field name
			std::string fieldName = reader.readString();
			ok(fieldName == "?column?", "Field name is '?column?'");

			// Read field table OID
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");

			// Read field attribute number
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");

			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Parameter type OID is 23 (int)");

			// Read field type size
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 4, "Field type size is 4 (integer size)");

			// Read field type modifier
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");

			// Read field format code
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 0, "Field format code is 0 (text format)");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received bind complete for prepared statement");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received data row for prepared statement");

		{
			BufferReader reader(buffer);
			int fieldCount = reader.readInt16();
			ok(fieldCount == 1, "Received 1 field in data row for prepared statement");
			int valueLen = reader.readInt32();
			ok(valueLen == 2, "Field length is 2 bytes");
			auto val = reader.readBytes(2);
			ok(val[0] == '4' && val[1] == '2' , "Received correct value 42 from prepared statement");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received command complete for prepared statement");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received row description for simple query");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received data row for simple query");
		{
			BufferReader reader(buffer);
			int fieldCount = reader.readInt16();
			ok(fieldCount == 1, "Received 1 field in data row for simple query");
			int valueLen = reader.readInt32();
			ok(valueLen == 1, "Field length is 1 byte");
			uint8_t val = reader.readByte();
			ok(val == '2', "Received correct value 2 from simple query");
		}
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received command complete for simple query");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query after all commands");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query + Simple Query without sync failed with error: %s", e.what());
	}
}

void test_invalid_query_parse_packet() {
	diag("Test %d: Invalid query in parse packet", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send multiple parse commands
		conn->prepareStatement("invalid_stmt_test", "SELECT * FROM dummy_table", false);

		// Send single sync
		conn->sendSync();

		// Should get 3 parse complete messages
		char type;
		int error_count = 0;
		bool got_ready = false;
		int other_count = 0;

		std::string errormsg;
		std::string errorcode;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);

			if (type == PgConnection::ERROR_RESPONSE) {
				error_count++;

				BufferReader reader(buffer);
				char field;
				while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
					if (field == 'M') {
						errormsg = reader.readString();
					} else if (field == 'C') {
						errorcode = reader.readString();
					} else {
						reader.readString(); // Skip other fields
					}
				}
			} else if (type == PgConnection::READY_FOR_QUERY) {
				got_ready = true;
			} else {
				other_count++;
			}
		}

		ok(error_count == 1, "Received error response (%d)", error_count);
		ok(errorcode == "42P01", "Received undefined table error code: %s", errorcode.c_str());
		 ok(errormsg.find("relation \"dummy_table\" does not exist") != std::string::npos, 
			   "Received expected error message: %s", errormsg.c_str());
		
		ok(got_ready, "Got ready for query packet");
		ok(other_count == 0, "No other messages received (%d)", other_count);
	}
	catch (const PgException& e) {
		ok(false, "Invalid query in parse packet failed with error: %s", e.what());
	}
}

bool test_text_binary_mix() {
	PGconn* conn = PQconnectdb("host=localhost dbname=postgres user=postgres password=postgres sslmode='disable'");

	ok(PQstatus(conn) == CONNECTION_OK, "Connected to database");

	PGresult* res;

	// Setup: ensure table exists
	res = PQexec(conn, "CREATE TEMP TABLE test_bin_text(id integer)");
	PQclear(res);
	res = PQexec(conn, "INSERT INTO test_bin_text VALUES (42)");
	PQclear(res);

	// 1. Prepare statement with declared parameter type as 'text'
	res = PQprepare(conn, "stmt1", "SELECT * FROM test_bin_text WHERE id = $1", 1, nullptr); // 25 = TEXTOID
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		diag("Prepare failed: %s", PQerrorMessage(conn));
	}
	ok(PQresultStatus(res) == PGRES_COMMAND_OK, "Prepared statement with param type text");
	PQclear(res);

	res = PQdescribePrepared(conn, "stmt1");
	PQclear(res);
	// 2. Attempt to bind binary-formatted int32 to text param
	int32_t intval = htonl(42); // Network byte order
	const char* paramValues[1] = { (char*)&intval };
	int paramLengths[1] = { sizeof(intval) };
	int paramFormats[1] = { 1 }; // Binary format
	Oid resultFormat = 0;


	res = PQexecPrepared(conn, "stmt1", 1, paramValues, paramLengths, paramFormats, resultFormat);

	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		diag("Unexpectedly succeeded: binary int bound to text param");
	}
	else {
		diag("Expected failure: %s", PQerrorMessage(conn));
	}

	ok(PQresultStatus(res) != PGRES_TUPLES_OK, "Binary format to text param fails as expected");

	PQclear(res);

	res = PQdescribePrepared(conn, "stmt1");
	PQclear(res);

	const char* paramValues1[1] = { "42" };
	res = PQexecPrepared(conn, "stmt1", 1, paramValues1, 0, NULL, 0);
	PQclear(res);

	res = PQdescribePrepared(conn, "stmt1");
	PQclear(res);

	PQfinish(conn);
	return 0;
}

bool test_text_binary_mix2() {
	PGconn* conn = PQconnectdb("host=localhost dbname=postgres user=postgres password=postgres sslmode='disable'");

	ok(PQstatus(conn) == CONNECTION_OK, "Connected to database");

	PGresult* res;

	// 1. Prepare statement with declared parameter type as 'text'
	res = PQprepare(conn, "stmt1", "SELECT $1", 1, nullptr); // 25 = TEXTOID
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		diag("Prepare failed: %s", PQerrorMessage(conn));
	}
	ok(PQresultStatus(res) == PGRES_COMMAND_OK, "Prepared statement with param type text");
	PQclear(res);

	res = PQdescribePrepared(conn, "stmt1");
	PQclear(res);
	// 2. Attempt to bind binary-formatted int32 to text param
	int32_t intval = htonl(42); // Network byte order
	const char* paramValues[1] = { (char*)&intval };
	int paramLengths[1] = { sizeof(intval) };
	int paramFormats[1] = { 1 }; // Binary format
	Oid resultFormat = 0;


	res = PQexecPrepared(conn, "stmt1", 1, paramValues, paramLengths, paramFormats, resultFormat);

	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		diag("Unexpectedly succeeded: binary int bound to text param");
	}
	else {
		diag("Expected failure: %s", PQerrorMessage(conn));
	}

	ok(PQresultStatus(res) != PGRES_TUPLES_OK, "Binary format to text param fails as expected");

	PQclear(res);

	res = PQdescribePrepared(conn, "stmt1");
	PQclear(res);

	const char* paramValues1[1] = { "42" };
	res = PQexecPrepared(conn, "stmt1", 1, paramValues1, 0, NULL, 0);
	PQclear(res);

	res = PQdescribePrepared(conn, "stmt1");
	PQclear(res);

	PQfinish(conn);
	return 0;
}

void test_describe_existing_statement() {
	diag("Test %d: Describe existing prepared statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare a valid statement
		conn->prepareStatement("valid_stmt", "SELECT 1", true);

		// Describe the prepared statement
		conn->describeStatement("valid_stmt", true);

		// Verify response
		char type;
		std::vector<uint8_t> buffer;
		

		{
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARAMETER_DESCRIPTION,
				"Received parameter description");

			// Read parameter description
			BufferReader reader(buffer);
			int paramCount = reader.readInt16();
			ok(paramCount == 0, "No parameters in prepared statement (%d/0)", paramCount);
		}

		{
			conn->readMessage(type, buffer);
			ok(type == PgConnection::ROW_DESCRIPTION,
				"Received row description");

			BufferReader reader(buffer);
			// Read row description
			int fieldCount = reader.readInt16();
			ok(fieldCount == 1, "Row description has 1 field (%d/1)", fieldCount);
			// Read field name
			std::string fieldName = reader.readString();
			ok(fieldName == "?column?", "Field name is '?column?'");

			// Read field table OID
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");

			// Read field attribute number
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");

			// Read field type OID
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Field type OID is 23 (integer)");

			// Read field type size
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 4, "Field type size is 4 (integer size)");

			// Read field type modifier
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");

			// Read field format code
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 0, "Field format code is 0 (text format)");
		}
		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after describe");
	}
	catch (const PgException& e) {
		ok(false, "Describe existing prepared statement failed with error: %s", e.what());
	}
}

void test_describe_nonexistent_statement() {
	diag("Test %d: Describe non-existent prepared statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Describe unknown statement
		conn->describeStatement("ghost_stmt", true);

		// Should get error response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error response for non-existent statement");
		
		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);

		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after describe non-existent statement");
	}
	catch (const PgException& e) {
		ok(false, "Describe non-existent prepared statement failed with error: %s", e.what());
	}
}

void test_describe_without_sync() {
	diag("Test %d: Describe without sync", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		int sock = conn->getSocket();
		conn->prepareStatement("async_stmt", "SELECT 1", false);
		conn->describeStatement("async_stmt", false);

		// Shouldn't get immediate response
		ok(!has_immediate_response(sock),
			"No immediate response after describe without sync");

		conn->sendSync();
	  
		char type;
		std::vector<uint8_t> buffer;
		int parse_count = 0;
		int param_desc_count = 0;
		int row_desc_count = 0;
		bool gotReady = false;

		while (!gotReady) {
			conn->readMessage(type, buffer);

			if (type == PgConnection::PARSE_COMPLETE) {
				parse_count++;
			} else if (type == PgConnection::PARAMETER_DESCRIPTION) {
				param_desc_count++;
			} else if (type == PgConnection::ROW_DESCRIPTION) {
				row_desc_count++;
			} else if (type == PgConnection::READY_FOR_QUERY) {
				gotReady = true;
			} else if (type == PgConnection::ERROR_RESPONSE) {
				BufferReader reader(buffer);
				std::string errorMsg;
				char field;
				while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
					if (field == 'M') errorMsg = reader.readString();
					else reader.readString();
				}
				throw PgException("Error: " + errorMsg);
			}
		}

		ok(parse_count == 1, "Received ParseComplete (%d/1)", parse_count);
		ok(param_desc_count == 1, "Received ParameterDescription (%d/1)", param_desc_count);
		ok(row_desc_count == 1, "Received RowDescription (%d/1)", row_desc_count);
		ok(gotReady, "Sync completed after describe");
	}
	catch (const PgException& e) {
		ok(false, "Describe without sync failed with error:%s", e.what());
	}
}

void test_describe_malformed_packet() {
	diag("Test %d: Malformed describe packet", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send garbage describe message
		std::vector<uint8_t> garbage{ 'X' };
		conn->sendMessage('D', garbage);

		// Should get error response
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received error response for malformed packet");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "08P01", "Received ERRCODE_PROTOCOL_VIOLATION Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(false, "Session should be terminated by server");
	}
	catch (const PgException& e) {
		ok(true, "Session should be terminated error: %s", e.what());
	}
}

void test_describe_after_close_statement() {
	diag("Test %d: Describe after statement close", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("temp_stmt", "SELECT 1", true);
		conn->closeStatement("temp_stmt", true);
		conn->describeStatement("temp_stmt", true);

		// Should get error response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::ERROR_RESPONSE, "Received error for closed statement");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after closed statement");
	}
	catch (const PgException& e) {
		ok(false, "Describe after statement close failed with error: %s", e.what());
	}
}

void test_multiple_describe_calls() {
	diag("Test %d: Multiple describe calls", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("multi_desc", "SELECT 1", true);

		// First describe
		conn->describeStatement("multi_desc", false);
		// Second describe
		conn->describeStatement("multi_desc", false);
		conn->sendSync();

		int param_desc_count = 0;
		int desc_count = 0;
		int other_count = 0;
		char type;
		bool got_ready = false;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);

			if (type == PgConnection::PARAMETER_DESCRIPTION) {
				param_desc_count++;
			} else if (type == PgConnection::ROW_DESCRIPTION) {
				desc_count++;
			} else if (type == PgConnection::READY_FOR_QUERY) {
				got_ready = true;
			} else {
				other_count++;
			}
		}

		ok(param_desc_count == 2, "Received parameter description (%d/2)", param_desc_count);
		ok(desc_count == 2, "Received description packets (%d/2)", desc_count);
		ok(got_ready, "Received ready for query after multiple describes");
		ok(other_count == 0, "No other messages received after multiple describes (%d)", other_count);
	}
	catch (const PgException& e) {
		ok(false, "Multiple describe calls failed with error: %s", e.what());
	}
}

void test_describe_parameter_types() {
	diag("Test %d: Verify parameter type reporting", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare statement with multiple parameter types
		conn->prepareStatement("param_types",
			"SELECT $1::int, $2::text, $3::bool",
			true);

		// Describe prepared statement
		conn->describeStatement("param_types", true);

		// Verify parameter description
		char type;
		std::vector<uint8_t> param_buffer;
		conn->readMessage(type, param_buffer);

		ok(type == PgConnection::PARAMETER_DESCRIPTION,
			"Received parameter description");

		// Parse parameter OIDs (format: [count] + [oids])
		if (param_buffer.size() >= 2) {
			int16_t num_params = (param_buffer[0] << 8) | param_buffer[1];
			ok(num_params == 3, "Three parameters reported");

			// Verify OIDs (int=23, text=25, bool=16)
			if (num_params == 3 && param_buffer.size() >= 8) {
				uint32_t oid1 = (param_buffer[2] << 24) | (param_buffer[3] << 16)
					| (param_buffer[4] << 8) | param_buffer[5];
				uint32_t oid2 = (param_buffer[6] << 24) | (param_buffer[7] << 16)
					| (param_buffer[8] << 8) | param_buffer[9];
				uint32_t oid3 = (param_buffer[10] << 24) | (param_buffer[11] << 16)
					| (param_buffer[12] << 8) | param_buffer[13];

				ok(oid1 == 23, "Parameter 1 type is int (OID: %u)", oid1);
				ok(oid2 == 25, "Parameter 2 type is text (OID: %u)", oid2);
				ok(oid3 == 16, "Parameter 3 type is bool (OID: %u)", oid3);
			} else {
				ok(false, "Invalid parameter description size");
			}
		} else {
			ok(false, "Invalid parameter description size");
		}

		// Read row description (should be empty for this query)
		std::vector<uint8_t> row_buffer;
		conn->readMessage(type, row_buffer);
		ok(type == PgConnection::ROW_DESCRIPTION,
			"Received row description after parameter description");
		// Verify no fields in row description
		BufferReader reader(row_buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 3, "No fields in row description (%d/3)", num_fields);

		// First field metadata
		// Read field name
		std::string fieldName = reader.readString();
		ok(fieldName == "int4", "Field name is 'int4'");

		// Read field table OID
		unsigned int tableOid = reader.readInt32();
		ok(tableOid == 0, "Field table OID is 0 (no table)");

		// Read field attribute number
		unsigned int attrNum = reader.readInt16();
		ok(attrNum == 0, "Field attribute number is 0 (no specific column)");

		// Read field type OID
		unsigned int typeOid = reader.readInt32();
		ok(typeOid == 23, "Field type OID is 23 (integer)");

		// Read field type size
		unsigned int typeSize = reader.readInt16();
		ok(typeSize == 4, "Field type size is 4 (integer size)");

		// Read field type modifier
		unsigned int typeModifier = reader.readInt32();
		ok(typeModifier == -1, "Field type modifier is -1 (default)");

		// Read field format code
		unsigned int formatCode = reader.readInt16();
		ok(formatCode == 0, "Field format code is 0 (text format)");
   
		// Second field metadata
		fieldName = reader.readString();
		ok(fieldName == "text", "Field name is 'text'");
		tableOid = reader.readInt32();
		ok(tableOid == 0, "Field table OID is 0 (no table)");
		attrNum = reader.readInt16();
		ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
		typeOid = reader.readInt32();
		ok(typeOid == 25, "Field type OID is 25 (text)");
		typeSize = reader.readInt16();
		ok(typeSize == -1, "Field type size is -1 (variable length)");
		typeModifier = reader.readInt32();
		ok(typeModifier == -1, "Field type modifier is -1 (default)");
		formatCode = reader.readInt16();
		ok(formatCode == 0, "Field format code is 0 (text format)");
		// Third field metadata
		fieldName = reader.readString();
			
		ok(fieldName == "bool", "Field name is 'bool'");
		tableOid = reader.readInt32();
		ok(tableOid == 0, "Field table OID is 0 (no table)");
		attrNum = reader.readInt16();
		ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
		typeOid = reader.readInt32();
		ok(typeOid == 16, "Field type OID is 16 (boolean)");
		typeSize = reader.readInt16();
		ok(typeSize == 1, "Field type size is 1 (boolean size)");
		typeModifier = reader.readInt32();
		ok(typeModifier == -1, "Field type modifier is -1 (default)");
		formatCode = reader.readInt16();
		ok(formatCode == 0, "Field format code is 0 (text format)");

		// Read ready for query
		conn->readMessage(type, row_buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after parameter description");
	}
	catch (const PgException& e) {
		ok(false, "Parameter type verification failed with error:%s", e.what());
	}
}

void test_describe_result_metadata() {
	diag("Test %d: Verify result metadata accuracy", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare complex query
		conn->prepareStatement("result_meta",
			"SELECT 1::int AS id, 'test'::text AS name, true::bool AS flag",
			true);

		// Describe prepared statement
		conn->describeStatement("result_meta", true);

		char type;
		std::vector<uint8_t> buffer;
		// Read parameter description
		{
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARAMETER_DESCRIPTION, "Received parameter description");
			BufferReader reader(buffer);
			int16_t param_count = reader.readInt16();
			for (int i = 0; i < param_count; i++) {
				reader.readInt32();  // Skip parameter type OID
			}
		}
		// Read row description
		int16_t num_fields = 0;
		std::vector<std::tuple<std::string, uint32_t>> fields;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received row description");
		BufferReader reader(buffer);
		num_fields = reader.readInt16();

		ok(num_fields == 3, "Three result columns");

		for (int i = 0; i < num_fields; i++) {
			std::string name = reader.readString();
			reader.readInt32();   // Skip table OID
			reader.readInt16();   // Skip column attr num
			uint32_t type_oid = reader.readInt32();
			reader.readInt16();   // Skip type size
			reader.readInt32();   // Skip type modifier
			reader.readInt16();   // Skip format

			fields.emplace_back(name, type_oid);
		}

		// Verify metadata
		ok(fields.size() == 3, "Result has 3 fields (%zu/3)", fields.size());
		ok(std::get<0>(fields[0]) == "id" && std::get<1>(fields[0]) == 23,
			"Field 1: id (OID: %u)", std::get<1>(fields[0]));
		ok(std::get<0>(fields[1]) == "name" && std::get<1>(fields[1]) == 25,
			"Field 2: name (OID: %u)", std::get<1>(fields[1]));
		ok(std::get<0>(fields[2]) == "flag" && std::get<1>(fields[2]) == 16,
			"Field 3: flag (OID: %u)", std::get<1>(fields[2]));

		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after result metadata");
	}
	catch (const PgException& e) {
		ok(false, "Result metadata verification failed with error:%s", e.what());
	}
}

void test_describe_prepared_noname() {
	diag("Test %d: Describe prepared with noname statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;
	try {
		// Prepare a statement without a name
		conn->prepareStatement("", "SELECT 1", true);
		// Describe the prepared statement
		conn->describeStatement("", true);
		// Verify response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARAMETER_DESCRIPTION,
			"Received parameter description for unnamed statement");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION,
			"Received row description for unnamed statement");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after describe unnamed statement");
	}
	catch (const PgException& e) {
		ok(false, "Describe prepared with noname failed with error:%s", e.what());
	}
}


void test_close_existing_statement() {
	diag("Test %d: Close existing prepared statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare a valid statement
		conn->prepareStatement("existing_stmt", "SELECT 1", true);

		// Close the statement
		conn->closeStatement("existing_stmt", false);
		conn->sendSync();

		// Verify response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::CLOSE_COMPLETE,
			"Received CloseComplete for existing statement");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after close existing statement");

		// Verify statement is actually closed
		conn->describeStatement("existing_stmt", true);
		conn->readMessage(type, buffer);  // Should get error
		ok(type == PgConnection::ERROR_RESPONSE,
				"Describe fails after close");
		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query");
	}
	catch (const PgException& e) {
		ok(false, "Close existing statement failed with error:%s", e.what());
	}
}

void test_close_nonexistent_statement() {
	diag("Test %d: Close non-existent statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Close unknown statement
		conn->closeStatement("ghost_stmt", false);
		conn->sendSync();

		// Should still get CloseComplete
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::CLOSE_COMPLETE,
			"Received CloseComplete for non-existent statement");
	}
	catch (const PgException& e) {
		ok(false, "Close non-existent failed with error:%s", e.what());
	}
}

void test_close_unnamed_statement() {
	diag("Test %d: Close unnamed statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare unnamed statement
		conn->prepareStatement("", "SELECT 1", false);
		conn->sendSync();
		conn->waitForMessage(PgConnection::PARSE_COMPLETE, "parse complete", true);

		// Close unnamed statement
		conn->closeStatement("", false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::CLOSE_COMPLETE,
			"Received CloseComplete for unnamed statement");
		
		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after close unnamed statement");
		
		// Verify closed
		conn->describeStatement("", true);
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE,
			"Describe fails for closed unnamed statement");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());
	}
	catch (const PgException& e) {
		ok(false, "Close unnamed failed with error:%s", e.what());
	}
}

void test_close_without_sync() {
	diag("Test %d: Close without sync", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		int sock = conn->getSocket();
		conn->prepareStatement("async_close_stmt", "SELECT 1", false);

		// Close without sync
		conn->closeStatement("async_close_stmt", false);

		// Shouldn't get immediate response
		ok(!has_immediate_response(sock),
			"No immediate response after close without sync");

		// Send sync and verify responses
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		bool gotParseComplete = false;
		bool gotCloseComplete = false;
		bool gotReady = false;

		while (!gotReady) {
			conn->readMessage(type, buffer);
			if (type == PgConnection::PARSE_COMPLETE) gotParseComplete = true;
			else if (type == PgConnection::CLOSE_COMPLETE) gotCloseComplete = true;
			else if (type == PgConnection::READY_FOR_QUERY) gotReady = true;
		}

		ok(gotParseComplete, "Received ParseComplete");
		ok(gotCloseComplete, "Received CloseComplete");
		ok(gotReady, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Close without sync failed with error:%s", e.what());
	}
}

void test_multiple_close_without_sync() {
	diag("Test %d: Multiple close without sync", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare multiple statements
		conn->prepareStatement("multi_close_1", "SELECT 1", false);
		conn->prepareStatement("multi_close_2", "SELECT 2", false);
		conn->prepareStatement("multi_close_3", "SELECT 3", false);

		// Close without sync
		conn->closeStatement("multi_close_1", false);
		conn->closeStatement("multi_close_2", false);
		conn->closeStatement("multi_close_3", false);

		// Send sync
		conn->sendSync();

		// Verify responses
		char type;
		int close_count = 0;
		int parse_count = 0;
		bool got_ready = false;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);
			if (type == PgConnection::PARSE_COMPLETE) parse_count++;
			else if (type == PgConnection::CLOSE_COMPLETE) close_count++;
			else if (type == PgConnection::READY_FOR_QUERY) got_ready = true;
		}

		ok(parse_count == 3, "Received 3 parse completes");
		ok(close_count == 3, "Received 3 close completes");
		ok(got_ready, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Multiple close failed with error:%s", e.what());
	}
}

void test_close_malformed_packet() {
	diag("Test %d: Malformed close packet", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send garbage close message (invalid target type)
		std::vector<uint8_t> garbage;
		garbage.push_back('X');  // Invalid target type
		garbage.push_back(0);	// Null-terminated empty name
		conn->sendMessage('C', garbage);


		// Should get error response
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received error response for malformed packet");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "08P01", "Received ERRCODE_PROTOCOL_VIOLATION Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(false, "Session should be terminated by server");
	}
	catch (const PgException& e) {
		ok(true, "Session should be terminated error: %s", e.what());
	}
}

void test_close_twice() {
	diag("Test %d: Close statement twice", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("dupe_close", "SELECT 1", true);

		// First close
		conn->closeStatement("dupe_close", false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::CLOSE_COMPLETE, "First close success");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "First close returns ReadyForQuery");

		// Second close
		conn->closeStatement("dupe_close", false);
		conn->sendSync();
		conn->readMessage(type, buffer);
		ok(type == PgConnection::CLOSE_COMPLETE,
			"Second close returns CloseComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Second close returns ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Close twice failed with error:%s", e.what());
	}
}

void test_close_without_prepare() {
	diag("Test %d: Close without preparing", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Close without preparing first
		conn->closeStatement("never_prepared", false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::CLOSE_COMPLETE,
			"Close succeeds for non-prepared statement");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after close without prepare");
	}
	catch (const PgException& e) {
		ok(false, "Close without prepare failed with error:%s", e.what());
	}
}

void test_close_during_pending_ops() {
	diag("Test %d: Close during pending operations", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		int sock = conn->getSocket();

		// Start parse without sync
		conn->prepareStatement("pending_stmt", "SELECT 1", false);

		// Close without sync
		conn->closeStatement("pending_stmt", false);

		// Shouldn't get immediate response
		ok(!has_immediate_response(sock),
			"No response during pending operations");

		// Send sync and verify responses
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete after close during pending ops");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::CLOSE_COMPLETE, "Received CloseComplete after close during pending ops");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after close during pending ops");
	}
	catch (const PgException& e) {
		ok(false, "Close during pending ops failed with error:%s", e.what());
	}
}

void test_close_all_types() {
	diag("Test %d: Close all types of targets", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare statements
		conn->prepareStatement("named_stmt", "SELECT 1", false);
		conn->prepareStatement("", "SELECT 2", false);  // Unnamed

		// Close named statement
		conn->closeStatement("named_stmt", false);

		// Close unnamed statement
		conn->closeStatement("", false);

		// Close non-existent (should still work)
		conn->closeStatement("ghost", false);

		// Send sync
		conn->sendSync();

		// Verify responses
		char type;
		int close_count = 0;
		int parse_count = 0;
		bool got_ready = false;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);
			if (type == PgConnection::PARSE_COMPLETE) parse_count++;
			else if (type == PgConnection::CLOSE_COMPLETE) close_count++;
			else if (type == PgConnection::READY_FOR_QUERY) got_ready = true;
		}

		ok(parse_count == 2, "Received 2 parse completes");
		ok(close_count == 3, "Received 3 close completes");
		ok(got_ready, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Close all types failed with error:%s", e.what());
	}
}

void test_parse_execute_without_bind() {
	diag("Test %d: Unnamed Prepared and Execute", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare a statement
		conn->prepareStatement("", "SELECT 1", true);
		// Execute statement directly
		conn->executeStatement(0, false);
		conn->sendSync();

		// Verify results
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received ErrorResponse");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "34000", "Received ERRCODE_UNDEFINED_CURSOR Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Unnamed Prepared and Execute failed with error:%s", e.what());
	}
}

void test_bind_basic() {
	diag("Test %d: Basic Bind and Execute", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare a statement
		conn->prepareStatement("basic_bind", "SELECT $1::int AS num", false);

		conn->describeStatement("basic_bind", false);
		// Bind parameters directly to statement
		PgConnection::Param param = { "42", 0 };
		conn->bindStatement("basic_bind", "", { param }, {}, false);
		conn->describePortal("", false);
		// Execute statement directly
		conn->executeStatement(0, false);
		conn->sendSync();

		// Verify results
		char type;
		std::vector<uint8_t> buffer;

		// Read parse complete
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete");

		// Read parameter description
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARAMETER_DESCRIPTION, "Received ParameterDescription");
		BufferReader reader(buffer);
		int16_t num_params = reader.readInt16();
		ok(num_params == 1, "One parameter reported");
		if (num_params == 1 && buffer.size() >= 4) {
			uint32_t oid = (buffer[2] << 24) | (buffer[3] << 16)
				| (buffer[4] << 8) | buffer[5];
			ok(oid == 23, "Parameter type is int (OID: %u)", oid);
		} else {
			ok(false, "Invalid parameter description size");
		}
		// Read row description
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		// Verify row description
		reader = BufferReader(buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in row description (%d/1)", num_fields);
		if (num_fields == 1 && buffer.size() >= 20) {
			// Read field metadata
			std::string fieldName = reader.readString();
			ok(fieldName == "num", "Field name is 'num'");
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Field type OID is 23 (integer)");
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 4, "Field type size is 4 (integer size)");
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 0, "Field format code is 0 (text format)");
		}
		else {
			ok(false, "Invalid row description size");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");

		// Verify row description
		conn->readMessage(type, buffer);
		reader = BufferReader(buffer);
		num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in row description (%d/1)", num_fields);
		if (num_fields == 1 && buffer.size() >= 20) {
			// Read field metadata
			std::string fieldName = reader.readString();
			ok(fieldName == "num", "Field name is 'num'");
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Field type OID is 23 (integer)");
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 4, "Field type size is 4 (integer size)");
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 0, "Field format code is 0 (text format)");
		}
		else {
			ok(false, "Invalid row description size");
		}

		// Read data row
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");
		// Verify data row
		reader = BufferReader(buffer);
		int16_t num_columns = reader.readInt16();
		ok(num_columns == 1, "One column in data row (%d/1)", num_columns);
		if (num_columns == 1 && buffer.size() >= 8) {
			// Read column length
			int32_t column_length = reader.readInt32();
			ok(column_length == 2, "Column length is 2");
			// Read column data
			buffer = reader.readBytes(column_length);
			ok(buffer[0] == '4' && buffer[1] == '2', "Column value is 42 (expected)");
		}
		else {
			ok(false, "Invalid data row size");
		}
		// Read command complete
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");
		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Basic Bind/Execute failed with error:%s", e.what());
	}
}

void test_bind_without_sync() {
	diag("Test %d: Bind without Sync", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		int sock = conn->getSocket();
		conn->prepareStatement("async_bind", "SELECT $1::int", false);

		// Bind without sync
		PgConnection::Param param = { "5", 0 };
		conn->bindStatement("async_bind", "", { param }, {}, false);

		// Shouldn't get immediate response
		ok(!has_immediate_response(sock), "No immediate response after bind without sync");

		// Execute without sync
		conn->executeStatement(0, false);

		// Send sync and verify responses
		conn->sendSync();

		char type;
		int parse_count = 0;
		int bind_count = 0;
		int execute_count = 0;
		bool got_ready = false;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);
			if (type == PgConnection::PARSE_COMPLETE) parse_count++;
			else if (type == PgConnection::BIND_COMPLETE) bind_count++;
			else if (type == PgConnection::DATA_ROW) execute_count++;
			else if (type == PgConnection::READY_FOR_QUERY) got_ready = true;
		}

		ok(parse_count == 1, "Received ParseComplete");
		ok(bind_count == 1, "Received BindComplete");
		ok(execute_count == 1, "Received DataRow");
		ok(got_ready, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Bind without sync failed with error:%s", e.what());
	}
}

void test_bind_nonexistent_statement() {
	diag("Test %d: Bind to non-existent statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		PgConnection::Param param = { "test", 1 };
		conn->bindStatement("ghost_stmt", "", { param }, {}, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::ERROR_RESPONSE, "Received ErrorResponse for non-existent statement");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after bind to non-existent statement");
	}
	catch (const PgException& e) {
		ok(false, "Bind to non-existent statement failed with error:%s", e.what());
	}
}

void test_bind_incorrect_parameters() {
	diag("Test %d: Bind with incorrect parameters", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("incorrect_params", "SELECT $1::int, $2::text", true);

		// Pass only one parameter instead of two
		PgConnection::Param param = { "42", 1 };
		conn->bindStatement("incorrect_params", "", { param }, {}, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for incorrect parameters");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received ErrorResponse for incorrect parameters");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "08P01", "Received ERRCODE_PROTOCOL_VIOLATION Error:%s", errormsg.c_str());
		
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after bind with incorrect parameters");
	}
	catch (const PgException& e) {
		ok(false, "Bind failed with incorrect parameters: %s", e.what());
	}
}

void test_binary_parameters() {
	diag("Test %d: Bind binary parameters", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("binary_params", "SELECT $1::int", true);

		// Create binary representation of integer 42 (network byte order)
		int32_t bin_value = htonl(42);
		PgConnection::Param param = {
			std::string(reinterpret_cast<char*>(&bin_value), sizeof(bin_value)),
			1 // Binary format
		};

		conn->bindStatement("binary_params", "", { param }, { 1 }, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->sendSync();

		// Verify we got a binary result
		char type;
		std::vector<uint8_t> buffer;
		
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");

		// Read row description
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		// Verify row description
		BufferReader reader(buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in row description (%d/1)", num_fields);
		if (num_fields == 1 && buffer.size() >= 20) {
			// Read field metadata
			std::string fieldName = reader.readString();
			ok(fieldName == "int4", "Field name is 'int4'");
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Field type OID is 23 (integer)");
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 4, "Field type size is 4 (integer size)");
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 1, "Field format code is 1 (binary format)");
		}
		else {
			ok(false, "Invalid row description size");
		}

		// Read data row
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");
		// Verify data row
		reader = BufferReader(buffer);
		int16_t num_columns = reader.readInt16();
		ok(num_columns == 1, "One column in data row (%d/1)", num_columns);
		if (num_columns == 1 && buffer.size() >= 8) {
			// Read column length
			int32_t column_length = reader.readInt32();
			ok(column_length == 4, "Column length is 4 (int32 size)");
			// Read column data
			int32_t val = reader.readInt32();
			ok(val == 42, "Column value is 42 (expected)");
		}

		// Read command complete
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");

		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Binary parameters test failed with error:%s", e.what());
	}
}

void test_bind_large_data() {
	diag("Test %d: Bind with large data", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("large_data", "SELECT length($1::text)", true);

		// Create 1MB string
		std::string large_data(1024 * 1024, 'X');
		PgConnection::Param param = { large_data, 1 };

		conn->bindStatement("large_data", "", { param }, {1}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");

		// Read row description
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");

		BufferReader reader(buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in row description (%d/1)", num_fields);
		if (num_fields == 1 && buffer.size() >= 20) {
			// Read field metadata
			std::string fieldName = reader.readString();
			ok(fieldName == "length", "Field name is 'length'");
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Field type OID is 23 (integer)");
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 4, "Field type size is 4 (integer size)");
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 1, "Field format code is 1 (binary format)");
		}
		else {
			ok(false, "Invalid row description size");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");

		reader = BufferReader(buffer);
		num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in data row (%d/1)", num_fields);
		if (num_fields == 1) {
			int32_t len = reader.readInt32();
			if (len == 4) {  // Length of int32
				int32_t val = reader.readInt32();
				ok(val == 1024 * 1024, "Received correct length: %d", val);
			}
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");
		
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Large data test failed with error:%s", e.what());
	}
}

void test_bind_null_parameters() {
	diag("Test %d: Bind with NULL parameters", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("null_params", "SELECT $1::int IS NULL", true);

		// Bind NULL parameter
		std::vector<PgConnection::Param> params = { { {}, 1} };  // is_null = true
		conn->bindStatement("null_params", "", params, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");

		// Read row description
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		BufferReader reader(buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in row description (%d/1)", num_fields);
		if (num_fields == 1 && buffer.size() >= 20) {
			// Read field metadata
			std::string fieldName = reader.readString();
			ok(fieldName == "?column?", "Field name is '?column?'");
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 16, "Field type OID is 16 (boolean)");
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 1, "Field type size is 1 (boolean size)");
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 0, "Field format code is 0 (text format)");
		}
		else {
			ok(false, "Invalid row description size");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");

		reader = BufferReader(buffer);
		num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in data row (%d/1)", num_fields);
		if (num_fields == 1) {
			int32_t len = reader.readInt32();
			if (len == 1) {
				char val = reader.readByte();
				ok(val == 't', "Received correct NULL check: %c", val);
			}
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "NULL parameter test failed with error:%s", e.what());
	}
}

void test_malformed_bind_packet() {
	diag("Test %d: Malformed Bind packet", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send garbage bind message
		std::vector<uint8_t> garbage{ 'X'};
		conn->sendMessage('B', garbage);

		// Should get error response
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received error response for malformed packet");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "08P01", "Received ERRCODE_PROTOCOL_VIOLATION Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(false, "Session should be terminated by server");
	}
	catch (const PgException& e) {
		ok(true, "Session should be terminated error: %s", e.what());
	}
}

void test_malformed_execute_packet() {
	diag("Test %d: Malformed Execute packet", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send garbage execute message
		std::vector<uint8_t> garbage{ 'X' };
		conn->sendMessage('E', garbage);

		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received error response for malformed packet");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "08P01", "Received ERRCODE_PROTOCOL_VIOLATION Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(false, "Session should be terminated by server");
	}
	catch (const PgException& e) {
		ok(true, "Session should be terminated error: %s", e.what());
	}
}

void test_bind_named_portal() {
	diag("Test %d: Bind with named portal (should fail)", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_portal", "SELECT $1", true);

		// Attempt to bind with named portal
		PgConnection::Param param = { "1", 0 };
		conn->bindStatement("stmt_portal", "named_portal", { param }, {}, false);
		conn->sendSync();

		// Should get error response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error for named portal bind");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "0A000",
			"Received ERRCODE_FEATURE_NOT_SUPPORTED for named portal: %s",
			errormsg.c_str());
	}
	catch (const PgException& e) {
		ok(false, "Bind named portal failed with error: %s", e.what());
	}
}

void test_describe_portal() {
	diag("Test %d: Describe portal", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_desc_portal", "SELECT $1 AS test", true);

		// Bind with unnamed portal
		PgConnection::Param param = { "1", 0 };
		conn->bindStatement("stmt_desc_portal", "", { param }, {}, false);
		conn->describePortal("", false);
		conn->executePortal("", 0, false);
		conn->describePortal("", false);
		conn->sendSync();

		// Verify response
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received Bind complete response");

		// Should get row description
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION,
			"Received row description for portal");

		// Verify description content
		BufferReader reader(buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in description");

		if (num_fields == 1) {
			std::string name = reader.readString();
			ok(name == "test", "Field name is 'test'");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received data row for portal");
		// Verify data row
		reader = BufferReader(buffer);
		num_fields = reader.readInt16();
		ok(num_fields == 1, "One column in data row (%d/1)", num_fields);
		if (num_fields == 1 && buffer.size() >= 5) {
			// Read column length
			int32_t column_length = reader.readInt32();
			ok(column_length == 1, "Column length is 1");
			// Read column data
			uint8_t val = reader.readByte();
			ok(val == '1', "Column value is '1' (expected)");
		} else {
			ok(false, "Invalid data row size");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");


		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error response for describe portal");
		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "34000",
			"Received ERRCODE_UNDEFINED_CURSOR for describe portal: %s",
			errormsg.c_str());
		
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after describe portal");
	}
	catch (const PgException& e) {
		ok(false, "Describe portal failed with error: %s", e.what());
	}
}

void test_close_portal() {
	diag("Test %d: Close portal", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_close_portal", "SELECT $1", true);

		// Bind and create portal
		PgConnection::Param param = { "1", 0 };
		conn->bindStatement("stmt_close_portal", "", { param }, {}, false);

		// Close portal
		conn->closePortal("", false);

		// Should get close complete
		conn->sendSync();
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE,
			"Received bind complete for portal");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::CLOSE_COMPLETE,
			"Received close complete for portal");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after portal close");

		// Verify portal is closed
		conn->executeStatement(0, true);

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error response for closed portal");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "34000",
			"Received ERRCODE_INVALID_CURSOR_DEFINITION for closed portal: %s",
			errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after closed portal error");
	}
	catch (const PgException& e) {
		ok(false, "Close portal failed with error: %s", e.what());
	}
}

void test_portal_lifecycle() {
	diag("Test %d: Unnamed portal lifecycle", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_portal_life", "SELECT $1::int", true);

		// First bind
		PgConnection::Param param1 = { "10", 0 };
		conn->bindStatement("stmt_portal_life", "", { param1 }, {}, false);

		param1 = { "42", 0 }; // Change value for next bind
		conn->bindStatement("stmt_portal_life", "", { param1 }, {}, false);
		conn->describePortal("", false);
		// Execute and verify
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		do {
			conn->readMessage(type, buffer);
		} while (type != PgConnection::DATA_ROW);

		BufferReader reader(buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in data row (%d/1)", num_fields);
		int32_t len = reader.readInt32();
		ok(len == 2, "Data row length is 2 (int32 size)");
		std::vector<uint8_t> val = reader.readBytes(len);
		ok(val[0] == '4' && val[1] == '2', "First execution returns 42");

		// Re-bind with new value (same statement)
		PgConnection::Param param2 = { "99", 0 };
		conn->bindStatement("stmt_portal_life", "", { param2 }, {}, false);

		// Execute again
		conn->executeStatement(0, false);
		conn->sendSync();

		// Skip to data row
		do  {
			conn->readMessage(type, buffer);
		} while (type != PgConnection::DATA_ROW);

		reader = BufferReader(buffer);
		num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in data row (%d/1)", num_fields);
		len = reader.readInt32();
		ok(len == 2, "Data row length is 2 (int32 size)");
		val = reader.readBytes(len);
		ok(val[0] == '9' && val[1] == '9', "Second execution returns 99 (bind replaced)");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE,
			"Received CommandComplete after second execution");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after second execution");

		// Close portal explicitly
		conn->closePortal("", false);
		conn->sendSync();

		conn->readMessage(type, buffer); // Close complete
		ok(type == PgConnection::CLOSE_COMPLETE, "Portal closed successfully");

		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after portal close");

		// Verify portal is closed
		conn->describePortal("", false);
		conn->sendSync();

		// Should get error response
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error for describe closed portal");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "34000",
			"Received ERRCODE_INVALID_CURSOR_DEFINITION: %s",
			errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after portal lifecycle test");

		// Auto-close on sync
		conn->bindStatement("stmt_portal_life", "", { param1 }, {}, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		do {
			conn->readMessage(type, buffer);
		} while (type != PgConnection::READY_FOR_QUERY);

		
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after auto-close on sync");

		conn->describePortal("", true);
		// Should get error response again
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error for describe closed portal after auto-close");
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "34000",
			"Received ERRCODE_INVALID_CURSOR_DEFINITION after auto-close: %s",
			errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after describe closed portal auto-close");
		
	}
	catch (const PgException& e) {
		ok(false, "Portal lifecycle test failed: %s", e.what());
	}
}

void test_describe_closed_portal() {
	diag("Test %d: Describe closed portal", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_desc_closed", "SELECT 1", true);

		// Bind and create portal
		PgConnection::Param param = { "1", 0 };
		conn->bindStatement("stmt_desc_closed", "", { param }, {}, false);

		// Close portal
		conn->closePortal("", false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		// Read bind complete
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE,
			"Received bind complete for closed portal");

		// Read close complete
		conn->readMessage(type, buffer);

		ok(type == PgConnection::CLOSE_COMPLETE,
			"Received close complete for portal");

		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after portal close");


		// Describe closed portal
		conn->describePortal("", false);
		conn->sendSync();

		// Should get error
		conn->readMessage(type, buffer);

		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error for closed portal describe");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "34000",
			"Received ERRCODE_INVALID_CURSOR_DEFINITION: %s",
			errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after describe closed portal");
	}
	catch (const PgException& e) {
		ok(false, "Describe closed portal failed: %s", e.what());
	}
}


void test_libpq_style_execute() {
	diag("Test %d: libpq Style Execute", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_libpq_execute", "SELECT $1", true);

		// Bind and create portal
		PgConnection::Param param = { "1", 0 };
		conn->bindStatement("stmt_libpq_execute", "", { param }, {}, false);

		// describe protal
		conn->describePortal("", false);
		conn->executePortal("", 0, false);

		// Should get close complete
		conn->sendSync();
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE,
			"Received bind complete for portal");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION,
			"Received row description");

		BufferReader reader(buffer);
		// Read row description
		int fieldCount = reader.readInt16();
		ok(fieldCount == 1, "Row description has 1 field (%d/1)", fieldCount);
		// Read field name
		std::string fieldName = reader.readString();
		ok(fieldName == "?column?", "Field name is '?column?'");

		// Read field table OID
		unsigned int tableOid = reader.readInt32();
		ok(tableOid == 0, "Field table OID is 0 (no table)");

		// Read field attribute number
		unsigned int attrNum = reader.readInt16();
		ok(attrNum == 0, "Field attribute number is 0 (no specific column)");

		// Read field type OID
		unsigned int typeOid = reader.readInt32();
		ok(typeOid == 25, "Field type OID is 25 (text)");

		// Read field type size
		unsigned int typeSize = reader.readInt16();
		ok(typeSize == -1, "Field type size is -1 (text size)");

		// Read field type modifier
		unsigned int typeModifier = reader.readInt32();
		ok(typeModifier == -1, "Field type modifier is -1 (default)");

		// Read field format code
		unsigned int formatCode = reader.readInt16();
		ok(formatCode == 0, "Field format code is 0 (text format)");
	

		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received Data Row");

		// Read data row
		reader = BufferReader(buffer);
		int16_t num_columns = reader.readInt16();
		ok(num_columns == 1, "One column in data row (%d/1)", num_columns);
		if (num_columns == 1 && buffer.size() >= 5) {
			// Read column length
			int32_t column_length = reader.readInt32();
			ok(column_length == 1, "Column length is 1 (text size)");
			// Read column data
			uint8_t val = reader.readByte();
			ok(val == '1', "Column value is '1' (expected)");
		} else {
			ok(false, "Invalid data row size");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after portal close");
	}
	catch (const PgException& e) {
		ok(false, "libpq Style Execute failed with error: %s", e.what());
	}
}

void test_multiple_execute_on_single_bind() {
	diag("Test %d: Multiple Execute On Single Bind", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_mul_execute", "SELECT $1", true);

		// Bind and create portal
		PgConnection::Param param = { "1", 0 };
		conn->bindStatement("stmt_mul_execute", "", { param }, {}, false);
		conn->describePortal("", false);
		conn->executePortal("", 0, false);
		conn->describePortal("", false);
		conn->executePortal("", 0, false);
		// Should get close complete
		conn->sendSync();
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE,
			"Received bind complete for portal");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION,
			"Received row description");

		BufferReader reader(buffer);
		// Read row description
		int fieldCount = reader.readInt16();
		ok(fieldCount == 1, "Row description has 1 field (%d/1)", fieldCount);
		// Read field name
		std::string fieldName = reader.readString();
		ok(fieldName == "?column?", "Field name is '?column?'");

		// Read field table OID
		unsigned int tableOid = reader.readInt32();
		ok(tableOid == 0, "Field table OID is 0 (no table)");

		// Read field attribute number
		unsigned int attrNum = reader.readInt16();
		ok(attrNum == 0, "Field attribute number is 0 (no specific column)");

		// Read field type OID
		unsigned int typeOid = reader.readInt32();
		ok(typeOid == 25, "Field type OID is 25 (text)");

		// Read field type size
		unsigned int typeSize = reader.readInt16();
		ok(typeSize == -1, "Field type size is -1 (text size)");

		// Read field type modifier
		unsigned int typeModifier = reader.readInt32();
		ok(typeModifier == -1, "Field type modifier is -1 (default)");

		// Read field format code
		unsigned int formatCode = reader.readInt16();
		ok(formatCode == 0, "Field format code is 0 (text format)");


		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received Data Row");

		// Read data row
		reader = BufferReader(buffer);
		int16_t num_columns = reader.readInt16();
		ok(num_columns == 1, "One column in data row (%d/1)", num_columns);
		if (num_columns == 1 && buffer.size() >= 5) {
			// Read column length
			int32_t column_length = reader.readInt32();
			ok(column_length == 1, "Column length is 1 (text size)");
			// Read column data
			uint8_t val = reader.readByte();
			ok(val == '1', "Column value is '1' (expected)");
		}
		else {
			ok(false, "Invalid data row size");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received error response for malformed packet");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "34000", "Received ERRCODE_UNDEFINED_CURSOR Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after portal close");
	}
	catch (const PgException& e) {
		ok(false, "libpq Style Execute failed with error: %s", e.what());
	}
}


void test_insert_command_complete() {
	diag("Test %d: Extended Query INSERT and CommandComplete", test_count++);
	auto conn = create_connection(); if (!conn) return;
	try {
		// CREATE TEMP TABLE via Extended Query
		conn->prepareStatement("create_tmp",
			"CREATE TEMP TABLE tmp_test(id SERIAL PRIMARY KEY, txt TEXT, flg BOOLEAN)",
			false);
		conn->bindStatement("create_tmp", "", {}, {}, false);
		conn->executeStatement(0, false);

		conn->sendSync();

		char type;
		std::vector<uint8_t> buf;

		conn->readMessage(type, buf);
		ok(type == PgConnection::PARSE_COMPLETE,
			"ParseComplete for CREATE TEMP TABLE");

		conn->readMessage(type, buf);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete for CREATE TEMP TABLE");
		
		conn->readMessage(type, buf);
		ok(type == PgConnection::COMMAND_COMPLETE,
			"CommandComplete for CREATE TEMP TABLE");

		auto tag = BufferReader(buf).readString();
		ok(tag.rfind("CREATE TABLE", 0) == 0,
			"CommandComplete tag is 'CREATE TABLE': %s", tag.c_str());

		conn->readMessage(type, buf);
		ok(type == PgConnection::READY_FOR_QUERY, "ReadyForQuery after CREATE TEMP TABLE");

		// INSERT via Extended Query
		conn->prepareStatement("ins_stmt",
			"INSERT INTO tmp_test(txt, flg) VALUES('hello', true)",
			false);
		conn->bindStatement("ins_stmt", "", {}, {}, false);
		conn->executeStatement(0, false);

		conn->sendSync();

		conn->readMessage(type, buf);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete for INSERT");

		conn->readMessage(type, buf);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete for INSERT");

		conn->readMessage(type, buf);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete for INSERT");

		tag = BufferReader(buf).readString();
		ok(tag.rfind("INSERT 0 1", 0) == 0, "CommandComplete tag is 'INSERT 0 1': %s", tag.c_str());

		conn->readMessage(type, buf);
		ok(type == PgConnection::READY_FOR_QUERY, "ReadyForQuery after INSERT");
	}
	catch (const PgException& e) {
		ok(false, "INSERT Extended Query test failed: %s", e.what());
	}
}

void test_parse_with_param_type() {
	diag("Test %d: Parse with Param Types", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		 
		conn->prepareStatement("test_param_type", "SELECT $1", false);
		conn->describeStatement("test_param_type", false);
		conn->sendSync();

		// Verify response
		char type;
		std::vector<uint8_t> buffer;

		{
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARSE_COMPLETE,
				"Received parse complete for statement with parameter types");

			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARAMETER_DESCRIPTION,
				"Received parameter description");

			// Read parameter description
			BufferReader reader(buffer);
			int paramCount = reader.readInt16();
			ok(paramCount == 1, "No parameters in prepared statement (%d/0)", paramCount);

			// Read parameter type OID
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 25, "Parameter type OID is 25 (text)");
		}

		{
			conn->readMessage(type, buffer);
			ok(type == PgConnection::ROW_DESCRIPTION,
				"Received row description");

			BufferReader reader(buffer);
			// Read row description
			int fieldCount = reader.readInt16();
			ok(fieldCount == 1, "Row description has 1 field (%d/1)", fieldCount);
			// Read field name
			std::string fieldName = reader.readString();
			ok(fieldName == "?column?", "Field name is '?column?'");

			// Read field table OID
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");

			// Read field attribute number
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");

			// Read field type OID
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 25, "Field type OID is 25 (text)");

			// Read field type size
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == -1, "Field type size is -1 (text size)");

			// Read field type modifier
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");

			// Read field format code
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 0, "Field format code is 0 (text format)");
		}
		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after describe");

		conn->prepareStatement("test_param_type2", "SELECT $1", false, { 23 });
		conn->describeStatement("test_param_type2", false);
		conn->sendSync();

		// Verify response
		{
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARSE_COMPLETE,
				"Received parse complete for statement with parameter types");
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARAMETER_DESCRIPTION,
				"Received parameter description");
			// Read parameter description
			BufferReader reader(buffer);
			int paramCount = reader.readInt16();
			ok(paramCount == 1, "Parameters in prepared statement (%d/1)", paramCount);
			// Read parameter type OID
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Parameter type OID is 23 (integer)");
		}

		{
			conn->readMessage(type, buffer);
			ok(type == PgConnection::ROW_DESCRIPTION,
				"Received row description");
			BufferReader reader(buffer);
			// Read row description
			int fieldCount = reader.readInt16();
			ok(fieldCount == 1, "Row description has 1 field (%d/1)", fieldCount);
			// Read field name
			std::string fieldName = reader.readString();
			ok(fieldName == "?column?", "Field name is '?column?'");
			// Read field table OID
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");
			// Read field attribute number
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
			// Read field type OID
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Field type OID is 23 (integer)");
			// Read field type size
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 4, "Field type size is 4 (integer size)");
			// Read field type modifier
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");
			// Read field format code
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 0, "Field format code is 0 (text format)");
		}
	}
	catch (const PgException& e) {
		ok(false, "Parse with sync test failed with error: %s", e.what());
	}
}

void test_set_statement_tracked() {
	diag("Test %d: Extended Query SET Statement Tracked", test_count++);
	auto conn = create_connection(); if (!conn) return;
	try {
		conn->prepareStatement("set_tracked_stmt", "SET client_min_messages TO 'error'", false);
		conn->bindStatement("set_tracked_stmt", "", {}, {}, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buf;
		conn->readMessage(type, buf);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete for SET STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete for SET STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete for SET EXECUTE");
		conn->readMessage(type, buf);
		ok(type == PgConnection::READY_FOR_QUERY, "ReadyForQuery after SET STATEMENT");
		usleep(1000);
		ok(check_logs_for_command(".*\\[WARNING\\] Unable to parse unknown SET query from client.*") == false, "Should not be locked on a hostgroup");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query SET Statement Tracked test failed: %s", e.what());
	}
}

void test_set_statement_tracked_with_describe() {
	diag("Test %d: Extended Query SET Statement Tracked with Describe", test_count++);
	auto conn = create_connection(); if (!conn) return;
	try {
		conn->prepareStatement("set_tracked_stmt_2", "SET client_min_messages TO 'error'", false);
		conn->bindStatement("set_tracked_stmt_2", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buf;
		conn->readMessage(type, buf);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete for SET STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete for SET STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::NO_DATA, "NoData for SET DESCRIBE");
		conn->readMessage(type, buf);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete for SET EXECUTE");
		conn->readMessage(type, buf);
		ok(type == PgConnection::READY_FOR_QUERY, "ReadyForQuery after SET STATEMENT");
		usleep(1000);
		ok(check_logs_for_command(".*\\[WARNING\\] Unable to parse unknown SET query from client.*") == false, "Should not be locked on a hostgroup");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query SET Statement Tracked test failed: %s", e.what());
	}
}

void test_set_statement_with_simple_query_mix() {
	diag("Test %d: Extended Query SET Statement with Simple Query Mix", test_count++);
	auto conn = create_connection(); if (!conn) return;
	try {
		conn->prepareStatement("set_stmt_mix", "SET client_min_messages TO 'error'", false);
		conn->bindStatement("set_stmt_mix", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->execute("SHOW client_min_messages");

		char type;
		std::vector<uint8_t> buf;
		conn->readMessage(type, buf);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete for SET STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete for SET STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::NO_DATA, "NoData for SET DESCRIBE");
		conn->readMessage(type, buf);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete for SET EXECUTE");
		conn->readMessage(type, buf);
		ok(type == PgConnection::ROW_DESCRIPTION, "RowDescription for SHOW");
		BufferReader buff(buf);
		int16_t fields = buff.readInt16();
		ok(fields == 1, "One field in RowDescription for SHOW (%d/1)", fields);
		std::string field_name = buff.readString();
		ok(field_name == "client_min_messages", "Field name is 'client_min_messages' (%s)", field_name.c_str());
		unsigned int table_oid = buff.readInt32();
		ok(table_oid == 0, "Field table OID is 0 (no table)");
		unsigned int attr_num = buff.readInt16();
		ok(attr_num == 0, "Field attribute number is 0 (no specific column)");
		unsigned int type_oid = buff.readInt32();
		ok(type_oid == 25, "Field type OID is 25 (text)");
		unsigned int type_size = buff.readInt16();
		ok(type_size == -1, "Field type size is -1 (text size)");
		unsigned int type_modifier = buff.readInt32();
		ok(type_modifier == -1, "Field type modifier is -1 (default)");
		unsigned int format_code = buff.readInt16();
		ok(format_code == 0, "Field format code is 0 (text format)");

		conn->readMessage(type, buf);
		ok(type == PgConnection::DATA_ROW, "DataRow for SHOW");
		buff = buf;
		int16_t cols = buff.readInt16();
		ok(cols == 1, "One column in DataRow for SHOW (%d/1)", cols);
		// Read column length
		int32_t col_len = buff.readInt32();
		ok(col_len == 5, "Column length is 5 (text size)");
		std::vector<uint8_t> val = buff.readBytes(col_len);
		ok(memcmp((char*)val.data(), "error", col_len) == 0, "SHOW returned 'error'");
		conn->readMessage(type, buf);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete for SHOW");
		conn->readMessage(type, buf);
		ok(type == PgConnection::READY_FOR_QUERY, "ReadyForQuery after SET STATEMENT and SHOW");
		
		usleep(1000);
		ok(check_logs_for_command(".*\\[WARNING\\] Unable to parse unknown SET query from client.*") == false, "Should not be locked on a hostgroup");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query SET Statement Tracked test failed: %s", e.what());
	}
}

void test_reset_statement_with_simple_query_mix() {
	diag("Test %d: Extended Query RESET Statement with Simple Query Mix", test_count++);
	auto conn = create_connection();
	if (!conn) return;
	try {
		conn->execute("SET client_min_messages='notice'");
		conn->waitForReady();

		conn->prepareStatement("reset_stmt_mix", "RESET client_min_messages", false);
		conn->bindStatement("reset_stmt_mix", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->execute("SHOW client_min_messages");

		char type;
		std::vector<uint8_t> buf;

		conn->readMessage(type, buf);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete for RESET STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete for RESET STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::NO_DATA, "NoData for RESET DESCRIBE");
		conn->readMessage(type, buf);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete for RESET EXECUTE");

		conn->readMessage(type, buf);
		ok(type == PgConnection::ROW_DESCRIPTION, "RowDescription for SHOW after RESET");

		BufferReader buff(buf);
		int16_t fields = buff.readInt16();
		ok(fields == 1, "One field in RowDescription for SHOW (%d/1)", fields);

		std::string field_name = buff.readString();
		ok(field_name == "client_min_messages", "Field name is 'client_min_messages' (%s)", field_name.c_str());

		buff.readInt32(); // table_oid
		buff.readInt16(); // attr_num
		unsigned int type_oid = buff.readInt32();
		ok(type_oid == 25, "Field type OID is 25 (text)");

		buff.readInt16(); // type_size
		buff.readInt32(); // type_modifier
		buff.readInt16(); // format_code

		conn->readMessage(type, buf);
		ok(type == PgConnection::DATA_ROW, "DataRow for SHOW after RESET");

		buff = buf;
		int16_t cols = buff.readInt16();
		ok(cols == 1, "One column in DataRow (%d/1)", cols);

		int32_t col_len = buff.readInt32();
		std::vector<uint8_t> val = buff.readBytes(col_len);
		ok(col_len == 6, "Column length is 6 (text size) after RESET");
		ok(memcmp((char*)val.data(), "notice", col_len) == 0, "SHOW after RESET returned 'notice'");

		conn->readMessage(type, buf);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete for SHOW");
		conn->readMessage(type, buf);
		ok(type == PgConnection::READY_FOR_QUERY, "ReadyForQuery after RESET and SHOW");

		usleep(1000);
		ok(check_logs_for_command(".*\\[WARNING\\] Unable to parse unknown RESET query from client.*") == false,
			"Should not be locked on a hostgroup");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query RESET Statement test failed: %s", e.what());
	}
}

void test_discard_statement_with_simple_query_mix() {
	diag("Test %d: Extended Query DISCARD Statement with Simple Query Mix", test_count++);
	auto conn = create_connection();
	if (!conn) return;
	try {
		conn->prepareStatement("discard_stmt_mix", "DISCARD TEMP", false);
		conn->bindStatement("discard_stmt_mix", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->execute("SELECT 1");

		char type;
		std::vector<uint8_t> buf;

		conn->readMessage(type, buf);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete for DISCARD STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete for DISCARD STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::NO_DATA, "NoData for DISCARD DESCRIBE");
		conn->readMessage(type, buf);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete for DISCARD EXECUTE");
		conn->readMessage(type, buf);
		ok(type == PgConnection::ROW_DESCRIPTION, "RowDescription for SELECT after DISCARD");
		BufferReader buff(buf);
		int16_t fields = buff.readInt16();
		ok(fields == 1, "One field in RowDescription for SELECT (%d/1)", fields);
		std::string field_name = buff.readString();
		ok(field_name == "?column?", "Field name is '?column?' (%s)", field_name.c_str());
		unsigned int table_oid = buff.readInt32();
		ok(table_oid == 0, "Field table OID is 0 (no table)");
		unsigned int attr_num = buff.readInt16();
		ok(attr_num == 0, "Field attribute number is 0 (no specific column)");
		unsigned int type_oid = buff.readInt32();
		ok(type_oid == 23, "Field type OID is 23 (integer)");
		unsigned int type_size = buff.readInt16();
		ok(type_size == 4, "Field type size is 4 (integer size)");
		unsigned int type_modifier = buff.readInt32();
		ok(type_modifier == -1, "Field type modifier is -1 (default)");
		unsigned int format_code = buff.readInt16();
		ok(format_code == 0, "Field format code is 0 (text format)");
		conn->readMessage(type, buf);
		ok(type == PgConnection::DATA_ROW, "DataRow for SELECT after DISCARD");
		buff = buf;
		int16_t cols = buff.readInt16();
		ok(cols == 1, "One column in DataRow for SELECT (%d/1)", cols);
		// Read column length
		int32_t col_len = buff.readInt32();
		ok(col_len == 1, "Column length is 1 (text size)");
		std::vector<uint8_t> val = buff.readBytes(col_len);
		ok(memcmp((char*)val.data(), "1", col_len) == 0, "SELECT after DISCARD returned '1'");
		conn->readMessage(type, buf);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete for SELECT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::READY_FOR_QUERY, "ReadyForQuery after DISCARD and SELECT");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query DISCARD Statement with Simple Query Mix test failed: %s", e.what());
	}
}

void test_deallocate_statement_with_simple_query_mix() {
	diag("Test %d: Extended Query DEALLOCATE Statement with Simple Query Mix", test_count++);
	auto conn = create_connection();
	if (!conn) return;
	try {
		// Prepare a dummy statement first
		conn->prepareStatement("dummy_stmt", "SELECT 1", false);

		// Now DEALLOCATE it
		conn->prepareStatement("dealloc_stmt_mix", "DEALLOCATE dummy_stmt", false);
		conn->bindStatement("dealloc_stmt_mix", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->execute("SELECT 1");

		char type;
		std::vector<uint8_t> buf;
		conn->readMessage(type, buf);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete for DEALLOCATE STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete for DEALLOCATE STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete for DEALLOCATE STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::NO_DATA, "NoData for DEALLOCATE DESCRIBE");
		conn->readMessage(type, buf);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete for DEALLOCATE EXECUTE");
		conn->readMessage(type, buf);
		ok(type == PgConnection::ROW_DESCRIPTION, "RowDescription for SELECT after DEALLOCATE");
		BufferReader buff(buf);
		int16_t fields = buff.readInt16();
		ok(fields == 1, "One field in RowDescription for SELECT (%d/1)", fields);
		std::string field_name = buff.readString();
		ok(field_name == "?column?", "Field name is '?column?' (%s)", field_name.c_str());
		unsigned int table_oid = buff.readInt32();
		ok(table_oid == 0, "Field table OID is 0 (no table)");
		unsigned int attr_num = buff.readInt16();
		ok(attr_num == 0, "Field attribute number is 0 (no specific column)");
		unsigned int type_oid = buff.readInt32();
		ok(type_oid == 23, "Field type OID is 23 (integer)");
		unsigned int type_size = buff.readInt16();
		ok(type_size == 4, "Field type size is 4 (integer size)");
		unsigned int type_modifier = buff.readInt32();
		ok(type_modifier == -1, "Field type modifier is -1 (default)");
		unsigned int format_code = buff.readInt16();
		ok(format_code == 0, "Field format code is 0 (text format)");
		conn->readMessage(type, buf);
		ok(type == PgConnection::DATA_ROW, "DataRow for SELECT after DEALLOCATE");
		buff = buf;
		int16_t cols = buff.readInt16();
		ok(cols == 1, "One column in DataRow for SELECT (%d/1)", cols);
		// Read column length
		int32_t col_len = buff.readInt32();
		ok(col_len == 1, "Column length is 1 (text size)");
		std::vector<uint8_t> val = buff.readBytes(col_len);
		ok(memcmp((char*)val.data(), "1", col_len) == 0, "SELECT after DEALLOCATE returned '1'");
		conn->readMessage(type, buf);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete for SELECT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::READY_FOR_QUERY, "ReadyForQuery after DEALLOCATE and SELECT");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query DEALLOCATE Statement with Simple Query Mix test failed: %s", e.what());
	}
}

void test_set_statement_untracked() {
	diag("Test %d: Extended Query SET Statement UnTracked", test_count++);
	auto conn = create_connection(); if (!conn) return;
	try {
		conn->prepareStatement("set_untracked_stmt", "SET dummy TO 'dummy'", false);
		conn->bindStatement("set_untracked_stmt", "", {}, {}, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buf;
		conn->readMessage(type, buf);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete for SET STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete for SET STATEMENT");
		conn->readMessage(type, buf);
		ok(type == PgConnection::ERROR_RESPONSE, "ErrorResponse for SET EXECUTE");
		conn->readMessage(type, buf);
		ok(type == PgConnection::READY_FOR_QUERY, "ReadyForQuery after SET STATEMENT");

		ok(check_logs_for_command(".*\\[WARNING\\] Unable to parse unknown SET query from client.*") == true, "Should be locked on a hostgroup");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query SET Statement UnTracked test failed: %s", e.what());
	}
}


void test_deallocate_having_stmt_name_via_simple_query() {
	diag("Test %d: Simple Query - DEALLOCATE named statement", test_count++);
	auto conn = create_connection(); if (!conn) return;

	try {
		// Prepare a valid statement
		conn->prepareStatement("deallocate_existing_stmt", "SELECT 1", true);

		// Close the statement
		conn->execute("DEALLOCATE PREPARE deallocate_existing_stmt");

		// Verify response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete was received after DEALLOCATE");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "ReadyForQuery was received after DEALLOCATE");

		// Verify statement is actually closed
		conn->describeStatement("deallocate_existing_stmt", true);
		conn->readMessage(type, buffer);  // Should get error
		ok(type == PgConnection::ERROR_RESPONSE, "Describe failed as expected after DEALLOCATE");
		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query");
	}
	catch (const PgException& e) {
		ok(false, "Simple Query - DEALLOCATE named statement failed with error:%s", e.what());
	}
}

void test_deallocate_having_stmt_name_via_prepared() {
	diag("Test %d: Extended Query - DEALLOCATE named statement via prepared execution", test_count++);
	auto conn = create_connection(); if (!conn) return;
	if (!conn) return;

	try {
		// Prepare a valid statement
		conn->prepareStatement("deallocate_existing_stmt2", "DEALLOCATE deallocate_existing_stmt2", false);
		conn->sendSync();

		// Verify response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete was received for DEALLOCATE");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query");

		// should be present in prepared statements
		conn->describeStatement("deallocate_existing_stmt2", true);
		conn->readMessage(type, buffer);  
		ok(type == PgConnection::PARAMETER_DESCRIPTION, "ParameterDescription was received for prepared DEALLOCATE");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::NO_DATA, "Received NoData");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query");

		conn->bindStatement("deallocate_existing_stmt2", "", {}, {}, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		// Verify response
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete was received for DEALLOCATE");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete was received after DEALLOCATE execution");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query after deallocate existing statement");

		// Verify statement is actually closed
		conn->describeStatement("deallocate_existing_stmt2", true);
		conn->readMessage(type, buffer);  // Should get error
		ok(type == PgConnection::ERROR_RESPONSE, "Describe failed as expected after DEALLOCATE");
		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query after deallocate existing statement");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query - DEALLOCATE named statement via prepared execution failed with error:%s", e.what());
	}
}

void test_deallocate_all_via_simple_query() {
	diag("Test %d: Simple Query - DEALLOCATE ALL", test_count++);
	auto conn = create_connection(); if (!conn) return;
	if (!conn) return;

	try {
		// Prepare a valid statement
		conn->prepareStatement("deallocate_all_1", "SELECT 1", true);
		conn->prepareStatement("deallocate_all_2", "SELECT 2", true);
		conn->prepareStatement("deallocate_all_3", "SELECT 3", true);

		// Close the statement
		conn->execute("DEALLOCATE PREPARE ALL");

		// Verify response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete was received after DEALLOCATE ALL");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query");

		// Verify statement is actually closed
		conn->describeStatement("deallocate_all_1", true);
		conn->readMessage(type, buffer);  // Should get error
		ok(type == PgConnection::ERROR_RESPONSE, "Describe failed for deallocate_all_1 as expected");
		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query");

		// Verify statement is actually closed
		conn->describeStatement("deallocate_all_2", true);
		conn->readMessage(type, buffer);  // Should get error
		ok(type == PgConnection::ERROR_RESPONSE, "Describe failed for deallocate_all_2 as expected");

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query");

		// Verify statement is actually closed
		conn->describeStatement("deallocate_all_3", true);
		conn->readMessage(type, buffer);  // Should get error
		ok(type == PgConnection::ERROR_RESPONSE, "Describe failed for deallocate_all_3 as expected");

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query DEALLOCATE having Statement Name failed with error:%s", e.what());
	}
}

void test_deallocate_all_via_prepared() {
	diag("Test %d: Extended Query - DEALLOCATE ALL via prepared execution", test_count++);
	auto conn = create_connection(); if (!conn) return;
	if (!conn) return;
	try {
		conn->execute("SET dummy TO 'test'"); // intentionally lock on hostgroup. DEALLOCATE should work regardless
		
		// Verify response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Session Locked On Hostgroup as expected");
		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "42704", "Received ERRCODE_UNDEFINED_OBJECT Error:%s", errormsg.c_str());
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query after SET dummy");

		// Prepare a valid statement
		conn->prepareStatement("deallocate_all_1", "SELECT 1", true);
		conn->prepareStatement("deallocate_all_2", "SELECT 2", true);
		conn->prepareStatement("deallocate_all_3", "SELECT 3", true);

		// Bind and execute DEALLOCATE ALL
		conn->prepareStatement("", "DEALLOCATE ALL", true);
		conn->bindStatement("", "", {}, {}, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete was received for DEALLOCATE ALL");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete was received for DEALLOCATE ALL");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query");

		// Verify statement is actually closed
		conn->describeStatement("deallocate_all_1", true);
		conn->readMessage(type, buffer);  // Should get error
		ok(type == PgConnection::ERROR_RESPONSE, "Describe failed for deallocate_all_1 as expected");
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query");


		// Verify statement is actually closed
		conn->describeStatement("deallocate_all_2", true);
		conn->readMessage(type, buffer);  // Should get error
		ok(type == PgConnection::ERROR_RESPONSE, "Describe failed for deallocate_all_2 as expected");
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query");

		// Verify statement is actually closed
		conn->describeStatement("deallocate_all_3", true);
		conn->readMessage(type, buffer);  // Should get error
		ok(type == PgConnection::ERROR_RESPONSE, "Describe failed for deallocate_all_3 as expected");

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query DEALLOCATE ALL via Prepared failed with error:%s", e.what());
	}
}

void test_deallocate_non_existent_stmt() {
	diag("Test %d: Extended Query - DEALLOCATE non-existent statement", test_count++);
	auto conn = create_connection(); if (!conn) return;
	if (!conn) return;
	try {
		// Attempt to deallocate a non-existent statement
		conn->execute("DEALLOCATE PREPARE non_existent_stmt");
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "ErrorResponse was received for DEALLOCATE non-existent statement");
		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query after DEALLOCATE non-existent statement");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query DEALLOCATE non-existent statement failed with error:%s", e.what());
	}
}

void test_describe_portal_returns_no_data() {
	diag("Test %d: Extended Query - Describe Returns No Data", test_count++);
	auto conn = create_connection(); if (!conn) return;
	if (!conn) return;
	try {
		conn->execute("CREATE TEMP TABLE test_describe (id integer)");
		conn->waitForReady();

		conn->prepareStatement("describe_no_data_stmt", "INSERT INTO test_describe VALUES (42)", false);
		conn->bindStatement("describe_no_data_stmt", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete was received for describe no data statement");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete was received for describe no data statement");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::NO_DATA, "NoData was received for describe no data statement");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete was received for describe no data statement");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query after describe no data statement");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query Describe Returns No Data failed with error:%s", e.what());
	}
}

void test_multiple_parse_bind_describe_execute_fail() {
	diag("Test %d: Extended Query - Multiple Parse/Bind/Describe/Execute Fail", test_count++);
	auto conn = create_connection(); if (!conn) return;
	if (!conn) return;
	try {
		// Prepare a valid statement
		conn->prepareStatement("multi_stmt", "SELECT 1", false);
		conn->bindStatement("multi_stmt", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->prepareStatement("multi_stmt2", "SELECT 1/0", false);
		conn->bindStatement("multi_stmt2", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->prepareStatement("multi_stmt3", "SELECT 2", false);
		conn->bindStatement("multi_stmt3", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->sendSync();
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete was received for multi_stmt");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete was received for multi_stmt");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "RowDescription was received for multi_stmt");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "DataRow was received for multi_stmt");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete was received for multi_stmt");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete was received for multi_stmt2");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "BindComplete was received for multi_stmt2");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "ErrorResponse was received for multi_stmt2");
		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "22012", "Received ERRCODE_DIVISION_BY_ZERO Error:%s", errormsg.c_str());
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query after multi_stmt2 error");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query Multiple Parse/Bind/Describe/Execute Fail failed with error:%s", e.what());
	}
}

void test_send_multiple_simple_query_without_waiting_for_response() {
	diag("Test %d: Simple Query - Send multiple queries without waiting for response", test_count++);
	auto conn = create_connection(); if (!conn) return;
	if (!conn) return;
	try {
		// Send multiple simple queries without waiting for response
		conn->execute("SELECT 1");
		conn->execute("SELECT 2");
		conn->execute("SELECT 3");
		conn->execute("SELECT 4");
		conn->execute("SELECT 5");

		char type;
		std::vector<uint8_t> buffer;
		
		for (int i = 1; i <= 5; i++) {
			conn->readMessage(type, buffer);
			ok(type == PgConnection::ROW_DESCRIPTION, "RowDescription was received for SELECT %d", i);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::DATA_ROW, "DataRow was received for SELECT %d", i);
			BufferReader reader(buffer);
			int fieldCount = reader.readInt16();
			ok(fieldCount == 1, "DataRow has 1 field for SELECT %d", i);
			int valueLen = reader.readInt32();
			ok(valueLen == 1, "DataRow value length is 1 for SELECT %d", i);
			uint8_t value = reader.readByte();
			ok(value == (i + '0'), "DataRow value is %c for SELECT %d", value, i);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete was received for SELECT %d", i);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query for SELECT %d", i);
		}
	}
	catch (const PgException& e) {
		ok(false, "Simple Query - Send multiple queries without waiting for response failed with error:%s", e.what());
	}
}

void test_send_multiple_simple_query_in_transaction_without_waiting_for_response() {
	diag("Test %d: Simple Query - Send multiple queries in transaction without waiting for response", test_count++);
	auto conn = create_connection(); if (!conn) return;
	if (!conn) return;
	try {
		// Send multiple simple queries without waiting for response
		conn->execute("BEGIN");
		conn->execute("SELECT 1");
		conn->execute("SELECT 2");
		conn->execute("SELECT 3");
		conn->execute("SELECT 4");
		conn->execute("SELECT 5");
		conn->execute("COMMIT");
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete was received for BEGIN");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query after BEGIN");

		for (int i = 1; i <= 5; i++) {
			conn->readMessage(type, buffer);
			ok(type == PgConnection::ROW_DESCRIPTION, "RowDescription was received for SELECT %d", i);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::DATA_ROW, "DataRow was received for SELECT %d", i);
			BufferReader reader(buffer);
			int fieldCount = reader.readInt16();
			ok(fieldCount == 1, "DataRow has 1 field for SELECT %d", i);
			int valueLen = reader.readInt32();
			ok(valueLen == 1, "DataRow value length is 1 for SELECT %d", i);
			uint8_t value = reader.readByte();
			ok(value == (i + '0'), "DataRow value is %c for SELECT %d", value, i);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete was received for SELECT %d", i);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query for SELECT %d", i);
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete was received for COMMIT");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query after all SELECTs and COMMIT");
	}
	catch (const PgException& e) {
		ok(false, "Simple Query - Send multiple queries in transaction without waiting for response failed with error:%s", e.what());
	}
}

void test_send_multiple_simple_query_without_waiting_for_response_proxysql_fast_forward_mode(PGconn* admin_conn) {
	diag("Test %d: Simple Query - Send multiple queries without waiting for response (ProxySQL Fast Forward Mode)", test_count++);
	// Enable ProxySQL Fast Forward Mode
	executeQueries(admin_conn, { "UPDATE pgsql_users SET fast_forward=1",
		"LOAD PGSQL USERS TO RUNTIME" });

	test_send_multiple_simple_query_without_waiting_for_response();

	// Restore ProxySQL Fast Forward Mode to default (disabled)
	executeQueries(admin_conn, { "UPDATE pgsql_users SET fast_forward=0", 
		"LOAD PGSQL USERS TO RUNTIME" });
}

void test_send_multiple_simple_query_in_transaction_without_waiting_for_response_proxysql_fast_forward_mode(PGconn* admin_conn) {
	diag("Test %d: Simple Query - Send multiple queries in transaction without waiting for response (ProxySQL Fast Forward Mode)", test_count++);
	// Enable ProxySQL Fast Forward Mode
	executeQueries(admin_conn, { "UPDATE pgsql_users SET fast_forward=1",
		"LOAD PGSQL USERS TO RUNTIME" });

	test_send_multiple_simple_query_in_transaction_without_waiting_for_response();

	// Restore ProxySQL Fast Forward Mode to default (disabled)
	executeQueries(admin_conn, { "UPDATE pgsql_users SET fast_forward=0",
		"LOAD PGSQL USERS TO RUNTIME" });
}

void test_send_simple_query_and_extended_query_without_waiting_for_response() {
	diag("Test %d: Simple Query and Extended Query without waiting for response", test_count++);
	auto conn = create_connection(); if (!conn) return;
	if (!conn) return;
	try {
		// Send multiple simple queries without waiting for response
		conn->execute("SELECT 1");
		conn->execute("SELECT 2");
		conn->execute("SELECT 3");
		conn->execute("SELECT 4");
		conn->execute("SELECT 5");

		conn->prepareStatement("ext_stmt", "SELECT $1", false);
		PgConnection::Param param = { "1", 0 };
		conn->bindStatement("ext_stmt", "", { param }, {}, false);
		conn->executeStatement(0, false);
		param = { "2", 0 };
		conn->bindStatement("ext_stmt", "", { param }, {}, false);
		conn->executeStatement(0, false);
		param = { "3", 0 };
		conn->bindStatement("ext_stmt", "", { param }, {}, false);
		conn->executeStatement(0, false);
		param = { "4", 0 };
		conn->bindStatement("ext_stmt", "", { param }, {}, false);
		conn->executeStatement(0, false);
		param = { "5", 0 };
		conn->bindStatement("ext_stmt", "", { param }, {}, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		param = { "1", 0 };
		conn->bindStatement("ext_stmt", "", { param }, {}, false);
		conn->executeStatement(0, false);
		param = { "2", 0 };
		conn->bindStatement("ext_stmt", "", { param }, {}, false);
		conn->executeStatement(0, false);
		param = { "3", 0 };
		conn->bindStatement("ext_stmt", "", { param }, {}, false);
		conn->executeStatement(0, false);
		param = { "4", 0 };
		conn->bindStatement("ext_stmt", "", { param }, {}, false);
		conn->executeStatement(0, false);
		param = { "5", 0 };
		conn->bindStatement("ext_stmt", "", { param }, {}, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		for (int i = 1; i <= 5; i++) {
			conn->readMessage(type, buffer);
			ok(type == PgConnection::ROW_DESCRIPTION, "RowDescription was received for SELECT %d", i);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::DATA_ROW, "DataRow was received for SELECT %d", i);
			BufferReader reader(buffer);
			int fieldCount = reader.readInt16();
			ok(fieldCount == 1, "DataRow has 1 field for SELECT %d", i);
			int valueLen = reader.readInt32();
			ok(valueLen == 1, "DataRow value length is 1 for SELECT %d", i);
			uint8_t value = reader.readByte();
			ok(value == (i + '0'), "DataRow value is %c for SELECT %d", value, i);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete was received for SELECT %d", i);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query for SELECT %d", i);
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "ParseComplete was received for extended query");

		for (int i = 1; i <= 5; i++) {
			conn->readMessage(type, buffer);
			ok(type == PgConnection::BIND_COMPLETE, "BindComplete was received (extended query P1)");
			//conn->readMessage(type, buffer);
			//ok(type == PgConnection::ROW_DESCRIPTION, "RowDescription was received for SELECT %d (extended query P1)", i);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::DATA_ROW, "DataRow was received for SELECT %d (extended query P1)", i);
			BufferReader reader(buffer);
			int fieldCount = reader.readInt16();
			ok(fieldCount == 1, "DataRow has 1 field for SELECT %d (extended query P1)", i);
			int valueLen = reader.readInt32();
			ok(valueLen == 1, "DataRow value length is 1 for SELECT %d (extended query P1)", i);
			uint8_t value = reader.readByte();
			ok(value == (i + '0'), "DataRow value is %c for SELECT %d (extended query P1)", value, i);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete was received for SELECT %d (extended query P1)", i);
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query (extended query P1)");

		for (int i = 1; i <= 5; i++) {
			conn->readMessage(type, buffer);
			ok(type == PgConnection::BIND_COMPLETE, "BindComplete was received (extended query P2)");
			//conn->readMessage(type, buffer);
			//ok(type == PgConnection::ROW_DESCRIPTION, "RowDescription was received for SELECT %d (extended query P2)", i);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::DATA_ROW, "DataRow was received for SELECT %d (extended query P2)", i);
			BufferReader reader(buffer);
			int fieldCount = reader.readInt16();
			ok(fieldCount == 1, "DataRow has 1 field for SELECT %d (extended query P2)", i);
			int valueLen = reader.readInt32();
			ok(valueLen == 1, "DataRow value length is 1 for SELECT %d (extended query P2)", i);
			uint8_t value = reader.readByte();
			ok(value == (i + '0'), "DataRow value is %c for SELECT %d (extended query P2)", value, i);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::COMMAND_COMPLETE, "CommandComplete was received for SELECT %d (extended query P2)", i);
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ready for query (extended query P2)");
	}
	catch (const PgException& e) {
		ok(false, "Simple Query and Extended Query without waiting for response failed with error:%s", e.what());
	}
}

void test_send_simple_query_and_extended_query_without_waiting_for_response_proxysql_fast_forward_mode(PGconn* admin_conn) {
	diag("Test %d: Simple Query and Extended Query without waiting for response (ProxySQL Fast Forward Mode)", test_count++);
	// Enable ProxySQL Fast Forward Mode
	executeQueries(admin_conn, { "UPDATE pgsql_users SET fast_forward=1",
		"LOAD PGSQL USERS TO RUNTIME" });

	test_send_simple_query_and_extended_query_without_waiting_for_response();

	// Restore ProxySQL Fast Forward Mode to default (disabled)
	executeQueries(admin_conn, { "UPDATE pgsql_users SET fast_forward=0",
		"LOAD PGSQL USERS TO RUNTIME" });
}

void test_pipeline_error() {
	diag("Test %d: Extended Query - Pipeline Error Handling", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("basic_bind", "SELECT 1/0", false);
		conn->bindStatement("basic_bind", "", { }, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		conn->prepareStatement("basic_bind2", "SELECT 2", false);
		conn->bindStatement("basic_bind2", "", { }, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->sendSync();

		// Verify results
		char type;
		std::vector<uint8_t> buffer;

		// Read parse complete
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received ErrorResponse for division by zero");
		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "22012", "Received ERRCODE_DIVISION_BY_ZERO Error:%s", errormsg.c_str());
		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after error");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query Pipeline Error Handling failed with error:%s", e.what());
	}
}

void test_pipeline_error_2() {
	diag("Test %d: Extended Query - Pipeline Error Handling 2", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("basic_bind", "SELECT 1/0", false);
		conn->bindStatement("basic_bind", "", { }, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->sendSync();

		// Verify results
		char type;
		std::vector<uint8_t> buffer;

		// Read parse complete
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received ErrorResponse for division by zero");
		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "22012", "Received ERRCODE_DIVISION_BY_ZERO Error:%s", errormsg.c_str());
		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after error");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query Pipeline Error Handling 2 failed with error:%s", e.what());
	}
}

void test_pipeline_exit() {
	diag("Test %d: Extended Query - Pipeline exit", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("basic_bind", "SELECT 1", false);
		conn->bindStatement("basic_bind", "", { }, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->prepareStatement("basic_bind2", "SELECT 1", false);
		conn->execute("SELECT 2");

		// Verify results
		char type;
		std::vector<uint8_t> buffer;

		// Read parse complete
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for second statement");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "RowDescription was received for simple query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "DataRow was received for simple query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for simple query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after all commands");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query Pipeline Error Handling failed with error:%s", e.what());
	}
}

void test_pipeline_exit_2() {
	diag("Test %d: Extended Query - Pipeline exit 2", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("basic_bind", "SELECT 1", false);
		conn->bindStatement("basic_bind", "", { }, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->sendSync();

		// Verify results
		char type;
		std::vector<uint8_t> buffer;

		// Read parse complete
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after all commands");
	}
	catch (const PgException& e) {
		ok(false, " Extended Query - Pipeline exit 2 failed with error:%s", e.what());
	}
}

void test_pipeline_exit_3() {
	diag("Test %d: Extended Query - Pipeline exit 3", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("basic_bind", "SELECT 1", false);
		conn->bindStatement("basic_bind", "", { }, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->prepareStatement("basic_bind2", "SELECT 1", false);
		conn->sendSync();

		// Verify results
		char type;
		std::vector<uint8_t> buffer;

		// Read parse complete
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for second statement");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after all commands");
	}
	catch (const PgException& e) {
		ok(false, " Extended Query - Pipeline exit 3 failed with error:%s", e.what());
	}
}

void test_pipeline_transaction_exit() {
	diag("Test %d: Extended Query - Pipeline exit in transaction", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->execute("BEGIN");
		conn->prepareStatement("basic_bind", "SELECT 1", false);
		conn->bindStatement("basic_bind", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->prepareStatement("basic_bind2", "SELECT 1", false);
		conn->execute("SELECT 2");
		conn->execute("ROLLBACK");
		// Verify results
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for BEGIN");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after BEGIN");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for second statement");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "RowDescription was received for simple query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "DataRow was received for simple query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for simple query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after all commands");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for ROLLBACK");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after all commands");
	}
	catch (const PgException& e) {
		ok(false, "Extended Query Pipeline exit in transaction failed with error:%s", e.what());
	}
}

void test_implicit_txn_error_first_insert() {
	diag("Test %d: Implicit transaction - error on first insert should rollback all", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->execute("CREATE TEMP TABLE temp_test(id INT)");

		// First insert has error (text instead of int)
		conn->prepareStatement("ins1", "INSERT INTO temp_test VALUES('abc')", false);
		conn->bindStatement("ins1", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		// Second insert should not execute
		conn->prepareStatement("ins2", "INSERT INTO temp_test VALUES(2)", false);
		conn->bindStatement("ins2", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		// Consume until ReadyForQuery
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for CREATE TEMP TABLE");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after CREATE TEMP TABLE");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received ErrorResponse for first insert");
		conn->readMessage(type, buffer); // ReadyForQuery
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after first insert error");

		// Now check count
		conn->execute("SELECT count(*) FROM temp_test");
		int rows = 0;
		conn->readMessage(type, buffer); 
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		conn->readMessage(type, buffer); // DataRow
		ok(type == PgConnection::DATA_ROW, "Received RowData");
		BufferReader reader(buffer);
		int fieldCount = reader.readInt16();
		ok(fieldCount == 1, "Received 1 field in data row");
		int valueLen = reader.readInt32();
		ok(valueLen == 1, "Field length is 1 bytes");
		uint8_t val = reader.readByte();
		ok(val == '0', "Received correct value '0' for count query");
		conn->readMessage(type, buffer); // CommandComplete
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for count query");
		conn->readMessage(type, buffer); // ReadyForQuery
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after count query");
	}
	catch (const PgException& e) {
		ok(false, "Implicit txn error-first-insert test failed: %s", e.what());
	}
}

void test_implicit_txn_error_middle_insert() {
	diag("Test %d: Implicit transaction - error on middle insert should rollback all", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->execute("CREATE TEMP TABLE temp_test(id INT)");

		// First insert valid
		conn->prepareStatement("ins1", "INSERT INTO temp_test VALUES(1)", false);
		conn->bindStatement("ins1", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		// Second insert invalid
		conn->prepareStatement("ins2", "INSERT INTO temp_test VALUES('oops')", false);
		conn->bindStatement("ins2", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		// Third insert valid (should be rolled back)
		conn->prepareStatement("ins3", "INSERT INTO temp_test VALUES(3)", false);
		conn->bindStatement("ins3", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		// CREATE TABLE
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for CREATE TEMP TABLE");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after CREATE TEMP TABLE");

		// First insert
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for first insert");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for first insert");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::NO_DATA, "Received NoData for first insert");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for first insert");

		// Second insert fails
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received ErrorResponse for second insert error");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after error");

		// Verify rollback (should have 0 rows)
		conn->execute("SELECT count(*) FROM temp_test");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");
		BufferReader reader(buffer);
		int fieldCount = reader.readInt16();
		ok(fieldCount == 1, "Received 1 field in data row");
		int valueLen = reader.readInt32();
		ok(valueLen == 1, "Field length is 1 byte");
		uint8_t val = reader.readByte();
		ok(val == '0', "Received correct value '0' for count query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for count query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after count query");
	}
	catch (const PgException& e) {
		ok(false, "Implicit txn error-middle-insert test failed: %s", e.what());
	}
}

void test_implicit_txn_error_last_insert() {
	diag("Test %d: Implicit transaction - error on last insert should rollback all", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->execute("CREATE TEMP TABLE temp_test(id INT)");

		// First insert valid
		conn->prepareStatement("ins1", "INSERT INTO temp_test VALUES(1)", false);
		conn->bindStatement("ins1", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		// Second insert valid
		conn->prepareStatement("ins2", "INSERT INTO temp_test VALUES(2)", false);
		conn->bindStatement("ins2", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		// Third insert invalid
		conn->prepareStatement("ins3", "INSERT INTO temp_test VALUES('bad')", false);
		conn->bindStatement("ins3", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		// CREATE TABLE
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for CREATE TEMP TABLE");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after CREATE TEMP TABLE");

		// First insert ok
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for first insert");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for first insert");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::NO_DATA, "Received NoData for first insert");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for first insert");

		// Second insert ok
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for second insert");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for second insert");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::NO_DATA, "Received NoData for second insert");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for second insert");

		// Third insert fails
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received ErrorResponse for third insert error");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after error");

		// Verify rollback (should have 0 rows)
		conn->execute("SELECT count(*) FROM temp_test");
		int rows = 0;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");
		BufferReader reader(buffer);
		int fieldCount = reader.readInt16();
		ok(fieldCount == 1, "Received 1 field in data row");
		int valueLen = reader.readInt32();
		ok(valueLen == 1, "Field length is 1 byte");
		uint8_t val = reader.readByte();
		ok(val == '0', "Received correct value '0' for count query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for count query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after count query");
	}
	catch (const PgException& e) {
		ok(false, "Implicit txn error-last-insert test failed: %s", e.what());
	}
}

void test_explicit_txn_error_with_rollback_extended() {
	diag("Test %d: Explicit transaction - extended query pipeline inside transaction, error -> ROLLBACK", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Create temp table and begin explicit transaction (simple commands; we verify their responses)
		conn->execute("CREATE TEMP TABLE temp_test(id INT)");
		conn->execute("BEGIN");

		char type;
		std::vector<uint8_t> buffer;

		// CREATE TABLE response
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for CREATE TEMP TABLE");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after CREATE TEMP TABLE");

		// BEGIN response
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for BEGIN");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after BEGIN");

		// Now issue three INSERTs using extended query pipeline (two good, one bad)
		conn->prepareStatement("ins1", "INSERT INTO temp_test VALUES(1)", false);
		conn->bindStatement("ins1", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		conn->prepareStatement("ins2", "INSERT INTO temp_test VALUES(2)", false);
		conn->bindStatement("ins2", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		conn->prepareStatement("ins3", "INSERT INTO temp_test VALUES('bad')", false);
		conn->bindStatement("ins3", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		conn->sendSync();

		// Read extended-protocol responses in sequence
		// ins1
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for ins1");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for ins1");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::NO_DATA, "Received NoData for ins1");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for ins1");

		// ins2
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for ins2");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for ins2");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::NO_DATA, "Received NoData for ins2");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for ins2");

		// ins3 (error)
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE || type == PgConnection::ERROR_RESPONSE,
			"Received ParseComplete or ErrorResponse for ins3 (got %d)", (int)type);
		if (type == PgConnection::PARSE_COMPLETE) {
			conn->readMessage(type, buffer);
			ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for ins3");
			conn->readMessage(type, buffer);
		}
		ok(type == PgConnection::ERROR_RESPONSE, "Received ErrorResponse for ins3 (bad value)");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after ins3 error");

		// Now ROLLBACK the explicit transaction
		conn->execute("ROLLBACK");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for ROLLBACK");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after ROLLBACK");

		// Verify table is empty
		conn->execute("SELECT count(*) FROM temp_test");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");
		BufferReader reader(buffer);
		int fieldCount = reader.readInt16();
		ok(fieldCount == 1, "Received 1 field in data row");
		int valueLen = reader.readInt32();
		ok(valueLen == 1, "Field length is 1 byte");
		uint8_t val = reader.readByte();
		ok(val == '0', "Received correct value '0' after rollback");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for count query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after count query");
	}
	catch (const PgException& e) {
		ok(false, "Explicit txn (extended) error-with-rollback test failed: %s", e.what());
	}
}

void test_explicit_txn_error_with_commit_extended() {
	diag("Test %d: Explicit transaction - extended query pipeline inside transaction, error -> COMMIT", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Create temp table and BEGIN
		conn->execute("CREATE TEMP TABLE temp_test(id INT)");
		conn->execute("BEGIN");

		char type;
		std::vector<uint8_t> buffer;

		// CREATE TABLE response
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for CREATE TEMP TABLE");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after CREATE TEMP TABLE");

		// BEGIN response
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for BEGIN");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after BEGIN");

		// Extended pipeline: two good inserts and one bad
		conn->prepareStatement("ins1", "INSERT INTO temp_test VALUES(1)", false);
		conn->bindStatement("ins1", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		conn->prepareStatement("ins2", "INSERT INTO temp_test VALUES(2)", false);
		conn->bindStatement("ins2", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		conn->prepareStatement("ins3", "INSERT INTO temp_test VALUES('bad')", false);
		conn->bindStatement("ins3", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		conn->sendSync();

		// Read responses for ins1
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for ins1");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for ins1");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::NO_DATA, "Received NoData for ins1");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for ins1");

		// ins2
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for ins2");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for ins2");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::NO_DATA, "Received NoData for ins2");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for ins2");

		// ins3 error
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE || type == PgConnection::ERROR_RESPONSE,
			"Received ParseComplete or ErrorResponse for ins3 (got %d)", (int)type);
		if (type == PgConnection::PARSE_COMPLETE) {
			conn->readMessage(type, buffer);
			ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for ins3");
			conn->readMessage(type, buffer);
		}
		ok(type == PgConnection::ERROR_RESPONSE, "Received ErrorResponse for ins3 (bad value)");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after ins3 error");

		// Attempt COMMIT of aborted transaction
		conn->execute("COMMIT");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE || type == PgConnection::COMMAND_COMPLETE,
			"Received response for COMMIT after error (either ErrorResponse or CommandComplete)");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after COMMIT");

		// Verify that no rows were committed (transaction was aborted and commit did not persist inserts)
		conn->execute("SELECT count(*) FROM temp_test");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");
		BufferReader reader(buffer);
		int fieldCount = reader.readInt16();
		ok(fieldCount == 1, "Received 1 field in data row");
		int valueLen = reader.readInt32();
		ok(valueLen == 1, "Field length is 1 byte");
		uint8_t val = reader.readByte();
		ok(val == '0', "Received correct value '0' after commit of aborted txn");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for count query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after count query");
	}
	catch (const PgException& e) {
		ok(false, "Explicit txn (extended) error-with-commit test failed: %s", e.what());
	}
}

void test_explicit_txn_success_then_rollback_extended() {
	diag("Test %d: Explicit transaction - extended inserts succeed but ROLLBACK discards them", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Create temp table and BEGIN
		conn->execute("CREATE TEMP TABLE temp_test(id INT)");
		conn->execute("BEGIN");

		char type;
		std::vector<uint8_t> buffer;

		// CREATE TABLE response
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for CREATE TEMP TABLE");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after CREATE TEMP TABLE");

		// BEGIN response
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for BEGIN");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after BEGIN");

		// Extended pipeline: three valid inserts
		conn->prepareStatement("ins1", "INSERT INTO temp_test VALUES(1)", false);
		conn->bindStatement("ins1", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		conn->prepareStatement("ins2", "INSERT INTO temp_test VALUES(2)", false);
		conn->bindStatement("ins2", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		conn->prepareStatement("ins3", "INSERT INTO temp_test VALUES(3)", false);
		conn->bindStatement("ins3", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);

		conn->sendSync();

		// Read responses for ins1
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for ins1");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for ins1");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::NO_DATA, "Received NoData for ins1");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for ins1");

		// ins2
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for ins2");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for ins2");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::NO_DATA, "Received NoData for ins2");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for ins2");

		// ins3
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for ins3");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for ins3");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::NO_DATA, "Received NoData for ins3");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for ins3");

		// End of batch
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after all inserts");

		// Now ROLLBACK explicitly
		conn->execute("ROLLBACK");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for ROLLBACK");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after ROLLBACK");

		// Verify rollback (table should be empty)
		conn->execute("SELECT count(*) FROM temp_test");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");
		BufferReader reader(buffer);
		int fieldCount = reader.readInt16();
		ok(fieldCount == 1, "Received 1 field in data row");
		int valueLen = reader.readInt32();
		ok(valueLen == 1, "Field length is 1 byte");
		uint8_t val = reader.readByte();
		ok(val == '0', "Received correct value '0' after rollback of successful inserts");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete for count query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after count query");
	}
	catch (const PgException& e) {
		ok(false, "Explicit txn (extended) success-then-rollback test failed: %s", e.what());
	}
}

void test_empty_query_describe_portal_returns_no_data() {
	diag("Test %d: Describe Portal Returns No Data for empty query", test_count++);
	auto conn = create_connection();
	if (!conn) return;
	try{
		conn->prepareStatement("empty_query_stmt", "", false);
		conn->bindStatement("empty_query_stmt", "", {}, {}, false);
		conn->describePortal("", false);
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for empty query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for empty query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::NO_DATA, "Received NoData for empty query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::EMPTY_QUERY_RESPONSE, "Received EmptyQueryResponse for empty query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after all commands");
	}
	catch (const PgException& e) {
		ok(false, "Describe Portal Returns No Data for empty query failed with error:%s", e.what());
	}
}

void test_empty_query_without_describe_portal() {
	diag("Test %d: Execute empty query without Describe Portal", test_count++);
	auto conn = create_connection();
	if (!conn) return;
	try {
		conn->prepareStatement("empty_query2_stmt", "", false);
		conn->bindStatement("empty_query2_stmt", "", {}, {}, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete for empty query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for empty query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::EMPTY_QUERY_RESPONSE, "Received EmptyQueryResponse for empty query");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after all commands");
	}
	catch (const PgException& e) {
		ok(false, "Execute empty query without Describe Portal failed with error:%s", e.what());
	}
}

int main(int argc, char** argv) {
	if (cl.getEnv())
		return exit_status();

	std::string f_path{get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log"};
	int of_err = open_file_and_seek_end(f_path, f_proxysql_log);
	if (of_err != EXIT_SUCCESS) {
		return exit_status();
	}

	plan(1061); // Adjust based on number of tests

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

	try {
		// Parse Prepared Statement
		test_parse_without_sync();
		test_parse_with_sync(); 
		test_malformed_packet();
		test_empty_query();
		test_multiple_parse();
		test_only_sync();
		test_empty_stmt();
		test_prepare_statement_mix();
		test_invalid_query_parse_packet();
		test_parse_use_same_stmt_name();
		test_parse_use_unnamed_stmt();
		
		// Describe Prepared Statement
		test_describe_existing_statement();
		test_describe_nonexistent_statement();
		test_describe_without_sync();
		test_describe_malformed_packet();
		test_describe_after_close_statement();
		test_multiple_describe_calls();
		test_describe_parameter_types();
		test_describe_result_metadata();
		test_describe_prepared_noname();
		
		// Close Statement
		test_close_existing_statement();
		test_close_nonexistent_statement();
		test_close_unnamed_statement();
		test_close_without_sync();
		test_multiple_close_without_sync();
		test_close_malformed_packet();
		test_close_twice();
		test_close_without_prepare();
		test_close_during_pending_ops();
		test_close_all_types();
		
		// Bind and Execute
		test_parse_execute_without_bind();
		test_bind_basic();
		test_bind_without_sync();
		test_bind_nonexistent_statement();
		test_bind_incorrect_parameters();
		test_binary_parameters();
		test_bind_large_data();
		test_bind_null_parameters();
		test_malformed_bind_packet();
		test_malformed_execute_packet();

		// Portals
		test_bind_named_portal(); 
		test_describe_portal(); 
		test_close_portal();   
		test_portal_lifecycle(); 
		test_describe_closed_portal();    
		test_describe_portal_returns_no_data();

		// random tests
		test_libpq_style_execute();       
		test_multiple_execute_on_single_bind(); 
		test_multiple_parse_bind_describe_execute_fail();
		test_insert_command_complete();
		test_parse_with_param_type();

		// SET statement tracking
		test_set_statement_tracked();
		test_set_statement_tracked_with_describe();
		test_set_statement_untracked();
		test_set_statement_with_simple_query_mix();
		test_reset_statement_with_simple_query_mix();

		// DEALLOCATE statements
		test_deallocate_having_stmt_name_via_simple_query();
		test_deallocate_having_stmt_name_via_prepared();
		test_deallocate_all_via_simple_query();
		test_deallocate_all_via_prepared();
		test_deallocate_non_existent_stmt();
		test_deallocate_statement_with_simple_query_mix();

		// Tests for sending multiple simple queries and extended queries without waiting for response
		test_send_multiple_simple_query_without_waiting_for_response();
		test_send_multiple_simple_query_in_transaction_without_waiting_for_response();
		test_send_simple_query_and_extended_query_without_waiting_for_response();
		test_send_multiple_simple_query_without_waiting_for_response_proxysql_fast_forward_mode(admin_conn.get());
		test_send_multiple_simple_query_in_transaction_without_waiting_for_response_proxysql_fast_forward_mode(admin_conn.get());
		test_send_simple_query_and_extended_query_without_waiting_for_response_proxysql_fast_forward_mode(admin_conn.get());

		// Extended Query (without sync) + Simple Query 
		test_extended_query_prepared_describe_execute_simple_query_without_sync();
		test_prepare_statement_mix();

		// DISCARD
		test_discard_statement_with_simple_query_mix();

		// Pipeline tests
		test_pipeline_error();
		test_pipeline_error_2();
		test_pipeline_exit();
		test_pipeline_exit_2();
		test_pipeline_exit_3();
		test_pipeline_transaction_exit();

		// Implicit transaction tests
		test_implicit_txn_error_first_insert();
		test_implicit_txn_error_middle_insert();
		test_implicit_txn_error_last_insert();
		test_explicit_txn_error_with_rollback_extended();
		test_explicit_txn_error_with_commit_extended();
		test_explicit_txn_success_then_rollback_extended();

		// Empty query tests
		test_empty_query_describe_portal_returns_no_data();
		test_empty_query_without_describe_portal();
	}
	catch (const std::exception& e) {
		diag("Fatal error: %s",e.what());
	}
	f_proxysql_log.close();
	return exit_status();
}
