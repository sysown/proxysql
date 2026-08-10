#ifdef PROXYSQLFFTO

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "MySQLFFTO.hpp"
#include "PgSQLFFTO.hpp"

#include <cstring>
#include <vector>
#include <string_view>

extern __thread int mysql_thread___ffto_max_buffer_size;
extern __thread int pgsql_thread___ffto_max_buffer_size;

static void test_mysql_ffto_constructor_destructor() {
	MySQLFFTO* ffto = new MySQLFFTO(nullptr);
	ok(ffto != nullptr, "MySQLFFTO: constructor with null session succeeds");
	ok(ffto->get_buffered_size() == 0, "MySQLFFTO: initial buffered size is 0");
	delete ffto;
	ok(1, "MySQLFFTO: destructor with null session succeeds");
}

static void test_mysql_ffto_null_data() {
	MySQLFFTO ffto(nullptr);
	ffto.on_client_data(nullptr, 0);
	ok(1, "MySQLFFTO: on_client_data with null data doesn't crash");
	ffto.on_server_data(nullptr, 0);
	ok(1, "MySQLFFTO: on_server_data with null data doesn't crash");
	ffto.on_client_data("data", 0);
	ok(1, "MySQLFFTO: on_client_data with zero length doesn't crash");
	ffto.on_server_data("data", 0);
	ok(1, "MySQLFFTO: on_server_data with zero length doesn't crash");
}

static void test_mysql_ffto_on_close_idle() {
	MySQLFFTO ffto(nullptr);
	ffto.on_close();
	ok(1, "MySQLFFTO: on_close in IDLE state doesn't crash");
	ok(ffto.get_buffered_size() == 0, "MySQLFFTO: buffered size 0 after close");
}

static void test_mysql_ffto_incomplete_packet() {
	mysql_thread___ffto_max_buffer_size = 16 * 1024 * 1024;
	MySQLFFTO ffto(nullptr);
	unsigned char incomplete_hdr[] = {0x05, 0x00};
	ffto.on_client_data((const char*)incomplete_hdr, 2);
	ok(ffto.get_buffered_size() == 2, "MySQLFFTO: incomplete header is buffered");
}

static void test_mysql_ffto_com_query_packet() {
	mysql_thread___ffto_max_buffer_size = 16 * 1024 * 1024;
	MySQLFFTO ffto(nullptr);
	unsigned char pkt[] = {
		0x09, 0x00, 0x00, 0x00,
		0x03, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'
	};
	ffto.on_client_data((const char*)pkt, sizeof(pkt));
	ok(1, "MySQLFFTO: COM_QUERY packet processed without crash");
	ffto.on_close();
	ok(1, "MySQLFFTO: on_close after COM_QUERY doesn't crash");
}

static void test_pgsql_ffto_constructor_destructor() {
	PgSQLFFTO* ffto = new PgSQLFFTO(nullptr);
	ok(ffto != nullptr, "PgSQLFFTO: constructor with null session succeeds");
	ok(ffto->get_buffered_size() == 0, "PgSQLFFTO: initial buffered size is 0");
	delete ffto;
	ok(1, "PgSQLFFTO: destructor with null session succeeds");
}

static void test_pgsql_ffto_null_data() {
	PgSQLFFTO ffto(nullptr);
	ffto.on_client_data(nullptr, 0);
	ok(1, "PgSQLFFTO: on_client_data with null data doesn't crash");
	ffto.on_server_data(nullptr, 0);
	ok(1, "PgSQLFFTO: on_server_data with null data doesn't crash");
	ffto.on_client_data("data", 0);
	ok(1, "PgSQLFFTO: on_client_data with zero length doesn't crash");
	ffto.on_server_data("data", 0);
	ok(1, "PgSQLFFTO: on_server_data with zero length doesn't crash");
}

static void test_pgsql_ffto_on_close_idle() {
	PgSQLFFTO ffto(nullptr);
	ffto.on_close();
	ok(1, "PgSQLFFTO: on_close in IDLE state doesn't crash");
	ok(ffto.get_buffered_size() == 0, "PgSQLFFTO: buffered size 0 after close");
}

static void test_pgsql_ffto_simple_query_message() {
	pgsql_thread___ffto_max_buffer_size = 16 * 1024 * 1024;
	PgSQLFFTO ffto(nullptr);
	const char* query = "SELECT 1";
	const size_t qlen = std::string_view(query).size() + 1;
	uint32_t msg_len = htonl((uint32_t)(qlen + 4));
	std::vector<char> msg(1 + 4 + qlen);
	msg[0] = 'Q';
	memcpy(&msg[1], &msg_len, 4);
	memcpy(&msg[5], query, qlen);
	ffto.on_client_data(msg.data(), msg.size());
	ok(1, "PgSQLFFTO: Simple Query message processed without crash");
	ffto.on_close();
	ok(1, "PgSQLFFTO: on_close after Simple Query doesn't crash");
}

static void test_pgsql_ffto_incomplete_message() {
	pgsql_thread___ffto_max_buffer_size = 16 * 1024 * 1024;
	PgSQLFFTO ffto(nullptr);
	char incomplete[] = {'Q', 0x00};
	ffto.on_client_data(incomplete, 2);
	ok(ffto.get_buffered_size() == 2, "PgSQLFFTO: incomplete message is buffered");
}

static void test_pgsql_ffto_parse_message() {
	pgsql_thread___ffto_max_buffer_size = 16 * 1024 * 1024;
	PgSQLFFTO ffto(nullptr);
	/* PostgreSQL Parse ('P'):
	 *   Byte1 'P'
	 *   Int32 length  = 4 + name\0 + query\0 + Int16(num_params)
	 *   String stmt_name (NUL-terminated; empty name is a single NUL)
	 *   String query     (NUL-terminated)
	 *   Int16  num_params
	 */
	const char* query = "SELECT 1";
	const size_t name_len = 1; /* empty name + NUL */
	const size_t query_len = std::string_view(query).size() + 1;
	const size_t payload_len = name_len + query_len + 2;
	const uint32_t wire_len = (uint32_t)(4 + payload_len);
	uint32_t msg_len_be = htonl(wire_len);
	std::vector<char> msg(1 + wire_len, 0);
	msg[0] = 'P';
	memcpy(&msg[1], &msg_len_be, 4);
	msg[5] = '\0'; /* empty statement name */
	memcpy(&msg[5 + name_len], query, query_len);
	/* num_params already 0 from zero-init */
	ffto.on_client_data(msg.data(), msg.size());
	ok(1, "PgSQLFFTO: Parse message processed without crash");
	ffto.on_close();
	ok(1, "PgSQLFFTO: on_close after Parse doesn't crash");
}

int main() {
	plan(27);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_mysql_ffto_constructor_destructor();
	test_mysql_ffto_null_data();
	test_mysql_ffto_on_close_idle();
	test_mysql_ffto_incomplete_packet();
	test_mysql_ffto_com_query_packet();

	test_pgsql_ffto_constructor_destructor();
	test_pgsql_ffto_null_data();
	test_pgsql_ffto_on_close_idle();
	test_pgsql_ffto_simple_query_message();
	test_pgsql_ffto_incomplete_message();
	test_pgsql_ffto_parse_message();

	test_cleanup_minimal();
	return exit_status();
}

#else

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

int main() {
	plan(1);
	ok(1, "FFTO state machine tests skipped (PROXYSQLFFTO not enabled)");
	return exit_status();
}

#endif
