/**
 * @file test_mariadb_metadata_check-t.cpp
 * @brief Tests the column count integrity check for libmariadb.
 * @details Two different tests are performed:
 *  - Isolated Test: A malformed packet (based on packet that generated the original crash report) is sent by
 *    a fake server to a client. The client should be able to read the packet and continue operations without
 *    presenting memory or internal state issues.
 *  - Integration Test: To exercise this column-count packet check, queries that generates different column
 *    numbers are executed through ProxySQL. Numbers should go below and above '251', to test different
 *    integer values encoding in the 'column-count' packet. See:
 *    https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_dt_integers.html
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>
#include <thread>
#include <unistd.h>
#include <utility>

#include "mysql.h"

#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::vector;
using std::pair;
using std::string;

/**
 * @brief MySQL 8.0.39 Greeting message
 */
unsigned char srv_greeting[] = {
	// Header
	0x4a, 0x00, 0x00, 0x00,
	// Protocol version number
	0x0a,
	// Server version string '8.0.39'; and NULL terminator
	0x38, 0x2e, 0x30, 0x2e, 0x33, 0x39, 0x00,
	// Length of the server thread ID
	0x6a, 0x00, 0x00, 0x00,
	// Salt
	0x51, 0x04, 0x7d, 0x6f, 0x1a, 0x4b, 0x17, 0x12, 0x00,
	// Server Capabilities
	0xff, 0xff,
	// Server Language: utf8mb4 COLLATE utf8mb4_0900_ai_ci (255))
	0xff,
	// Server Status
	0x02, 0x00,
	// Extended server capabilities
	0xff, 0xdf,
	// Authentication Plugin
	0x15,
	// Unused
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// Salt
	0x15, 0x6e, 0x3c, 0x6e, 0x73, 0x0e, 0x6c, 0x5a, 0x28, 0x7d, 0x67, 0x11, 0x00,
	// 'mysql_native_password'
	0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70,
	0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00
};

/**
 * @brief OK packet after accepting fake auth.
 */
unsigned char srv_login_resp_ok_pkt[] = {
	0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};

/**
 * @brief Malformed packet, invalid encoding of initial 'column-count' packet.
 */
unsigned char srv_malformed_resultset[] = {
	// Column-Count 'packet'; invalid encoding; header specifies size '8' for a packet
	// encoding a single int with value '7', size should be '1'.
	0x08, 0x00, 0x00, 0x01, 0x07,
	// No field definition; just value
	0x35, 0x32, 0x34, 0x32, 0x33, 0x32, 0x32,
	// EOF
	0x05, 0x00, 0x00, 0x02, 0xfe, 0x00, 0x00, 0x0a, 0x00,
};

/**
 * @brief Valid packet holding the resulset of a 'SELECT 1' query.
 * @details This is used as a control query to check the client library status after
 *  reading through the whole previously sent 'srv_malformed_resultset'.
 */
unsigned char srv_resp_select_1[] = {
	// Column-Count packet
	0x01, 0x00, 0x00, 0x01, 0x01,
	// Field definition
	0x17, 0x00, 0x00, 0x02, 0x03, 0x64, 0x65, 0x66, 0x00, 0x00, 0x00, 0x01, 0x31, 0x00, 0x0c, 0x3f, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x08, 0x81, 0x00, 0x00, 0x00, 0x00,
	// Row packet
	0x02, 0x00, 0x00, 0x03, 0x01, 0x31,
	// OK packet
	0x07, 0x00, 0x00, 0x04, 0xfe, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};

/**
 * @brief Sequence of messages used by 'fake_server'.
 * @details The messages fake a simple interation between a client using `libmariadb` and
 *  a MySQL 8.0.39 server. See messages descriptions in list and above.
 */
const vector<pair<unsigned char*, size_t>> srv_resps = {
	// Server greeting message
	{ srv_greeting, sizeof(srv_greeting) },
	// OK packet after 'Auth' packet from client; auth always works here :)
	{ srv_login_resp_ok_pkt, sizeof(srv_login_resp_ok_pkt) },
	// Send malformed resultset; The resultset fields definitions are mangled, and the
	// 'column-count' packet header purposely fails to encode the payload size.
	{ srv_malformed_resultset, sizeof(srv_malformed_resultset) },
	// A simple final resultset corresponding to a 'SELECT 1'. This is used to check if
	// client is able to read through the whole invalid resulset.
	{ srv_resp_select_1, sizeof(srv_resp_select_1) }
};

/**
 * @brief Creates a fake server with the specified port.
 * @details For each client input, the server reads and discards it, and sends the next
 *  message specified in the list 'srv_resps'. For description see doc on 'srv_resps'.
 * @param port The port in which the server should listen.
 * @return 0 if the server shutdown succesfully, 1 otherwise.
 */
int fake_server(int port) {
	int sockfd, clientfd;
	struct sockaddr_in server_addr, client_addr;
	socklen_t client_addr_len = sizeof(client_addr);

	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket");
		exit(1);
	}

	// Set server address
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port);

	int opval = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opval, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
	}

	// Bind socket
	if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		perror("bind");
		exit(1);
	}

	// Listen for connections
	if (listen(sockfd, 5) == -1) {
		perror("listen");
		exit(1);
	}

	diag("Server started on port %d", port);

	// Accept connection
	clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
	if (clientfd == -1) {
		perror("accept");
		exit(1);
	}

	diag(
		"Client connected   addr='%s:%d'",
		inet_ntoa(client_addr.sin_addr),  ntohs(client_addr.sin_port)
	);

	struct pollfd pfd;
	pfd.fd = clientfd;
	pfd.events = POLLIN;
	char dummy[256] = { 0 };

	// Receive data
	for (const auto& resp : srv_resps) {
		int n = static_cast<int>(write(clientfd, resp.first, resp.second));
		diag("Server: Written response   n=%d", n);

		if (n < 0) {
			perror("write");
			break;
		}

		if (&resp != &srv_resps.back()) {
			n = poll(&pfd, 1, -1);
			if (n < 0) {
				perror("poll");
				break;
			}

			n = static_cast<int>(recv(clientfd, dummy, sizeof(dummy), 0));
			diag("Server: Received response   n=%d", n);

			if (n == 0) {
				diag("Client disconnected");
				break;
			} else if (n < 0) {
				perror("recv");
				break;
			}
		}
	}

	// Close sockets
	close(clientfd);

	return 0;
}

/**
 * @brief Test the reception of a malformed packet using a fake server.
 * @details The client performs the following actions:
 *  - 1: Connects to the fake server; connection is always accepted.
 *  - 2: Attempts to read and checks ('ok') the detection the malformed packet.
 *  - 3: Read through the malformed packet. The client keeps attempting to perform a new
 *       query until the remains of the malformed packet are processed by the library, and a
 *       new query can be performed.
 *  - 4: Check ('ok') that a valid resulset is received for final query performed after
 *       receiving the malformed packet.
 */
void test_malformed_packet() {
	const uint16_t port { 9091 };
	const char* user { "foo" };
	const char* pass { "bar" };
	std::thread srv_th(fake_server, port);

	MYSQL* conn = mysql_init(NULL);
	mysql_options(conn, MYSQL_DEFAULT_AUTH, "mysql_native_password");
	conn->options.client_flag |= CLIENT_DEPRECATE_EOF;

	if (!mysql_real_connect(conn, "127.0.0.1", user, pass, NULL, port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(conn));
		goto cleanup;
	}

	{
		int rc = mysql_query(conn, "SELECT LAST_INSERT_ID()");
		ok(
			rc && mysql_errno(conn) == 2027,
			"'mysql_query' should fail with 'malformed_packet'   rc=%d errno=%d error='%s'",
			rc, mysql_errno(conn), mysql_error(conn)
		);

		mysql_free_result(mysql_store_result(conn));
	}

	// Should be able to read through malformed packet to the healthy one
	{
		int rc = 0;
		while ((rc = mysql_query(conn, "SELECT 1"))) {
			diag(
				"Client: Still reading malformed packet...   rc=%d errno=%d error='%s'",
				rc, mysql_errno(conn), mysql_error(conn)
			);
		}

		diag("Client: Integrity checks allowed to continue reading");

		ok(
			rc == 0,
			"Simple query should work   rc=%d errno=%d error='%s'",
			rc, mysql_errno(conn), mysql_error(conn)
		);

		MYSQL_RES* myres = mysql_store_result(conn);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		ok(
			myres->field_count == 1 && myrow[0][0] == 49,
			"Fetched resulset should be well-formed   fields=%d data=%d",
			myres->field_count, myrow[0][0]
		);

		mysql_free_result(myres);
	}

cleanup:

	mysql_close(conn);

	pthread_cancel(srv_th.native_handle());
	srv_th.join();
}

string gen_dyn_cols_select(size_t n) {
	string q { "SELECT " };

	for (size_t i = 0; i < n; i++) {
		q += "NULL AS col_" + std::to_string(n);

		if (i < n - 1) {
			q += ",";
		}
	}

	return q;
}

// Needs to be above and below '251'. See:
// - https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_dt_integers.html
const vector<size_t> cols_counts { 1, 2, 128, 251, 252, 253, 512 };

/**
 * @brief Tests that the integrity check introduced in 'libmariadbclient'.
 * @details Ensures that the check works for queries returning less/more than `251` columns. This forces the
 *  encoding at protocol level of different integers, exercising the check for more values.
 * @param cl Used for connection creation.
 */
void test_integrity_check(CommandLine& cl) {
	MYSQL* conn = mysql_init(NULL);
	mysql_options(conn, MYSQL_DEFAULT_AUTH, "mysql_native_password");

	if (!mysql_real_connect(conn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(conn));
		goto cleanup;
	}

	for (const auto& count : cols_counts) {
		const string query { gen_dyn_cols_select(count) };
		int rc = mysql_query(conn, query.c_str());

		if (rc) {
			diag("Query failed   errno=%d error='%s'", mysql_errno(conn), mysql_error(conn));
			goto cleanup;
		} else {
			MYSQL_RES* myres = mysql_store_result(conn);

			ok(
				myres->field_count == count,
				"Number of columns should match expected   exp=%ld act=%d",
				count, myres->field_count
			);

			mysql_free_result(myres);
		}
	}

cleanup:

	mysql_close(conn);
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(3 + static_cast<int>(cols_counts.size()));

	test_malformed_packet();
	test_integrity_check(cl);

	return exit_status();
}
