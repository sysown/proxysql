/**
 * @file reg_test_stmt_inv_param_offset-t.cpp
 * @brief Ensures valid handling of malformed COM_STMT_EXECUTE packets.
 * @details Checks that the following flows are covered:
 *
 *   - Malformed STMT_EXECUTE (1-param) with mangled UPPER 4-bytes for param-length are executed normally.
 *   - Malformed STMT_EXECUTE (2-params) with mangled UPPER 4-bytes for param-length are executed normally.
 *   - Malformed STMT_EXECUTE (1-param) with mangled LOWER 4-bytes for param-length are detected as malformed.
 *   - Malformed STMT_EXECUTE (2-params) with mangled LOWER 4-bytes for param-length are detected as malformed.
 *
 *  Packets with 1 and 2 params are tested to cover different regression flows:
 *
 *   - Invalid allocation attempt due to big param length (1 param).
 *   - Invalid memory access due to invalid offset-jump (length) during packet processing (2 >= params).
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>
#include <utility>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::vector;
using std::string;
using std::pair;

/**
 * @brief SUCCESS (Invalid 4 upper-bytes) - Hardcoded STMT_EXECUTE packet header.
 */
unsigned char SUCCESS_FAKE_EXEC_HEADER_1[] = {
	0xff,0xff,0xff,0x00,0x17,0x01,0x00,0x00,   0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x01,
	0xfd,0x00,0xfe,0x00,0x00,0x10,0x01,0x00,   0x00,0x10,0x01 // 0x00,   0x00,0x00,0x00
};

/**
 * @brief Hardcoded STMT_EXECUTE packet header - continuation.
 */
unsigned char SUCCESS_FAKE_EXEC_HEADER_1_2[] = {
	0x18,0x00,0x10,0x01
};

/**
 * @brief SUCCESS (Invalid 4 upper-bytes) - Hardcoded STMT_EXECUTE packet header.
 */
unsigned char SUCCESS_FAKE_EXEC_HEADER_2[] = {
	0xff,0xff,0xff,0x00,0x17,0x02,0x00,0x00,   0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x01,
	0xfd,0x00,0x03,0x00,0xfe,0x00,0x00,0x10,   0x01,0x00,0x00,0x10,0x01, // 0x00,0x00,0x00,0x00
};

/**
 * @brief Hardcoded STMT_EXECUTE packet header - continuation.
 */
unsigned char SUCCESS_FAKE_EXEC_HEADER_2_1[] = {
	0x1e,0x00,0x10,0x01
};

/**
 * @brief FAIL (Invalid 4 upper-bytes) - Hardcoded STMT_EXECUTE packet header.
 */
unsigned char FAIL_FAKE_EXEC_HEADER_1[] = {
	0xff,0xff,0xff,0x00,0x17,0x01,0x00,0x00,   0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x01,
	0xfd,0x00,0xfe,0x00,0x00,0x10,0x02,0x00,   0x00,0x10,0x01
};

/**
 * @brief Hardcoded STMT_EXECUTE packet header - continuation.
 */
unsigned char FAIL_FAKE_EXEC_HEADER_1_2[] = {
	0x18,0x00,0x10,0x01
};

/**
 * @brief FAIL (Invalid 4 upper-bytes) - Hardcoded STMT_EXECUTE packet header.
 */
unsigned char FAIL_FAKE_EXEC_HEADER_2[] = {
	0xff,0xff,0xff,0x00,0x17,0x02,0x00,0x00,   0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x01,
	0xfd,0x00,0x03,0x00,0xfe,0x00,0x00,0x10,   0x02,0x00,0x00,0x10,0x01
};

/**
 * @brief Hardcoded STMT_EXECUTE packet header - continuation.
 */
unsigned char FAIL_FAKE_EXEC_HEADER_2_1[] = {
	0x1e,0x00,0x10,0x01
};

struct hdr_t {
	unsigned char* hdr_1 { nullptr };
	size_t size_1 { 0 };
	unsigned char* hdr_2 { nullptr };
	size_t size_2 { 0 };
};

struct q_params_t {
	const char* q { nullptr };
	const vector<MYSQL_BIND> p {};
	hdr_t hdrs {};
	const vector<char> d {};
};

struct stmt_params_t {
	MYSQL_STMT* stmt;
	vector<MYSQL_BIND> p;
	hdr_t hdrs {};
	const vector<char> d {};
};

rc_t<stmt_params_t> prepare_stmt(MYSQL* conn, const q_params_t& qp) {
	MYSQL_STMT* stmt = mysql_stmt_init(conn);
	if (!stmt) {
		diag("'mysql_stmt_init' failed   error=\"out of memory\"");
		return { EXIT_FAILURE, {} };
	}

	diag("Issuing STMT PREPARE   query=\"%s\"", qp.q);
	int my_err = mysql_stmt_prepare(stmt, qp.q, strlen(qp.q));
	if (my_err) {
		diag(
			"'mysql_stmt_prepare' failed   query=\"%s\" err=\"%d\" msg=\"%s\"",
			qp.q, mysql_stmt_errno(stmt), mysql_stmt_error(stmt)
		);
		return { EXIT_FAILURE, { stmt, qp.p, qp.hdrs, qp.d } };
	}

	return { EXIT_SUCCESS, { stmt, qp.p, qp.hdrs, qp.d } };
}

uint32_t perform_real_execute(const stmt_params_t& sp) {
	int myerr = 0;

	if ((myerr=mysql_stmt_bind_param(sp.stmt, const_cast<MYSQL_BIND*>(sp.p.data())))) {
		diag("'mysql_stmt_bind_param' failed   error=\"%s\"", mysql_stmt_error(sp.stmt));
		return EXIT_FAILURE;
	}

	if (mysql_stmt_execute(sp.stmt)) {
		diag("'mysql_stmt_execute' failed   error=\"%s\"", mysql_stmt_error(sp.stmt));
		return EXIT_FAILURE;
	} else {
		return EXIT_SUCCESS;
	}
}


int perform_fake_execute(MYSQL* mysql, const hdr_t& hdr, const vector<char>& data) {
	size_t pkt_size_1 { 16 * 1024 * 1024 - 1 + 4 };

	int rc = write(mysql->net.fd, hdr.hdr_1, hdr.size_1);
	diag("1 - Header written to socket   len=%d", rc);
	if (rc == -1) { return rc; }

	size_t body_size_1 { pkt_size_1 - hdr.size_1 };
	rc = write(mysql->net.fd, data.data(), body_size_1);
	diag("1 - Body written to socket   len=%d", rc);
	if (rc == -1) { return rc; }

	rc = write(mysql->net.fd, hdr.hdr_2, hdr.size_2);
	diag("2 - Header written to socket   len=%d", rc);

	size_t body_size_2 { data.size() - body_size_1 };
	rc = write(mysql->net.fd, data.data() + body_size_1, body_size_2);
	diag("2 - Body written to socket   len=%d body_size_2=%ld", rc, body_size_2);

	return rc;
}

int prepare_server_defaults(const CommandLine& cl) {
	MYSQL* proxy = mysql_init(NULL);

	if (!mysql_real_connect(proxy, cl.host, cl.root_username, cl.root_password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	int rc = 0;
	if ((rc=mysql_query_t(proxy, "/* hostgroup=0 */ SET GLOBAL max_allowed_packet=20971520"))) {
		diag("'mysql_query' failed   error=\"%s\"", mysql_error(proxy));
	}

	mysql_close(proxy);

	return rc;
}

void check_execute(MYSQL* proxy, const vector<stmt_params_t>& stmts, bool exp_scs) {
	size_t exec_count { 0 };

	for (const stmt_params_t& sp : stmts) {
		if (getenv("REG_TEST_STMT_INV_PARAM_OFFSET___REAL_EXECUTE")) {
			uint32_t rc = perform_real_execute(sp);

			ok(
				rc == EXIT_SUCCESS,
				"Real execute for packet capture should succeed   error=\"%s\"",
				mysql_error(proxy)
			);
		} else {
			errno = 0;

			int rc = perform_fake_execute(proxy, sp.hdrs, sp.d);
			ok (
				rc > 0,
				"%ld - Fake EXECUTE written correctly   error=\"%s\"",
				exec_count, strerror(errno)
			);

			char res_buf[200] { 0 }; // OK ~= 11 bytes || ERR ~= 50 bytes
			rc = read(proxy->net.fd, &res_buf, sizeof(res_buf));
			ok (
				rc > 0,
				"%ld - Fake EXECUTE response read   error=\"%s\" packet_str=\"%s\"",
				exec_count, strerror(errno), res_buf + 7
			);

			bool act_scs = strncasecmp(res_buf + 7, "#28000", strlen("#28000")) != 0;
			ok(
				act_scs == exp_scs,
				"%ld - Fake EXECUTE success should match expected   exp_scs=%d act_scs=%d",
				exec_count, exp_scs, act_scs
			);
			exec_count += 1;
		}
	}
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	if (prepare_server_defaults(cl)) {
		diag("Failed to prepare server defaults, exiting...");
		return EXIT_FAILURE;
	}

	plan(24);

	MYSQL* proxy_1 = mysql_init(NULL);
	MYSQL* proxy_2 = mysql_init(NULL);
	MYSQL* admin = mysql_init(NULL);

	diag(
		"Creating MySQL connection   host=\"%s\" port=%d user=\"%s\" pass=\"%s\"",
		cl.host, cl.port, cl.username, cl.password
	);
	if (!mysql_real_connect(proxy_1, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_1));
		return EXIT_FAILURE;
	}
	diag(
		"Creating MySQL connection   host=\"%s\" port=%d user=\"%s\" pass=\"%s\"",
		cl.host, cl.port, cl.username, cl.password
	);
	if (!mysql_real_connect(proxy_2, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_2));
		return EXIT_FAILURE;
	}

	diag(
		"Creating Admin MySQL connection   host=\"%s\" port=%d user=\"%s\" pass=\"%s\"",
		cl.host, cl.admin_port, cl.admin_username, cl.admin_password
	);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY_T(proxy_1, "CREATE DATABASE IF NOT EXISTS test");

	diag("Start_Ting trx in new connection; required for 'max_allowed_packet'   conn=%p", proxy_1);
	MYSQL_QUERY_T(proxy_1, "/* create_new_connection=1 */ BEGIN");

	MYSQL_QUERY_T(proxy_2, "USE test");
	diag("Start_Ting trx in new connection; required for 'max_allowed_packet'   conn=%p", proxy_2);
	MYSQL_QUERY_T(proxy_2, "/* create_new_connection=1 */ BEGIN");

	MYSQL_QUERY_T(proxy_1,
		"CREATE TABLE IF NOT EXISTS test.test_stmt_inv__large_col_1 ("
			"id INT AUTO_INCREMENT PRIMARY KEY,"
			"data_column LONGTEXT"
		")"
	);

	MYSQL_QUERY_T(proxy_1,
		"CREATE TABLE IF NOT EXISTS test.test_stmt_inv__large_col_2 ("
			"id INT AUTO_INCREMENT PRIMARY KEY,"
			"data_column LONGTEXT,"
			"data_int INT"
		")"
	);

	const char* q1 { "INSERT INTO test.test_stmt_inv__large_col_1 (data_column) VALUES (?)" };
	const char* q2 { "INSERT INTO test.test_stmt_inv__large_col_2 (data_column,data_int) VALUES (?,?)" };

	MYSQL_BIND b1 {};
	vector<char> p1(17 * 1024 * 1024, 'a');
	uint64_t p1_len { p1.size() };
	b1.buffer_type = MYSQL_TYPE_VAR_STRING;
	b1.buffer = p1.data();
	b1.buffer_length = p1_len;
	b1.is_null = 0;
	b1.length = &p1_len;

	MYSQL_BIND b2 {};
	uint64_t p2 { 7 };
	b2.buffer_type = MYSQL_TYPE_LONG;
	b2.buffer = reinterpret_cast<char*>(&p2);
	b2.is_null = 0;
	b2.length = 0;

	const hdr_t scs_hdr_1 {
		SUCCESS_FAKE_EXEC_HEADER_1, sizeof(SUCCESS_FAKE_EXEC_HEADER_1),
		SUCCESS_FAKE_EXEC_HEADER_1_2, sizeof(SUCCESS_FAKE_EXEC_HEADER_1_2)
	};
	const hdr_t scs_hdr_2 {
		SUCCESS_FAKE_EXEC_HEADER_2, sizeof(SUCCESS_FAKE_EXEC_HEADER_2),
		SUCCESS_FAKE_EXEC_HEADER_2_1, sizeof(SUCCESS_FAKE_EXEC_HEADER_2_1)
	};
	const hdr_t fail_hdr_1 {
		FAIL_FAKE_EXEC_HEADER_1, sizeof(FAIL_FAKE_EXEC_HEADER_1),
		FAIL_FAKE_EXEC_HEADER_1_2, sizeof(FAIL_FAKE_EXEC_HEADER_1_2)
	};
	const hdr_t fail_hdr_2 {
		FAIL_FAKE_EXEC_HEADER_2, sizeof(FAIL_FAKE_EXEC_HEADER_2),
		FAIL_FAKE_EXEC_HEADER_2_1, sizeof(FAIL_FAKE_EXEC_HEADER_2_1)
	};

	vector<char> p1_2 {};
	std::copy(std::begin(p1), std::end(p1), std::back_inserter(p1_2));
	vector<char> vp2 { static_cast<char>(p2), 0, 0, 0 };
	std::copy(std::begin(vp2), std::end(vp2), std::back_inserter(p1_2));

	const vector<q_params_t> scs_q_params {
		{ q1, { b1 }, scs_hdr_1, p1 },
		{ q2, { b1, b2 }, scs_hdr_2, p1_2 }
	};
	const vector<hdr_t> fail_hdrs { fail_hdr_1, fail_hdr_2 };
	vector<rc_t<stmt_params_t>> scs_stmt_params {};

	std::transform(scs_q_params.begin(), scs_q_params.end(), std::back_inserter(scs_stmt_params),
		[&proxy_1] (const q_params_t& qp) -> rc_t<stmt_params_t> {
			return prepare_stmt(proxy_1, qp);
		}
	);

	vector<rc_t<stmt_params_t>> scs_stmt_params_2 {};
	vector<rc_t<stmt_params_t>> fail_stmt_params_2 {};

	std::transform(scs_q_params.begin(), scs_q_params.end(), std::back_inserter(scs_stmt_params_2),
		[&proxy_2] (const q_params_t& qp) -> rc_t<stmt_params_t> {
			return prepare_stmt(proxy_2, qp);
		}
	);

	vector<stmt_params_t> v_stmts {};
	vector<stmt_params_t> v_stmts_2 {};

	for (const auto& sp : scs_stmt_params) {
		if (sp.first) {
			diag("Exiting due to failed prepare   error=\"%s\"", mysql_stmt_error(sp.second.stmt));
			goto cleanup;
		} else {
			v_stmts.push_back(sp.second);
		}
	}
	for (const auto& sp : scs_stmt_params_2) {
		if (sp.first) {
			diag("Exiting due to failed prepare   error=\"%s\"", mysql_stmt_error(sp.second.stmt));
			goto cleanup;
		} else {
			v_stmts_2.push_back(sp.second);
		}
	}

	{
		// Check for SUCCESS for payloads with invalid UPPER 4-bytes in string<var> - CONN 1
		check_execute(proxy_1, v_stmts, true);

		for (size_t i = 0; i < scs_stmt_params.size(); i++) {
			v_stmts[i].hdrs = fail_hdrs[i];
		}

		// Check for FAILURE for payloads with invalid LOWER 4-bytes in string<var> - CONN 1
		check_execute(proxy_1, v_stmts, false);

		vector<stmt_params_t> v_stmts_2_inv { v_stmts_2 };

		for (size_t i = 0; i < scs_stmt_params_2.size(); i++) {
			v_stmts_2_inv[i].hdrs = fail_hdrs[i];
		}

		// Check for FAILURE for payloads with invalid LOWER 4-bytes in string<var> - CONN 2
		check_execute(proxy_2, v_stmts_2_inv, false);
		// Check for SUCCESS for payloads with invalid UPPER 4-bytes in string<var> - CONN 2
		check_execute(proxy_2, v_stmts_2, true);
	}

cleanup:
	MYSQL_QUERY_T(proxy_1, "ROLLBACK");
	MYSQL_QUERY_T(proxy_2, "ROLLBACK");

	MYSQL_QUERY_T(proxy_1, "DELETE FROM test.test_stmt_inv__large_col_1");
	MYSQL_QUERY_T(proxy_1, "DELETE FROM test.test_stmt_inv__large_col_2");

	for (const auto& sp : scs_stmt_params) {
		mysql_stmt_close(sp.second.stmt);
	}
	for (const auto& sp : scs_stmt_params_2) {
		mysql_stmt_close(sp.second.stmt);
	}

	mysql_close(proxy_1);
	mysql_close(proxy_2);
	mysql_close(admin);

	return exit_status();
}
