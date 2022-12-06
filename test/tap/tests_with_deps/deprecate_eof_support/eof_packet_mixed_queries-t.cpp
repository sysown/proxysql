/**
 * @file eof_packet_mixed_queries-t.cpp
 * @brief This test performs a generic load in both TEXT and binary protocol. It can be cross-compiled between
 *   different versions of libmariadbclient with and without support for 'deprecate_eof'.
 * @details The test is compiled twice, once with support for 'DEPRECATE_EOF' and another time without. Since
 *   the test performs a generic traffic test, is used by `eof_cache_mixed_flags` to check multiple different
 *   configurations. These are:
 *     - 'mysql-enable_client_deprecate_eof'
 *     - 'mysql-enable_server_deprecate_eof'
 *     - Compression for frontend and backend connections.
 *     - Fast forward
 */

#include <algorithm>
#include <unistd.h>
#include <vector>
#include <string>
#include <string.h>
#include <stdio.h>

#include "mysql.h"
#include "mysql/mysqld_error.h"

#include <proxysql_utils.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::pair;
using std::string;
using std::vector;

std::vector<std::string> queries {
	"SELECT * FROM test.ok_packet_mariadb_test WHERE id=%d",
	"INSERT INTO test.ok_packet_mariadb_test (c, pad) VALUES ('%s', '%s')",
	"UPDATE test.ok_packet_mariadb_test SET c='%s', pad='%s' WHERE id=%d"
};

int create_testing_tables(MYSQL* mysql_server) {
	// Create the testing database
	mysql_query(mysql_server, "CREATE DATABASE IF NOT EXISTS test");
	mysql_query(mysql_server, "DROP TABLE IF EXISTS test.ok_packet_mariadb_test");

	mysql_query(
		mysql_server,
		"CREATE TABLE IF NOT EXISTS test.ok_packet_mariadb_test ("
		"  id INTEGER NOT NULL AUTO_INCREMENT,"
		"  c varchar(255),"
		"  pad CHAR(60),"
		"  PRIMARY KEY (id)"
		")"
	);

	return mysql_errno(mysql_server);
}

std::vector<std::string> stmt_queries {
	"SELECT id,c,pad FROM test.stmt_ok_packet_mariadb_test WHERE id=?",
	"INSERT INTO test.stmt_ok_packet_mariadb_test (c, pad) VALUES (?, ?)",
	"UPDATE test.stmt_ok_packet_mariadb_test SET c=?, pad=? WHERE id=?"
};

int create_stmt_testing_tables(MYSQL* mysql_server) {
	// Create the testing database
	mysql_query(mysql_server, "CREATE DATABASE IF NOT EXISTS test");
	mysql_query(mysql_server, "DROP TABLE IF EXISTS test.stmt_ok_packet_mariadb_test");

	mysql_query(
		mysql_server,
		"CREATE TABLE IF NOT EXISTS test.stmt_ok_packet_mariadb_test ("
		"  id INTEGER NOT NULL AUTO_INCREMENT,"
		"  c varchar(255),"
		"  pad CHAR(60),"
		"  PRIMARY KEY (id)"
		")"
	);

	return mysql_errno(mysql_server);
}

pair<uint32_t,string> perform_stmt_insert_query(
	MYSQL* mysql_server, MYSQL_STMT* stmti, vector<pair<string,string>>& stored_pairs
) {
	string err_msg {};

	const string rnd_c = random_string(rand() % 80);
	const string rnd_pad = random_string(rand() % 15);

	string insert_query {};

	// Store the random generated strings
	stored_pairs.push_back(pair<string, string>{rnd_c, rnd_pad});

	uint64_t c_length = rnd_c.size();
	uint64_t pad_length = rnd_pad.size();

	MYSQL_BIND bindsi[2];
	memset(bindsi, 0, sizeof(bindsi));

	bindsi[0].buffer_type = MYSQL_TYPE_VAR_STRING;
	bindsi[0].buffer = const_cast<char*>(rnd_c.c_str());
	bindsi[0].buffer_length = rnd_c.size();
	bindsi[0].is_null = 0;
	bindsi[0].length = &c_length;

	bindsi[1].buffer_type = MYSQL_TYPE_VAR_STRING;
	bindsi[1].buffer = const_cast<char*>(rnd_pad.c_str());
	bindsi[1].buffer_length = rnd_pad.size();
	bindsi[1].is_null = 0;
	bindsi[1].length = &pad_length;

	if (mysql_stmt_bind_param(stmti, bindsi)) {
		string_format("'mysql_stmt_bind_param' at line %d failed: %s", err_msg, __LINE__, mysql_stmt_error(stmti));
		return { EXIT_FAILURE, err_msg };
	}

	if (mysql_stmt_execute(stmti)) {
		string_format("'mysql_stmt_execute' at line %d failed: %s", err_msg, __LINE__, mysql_stmt_error(stmti));
		return { EXIT_FAILURE, err_msg };
	} else {
		return { EXIT_SUCCESS, "" };
	}
}

pair<uint32_t,string> perform_stmt_select_query(
	MYSQL* mysql_server, MYSQL_STMT* stmts, const vector<pair<string,string>>& stored_pairs, uint32_t id
) {
	string err_msg {};

	// select binds
	MYSQL_BIND p_binds[1];
	MYSQL_BIND r_binds[3];

	// result values
	char is_null[3];
	uint64_t length[3];
	char error[3];

	// result buffers
	char b_c[255] = { 0 };
	char b_pad[60] = { 0 };
	uint32_t b_id = 0;

	memset(p_binds, 0, sizeof(p_binds));
	memset(r_binds, 0, sizeof(r_binds));

	p_binds[0].buffer_type = MYSQL_TYPE_LONG;
	p_binds[0].buffer = reinterpret_cast<char*>(&id);
	p_binds[0].is_null = 0;
	p_binds[0].length = 0;

	if (mysql_stmt_bind_param(stmts, p_binds)) {
		string_format("'mysql_stmt_bind_param' at line %d failed: %s", err_msg, __LINE__, mysql_stmt_error(stmts));
		return { EXIT_FAILURE, err_msg };
	}

	int s_err = mysql_stmt_execute(stmts);
	if (s_err != EXIT_SUCCESS) {
		string_format("'mysql_stmt_execute' at line %d failed: %s", err_msg, __LINE__, mysql_stmt_error(stmts));
		return { EXIT_FAILURE, err_msg };
	}

	/* id COLUMN */
	r_binds[0].buffer_type= MYSQL_TYPE_LONG;
	r_binds[0].buffer= reinterpret_cast<char*>(&b_id);
	r_binds[0].is_null= &is_null[0];
	r_binds[0].length= &length[0];
	r_binds[0].error= &error[0];

	/* c COLUMN */
	r_binds[1].buffer_type= MYSQL_TYPE_STRING;
	r_binds[1].buffer= b_c;
	r_binds[1].buffer_length= 255;
	r_binds[1].is_null= &is_null[1];
	r_binds[1].length= &length[1];
	r_binds[1].error= &error[1];

	/* pad COLUMN */
	r_binds[2].buffer_type= MYSQL_TYPE_STRING;
	r_binds[2].buffer= b_pad;
	r_binds[2].buffer_length= 60;
	r_binds[2].is_null= &is_null[2];
	r_binds[2].length= &length[2];
	r_binds[2].error= &error[2];

	s_err = mysql_stmt_bind_result(stmts, r_binds);
	if (s_err != EXIT_SUCCESS) {
		string_format("'mysql_stmt_bind_result' at line %d failed: %s", err_msg, __LINE__, mysql_stmt_error(stmts));
		return { EXIT_FAILURE, err_msg };
	}

	if (mysql_stmt_store_result(stmts) || mysql_errno(mysql_server) != EXIT_SUCCESS) {
		string_format("'mysql_stmt_store_result' at line %d failed: %s", err_msg, __LINE__, mysql_stmt_error(stmts));
		return { EXIT_FAILURE, err_msg };
	}

	s_err = mysql_stmt_fetch(stmts);
	if (s_err != EXIT_SUCCESS) {
		string_format("'mysql_stmt_fetch' at line %d failed: %s", err_msg, __LINE__, mysql_stmt_error(stmts));
		return { EXIT_FAILURE, err_msg };
	}

	bool same_c = stored_pairs[id].first == b_c;
	bool same_pad = stored_pairs[id].second == b_pad;

	if (same_c == false || same_pad == false) {
		string_format(
			"Received 'c' and 'pad' matches expected values. 'c': (Act: %s, Exp: %s), 'pad': (Act: %s, Exp: %s)",
			err_msg, b_c, stored_pairs[id].first.c_str(), b_pad, stored_pairs[id].second.c_str()
		);
		return { EXIT_FAILURE, err_msg };
	}

	return { EXIT_SUCCESS, "" };
}


pair<uint32_t,string> perform_select_query(
	MYSQL* mysql_server, const vector<pair<string,string>>& stored_pairs, uint32_t id
) {
	const std::string& t_select_query = queries[0];
	std::string select_query {};
	string_format(t_select_query, select_query, id);

	MYSQL_RES* select_res = nullptr;
	string err_msg {};

	int s_res = mysql_query(mysql_server, select_query.c_str());
	if (s_res != 0) {
		string_format(
			"Select query failed. ErrCode: %d, ErrMsg: %s", err_msg,
			mysql_errno(mysql_server), mysql_error(mysql_server)
		);
		goto cleanup;
	}

	{
		// Check that the SELECT resultset isn't illformed
		select_res = mysql_store_result(mysql_server);
		if (select_res == nullptr || mysql_errno(mysql_server) != EXIT_SUCCESS) {
			string_format("'mysql_store_result' at line %d failed: %s", err_msg, __LINE__, mysql_error(mysql_server));
			goto cleanup;
		}

		int field_count = mysql_field_count(mysql_server);
		int row_count = mysql_num_rows(select_res);

		if (field_count != 3 || row_count != 1) {
			string_format(
				"Received resulset should have: 'field_count': (Act: %d, Exp: 3), 'row_count': (Act: %d, Exp: 1)",
				err_msg, field_count, row_count
			);
			goto cleanup;
		}

		MYSQL_ROW row = mysql_fetch_row(select_res);
		bool same_c = stored_pairs[id].first == row[1];
		bool same_pad = stored_pairs[id].second == row[2];

		if (same_c == false || same_pad == false) {
			const string t_select_err_str {
				"Received 'c' and 'pad' matches expected values."
				" ('c': %s) == ('exp_c': %s), ('pad': %s) == ('exp_pad': %s)",
			};
			string_format(
				t_select_err_str, err_msg, row[1], stored_pairs[id].first.c_str(),
				row[2], stored_pairs[id].second.c_str()
			);
			goto cleanup;
		}
	}

cleanup:
	mysql_free_result(select_res);

	int err_code = err_msg.empty() == true ? EXIT_SUCCESS : EXIT_FAILURE;
	return { err_code, err_msg };
}

pair<uint32_t,string> perform_stmt_update_query(
	MYSQL* mysql_server, MYSQL_STMT* stmtu, vector<pair<string,string>>& stored_pairs, uint32_t id
) {
	string err_msg {};

	MYSQL_BIND bindsu[3];
	memset(bindsu, 0, sizeof(bindsu));

	std::string rnd_c = random_string(rand() % 100);
	std::string rnd_pad = random_string(rand() % 60);

	// Store the new random generated strings
	stored_pairs[id].first = rnd_c;
	stored_pairs[id].second = rnd_pad;

	uint64_t c_length = rnd_c.size();
	uint64_t pad_length = rnd_pad.size();

	bindsu[0].buffer_type = MYSQL_TYPE_VAR_STRING;
	bindsu[0].buffer = const_cast<char*>(rnd_c.c_str());
	bindsu[0].buffer_length = rnd_c.size();
	bindsu[0].is_null = 0;
	bindsu[0].length = &c_length;

	bindsu[1].buffer_type = MYSQL_TYPE_VAR_STRING;
	bindsu[1].buffer = const_cast<char*>(rnd_pad.c_str());
	bindsu[1].buffer_length = rnd_pad.size();
	bindsu[1].is_null = 0;
	bindsu[1].length = &pad_length;

	bindsu[2].buffer_type = MYSQL_TYPE_LONG;
	bindsu[2].buffer = reinterpret_cast<char*>(&id);
	bindsu[2].is_null = 0;
	bindsu[2].length = 0;

	if (mysql_stmt_bind_param(stmtu, bindsu)) {
		string_format("'mysql_stmt_bind_param' at line %d failed: %s", err_msg, __LINE__, mysql_stmt_error(stmtu));
		return { EXIT_FAILURE, err_msg };
	}

	if (mysql_stmt_execute(stmtu)) {
		string_format("'mysql_stmt_execute' at line %d failed: %s", err_msg, __LINE__, mysql_stmt_error(stmtu));
		return { EXIT_FAILURE, err_msg };
	} else {
		return { EXIT_SUCCESS, err_msg };
	}
}

pair<uint32_t,string> perform_update_query(
	MYSQL* mysql_server, vector<pair<string,string>> stored_pairs, uint32_t id
) {
	std::string rnd_c = random_string(rand() % 100);
	std::string rnd_pad = random_string(rand() % 60);

	// Store the new random generated strings
	stored_pairs[id].first = rnd_c;
	stored_pairs[id].second = rnd_pad;

	const std::string& t_update_query = queries[2];
	std::string update_query {};

	string_format(t_update_query, update_query, rnd_c.c_str(), rnd_pad.c_str(), id);
	int u_res = mysql_query(mysql_server, update_query.c_str());
	string update_err_str {};

	if (u_res != EXIT_SUCCESS) {
		const string t_update_err_str { "Update queries should be executed correctly. ErrCode: %d, ErrMsg: %s" };
		string_format(t_update_err_str, update_err_str, mysql_errno(mysql_server), mysql_error(mysql_server));
	}

	return { u_res, update_err_str };
}

int test_target_stmt_queries(MYSQL* proxy) {
	int c_err = create_stmt_testing_tables(proxy);
	ok(c_err == 0, "Table creation should succeed. ErrCode: %d", c_err);

	if (c_err != 0) {
		std::string error = mysql_error(proxy);
		diag("Table creation failed with error: '%s'", error.c_str());

		return EXIT_FAILURE;
	}

	uint32_t c_operations = 500;
	vector<pair<string, string>> stored_pairs {};
	std::string pad {};
	std::string c {};

	// Include one initial null element to make index match
	stored_pairs.push_back(pair<string, string>{"", ""});
	srand(time(NULL));

	MYSQL_STMT* stmti = mysql_stmt_init(proxy);
	if (mysql_stmt_prepare(stmti, stmt_queries[1].c_str(), stmt_queries[1].size())) {
		diag("'mysql_stmt_prepare' failed with error: '%s'", mysql_stmt_error(stmti));
		return EXIT_FAILURE;
	}

	pair<uint32_t,string> op_res {};

	MYSQL_BIND bindsi[2];
	memset(bindsi, 0, sizeof(bindsi));

	for (auto i = 0; i < c_operations; i++) {
		op_res = perform_stmt_insert_query(proxy, stmti, stored_pairs);
		if (op_res.first != EXIT_SUCCESS) { break; }
	}

	mysql_stmt_close(stmti);

	if (op_res.first == EXIT_SUCCESS) {
		MYSQL_STMT* stmts = mysql_stmt_init(proxy);

		if (mysql_stmt_prepare(stmts, stmt_queries[0].c_str(), stmt_queries[0].size())) {
			diag("'mysql_stmt_prepare' at line %d failed: %s", __LINE__, mysql_stmt_error(stmts));
			return EXIT_FAILURE;
		}

		MYSQL_STMT* stmtu = mysql_stmt_init(proxy);
		if (mysql_stmt_prepare(stmtu, stmt_queries[2].c_str(), stmt_queries[2].size())) {
			diag("'mysql_stmt_prepare' at line %d failed: %s", __LINE__, mysql_stmt_error(stmtu));
			return EXIT_FAILURE;
		}

		for (auto id = 1; id < c_operations; id++) {
			int64_t op = rand() % 2;

			if (op == 0) { // Do a random SELECT
				op_res = perform_stmt_select_query(proxy, stmts, stored_pairs, id);
				if (op_res.first != EXIT_SUCCESS) { break; }
			} else { // Do a random UPDATE
				op_res = perform_stmt_update_query(proxy, stmtu, stored_pairs, id);
				if (op_res.first != EXIT_SUCCESS) { break; }
			}
		}

		mysql_stmt_close(stmts);
		mysql_stmt_close(stmtu);
	}

	ok(
		op_res.first == EXIT_SUCCESS, "All 'INSERT/SELECT/UPDATE' operations should succeed: '%s'",
		op_res.second.c_str()
	);

	return !(op_res.first == EXIT_SUCCESS);
}

int test_target_queries(MYSQL* proxy) {
	int c_err = create_testing_tables(proxy);
	ok(c_err == 0, "Table creation should succeed. ErrCode: %d", c_err);

	if (c_err) {
		std::string error = mysql_error(proxy);
		diag("MySQL Error: '%s'", error.c_str());
		return EXIT_FAILURE;
	}

	uint32_t c_operations = 500;
	vector<pair<string, string>> stored_pairs {};
	std::string pad {};
	std::string c {};

	// Include one initial null element to make index match
	stored_pairs.push_back(pair<string, string>{"", ""});
	srand(time(NULL));

	string insert_error {};
	uint32_t i_err = 0;
	string i_err_str {};

	for (auto i = 0; i < c_operations; i++) {
		const string rnd_c = random_string(rand() % 80);
		const string rnd_pad = random_string(rand() % 15);
		const string& t_insert_query = queries[1];
		string insert_query {};

		// Store the random generated strings
		stored_pairs.push_back(pair<string, string>{rnd_c, rnd_pad});

		// Execute the INSERT queries
		string_format(t_insert_query, insert_query, rnd_c.c_str(), rnd_pad.c_str());
		int i_res = mysql_query(proxy, insert_query.c_str());
		i_err = mysql_errno(proxy);

		if (i_err != 0) {
			i_err_str = mysql_error(proxy);
			break;
		}
	}

	ok(i_err == 0, "Insert queries should be executed correctly. ErrCode: %d, ErrMsg: %s", i_err, i_err_str.c_str());
	if (i_err != 0) {
		return EXIT_FAILURE;
	}

	pair<uint32_t,string> op_res {};

	for (auto id = 1; id < c_operations; id++) {
		int64_t op = rand() % 2;

		if (op == 0) { // Do a random SELECT
			op_res = perform_select_query(proxy, stored_pairs, id);
			if (op_res.first != EXIT_SUCCESS) { break; }
		} else { // Do a random UPDATE
			op_res = perform_update_query(proxy, stored_pairs, id);
			if (op_res.first != EXIT_SUCCESS) { break; }
		}
	}

	ok(
		op_res.first == EXIT_SUCCESS, "All 'INSERT/SELECT/UPDATE' operations should succeed: '%s'",
		op_res.second.c_str()
	);

	return !(op_res.first == EXIT_SUCCESS);
}

// NOTE: Test hardcoded to hostgroup '0'
const uint32_t HG_ID = 0;

int main(int argc, char** argv) {
	CommandLine cl;

	plan(
		3 + // TEXT protocol checks
		2 // Binary protocol checks
	);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// Change default query rules to avoid replication issues
	MYSQL_QUERY(admin, "UPDATE mysql_query_rules SET destination_hostgroup=0 WHERE rule_id=2");
	MYSQL_QUERY(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	MYSQL* proxy = mysql_init(NULL);
	// Initialize connections
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	#ifdef NON_EOF_SUPPORT
		std::string mdb_plugins_dir = std::string(cl.workdir) + "../deps/mariadb-connector-c";
		mysql_options(proxy, MYSQL_PLUGIN_DIR, mdb_plugins_dir.c_str());
	#else
		// Ensure that we make the connection with ProxySQL with 'DEPRECATED_EOF' support
		proxy->options.client_flag |= CLIENT_DEPRECATE_EOF;
	#endif

	bool eof_support = proxy->options.client_flag & (1UL << 24);

	// Perform the connection
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, cl.client_flags)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	diag(
		"Testing 'TEXT PROTOCOL' with: { 'eof_support': %d, 'user': '%s', 'client_flags': %lu }",
		eof_support, cl.username, cl.client_flags
	);
	int rc = test_target_queries(proxy);
	if (rc) {
		diag("'TEXT PROTOCOL' queries failed to be executed, aborting further testing");
		mysql_close(proxy);
		goto cleanup;
	}

	diag(
		"Testing 'BINARY PROTOCOL' with: { 'eof_support': %d, 'user': '%s', 'client_flags': %lu }",
		eof_support, cl.username, cl.client_flags
	);
	rc = test_target_stmt_queries(proxy);
	if (rc) {
		diag("'BINARY PROTOCOL' queries failed to be executed, aborting further testing");
		mysql_close(proxy);
		goto cleanup;
	}

	mysql_close(proxy);

cleanup:

	// Recover default query rules
	MYSQL_QUERY(admin, "UPDATE mysql_query_rules SET destination_hostgroup=0 WHERE rule_id=2");
	MYSQL_QUERY(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	mysql_close(admin);

	return exit_status();
}
