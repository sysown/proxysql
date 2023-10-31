#include <algorithm>
#include <vector>
#include <string>
#include <stdio.h>
#include <iostream>
#include <random>

#include "mysql.h"
#include "mysqld_error.h"

#include "proxysql_utils.h"

#include "tap.h"
#include "command_line.h"

#include "json.hpp"

#include "MySQL_Protocol.h"

using namespace nlohmann;

using std::string;
using std::vector;

int check_arguments(int argc, char** argv) {
	int err_code = 0;

	if (argc == 2) {
		std::string query = argv[1];

		bool is_select = query.rfind("SELECT", 0) == 0;
		bool is_insert = query.rfind("INSERT", 0) == 0;
		bool is_update = query.rfind("UPDATE", 0) == 0;

		if (!(is_select | is_insert || is_update)) {
			std::cerr << "Error: Supplied query is not either ['SELECT'|'INSERT'|'UPDATE'].\r\n";
			err_code = -1;
		}
	} else {
		std::cerr << "Error: Invalid number of arguments.\r\n";
		err_code = -1;
	}

	return err_code;
}

void MySQL_result_to_JSON(MYSQL_RES* resultset, json& j_res) {
	int rows_count = mysql_num_rows(resultset);
	if (rows_count) {
		MYSQL_FIELD* field { nullptr };
		vector<string> field_names {};

		while((field = mysql_fetch_field(resultset))) {
			field_names.push_back(field->name);
		}

		MYSQL_ROW row;
		unsigned int num_fields = 0;

		num_fields = mysql_num_fields(resultset);
		while ((row = mysql_fetch_row(resultset))) {
			json j {};
			unsigned long* lengths { nullptr };
			lengths = mysql_fetch_lengths(resultset);

			for(unsigned int i = 0; i < num_fields; i++) {
				j[field_names[i]] = ( row[i] ? row[i] : "(null)" );
			}
			j_res.push_back(j);
		}
	} else {
		j_res = json::array();
	}
}

int main(int argc, char** argv) {
	CommandLine cl;
	int res_code { 0 };

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	int check_res = check_arguments(argc, argv);
	if (check_res) { return -1; }

	// Extract the query from the arguments
	std::string query = argv[1];

	MYSQL* proxy = mysql_init(NULL);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return -1;
	}

	#ifdef NON_EOF_SUPPORT
		std::string mdb_plugins_dir = std::string(cl.workdir) + "../deps/mariadb-connector-c";
		mysql_options(proxy, MYSQL_PLUGIN_DIR, mdb_plugins_dir.c_str());
	#else
		// Ensure that we make the connection with ProxySQL with 'DEPRECATED_EOF' support
		proxy->options.client_flag |= CLIENT_DEPRECATE_EOF;
	#endif

	bool eof_support = proxy->options.client_flag & (1UL << 24);

	// NOTE: This is just for debugging purposes when testing both executable versions `fwd_eof_ok_query` and
	// `fwd_eof_query` in isolation. Test `deprecate_eof_cache` is expecting a valid JSON as output.
	/*
	diag(
		"Testing 'TEXT PROTOCOL' with: { 'eof_support': %d, 'user': '%s', 'client_flags': %lu }",
		eof_support, cl.username, cl.client_flags
	);
	*/

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		std::string err_msg { "MySQL Error:" + std::string { mysql_error(proxy) } + " at line " + std::to_string(__LINE__) };
		std::cerr << "{ \"Code\": \"Err\", \"Result\": \"" <<  err_msg << "\" }";
		return -1;
	}

	int query_res = mysql_query(proxy, query.c_str());
	if (query_res != 0) {
		std::string err_msg { "MySQL Error:" + std::string { mysql_error(proxy) } + " at line " + std::to_string(__LINE__) };
		std::cerr << "{ \"Code\": \"Err\", \"Result\": \"" <<  err_msg << "\" }";
		return -1;
	}

	if (query.rfind("SELECT", 0) == 0) {
		MYSQL_RES* select_res = mysql_store_result(proxy);

		if (select_res != NULL) {
			json j_res {};
			MySQL_result_to_JSON(select_res, j_res);
			std::cout << "{ \"Code\": \"OK\", \"Result\": " << j_res.dump()
				  << ", \"Status\": " << proxy->server_status
				  << ", \"Warnings\": " << mysql_warning_count(proxy) 
				  << ", \"Line\": " <<  __LINE__
				  << " }";
		} else {
			std::string err_msg {
				"MySQL Error: " + std::string { mysql_error(proxy) }+ ""
			};
			std::cerr << "{ \"Code\": \"Err\", \"Result\": \"" <<  err_msg << "\" }";
			res_code = -1;
		}

		mysql_free_result(select_res);
	} else {
		std::string err_msg { "MySQL Error:" + std::string { mysql_error(proxy) }+ "" };
		std::cerr << "{ \"Code\": \"OK\", \"Result\": 0 }";
	}

	mysql_close(proxy);
	return res_code;
}
