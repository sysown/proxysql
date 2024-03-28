#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

CommandLine cl;

struct transaction_param {
	struct next_transaction {
		std::string set_transaction_val;
		std::string exp_transaction_val;
	};

	std::string session_transaction_val;
	std::vector<next_transaction> next_transaction_val;
};

transaction_param next_trx_isolation_level_test[] = { 
		 {"REPEATABLE READ", {{"", "REPEATABLE READ"}, {"SERIALIZABLE", "SERIALIZABLE"},		 {"", "REPEATABLE READ"}}},
		 {"REPEATABLE READ", {{"", "REPEATABLE READ"}, {"READ UNCOMMITTED", "READ UNCOMMITTED"}, {"", "REPEATABLE READ"}}},
		 {"REPEATABLE READ", {{"", "REPEATABLE READ"}, {"READ COMMITTED", "READ COMMITTED"},	 {"", "REPEATABLE READ"}}},
		 {"SERIALIZABLE",	 {{"", "SERIALIZABLE"},	   {"REPEATABLE READ", "REPEATABLE READ"},   {"", "SERIALIZABLE"}}},
};

transaction_param next_trx_access_mode_test[] = { 
		 {"READ WRITE", {{"", "READ WRITE"}, {"READ ONLY",  "READ ONLY"},  {"", "READ WRITE"}}},
		 {"READ WRITE", {{"", "READ WRITE"}, {"READ WRITE", "READ WRITE"}, {"", "READ WRITE"}}},
		 {"READ ONLY",  {{"", "READ ONLY"},  {"READ ONLY",  "READ ONLY"},  {"", "READ ONLY"}}},
		 {"READ ONLY",  {{"", "READ ONLY"},  {"READ WRITE", "READ WRITE"}, {"", "READ ONLY"}}},
};

int check_transaction_isolation_level(MYSQL* mysql) {
	const std::string set_session_trx_isolation_level = "SET SESSION TRANSACTION ISOLATION LEVEL ";
	const std::string set_next_trx_isolation_level = "SET TRANSACTION ISOLATION LEVEL ";
	const std::string get_trx_isolation_level = "SELECT trx_isolation_level FROM information_schema.INNODB_TRX trx WHERE trx_mysql_thread_id=CONNECTION_ID();";
	const unsigned int test_size = sizeof(next_trx_isolation_level_test) / sizeof(transaction_param);

	for (unsigned int i = 0; i < test_size; i++) {
		const transaction_param& param = next_trx_isolation_level_test[i];

		if (param.session_transaction_val.empty() == false) {
			MYSQL_QUERY(mysql, (set_session_trx_isolation_level + param.session_transaction_val).c_str());
		}

		for (const auto& isolation_level : param.next_transaction_val) {
			if (isolation_level.set_transaction_val.empty() == false) {
				MYSQL_QUERY(mysql, (set_next_trx_isolation_level + isolation_level.set_transaction_val).c_str());
			}

			MYSQL_QUERY(mysql, "BEGIN");
			MYSQL_QUERY(mysql, "INSERT INTO sbtest1 (id) VALUES (NULL)");
			MYSQL_QUERY(mysql, get_trx_isolation_level.c_str());
			
			MYSQL_RES *res = mysql_store_result(mysql);
			MYSQL_ROW row;

			const unsigned long long num_rows = mysql_num_rows(res);
			ok(num_rows == 1, "check_transaction_isolation_level() -> mysql_num_rows(), expected: 1, actual: %llu", num_rows);
			while ((row = mysql_fetch_row(res))) {
				ok(strncmp(isolation_level.exp_transaction_val.c_str(), row[0], isolation_level.exp_transaction_val.size()) == 0, "check_transaction_isolation_level() -> row: expected: \"%s\", actual: \"%s\"", isolation_level.exp_transaction_val.c_str(), row[0]);
			}	
			mysql_free_result(res);
			MYSQL_QUERY(mysql, "ROLLBACK");
			sleep(1);
		}
	}

	return EXIT_SUCCESS;
}

int check_transaction_access_mode(MYSQL* mysql) {
	const char* access_mode_mapping[] = { "READ WRITE", "READ ONLY" };
	const std::string set_session_trx_access_mode = "SET SESSION TRANSACTION ";
	const std::string set_next_trx_access_mode = "SET TRANSACTION ";
	const std::string get_trx_access_mode = "SELECT trx_is_read_only FROM information_schema.INNODB_TRX trx WHERE trx_mysql_thread_id=CONNECTION_ID();";
	const unsigned int test_size = sizeof(next_trx_access_mode_test) / sizeof(transaction_param);

	for (unsigned int i = 0; i < test_size ; i++) {
		const transaction_param& param = next_trx_access_mode_test[i];

		if (param.session_transaction_val.empty() == false) {
			MYSQL_QUERY(mysql, (set_session_trx_access_mode + param.session_transaction_val).c_str());
		}

		for (const auto& access_mode : param.next_transaction_val) {
			if (access_mode.set_transaction_val.empty() == false) {
				MYSQL_QUERY(mysql, (set_next_trx_access_mode + access_mode.set_transaction_val).c_str());
			}

			MYSQL_QUERY(mysql, "BEGIN");
			MYSQL_QUERY(mysql, "SELECT COUNT(*) FROM sbtest1");
			mysql_free_result(mysql_store_result(mysql));

			MYSQL_QUERY(mysql, get_trx_access_mode.c_str());
			
			MYSQL_RES *res = mysql_store_result(mysql);
			MYSQL_ROW row;

			const unsigned long long num_rows = mysql_num_rows(res);
			ok(num_rows == 1, "check_transaction_access_mode() -> mysql_num_rows(), expected: 1, actual: %llu", num_rows);
			while ((row = mysql_fetch_row(res))) {
				const char* access_mode_str = access_mode_mapping[atoi(row[0])];
				ok(strncmp(access_mode.exp_transaction_val.c_str(), access_mode_str, access_mode.exp_transaction_val.size()) == 0, "check_transaction_access_mode() -> row: expected: \"%s\", actual: \"%s\"", access_mode.exp_transaction_val.c_str(), access_mode_str);
			}	
			mysql_free_result(res);
			MYSQL_QUERY(mysql, "ROLLBACK");
			sleep(1);
		}
	}
	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {

	plan(2 + 48);

	MYSQL* mysql = mysql_init(NULL);
	diag("Connecting: cl.root_username='%s' cl.use_ssl=%d cl.compression=%d", cl.root_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql, cl.root_host, cl.root_username, cl.root_password, NULL, cl.root_port, NULL, 0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql->net.compress, "Compression: (%d)", mysql->net.compress);
	}

	if (create_table_test_sbtest1(0,mysql)) {
		fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
		return exit_status();
	}

	diag("Waiting few seconds for replication...");
	sleep(2);
	MYSQL_QUERY(mysql, "USE test");

	if (check_transaction_isolation_level(mysql)) {
		fprintf(stderr, "check_transaction_isolation_level() failed\n");
		return exit_status();
	}
	if (check_transaction_access_mode(mysql)) {
		fprintf(stderr, "check_transaction_access_mode() failed\n");
		return exit_status();
	}

	mysql_close(mysql);
	return exit_status();
}
