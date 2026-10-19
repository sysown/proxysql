/**
 * @file reg_test_stmt_error_autocommit0_rollback-t.cpp
 * @brief Verifies that a failed COM_STMT_EXECUTE keeps the backend connection attached to the session
 *   when the transaction status is unknown, and that the following 'ROLLBACK' reaches the backend.
 * @details With 'autocommit=0' and a server-side prepared statement failing with a server error
 *   (e.g. 1062) as the first statement of the transaction, the backend never reports
 *   'SERVER_STATUS_IN_TRANS' (an ERR packet carries no status flags), yet MySQL keeps the transaction
 *   open with the locks taken by the failed statement. 'mysql_stmt_free_result()' clears the
 *   connection-level error, and ProxySQL used to recompute the 'unknown transaction status' from it after
 *   freeing the statement result: the backend was returned to the connection pool, and the client's
 *   'ROLLBACK' was answered locally ('Com_rollback_filtered'), leaving the transaction open on a pooled
 *   backend connection.
 *
 *   For each of the text and binary protocols the test:
 *    1. Runs 'SET autocommit=0' and a duplicate-key 'INSERT'.
 *    2. Checks via 'PROXYSQL INTERNAL SESSION' that the backend is still attached to the session.
 *    3. Runs 'ROLLBACK' and checks that 'Com_rollback_filtered' did not increase.
 *    4. Checks directly on the backend that its connection has no open transaction left.
 */

#include <cstring>
#include <string>
#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"
#include "json.hpp"

using std::string;
using nlohmann::json;

const char* TABLE { "test.reg_test_stmt_error_autocommit0_rollback" };

struct backend_t {
	string host {};
	int port { 0 };
	unsigned long thread_id { 0 };
};

int get_stat(MYSQL* admin, const char* name, long long& value) {
	const string q { string("SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='") + name + "'" };
	if (mysql_query(admin, q.c_str())) {
		diag("Query '%s' failed: %s", q.c_str(), mysql_error(admin));
		return EXIT_FAILURE;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
	int rc = EXIT_FAILURE;
	if (row && row[0]) {
		value = std::stoll(row[0]);
		rc = EXIT_SUCCESS;
	}
	mysql_free_result(res);
	return rc;
}

/**
 * @brief Returns the number of backend connections attached to the session, and the first one's details.
 */
size_t attached_backends(MYSQL* proxy, backend_t& backend) {
	json j_session = fetch_internal_session(proxy, false);
	size_t n = 0;
	if (j_session.contains("backends")) {
		for (const auto& b : j_session["backends"]) {
			if (b.contains("conn") && b["conn"].contains("mysql")) {
				if (n == 0) {
					const json& m = b["conn"]["mysql"];
					backend.host = m.value("host", "");
					backend.port = m.value("port", 0);
					backend.thread_id = m.value("thread_id", 0UL);
				}
				n++;
			}
		}
	}
	return n;
}

/**
 * @brief Returns the number of open InnoDB transactions of the supplied backend connection, or -1 on error.
 */
int backend_open_trxs(const CommandLine& cl, const backend_t& backend) {
	MYSQL* mysql = mysql_init(NULL);
	if (!mysql_real_connect(
		mysql, backend.host.c_str(), cl.mysql_username, cl.mysql_password, NULL, backend.port, NULL, 0
	)) {
		diag("Failed to connect to backend %s:%d: %s", backend.host.c_str(), backend.port, mysql_error(mysql));
		mysql_close(mysql);
		return -1;
	}
	// 'information_schema.innodb_trx' is served from a cache refreshed at most every 100ms
	usleep(200 * 1000);
	const string q {
		"SELECT COUNT(*) FROM information_schema.innodb_trx WHERE trx_mysql_thread_id=" +
		std::to_string(backend.thread_id)
	};
	int n = -1;
	if (mysql_query(mysql, q.c_str()) == 0) {
		MYSQL_RES* res = mysql_store_result(mysql);
		MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
		if (row && row[0]) { n = atoi(row[0]); }
		mysql_free_result(res);
	} else {
		diag("Query '%s' failed: %s", q.c_str(), mysql_error(mysql));
	}
	mysql_close(mysql);
	return n;
}

int failing_insert(MYSQL* proxy, bool binary_protocol) {
	const string query { string("INSERT INTO ") + TABLE + " (u) VALUES (1)" };

	if (!binary_protocol) {
		if (mysql_query(proxy, query.c_str()) == 0) {
			diag("Text 'INSERT' unexpectedly succeeded");
			return -1;
		}
		return mysql_errno(proxy);
	}

	MYSQL_STMT* stmt = mysql_stmt_init(proxy);
	if (!stmt) {
		diag("mysql_stmt_init() failed: %s", mysql_error(proxy));
		return -1;
	}
	if (mysql_stmt_prepare(stmt, query.c_str(), query.size())) {
		diag("mysql_stmt_prepare() failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return -1;
	}
	int err = -1;
	if (mysql_stmt_execute(stmt)) {
		err = mysql_stmt_errno(stmt);
	} else {
		diag("Binary 'INSERT' unexpectedly succeeded");
	}
	mysql_stmt_close(stmt);
	return err;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(2 * 4);

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("File %s, line %d, Error: %s", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY(admin, "SET mysql-autocommit_false_is_transaction='false'");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL* setup = mysql_init(NULL);
	if (!mysql_real_connect(setup, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("File %s, line %d, Error: %s", __FILE__, __LINE__, mysql_error(setup));
		return EXIT_FAILURE;
	}
	MYSQL_QUERY(setup, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(setup, (string("DROP TABLE IF EXISTS ") + TABLE).c_str());
	MYSQL_QUERY(setup,
		(string("CREATE TABLE ") + TABLE +
		" (id BIGINT AUTO_INCREMENT PRIMARY KEY, u BIGINT NOT NULL, UNIQUE KEY uk_test_u (u)) ENGINE=InnoDB").c_str()
	);
	MYSQL_QUERY(setup, (string("INSERT INTO ") + TABLE + " (u) VALUES (1)").c_str());

	for (const bool binary_protocol : { false, true }) {
		const char* proto = binary_protocol ? "binary" : "text";

		MYSQL* proxy = mysql_init(NULL);
		if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			diag("File %s, line %d, Error: %s", __FILE__, __LINE__, mysql_error(proxy));
			return EXIT_FAILURE;
		}

		MYSQL_QUERY(proxy, "SET autocommit=0");
		const int err = failing_insert(proxy, binary_protocol);
		ok(err == ER_DUP_ENTRY, "Protocol '%s': 'INSERT' failed with duplicate key   err=%d", proto, err);

		backend_t backend {};
		const size_t backends = attached_backends(proxy, backend);
		ok(backends == 1,
			"Protocol '%s': backend stays attached after the failed 'INSERT'   backends=%zu backend=%s:%d thread_id=%lu",
			proto, backends, backend.host.c_str(), backend.port, backend.thread_id);

		long long filtered_before = 0, filtered_after = 0;
		if (get_stat(admin, "Com_rollback_filtered", filtered_before)) { return EXIT_FAILURE; }
		MYSQL_QUERY(proxy, "ROLLBACK");
		if (get_stat(admin, "Com_rollback_filtered", filtered_after)) { return EXIT_FAILURE; }
		ok(filtered_after == filtered_before,
			"Protocol '%s': 'ROLLBACK' is forwarded to the backend   Com_rollback_filtered before=%lld after=%lld",
			proto, filtered_before, filtered_after);

		if (backends == 1) {
			const int open_trxs = backend_open_trxs(cl, backend);
			ok(open_trxs == 0,
				"Protocol '%s': no transaction left open on the backend connection   thread_id=%lu open_trxs=%d",
				proto, backend.thread_id, open_trxs);
		} else {
			ok(false, "Protocol '%s': backend connection unknown, its transaction state can't be checked", proto);
		}

		MYSQL_QUERY(proxy, "SET autocommit=1");
		mysql_close(proxy);
	}

	// The table isn't dropped: without the fix, the stranded transaction holds a metadata lock on it
	mysql_close(setup);
	mysql_close(admin);

	return exit_status();
}
