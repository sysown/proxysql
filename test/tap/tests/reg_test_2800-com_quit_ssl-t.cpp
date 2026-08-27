/**
 * @file reg_test_2800-com_quit_ssl-t.cpp
 * @brief Regression test for issue #2800 .
 *
 * ProxySQL doesn't use mysql_close() to close backend connections, because it
 * is blocking. Instead, MySQL_Connection::close_mysql() writes a COM_QUIT
 * packet on the socket and closes it.
 *
 * That packet used to be written in clear text even when the connection was
 * using TLS, corrupting the TLS stream. PR #5096 stopped writing it at all for
 * TLS connections, which is better, but it still leaves the backend logging
 *   Aborted connection NNN to db: ... (Got an error reading communication packets)
 * and incrementing 'Aborted_clients' for every connection ProxySQL closes.
 *
 * This test verifies that closing backend connections that use SSL does NOT
 * increment 'Aborted_clients' on the backend, exactly as it happens for the
 * connections that don't use SSL.
 *
 * The backend is queried directly - not through ProxySQL - for its global
 * status counters, using a single connection that is kept open for the whole
 * test so that it doesn't alter the counters being measured.
 * 'Ssl_accepts' is used to verify that the connections created during the SSL
 * phase were really using TLS, so that the test can't silently pass by not
 * using SSL at all.
 *
 * A dedicated hostgroup and a dedicated query rule are created, so that the
 * test doesn't depend on the topology or on the query rules of the infra it
 * runs against, and so that only the connections towards the backend we can
 * read the counters from are involved.
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

/* hostgroup and query rule created by this test */
const int TEST_HG = 2800;
const int TEST_RULE_ID = 2800;
/* the query routed to TEST_HG by the query rule created by this test */
const char* TEST_QUERY = "SELECT 2800";
/* number of connections to ProxySQL opened on each phase */
const int NCONN = 20;
/**
 * Minimum number of backend connections that each phase is expected to create
 * and close. It is way lower than NCONN because ProxySQL is free to reuse a
 * connection from the pool for more than one session: what matters is that
 * enough connections were closed for the assertions to be meaningful.
 */
const int MIN_CONNS = 5;

static int get_status_var(MYSQL* my, const char* var, long long* out) {
	std::string q = "SHOW GLOBAL STATUS LIKE '" + std::string(var) + "'";
	if (mysql_query(my, q.c_str())) {
		diag("'%s' failed: %s", q.c_str(), mysql_error(my));
		return -1;
	}
	MYSQL_RES* res = mysql_store_result(my);
	if (res == NULL) {
		diag("mysql_store_result() failed: %s", mysql_error(my));
		return -1;
	}
	int rc = -1;
	MYSQL_ROW row = mysql_fetch_row(res);
	if (row != NULL && row[1] != NULL) {
		*out = atoll(row[1]);
		rc = 0;
	} else {
		diag("Status variable '%s' not found", var);
	}
	mysql_free_result(res);
	return rc;
}

/**
 * @brief Number of backend connections successfully created towards TEST_HG
 *   since ProxySQL started.
 */
static int get_conn_ok(MYSQL* proxyadmin, long long* out) {
	std::string q = "SELECT IFNULL(SUM(ConnOK),0) FROM stats_mysql_connection_pool WHERE hostgroup="
		+ std::to_string(TEST_HG);
	if (mysql_query(proxyadmin, q.c_str())) {
		diag("'%s' failed: %s", q.c_str(), mysql_error(proxyadmin));
		return -1;
	}
	MYSQL_RES* res = mysql_store_result(proxyadmin);
	if (res == NULL) {
		diag("mysql_store_result() failed: %s", mysql_error(proxyadmin));
		return -1;
	}
	int rc = -1;
	MYSQL_ROW row = mysql_fetch_row(res);
	if (row != NULL && row[0] != NULL) {
		*out = atoll(row[0]);
		rc = 0;
	}
	mysql_free_result(res);
	return rc;
}

/**
 * @brief Opens NCONN connections to ProxySQL, each one creating and then
 *   releasing a backend connection towards TEST_HG .
 * @return The number of connections for which the query succeeded.
 */
static int create_and_close_backend_conns(const CommandLine& cl) {
	int oks = 0;

	for (int i = 0; i < NCONN; i++) {
		MYSQL* proxy = mysql_init(NULL);
		if (proxy == NULL) {
			diag("mysql_init() failed");
			break;
		}
		if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			diag("Failed to connect to ProxySQL: %s", mysql_error(proxy));
			mysql_close(proxy);
			break;
		}
		if (mysql_query(proxy, TEST_QUERY) == 0) {
			MYSQL_RES* res = mysql_store_result(proxy);
			if (res != NULL) {
				mysql_free_result(res);
			}
			oks++;
		} else {
			diag("Query '%s' failed: %s", TEST_QUERY, mysql_error(proxy));
		}
		mysql_close(proxy);
	}

	/* give ProxySQL the time to actually tear down the backend connections */
	usleep(500 * 1000);

	return oks;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv())
		return exit_status();

	plan(7);

	MYSQL* proxyadmin = mysql_init(NULL);
	if (!proxyadmin) {
		diag("mysql_init() failed");
		return exit_status();
	}
	if (!mysql_real_connect(proxyadmin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Failed to connect to ProxySQL Admin: %s", mysql_error(proxyadmin));
		return exit_status();
	}

	MYSQL* backend = mysql_init(NULL);
	if (!backend) {
		diag("mysql_init() failed");
		return exit_status();
	}
	if (!mysql_real_connect(backend, cl.mysql_host, cl.mysql_username, cl.mysql_password, NULL, cl.mysql_port, NULL, 0)) {
		diag("Failed to connect to backend %s:%d : %s", cl.mysql_host, cl.mysql_port, mysql_error(backend));
		return exit_status();
	}
	diag("Reading the status counters directly from backend %s:%d", cl.mysql_host, cl.mysql_port);

	/**
	 * - the monitor is disabled: monitoring connections are opened and closed
	 *   towards the very same backend, and they would add noise to
	 *   'Aborted_clients' .
	 * - 'connection_max_age_ms' and 'reset_connection_algorithm' make a backend
	 *   connection be destroyed - instead of being reset and returned to the
	 *   connection pool - as soon as the session is done with it.
	 * - 'connpoll_reset_queue_length=0' disables the asynchronous
	 *   COM_RESET_CONNECTION queue, which would otherwise recycle the very same
	 *   connections instead of closing them . See
	 *   MySQL_HostGroups_Manager::destroy_MyConn_from_pool() .
	 */
	MYSQL_QUERY(proxyadmin, "SET mysql-monitor_enabled='false'");
	MYSQL_QUERY(proxyadmin, "SET mysql-connection_max_age_ms=1");
	MYSQL_QUERY(proxyadmin, "SET mysql-reset_connection_algorithm=1");
	MYSQL_QUERY(proxyadmin, "SET mysql-connpoll_reset_queue_length=0");
	MYSQL_QUERY(proxyadmin, "LOAD MYSQL VARIABLES TO RUNTIME");

	/* route TEST_QUERY to a hostgroup holding only the backend we can inspect */
	{
		std::string q = "DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(TEST_HG);
		MYSQL_QUERY(proxyadmin, q.c_str());
		q = "INSERT INTO mysql_servers (hostgroup_id,hostname,port,use_ssl) VALUES ("
			+ std::to_string(TEST_HG) + ",'" + std::string(cl.mysql_host) + "',"
			+ std::to_string(cl.mysql_port) + ",0)";
		diag("Running query: %s", q.c_str());
		MYSQL_QUERY(proxyadmin, q.c_str());
		MYSQL_QUERY(proxyadmin, "LOAD MYSQL SERVERS TO RUNTIME");

		/**
		 * Every rule is removed: the rules loaded by the infra match '^SELECT'
		 * with 'apply=1' and a lower rule_id, so they would be applied before
		 * the one created here and TEST_QUERY would never reach TEST_HG .
		 * They are restored from disk at the end of the test.
		 */
		MYSQL_QUERY(proxyadmin, "DELETE FROM mysql_query_rules");
		q = "INSERT INTO mysql_query_rules (rule_id,active,match_pattern,destination_hostgroup,apply) VALUES ("
			+ std::to_string(TEST_RULE_ID) + ",1,'^" + std::string(TEST_QUERY) + "$',"
			+ std::to_string(TEST_HG) + ",1)";
		diag("Running query: %s", q.c_str());
		MYSQL_QUERY(proxyadmin, q.c_str());
		MYSQL_QUERY(proxyadmin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	}

	/* let the already established monitoring connections go away */
	sleep(2);

	long long aborted_before = 0, aborted_after = 0;
	long long ssl_accepts_before = 0, ssl_accepts_after = 0;
	long long conn_ok_before = 0, conn_ok_after = 0;

	/* ############################ phase 1: no SSL ############################ */

	if (get_status_var(backend, "Aborted_clients", &aborted_before)
		|| get_conn_ok(proxyadmin, &conn_ok_before)) {
		return exit_status();
	}

	int oks = create_and_close_backend_conns(cl);
	ok(oks == NCONN, "Non-SSL phase: %d out of %d queries succeeded", oks, NCONN);

	if (get_status_var(backend, "Aborted_clients", &aborted_after)
		|| get_conn_ok(proxyadmin, &conn_ok_after)) {
		return exit_status();
	}

	long long nossl_aborted = aborted_after - aborted_before;
	long long nossl_conns = conn_ok_after - conn_ok_before;

	/**
	 * Verify that the backend connections were really created and closed
	 * towards TEST_HG , this is what makes the counters read from the backend
	 * meaningful.
	 */
	ok(nossl_conns >= MIN_CONNS, "Non-SSL phase: hostgroup %d created at least %d backend connections. ConnOK delta: %lld",
		TEST_HG, MIN_CONNS, nossl_conns);
	ok(nossl_aborted == 0, "Non-SSL phase: 'Aborted_clients' didn't increase. Delta: %lld", nossl_aborted);

	/* ############################# phase 2: SSL ############################## */

	{
		std::string q = "UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id=" + std::to_string(TEST_HG);
		MYSQL_QUERY(proxyadmin, q.c_str());
		MYSQL_QUERY(proxyadmin, "LOAD MYSQL SERVERS TO RUNTIME");
	}
	sleep(1);

	if (get_status_var(backend, "Aborted_clients", &aborted_before)
		|| get_status_var(backend, "Ssl_accepts", &ssl_accepts_before)
		|| get_conn_ok(proxyadmin, &conn_ok_before)) {
		return exit_status();
	}

	oks = create_and_close_backend_conns(cl);
	ok(oks == NCONN, "SSL phase: %d out of %d queries succeeded", oks, NCONN);

	if (get_status_var(backend, "Aborted_clients", &aborted_after)
		|| get_status_var(backend, "Ssl_accepts", &ssl_accepts_after)
		|| get_conn_ok(proxyadmin, &conn_ok_after)) {
		return exit_status();
	}

	long long ssl_aborted = aborted_after - aborted_before;
	long long ssl_ssl_accepts = ssl_accepts_after - ssl_accepts_before;
	long long ssl_conns = conn_ok_after - conn_ok_before;

	ok(ssl_conns >= MIN_CONNS, "SSL phase: hostgroup %d created at least %d backend connections. ConnOK delta: %lld",
		TEST_HG, MIN_CONNS, ssl_conns);
	ok(ssl_ssl_accepts >= ssl_conns,
		"SSL phase: 'Ssl_accepts' increased at least as much as the backend connections created,"
		" they were really using TLS. Ssl_accepts delta: %lld , ConnOK delta: %lld",
		ssl_ssl_accepts, ssl_conns);

	/**
	 * This is the actual regression check for #2800 : if the COM_QUIT isn't
	 * sent through the TLS layer, the backend reports one aborted connection
	 * for each connection ProxySQL closed.
	 */
	ok(ssl_aborted == 0,
		"SSL phase: 'Aborted_clients' didn't increase. Delta: %lld (non-SSL phase delta was %lld)",
		ssl_aborted, nossl_aborted);

	/* restore the configuration */
	{
		std::string q = "DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(TEST_HG);
		mysql_query(proxyadmin, q.c_str());
		mysql_query(proxyadmin, "LOAD MYSQL SERVERS TO RUNTIME");
		mysql_query(proxyadmin, "LOAD MYSQL QUERY RULES FROM DISK");
		mysql_query(proxyadmin, "LOAD MYSQL QUERY RULES TO RUNTIME");
		mysql_query(proxyadmin, "LOAD MYSQL VARIABLES FROM DISK");
		mysql_query(proxyadmin, "LOAD MYSQL VARIABLES TO RUNTIME");
	}

	mysql_close(backend);
	mysql_close(proxyadmin);

	return exit_status();
}
