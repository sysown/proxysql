/**
 * Regression #6521: a query cancel for a session that is not running a query
 * must not leave cancel_query set on its backend. While it was set, BeforePoll
 * gave poll() a 0 ms timeout and the worker thread busy-polled: until the next
 * query for a session idle in a transaction, for the life of a fast-forward
 * session. ProxySQL's CPU is read through the admin system_cpu stats.
 */
#include "command_line.h"
#include "libpq-fe.h"
#include "tap.h"
#include "utils.h"
#include <cstdlib>
#include <string>
#include <unistd.h>

// A busy-polling worker thread shows as ~100% (one core); an idle ProxySQL stays far below.
static const int MAX_IDLE_CPU = 30;

static CommandLine cl;

static PGconn *connect(const char *host, int port, const char *user, const char *pass) {
	std::string s = "host=" + std::string(host) + " port=" + std::to_string(port) + " user=" + user +
					" password=" + pass + " sslmode=disable connect_timeout=5";
	PGconn *c = PQconnectdb(s.c_str());
	if (PQstatus(c) != CONNECTION_OK)
		BAIL_OUT("connect: %s", PQerrorMessage(c));
	return c;
}

static std::string value(PGconn *c, const std::string &q) {
	PGresult *r = PQexec(c, q.c_str());
	if (PQresultStatus(r) != PGRES_TUPLES_OK && PQresultStatus(r) != PGRES_COMMAND_OK)
		BAIL_OUT("query '%s': %s", q.c_str(), PQresultErrorMessage(r));
	std::string s = PQntuples(r) ? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return s;
}

// Sends a CancelRequest for the idle session behind c, then reads ProxySQL's CPU.
static void cancel_and_check_cpu(PGconn *c, const char *what) {
	PGcancel *cancel = PQgetCancel(c);
	char errbuf[256];
	ok(cancel && PQcancel(cancel, errbuf, sizeof(errbuf)) == 1, "PQcancel on %s succeeds", what);
	if (cancel)
		PQfreeCancel(cancel);
	double cpu = 0;
	if (get_proxysql_cpu_usage(cl, cpu, 5))
		BAIL_OUT("failed to read ProxySQL CPU usage");
	ok(cpu < MAX_IDLE_CPU, "ProxySQL CPU after cancelling %s stays below %d%%: %.1f%%", what, MAX_IDLE_CPU, cpu);
}

int main() {
	alarm(120);
	plan(5);
	if (cl.getEnv())
		return exit_status();
	PGconn *admin = connect(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password);
	const std::string user = cl.pgsql_username;

	// Idle inside a transaction: the backend stays attached and polled.
	PGconn *c = connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password);
	value(c, "BEGIN");
	value(c, "SELECT 1");
	cancel_and_check_cpu(c, "a session idle in a transaction");
	PGresult *r = PQexec(c, "SELECT 1");
	ok(PQresultStatus(r) == PGRES_TUPLES_OK, "the transaction still runs its next query");
	PQclear(r);
	value(c, "COMMIT");
	PQfinish(c);

	// Fast forward never acts on a cancel, so nothing would ever clear it.
	value(admin, "UPDATE pgsql_users SET fast_forward=1 WHERE username='" + user + "'");
	value(admin, "LOAD PGSQL USERS TO RUNTIME");
	c = connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password);
	value(c, "SELECT 1");
	cancel_and_check_cpu(c, "an idle fast-forward session");
	PQfinish(c);
	value(admin, "UPDATE pgsql_users SET fast_forward=0 WHERE username='" + user + "'");
	value(admin, "LOAD PGSQL USERS TO RUNTIME");

	PQfinish(admin);
	return exit_status();
}
