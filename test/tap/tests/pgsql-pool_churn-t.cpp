#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static PGConnPtr mk() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static std::string scalar(PGconn* c, const char* q) {
	PGresult* r = PQexec(c, q);
	std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) ? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return v;
}

int main(int argc, char** argv) {
	if (cl.getEnv()) return exit_status();
	plan(3);

	// 1) Connection storm: open many short-lived connections; none should error out.
	bool all_ok = true;
	for (int i = 0; i < 100; ++i) {
		PGConnPtr c = mk();
		if (!c || PQstatus(c.get()) != CONNECTION_OK) { all_ok = false; break; }
		if (scalar(c.get(), "SELECT 1") != "1") { all_ok = false; break; }
	}
	ok(all_ok, "100 sequential short connections all succeed (no pool leak/exhaustion)");

	// 2) Session-state isolation across backend reuse.
	// Connection A sets a session GUC, then A is closed so its backend connection
	// is returned to ProxySQL's pool. Connection B is then opened fresh: if
	// ProxySQL reuses A's now-idle backend for B (which is exactly what pooling/
	// multiplexing is meant to do), B must NOT observe A's session state - a
	// reset/isolation step must have run on the backend before handing it to B.
	// Closing A first (rather than keeping A and B open concurrently) is what
	// makes this a real reuse test: with A still open, ProxySQL could simply hand
	// B an entirely different backend without ever exercising the reset path,
	// which would make the "B doesn't see A's state" assertion pass trivially
	// regardless of correctness. Closing A forces the backend to become eligible
	// for reuse before B connects.
	//
	// NB: application_name is deliberately excluded from ProxySQL's tracked
	// variables (see PgSQL_Variables::PgSQL_Variables() ignore_vars, in
	// lib/PgSQL_Variables.cpp) - ProxySQL owns application_name on the backend
	// connection for its own bookkeeping, so a client's SET application_name is
	// parsed but never forwarded/tracked. That makes it unsuitable here: it
	// would never round-trip regardless of pooling correctness. TimeZone *is* a
	// tracked variable (pgsql_tracked_variables[] in include/proxysql_structs.h)
	// that IS forwarded to, and reset on, the backend, so it actually exercises
	// the reuse/reset path we want to test.
	{
		PGConnPtr a = mk();
		PQclear(PQexec(a.get(), "SET TimeZone = 'America/New_York'"));
		std::string a_val = scalar(a.get(), "SHOW TimeZone");
		ok(a_val == "America/New_York", "connection A sees its own SET TimeZone");

		a.reset(); // close A, returning its backend to the pool

		PGConnPtr b = mk();
		std::string b_val = scalar(b.get(), "SHOW TimeZone");
		ok(b_val != "America/New_York", "connection B does NOT inherit A's session state (got '%s')", b_val.c_str());
	}

	return exit_status();
}
