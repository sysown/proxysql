#include <string>
#include <sstream>
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

static std::string sqlstate_of(PGresult* r) {
	const char* s = PQresultErrorField(r, PG_DIAG_SQLSTATE);
	return s ? s : "";
}

int main(int argc, char** argv) {
	if (cl.getEnv()) return exit_status();
	plan(4);

	PGConnPtr c = mk();
	ok(c && PQstatus(c.get()) == CONNECTION_OK, "connected for listen/notify contract");

	// LISTEN over simple protocol -> 0A000 feature_not_supported (libpq path).
	PGresult* r = PQexec(c.get(), "LISTEN chan1");
	ok(PQresultStatus(r) == PGRES_FATAL_ERROR && sqlstate_of(r) == "0A000",
	   "simple LISTEN rejected with 0A000 (got status=%d sqlstate=%s)",
	   PQresultStatus(r), sqlstate_of(r).c_str());
	PQclear(r);

	// LISTEN over extended protocol (PQexecParams uses Parse/Bind/Execute) -> same 0A000.
	r = PQexecParams(c.get(), "LISTEN chan2", 0, NULL, NULL, NULL, NULL, 0);
	ok(PQresultStatus(r) == PGRES_FATAL_ERROR && sqlstate_of(r) == "0A000",
	   "extended LISTEN rejected with 0A000 (got sqlstate=%s)", sqlstate_of(r).c_str());
	PQclear(r);

	// NOTIFY as a plain query completes cleanly and the connection stays usable.
	PGConnPtr c2 = mk();
	PGresult* rn = PQexec(c2.get(), "NOTIFY chan1, 'hello'");
	bool notify_ok = (PQresultStatus(rn) == PGRES_COMMAND_OK);
	PQclear(rn);
	PGresult* rq = PQexec(c2.get(), "SELECT 1");
	bool still_usable = (PQresultStatus(rq) == PGRES_TUPLES_OK);
	PQclear(rq);
	ok(notify_ok && still_usable, "NOTIFY completes cleanly and connection remains usable");

	return exit_status();
}
