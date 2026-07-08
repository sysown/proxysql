#include <string>
#include <sstream>
#include "pg_lite_client.h"
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static PGConnPtr backend_conn() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
       << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
       << " dbname=" << cl.pgsql_username << " sslmode=disable";
    PGconn* c = PQconnectdb(ss.str().c_str());
    return PGConnPtr(c, &PQfinish);
}

// Extended-protocol portal suspension: Execute with maxRows=2 over a 5-row result.
//
// NOTE: the statement bound here has 0 parameters. A naive
// bindStatementSingleFormat("", "", {}, 0, {0}, false) would send a Bind message
// with num_param_formats=1, num_params=0, which trips a real ProxySQL bug
// (Task 4 finding: PgSQL_Connection.cpp's stmt_execute_start() rejects this with
// "Invalid param format count", even though the PG protocol spec and real
// PostgreSQL both accept num_param_formats==1 unconditionally). We avoid the bug
// here (rather than re-proving it) by using bindStatementEx with an EMPTY
// paramFormats array (num_param_formats=0), which is the protocol-correct way to
// bind a parameterless statement.
static bool portal_suspends_at_2() {
    std::vector<std::string> trace; // message-type trace, dumped only on failure
    try {
        PgConnection conn(2000);
        conn.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
        conn.prepareStatement("", "SELECT g FROM generate_series(1,5) g", false, {});
        conn.bindStatementEx("", "", {} /*params*/, {} /*paramFormats EMPTY*/, {} /*resultFormats*/, false);
        conn.executePortal("", 2, true);   // maxRows=2 -> expect 2 DataRows then PortalSuspended
        char type; std::vector<uint8_t> buf; int rows = 0; bool suspended = false;
        while (true) {
            conn.readMessage(type, buf);
            trace.push_back(std::string(1, type) + "(len=" + std::to_string(buf.size()) + ")");
            if (type == PgConnection::DATA_ROW) rows++;
            else if (type == PgConnection::PORTAL_SUSPENDED) { suspended = true; }
            else if (type == PgConnection::READY_FOR_QUERY) break;
            else if (type == PgConnection::ERROR_RESPONSE) { conn.disconnect(); break; }
        }
        conn.disconnect();
        bool ok_result = (rows == 2 && suspended);
        if (!ok_result) {
            std::string joined;
            for (auto& t : trace) joined += t + " ";
            diag("portal test observed rows=%d suspended=%d; message trace: %s",
                 rows, (int)suspended, joined.c_str());
        }
        return ok_result;
    } catch (const PgException& e) { diag("portal test threw: %s", e.what()); return false; }
}

int main(int argc, char** argv) {
    if (cl.getEnv()) return exit_status();
    plan(4);

    PGConnPtr c = backend_conn();
    ok(c && PQstatus(c.get()) == CONNECTION_OK, "connected for cursor test");

    // DECLARE / FETCH / MOVE / CLOSE inside a transaction (cursors require a txn).
    PQexec(c.get(), "BEGIN");
    PQexec(c.get(), "DECLARE cur CURSOR FOR SELECT g FROM generate_series(1,10) g");
    PGresult* r = PQexec(c.get(), "FETCH 3 cur");
    ok(PQntuples(r) == 3, "FETCH 3 returns 3 rows");
    PQclear(r);
    r = PQexec(c.get(), "MOVE 2 cur");           // skip 2
    PQclear(r);
    r = PQexec(c.get(), "FETCH 10 cur");         // remaining 5
    ok(PQntuples(r) == 5, "MOVE 2 then FETCH returns remaining 5 rows");
    PQclear(r);
    PQexec(c.get(), "CLOSE cur");
    PQexec(c.get(), "COMMIT");

    ok(portal_suspends_at_2(), "extended-protocol portal suspends at maxRows=2");

    return exit_status();
}
