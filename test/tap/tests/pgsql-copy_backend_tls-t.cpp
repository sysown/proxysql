/**
 * @file pgsql-copy_backend_tls-t.cpp
 * @brief COPY through a TLS-encrypted backend connection, on both backend paths.
 *
 * COPY makes the session switch to fast forward, which takes the backend TLS
 * session over from the connection. Existing COPY tests encrypt the CLIENT leg
 * only (sslmode=require towards ProxySQL); this one turns on use_ssl for the
 * SERVER leg, which is the leg that handover touches. libpq runs first as the
 * reference, then the native path has to produce the same bytes and leave the
 * connection usable afterwards.
 */

#include <unistd.h>
#include <memory>
#include <string>
#include <sstream>
#include <vector>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static const int BACKEND_HG = 0;
static const std::string APP_NAME = "copytls_" + std::to_string(getpid());
static const std::string TBL = "pgsql_copy_tls_" + std::to_string(getpid());

static PGConnPtr open_admin_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password
	   << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr open_client_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username
	   << " application_name=" << APP_NAME
	   << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execSQL(PGconn* c, const std::string& q) {
	PGresult* res = PQexec(c, q.c_str());
	ExecStatusType st = PQresultStatus(res);
	bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(res);
	return good;
}

static std::string queryOneValue(PGconn* c, const std::string& q) {
	PGresult* res = PQexec(c, q.c_str());
	std::string out;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0))
		out = PQgetvalue(res, 0, 0);
	PQclear(res);
	return out;
}

struct ServerRow { std::string hostname, port, max_connections, comment; };

static std::vector<ServerRow> readServers(PGconn* admin) {
	std::vector<ServerRow> rows;
	PGresult* res = PQexec(admin,
		("SELECT hostname, port, max_connections, COALESCE(comment,'') FROM pgsql_servers"
		 " WHERE hostgroup_id=" + std::to_string(BACKEND_HG)).c_str());
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		for (int i = 0; i < PQntuples(res); i++)
			rows.push_back(ServerRow { PQgetvalue(res,i,0), PQgetvalue(res,i,1),
			                           PQgetvalue(res,i,2), PQgetvalue(res,i,3) });
	}
	PQclear(res);
	return rows;
}

// Deleting the servers drops every pooled connection to them, so the next
// query opens a fresh one under whatever use_ssl / native setting is current.
// Without this the phase would keep reusing connections made under the old one.
static bool reloadServers(PGconn* admin, const std::vector<ServerRow>& rows, int use_ssl) {
	if (rows.empty()) return false;
	if (!execSQL(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(BACKEND_HG))) return false;
	if (!execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	for (const auto& r : rows) {
		std::string ins = "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment)"
			" VALUES (" + std::to_string(BACKEND_HG) + ",'" + r.hostname + "'," + r.port + ","
			+ (r.max_connections.empty() ? std::string("1000") : r.max_connections) + ","
			+ std::to_string(use_ssl) + ",'" + r.comment + "')";
		if (!execSQL(admin, ins)) return false;
	}
	if (!execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	usleep(300000);
	return true;
}

static bool setNativeMode(PGconn* admin, bool on) {
	return execSQL(admin, std::string("SET pgsql-use_native_backend_protocol='") + (on ? "true" : "false") + "'")
	    && execSQL(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

// Asks the backend itself whether the connection carrying this session is
// encrypted. pg_backend_pid() is intercepted by ProxySQL and answers with a
// made-up pid, so the backend session is found by the text of this very query:
// the marker below appears in the query, so the row it matches is its own.
static bool backendLegIsEncrypted(PGconn* client) {
	const std::string v = queryOneValue(client,
		"SELECT s.ssl FROM pg_stat_ssl s JOIN pg_stat_activity a ON s.pid = a.pid"
		" WHERE a.state = 'active' AND a.query LIKE '%copytls_self_marker%' LIMIT 1");
	diag("backend reports ssl=%s for the connection running this query", v.empty() ? "(none)" : v.c_str());
	return v == "t";
}

static std::string copyOut(PGconn* client, const std::string& sql, bool* ok) {
	std::string out;
	*ok = false;
	PGresult* res = PQexec(client, sql.c_str());
	if (PQresultStatus(res) != PGRES_COPY_OUT) {
		diag("COPY OUT did not start: %s -- %s", PQresStatus(PQresultStatus(res)), PQerrorMessage(client));
		PQclear(res);
		return out;
	}
	PQclear(res);
	char* buf = nullptr;
	int n;
	while ((n = PQgetCopyData(client, &buf, 0)) > 0) {
		out.append(buf, n);
		PQfreemem(buf);
		buf = nullptr;
	}
	if (n == -2) {
		diag("COPY OUT failed mid-stream: %s", PQerrorMessage(client));
		return out;
	}
	res = PQgetResult(client);
	*ok = (res != nullptr && PQresultStatus(res) == PGRES_COMMAND_OK);
	if (!*ok) diag("COPY OUT did not complete: %s", PQerrorMessage(client));
	PQclear(res);
	while ((res = PQgetResult(client)) != nullptr) PQclear(res);
	return out;
}

static bool copyIn(PGconn* client, const std::string& table, const std::string& payload) {
	PGresult* res = PQexec(client, ("COPY " + table + " FROM STDIN").c_str());
	if (PQresultStatus(res) != PGRES_COPY_IN) {
		diag("COPY IN did not start: %s -- %s", PQresStatus(PQresultStatus(res)), PQerrorMessage(client));
		PQclear(res);
		return false;
	}
	PQclear(res);
	if (PQputCopyData(client, payload.data(), (int)payload.size()) != 1) {
		diag("PQputCopyData failed: %s", PQerrorMessage(client));
		return false;
	}
	if (PQputCopyEnd(client, nullptr) != 1) {
		diag("PQputCopyEnd failed: %s", PQerrorMessage(client));
		return false;
	}
	res = PQgetResult(client);
	bool ok = (res != nullptr && PQresultStatus(res) == PGRES_COMMAND_OK);
	if (!ok) diag("COPY IN did not complete: %s", PQerrorMessage(client));
	PQclear(res);
	while ((res = PQgetResult(client)) != nullptr) PQclear(res);
	return ok;
}

static const char* COPY_OUT_SQL =
	"COPY (SELECT g, 'row'||g FROM generate_series(1,5) g) TO STDOUT";
static const char* COPY_IN_PAYLOAD = "1\tone\n2\ttwo\n3\tthree\n";

int main(int argc, char** argv) {
	plan(10);

	if (cl.getEnv())
		return exit_status();

	auto admin = open_admin_conn();
	ok(PQstatus(admin.get()) == CONNECTION_OK, "ADMIN connection created");
	if (PQstatus(admin.get()) != CONNECTION_OK) return exit_status();

	const std::vector<ServerRow> saved = readServers(admin.get());
	if (saved.empty()) BAIL_OUT("no servers in hostgroup 0 to work with");

	const std::string saved_native = queryOneValue(admin.get(),
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
	diag("saved: %lu server rows, native=%s", saved.size(), saved_native.c_str());

	// ---------------- Phase 1: libpq, backend TLS on ----------------
	diag("---- Phase 1: libpq path, use_ssl=1 ----");
	setNativeMode(admin.get(), false);
	ok(reloadServers(admin.get(), saved, 1), "backend servers set to use_ssl=1 and pool flushed");

	std::string libpq_out;
	bool libpq_copy_out_ok = false, libpq_copy_in_ok = false, libpq_tls = false;
	{
		auto client = open_client_conn();
		if (PQstatus(client.get()) != CONNECTION_OK)
			BAIL_OUT("client connection failed: %s", PQerrorMessage(client.get()));
		execSQL(client.get(), "DROP TABLE IF EXISTS " + TBL);
		execSQL(client.get(), "CREATE TABLE " + TBL + " (id int, name text)");
		libpq_tls = backendLegIsEncrypted(client.get());
		libpq_out = copyOut(client.get(), COPY_OUT_SQL, &libpq_copy_out_ok);
		libpq_copy_in_ok = copyIn(client.get(), TBL, COPY_IN_PAYLOAD);
	}
	ok(libpq_tls, "libpq phase really ran over an encrypted backend connection");
	ok(libpq_copy_out_ok && !libpq_out.empty(), "libpq: COPY TO STDOUT completed (%zu bytes)", libpq_out.size());
	ok(libpq_copy_in_ok, "libpq: COPY FROM STDIN completed");

	// ---------------- Phase 2: native, backend TLS on ----------------
	diag("---- Phase 2: native path, use_ssl=1 ----");
	setNativeMode(admin.get(), true);
	reloadServers(admin.get(), saved, 1);

	std::string native_out;
	bool native_copy_out_ok = false, native_copy_in_ok = false, native_tls = false, still_usable = false;
	{
		auto client = open_client_conn();
		if (PQstatus(client.get()) != CONNECTION_OK)
			BAIL_OUT("client connection failed in native phase: %s", PQerrorMessage(client.get()));
		execSQL(client.get(), "TRUNCATE " + TBL);
		native_tls = backendLegIsEncrypted(client.get());
		native_out = copyOut(client.get(), COPY_OUT_SQL, &native_copy_out_ok);
		native_copy_in_ok = copyIn(client.get(), TBL, COPY_IN_PAYLOAD);
		// The connection is handed back to the pool after the COPY; a plain
		// query has to still work on it.
		still_usable = (queryOneValue(client.get(), "SELECT 42") == "42");
	}
	ok(native_tls, "native phase really ran over an encrypted backend connection");
	ok(native_copy_out_ok && !native_out.empty(), "native: COPY TO STDOUT completed (%zu bytes)", native_out.size());
	ok(native_out == libpq_out, "native COPY TO STDOUT bytes match libpq");
	ok(native_copy_in_ok, "native: COPY FROM STDIN completed");
	ok(still_usable, "the session still works after a COPY over a TLS backend connection");

	// ---------------- restore ----------------
	{
		auto client = open_client_conn();
		if (PQstatus(client.get()) == CONNECTION_OK)
			execSQL(client.get(), "DROP TABLE IF EXISTS " + TBL);
	}
	setNativeMode(admin.get(), saved_native == "true");
	reloadServers(admin.get(), saved, 0);

	return exit_status();
}
