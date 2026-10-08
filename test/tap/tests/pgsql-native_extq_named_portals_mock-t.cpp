/**
 * @file pgsql-native_extq_named_portals_mock-t.cpp
 * @brief A native extended-query unit that uses named portals reaches the backend whole, ending
 *        in its Sync, before ProxySQL waits for any reply.
 *
 * The backend here is pgsql_mock_backend. After the warm-up query it reads frontend messages up
 * to a Sync and answers nothing until it has one, then answers the whole unit at once. A proxy
 * that sends a message with a Flush and waits for its reply before sending the next never gets
 * that reply, and the client gives up after 3 seconds.
 *
 * pgsql-native_extq_named_portals-t checks what the client receives against PostgreSQL itself;
 * this one only checks how the unit travels.
 */

#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>
#include "libpq-fe.h"
#include "pg_lite_client.h"  // raw frontend messages (MUST precede utils.h: mysql.h clash)
#include "pgsql_mock_backend.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int MOCK_HG = 49;
static const char* MOCK_USER = "extq_portals_mock_user";
static const char* MOCK_PASS = "extq_portals_mock_pw";

static PGConnPtr openConn(const char* host, int port, const char* user, const char* pass, const char* db) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
	if (db && *db) ss << " dbname=" << db;
	ss << " sslmode=disable connect_timeout=10";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}
static bool exec(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	const bool good = (PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK);
	if (!good) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(r);
	return good;
}
static bool setVar(PGconn* admin, const std::string& name, const std::string& val) {
	return exec(admin, "SET " + name + "='" + val + "'") && exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

// Removing and re-adding the server drops its pooled connections, so each case gets a new one
// and runs its own script.
static bool resetMockPool(PGconn* admin, const std::string& ip, uint16_t port) {
	if (!exec(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(MOCK_HG))
	    || !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		return false;
	std::stringstream ins;
	ins << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment) "
	    << "VALUES (" << MOCK_HG << ",'" << ip << "'," << port << ",4,0,'extq named portals mock')";
	if (!exec(admin, ins.str()) || !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	usleep(150000);
	return true;
}

static std::string handshake() {
	return pgmb_auth_ok() +
	       pgmb_parameter_status("server_version", "16.2") +
	       pgmb_parameter_status("client_encoding", "UTF8") +
	       pgmb_backend_key_data(4242, 987654321) +
	       pgmb_ready_for_query('I');
}

// Backend replies with no payload.
static std::string bare(char type) { std::string out; pgmb_append_msg(out, type, ""); return out; }
static const std::string PARSE_OK = bare('1');
static const std::string BIND_OK = bare('2');
static const std::string CLOSE_OK = bare('3');
static const std::string SUSPENDED = bare('s');

static std::string errorSqlstate(const std::vector<uint8_t>& payload) {
	size_t i = 0;
	while (i < payload.size() && payload[i] != 0) {
		const char code = (char)payload[i++];
		const size_t start = i;
		while (i < payload.size() && payload[i] != 0) i++;
		if (code == 'C') return std::string((const char*)payload.data() + start, i - start);
		if (i < payload.size()) i++;
	}
	return "";
}

// What the client receives up to the ReadyForQuery, one token per message: "1 2 T D=1 s Z(T)".
static std::string replies(PgConnection& c) {
	std::string out;
	for (;;) {
		char type = 0;
		std::vector<uint8_t> buf;
		c.readMessage(type, buf);
		if (type == 'N' || type == 'S') continue;
		if (!out.empty()) out += ' ';
		out += type;
		if (type == 'D' && buf.size() >= 6) {
			const int32_t len = (int32_t)((buf[2] << 24) | (buf[3] << 16) | (buf[4] << 8) | buf[5]);
			out += "=" + (len < 0 ? std::string("NULL") : std::string((const char*)buf.data() + 6, len));
		} else if (type == 'E') {
			out += "(" + errorSqlstate(buf) + ")";
		} else if (type == 'Z' && buf.size() >= 1) {
			out += std::string("(") + (char)buf[0] + ")";
			break;
		}
	}
	return out;
}

// One case: the mock answers the warm-up, then each unit with the reply given for it. The
// client sends the warm-up and then the units, and reports all it received, " | " between units.
struct Unit {
	std::function<void(PgConnection&)> send;
	std::string backend_reply;
};

static void runCase(PGconn* admin, PgSQL_Mock_Backend& mock, const std::string& ip, const char* label,
                    const std::vector<Unit>& units, const std::string& expected) {
	std::vector<Step> script = { step_expect_startup(), step_send(handshake()),
	                             step_expect_query(), step_send(pgmb_simple_result("c", "1", 1)) };
	for (const Unit& u : units) {
		script.push_back(step_expect_sync());
		script.push_back(step_send(u.backend_reply));
	}
	script.push_back(step_sleep(5000));   // hold the connection until the client is done

	if (!resetMockPool(admin, ip, mock.port())) BAIL_OUT("could not reset the mock pool");
	mock.set_script(script);
	mock.reset_stats();

	std::string got;
	try {
		PgConnection c(3000);
		c.connect(cl.pgsql_host, cl.pgsql_port, MOCK_USER, MOCK_USER, MOCK_PASS);
		c.sendQuery("SELECT 1");
		const std::string warm = replies(c);
		if (warm != "T D=1 C Z(I)") throw PgException("warm-up got [" + warm + "]");
		for (const Unit& u : units) {
			u.send(c);
			if (!got.empty()) got += " | ";
			got += replies(c);
		}
	} catch (const PgException& e) {
		got += std::string(got.empty() ? "" : " | ") + "threw: " + e.what();
	}

	const std::vector<std::string> seen = mock.unit_types();
	std::string seen_s;
	bool flushed = false;
	for (const std::string& t : seen) {
		seen_s += (seen_s.empty() ? "" : ",") + t;
		if (t.find('H') != std::string::npos) flushed = true;
	}
	ok(got == expected, "%s: client got [%s] expected [%s]", label, got.c_str(), expected.c_str());
	ok(seen.size() == units.size() && !flushed,
	   "%s: backend read %zu unit(s) through Sync with no Flush inside [%s]", label, units.size(), seen_s.c_str());
}

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}
	plan(11);

	PGConnPtr adminOwner = openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
	PGconn* admin = adminOwner.get();
	if (PQstatus(admin) != CONNECTION_OK) BAIL_OUT("cannot reach the admin interface");
	if (!setVar(admin, "pgsql-monitor_enabled", "false")) BAIL_OUT("cannot disable the monitor");
	if (!setVar(admin, "pgsql-shun_on_failures", "10000")) BAIL_OUT("cannot raise shun_on_failures");
	if (!setVar(admin, "pgsql-use_native_backend_protocol", "true")) BAIL_OUT("cannot enable the native protocol");

	PgSQL_Mock_Backend mock;
	if (!mock.start()) BAIL_OUT("mock backend failed to listen");
	const std::string ip = pgmb_local_ip_towards(cl.pgsql_host, cl.pgsql_port);
	if (ip.empty()) BAIL_OUT("could not discover this container's IP toward ProxySQL");
	diag("mock backend listening on %s:%u (hostgroup %d)", ip.c_str(), mock.port(), MOCK_HG);
	{
		std::stringstream u;
		u << "INSERT OR REPLACE INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('"
		  << MOCK_USER << "','" << MOCK_PASS << "',1," << MOCK_HG << ")";
		if (!exec(admin, u.str()) || !exec(admin, "LOAD PGSQL USERS TO RUNTIME"))
			BAIL_OUT("could not register the mock user");
	}

	const std::string row = pgmb_row_description_1col("n", 23);

	// M0, the control: an unnamed portal. Its unit already goes out whole, so a failure here
	// means the fixture is broken, not the named-portal path.
	runCase(admin, mock, ip, "M0 control: unnamed portal", {
		{ [](PgConnection& c) {
			c.prepareStatement("s", "SELECT 7 AS n", false);
			c.bindStatement("s", "", {}, {}, false);
			c.executePortal("", 0, false);
			c.sendSync();
		  }, PARSE_OK + BIND_OK + pgmb_data_row_1col("7") + pgmb_command_complete("SELECT 1") + pgmb_ready_for_query('I') } },
		"1 2 D=7 C Z(I)");

	// M1:Parse, named Bind, Describe of the portal, Execute.
	runCase(admin, mock, ip, "M1 named Bind + Describe + Execute", {
		{ [](PgConnection& c) {
			c.prepareStatement("s", "SELECT 7 AS n", false);
			c.bindStatement("s", "p1", {}, {}, false);
			c.describePortal("p1", false);
			c.executePortal("p1", 0, false);
			c.sendSync();
		  }, PARSE_OK + BIND_OK + row + pgmb_data_row_1col("7") + pgmb_command_complete("SELECT 1") + pgmb_ready_for_query('I') } },
		"1 2 T D=7 C Z(I)");

	// M2: two portals of one statement, both run, one closed.
	runCase(admin, mock, ip, "M2 two named portals and a Close", {
		{ [](PgConnection& c) {
			c.prepareStatement("s", "SELECT 7 AS n", false);
			c.bindStatement("s", "p1", {}, {}, false);
			c.bindStatement("s", "p2", {}, {}, false);
			c.executePortal("p1", 0, false);
			c.executePortal("p2", 0, false);
			c.closePortal("p1", false);
			c.sendSync();
		  }, PARSE_OK + BIND_OK + BIND_OK
		     + pgmb_data_row_1col("7") + pgmb_command_complete("SELECT 1")
		     + pgmb_data_row_1col("7") + pgmb_command_complete("SELECT 1")
		     + CLOSE_OK + pgmb_ready_for_query('I') } },
		"1 2 2 D=7 C D=7 C 3 Z(I)");

	// M3: a portal opened inside a transaction and fetched again in the next unit. The mock's
	// ReadyForQuery says 'T', which is all ProxySQL goes by.
	runCase(admin, mock, ip, "M3 named portal fetched across units", {
		{ [](PgConnection& c) {
			c.prepareStatement("s", "SELECT g FROM generate_series(1, 5) AS g", false);
			c.bindStatement("s", "p1", {}, {}, false);
			c.executePortal("p1", 1, false);
			c.sendSync();
		  }, PARSE_OK + BIND_OK + pgmb_data_row_1col("1") + SUSPENDED + pgmb_ready_for_query('T') },
		{ [](PgConnection& c) {
			c.executePortal("p1", 1, false);
			c.sendSync();
		  }, pgmb_data_row_1col("2") + SUSPENDED + pgmb_ready_for_query('T') } },
		"1 2 D=1 s Z(T) | D=2 s Z(T)");

	// M5: a named portal run while the unnamed portal waits for its Execute. The unnamed Bind goes
	// out with its Execute, and its BindComplete is ProxySQL's own, so the backend's is dropped.
	runCase(admin, mock, ip, "M5 named and unnamed portals interleaved", {
		{ [](PgConnection& c) {
			c.prepareStatement("s1", "SELECT 7 AS n", false);
			c.prepareStatement("s2", "SELECT 8 AS n", false);
			c.bindStatement("s1", "p1", {}, {}, false);
			c.bindStatement("s2", "", {}, {}, false);
			c.executePortal("p1", 0, false);
			c.executePortal("", 0, false);
			c.sendSync();
		  }, PARSE_OK + PARSE_OK + BIND_OK + pgmb_data_row_1col("7") + pgmb_command_complete("SELECT 1")
		     + BIND_OK + pgmb_data_row_1col("8") + pgmb_command_complete("SELECT 1") + pgmb_ready_for_query('I') } },
		"1 1 2 2 D=7 C D=8 C Z(I)");

	// M4: the backend reads a unit that opens a portal and then drops the connection. The client
	// gets an error, not a hang, and the portal never opened: the next Execute of it is refused.
	{
		if (!resetMockPool(admin, ip, mock.port())) BAIL_OUT("could not reset the mock pool");
		mock.set_script({ step_expect_startup(), step_send(handshake()),
		                  step_expect_query(), step_send(pgmb_simple_result("c", "1", 1)),
		                  step_expect_sync(), step_close() });
		mock.reset_stats();
		std::string first, second;
		try {
			PgConnection c(3000);
			c.connect(cl.pgsql_host, cl.pgsql_port, MOCK_USER, MOCK_USER, MOCK_PASS);
			c.sendQuery("SELECT 1");
			replies(c);
			c.prepareStatement("s", "SELECT 7 AS n", false);
			c.bindStatement("s", "p1", {}, {}, false);
			c.executePortal("p1", 0, false);
			c.sendSync();
			first = replies(c);
			c.executePortal("p1", 0, false);
			c.sendSync();
			second = replies(c);
		} catch (const PgException& e) {
			(first.empty() ? first : second) = std::string("threw: ") + e.what();
		}
		ok(first.rfind("E(", 0) == 0 && second == "E(34000) Z(I)",
		   "M4 backend drops after a unit that opens a portal: error, then the portal is unknown [%s | %s]",
		   first.c_str(), second.c_str());
	}

	mock.stop();
	return exit_status();
}
