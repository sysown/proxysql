/**
 * @file test_addl_pass_backend_password-t.cpp
 * @brief Checks user attribute 'use_backend_password'.
 * @details A session connects to the backends with the password it authenticated with (primary or
 *   'attributes.additional_password'). Backends with a single password per account (e.g. MySQL 5.7)
 *   reject the one they don't hold. With 'use_backend_password=true' every session of the user uses the
 *   clear-text password of the user's backend entry ('backend=1') instead, or is rejected when there
 *   isn't a usable one. See 'doc/additional_password_backend_password.md'.
 *
 *   The backend user only knows the primary password ('prim'); the additional one ('addl') never exists
 *   on the backend. Checked:
 *    1. Attribute absent: 'addl' passes frontend auth, the backend rejects it (default behaviour).
 *    2. Attribute true, separate backend row: 'addl' and 'prim' reach the backend; a wrong password is
 *       still rejected.
 *    3. Same with hashed ('mysql_native_password') primary and additional passwords.
 *    4. Single row (frontend=1,backend=1) with clear-text primary.
 *    5. Attribute not the JSON boolean 'true' ("true", 1, false): default behaviour.
 *    6. Backend entry password hashed, or no backend entry: sessions are rejected at authentication, whichever
 *       password they authenticated with.
 *    7. Clearing 'additional_password' rejects new 'addl' logins.
 *    8. Rotating the backend password (backend 'ALTER USER' + backend row update + LOAD): sessions opened
 *       after the rotation reach the backend; a session opened before it keeps the backend password it
 *       resolved at authentication, so its new backend connections fail (documented limitation).
 *
 *   Every check queries with 'create_new_connection=1' and a successful one must open a new backend
 *   connection (ConnOK delta): a pooled connection authenticated by a primary-password session of the same
 *   user is reused without re-authentication and would hide the backend result.
 *
 *   The backend user holds a single password (TAP group 'legacy', MySQL 5.7).
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::pair;
using std::string;
using std::vector;

static const char* TEST_USER { "addl_pass_be_user" };
static const char* ATTR { "use_backend_password" };

/**
 * @brief Fixed primary and additional passwords, with their precomputed 'mysql_native_password' hashes
 *   ('*' + HEX(SHA1(SHA1(pass)))) for the checks storing the frontend passwords hashed.
 */
static const string PRIM { "ubp-primary-pass-01" };
static const string PRIM_HASH { "*62B989DDE7192872B38130CCF2F479E97E7C2373" };
static const string ADDL { "ubp-additional-pass-02" };
static const string ADDL_HASH { "*9391F21571FF973FB0B69F48D93E32A050E6706D" };

static string to_hex(const string& s) {
	static const char digits[] { "0123456789ABCDEF" };
	string res {};
	for (unsigned char c : s) {
		res.push_back(digits[c >> 4]);
		res.push_back(digits[c & 0x0F]);
	}
	return res;
}

/**
 * @brief Builds the 'attributes' value; 'opt' is the raw JSON value of the attribute, or empty to omit it.
 */
static string attrs(const string& addl_pass, const string& opt) {
	string res { "{" };
	if (!addl_pass.empty()) {
		res += "\"additional_password\":\"" + to_hex(addl_pass) + "\"";
	}
	if (!opt.empty()) {
		res += string { addl_pass.empty() ? "" : "," } + "\"" + ATTR + "\":" + opt;
	}
	return res + "}";
}

struct user_row_t {
	string pass;
	int frontend;
	int backend;
	string attributes;
};

/**
 * @brief Replaces the test user rows in 'mysql_users' and loads them to runtime.
 * @details Uses 'mysql_query' instead of 'mysql_query_t' to keep the passwords out of the test log.
 */
static int set_users(MYSQL* admin, int hg, const vector<user_row_t>& rows) {
	MYSQL_QUERY(admin, (string { "DELETE FROM mysql_users WHERE username='" } + TEST_USER + "'").c_str());
	for (const auto& r : rows) {
		const string q {
			string { "INSERT INTO mysql_users (username,password,default_hostgroup,frontend,backend,attributes)"
				" VALUES ('" } + TEST_USER + "','" + r.pass + "'," + std::to_string(hg) + ","
				+ std::to_string(r.frontend) + "," + std::to_string(r.backend) + ",'" + r.attributes + "')"
		};
		MYSQL_QUERY(admin, q.c_str());
	}
	MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");
	return EXIT_SUCCESS;
}

enum class outcome_t { OK, FRONTEND_REJECTED, BACKEND_FAILED };

static const char* to_str(outcome_t o) {
	return o == outcome_t::OK ? "OK" : o == outcome_t::FRONTEND_REJECTED ? "FRONTEND_REJECTED" : "BACKEND_FAILED";
}

/**
 * @brief Runs, on an open ProxySQL session, a query that needs a new backend connection.
 */
static outcome_t query_new_conn(MYSQL* proxy) {
	outcome_t res { outcome_t::OK };
	// 'create_new_connection=1': the query gets a new backend connection, authenticated with this session's
	// backend credentials, instead of a pooled one of the same user (reused without re-authentication)
	if (mysql_query(proxy, "SELECT /* create_new_connection=1 */ CURRENT_USER()")) {
		diag("Query failed   errno=%u error='%s'", mysql_errno(proxy), mysql_error(proxy));
		res = outcome_t::BACKEND_FAILED;
	} else {
		MYSQL_RES* myres = mysql_store_result(proxy);
		MYSQL_ROW row = myres ? mysql_fetch_row(myres) : nullptr;
		if (row == nullptr || row[0] == nullptr || string { row[0] }.rfind(TEST_USER, 0) != 0) {
			res = outcome_t::BACKEND_FAILED;
		}
		mysql_free_result(myres);
	}

	return res;
}

/**
 * @brief Opens a connection to ProxySQL and runs a query that needs a backend connection.
 */
static outcome_t login(const CommandLine& cl, const string& pass) {
	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, TEST_USER, pass.c_str(), NULL, cl.port, NULL, 0)) {
		diag("Connect failed   errno=%u error='%s'", mysql_errno(proxy), mysql_error(proxy));
		mysql_close(proxy);
		return outcome_t::FRONTEND_REJECTED;
	}
	const outcome_t res { query_new_conn(proxy) };
	mysql_close(proxy);

	return res;
}

static int64_t hg_conn_ok(MYSQL* admin, int hg) {
	const string q { "SELECT COALESCE(SUM(ConnOK),0) FROM stats_mysql_connection_pool WHERE hostgroup=" + std::to_string(hg) };
	if (mysql_query(admin, q.c_str())) { return -1; }
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row = mysql_fetch_row(res);
	const int64_t val { row && row[0] ? std::stoll(row[0]) : -1 };
	mysql_free_result(res);
	return val;
}

static MYSQL* g_admin { nullptr };
static int g_hg { -1 };

/**
 * @brief Checks the outcome of a login; an 'OK' must have opened a new backend connection.
 * @details A pooled connection opened by a primary-password session of the same user is reused without
 *   re-authentication; the 'ConnOK' delta proves the backend accepted this session's own credentials.
 */
static void check(const CommandLine& cl, const string& pass, outcome_t exp, const string& what) {
	const int64_t before { hg_conn_ok(g_admin, g_hg) };
	const outcome_t act { login(cl, pass) };
	const int64_t after { hg_conn_ok(g_admin, g_hg) };
	const bool new_conn { act != outcome_t::OK || after > before };
	ok(act == exp && new_conn, "%s   exp='%s' act='%s' new_backend_conn=%d", what.c_str(), to_str(exp), to_str(act),
		new_conn);
}

/**
 * @brief Same as 'check', on an already open ProxySQL session.
 */
static void check_session(MYSQL* proxy, outcome_t exp, const string& what) {
	const int64_t before { hg_conn_ok(g_admin, g_hg) };
	const outcome_t act { query_new_conn(proxy) };
	const int64_t after { hg_conn_ok(g_admin, g_hg) };
	const bool new_conn { act != outcome_t::OK || after > before };
	ok(act == exp && new_conn, "%s   exp='%s' act='%s' new_backend_conn=%d", what.c_str(), to_str(exp), to_str(act),
		new_conn);
}

int main() {
	CommandLine cl;

	plan(21);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connect failed: %s", mysql_error(admin));
		return exit_status();
	}
	MYSQL* backend = mysql_init(NULL);
	if (!mysql_real_connect(backend, cl.mysql_host, cl.mysql_username, cl.mysql_password, NULL, cl.mysql_port, NULL, 0)) {
		diag("Backend connect failed: %s", mysql_error(backend));
		return exit_status();
	}

	// hostgroup serving the backend we create the user in
	int hg { -1 };
	{
		const string q {
			string { "SELECT hostgroup_id FROM runtime_mysql_servers WHERE hostname='" } + cl.mysql_host
				+ "' AND port=" + std::to_string(cl.mysql_port) + " ORDER BY hostgroup_id LIMIT 1"
		};
		MYSQL_QUERY(admin, q.c_str());
		MYSQL_RES* res = mysql_store_result(admin);
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row && row[0]) { hg = atoi(row[0]); }
		mysql_free_result(res);
	}
	if (hg < 0) {
		diag("No hostgroup found for backend %s:%d", cl.mysql_host, cl.mysql_port);
		return exit_status();
	}
	diag("Using hostgroup %d (backend %s:%d)", hg, cl.mysql_host, cl.mysql_port);
	g_admin = admin;
	g_hg = hg;


	const string& prim { PRIM };
	const string& addl { ADDL };
	const string wrong { random_string(16) };

	MYSQL_QUERY(backend, (string { "DROP USER IF EXISTS '" } + TEST_USER + "'@'%'").c_str());
	MYSQL_QUERY(backend,
		(string { "CREATE USER '" } + TEST_USER + "'@'%' IDENTIFIED BY '" + prim + "'").c_str());

	// 1. attribute absent: default behaviour
	if (set_users(admin, hg, { { PRIM_HASH, 1, 0, attrs(ADDL_HASH, "") }, { prim, 0, 1, "" } })) {
		return exit_status();
	}
	check(cl, addl, outcome_t::BACKEND_FAILED, "No attribute: additional password reaches the backend, which rejects it");

	// 2. attribute true, separate backend row with clear-text password
	if (set_users(admin, hg, { { prim, 1, 0, attrs(addl, "true") }, { prim, 0, 1, "" } })) {
		return exit_status();
	}
	check(cl, addl, outcome_t::OK, "Attribute true: additional password uses the backend row password");
	check(cl, prim, outcome_t::OK, "Attribute true: primary password works");
	check(cl, wrong, outcome_t::FRONTEND_REJECTED, "Attribute true: wrong password rejected");

	// 3. hashed primary and additional passwords
	if (set_users(admin, hg, { { PRIM_HASH, 1, 0, attrs(ADDL_HASH, "true") }, { prim, 0, 1, "" } })) {
		return exit_status();
	}
	check(cl, addl, outcome_t::OK, "Hashed passwords: additional password uses the backend row password");
	check(cl, prim, outcome_t::OK, "Hashed passwords: primary password works");
	check(cl, wrong, outcome_t::FRONTEND_REJECTED, "Hashed passwords: wrong password rejected");

	// 4. single row (frontend=1,backend=1), clear-text primary
	if (set_users(admin, hg, { { prim, 1, 1, attrs(ADDL_HASH, "true") } })) {
		return exit_status();
	}
	check(cl, addl, outcome_t::OK, "Single row: additional password uses the row clear-text password");
	check(cl, prim, outcome_t::OK, "Single row: primary password works");

	// 5. only the JSON boolean 'true' enables the attribute
	for (const string& v : { string { "\"true\"" }, string { "1" }, string { "false" } }) {
		if (set_users(admin, hg, { { PRIM_HASH, 1, 0, attrs(ADDL_HASH, v) }, { prim, 0, 1, "" } })) {
			return exit_status();
		}
		check(cl, addl, outcome_t::BACKEND_FAILED, "Attribute value " + v + ": default behaviour");
	}

	// 6. no usable backend password: additional password rejected at authentication
	if (set_users(admin, hg, { { PRIM_HASH, 1, 1, attrs(ADDL_HASH, "true") } })) {
		return exit_status();
	}
	check(cl, addl, outcome_t::FRONTEND_REJECTED, "Single row, hashed: additional password rejected");
	check(cl, prim, outcome_t::FRONTEND_REJECTED, "Single row, hashed: primary password rejected too (no clear-text backend password)");
	if (set_users(admin, hg, { { PRIM_HASH, 1, 0, attrs(ADDL_HASH, "true") }, { PRIM_HASH, 0, 1, "" } })) {
		return exit_status();
	}
	check(cl, addl, outcome_t::FRONTEND_REJECTED, "Hashed backend row: additional password rejected");
	if (set_users(admin, hg, { { PRIM_HASH, 1, 0, attrs(ADDL_HASH, "true") } })) {
		return exit_status();
	}
	check(cl, addl, outcome_t::FRONTEND_REJECTED, "No backend row: additional password rejected");

	// 7. clearing the additional password
	if (set_users(admin, hg, { { PRIM_HASH, 1, 0, attrs("", "true") }, { prim, 0, 1, "" } })) {
		return exit_status();
	}
	check(cl, addl, outcome_t::FRONTEND_REJECTED, "Additional password cleared: rejected");
	check(cl, prim, outcome_t::OK, "Additional password cleared: primary password works");

	// 8. backend password rotation with a session open
	if (set_users(admin, hg, { { PRIM_HASH, 1, 0, attrs(ADDL_HASH, "true") }, { prim, 0, 1, "" } })) {
		return exit_status();
	}
	MYSQL* open_sess = mysql_init(NULL);
	if (!mysql_real_connect(open_sess, cl.host, TEST_USER, addl.c_str(), NULL, cl.port, NULL, 0)) {
		diag("Connect failed   errno=%u error='%s'", mysql_errno(open_sess), mysql_error(open_sess));
		return exit_status();
	}
	check_session(open_sess, outcome_t::OK, "Rotation: session opened before it reaches the backend");
	const string next { random_string(16) };
	if (mysql_query(backend, (string { "ALTER USER '" } + TEST_USER + "'@'%' IDENTIFIED BY '" + next + "'").c_str())) {
		diag("ALTER USER failed: %s", mysql_error(backend));
		return exit_status();
	}
	if (mysql_query(admin, (string { "UPDATE mysql_users SET password='" } + next + "' WHERE username='" + TEST_USER
		+ "' AND frontend=0 AND backend=1").c_str())) {
		diag("UPDATE mysql_users failed: %s", mysql_error(admin));
		return exit_status();
	}
	MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");
	check_session(open_sess, outcome_t::BACKEND_FAILED,
		"Rotation: session opened before it keeps the old backend password (must reconnect)");
	mysql_close(open_sess);
	check(cl, addl, outcome_t::OK, "Rotation: new session with the additional password uses the new backend password");

	// cleanup
	MYSQL_QUERY(admin, (string { "DELETE FROM mysql_users WHERE username='" } + TEST_USER + "'").c_str());
	MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");
	MYSQL_QUERY(backend, (string { "DROP USER IF EXISTS '" } + TEST_USER + "'@'%'").c_str());

	mysql_close(backend);
	mysql_close(admin);

	return exit_status();
}
