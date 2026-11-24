/**
 * @file reg_test_4618-change_user_caching_sha2.cpp
 * @brief Regression test for #4618: COM_CHANGE_USER for 'caching_sha2_password' clients.
 * @details Built as 'reg_test_4618-change_user_caching_sha2_libmysql-t' against Oracle's
 *  libmysqlclient (8.4). That client's 'caching_sha2_password' plugin sends COM_CHANGE_USER
 *  with an EMPTY auth response and waits for the server to supply a scramble, so every
 *  change of user goes through an Auth Switch. The inline-scramble variant (Connector/J,
 *  Connector/Python, ...) is covered by 'reg_test_4618-change_user_caching_sha2_inline-t.py'.
 *
 *  For each case a fresh target user is created (fresh name, so no clear-text password is
 *  cached by a previous successful full authentication) with its password stored in one of
 *  the three formats ProxySQL accepts:
 *    - clear text
 *    - 'mysql_native_password' hash ('*...', via MYSQL_NATIVE_PASSWORD())
 *    - 'caching_sha2_password' hash ('$A$005...', via CACHING_SHA2_PASSWORD())
 *  The test connects as a source user and runs 'mysql_change_user()' to the target user
 *  over TLS and over a plain connection (RSA public-key exchange), with
 *  'mysql-default_authentication_plugin' set to 'caching_sha2_password' and to
 *  'mysql_native_password'. It checks that:
 *    - a correct password is accepted and the session now belongs to the target user;
 *    - a wrong password is rejected with ER_ACCESS_DENIED_ERROR (1045);
 *    - a second COM_CHANGE_USER on the same connection works (no stale auth state);
 *    - COM_CHANGE_USER works on a compressed connection, zlib and zstd (the switch must
 *      keep the negotiated algorithm).
 */

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "json.hpp"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using nlohmann::json;
using std::string;
using std::vector;

namespace {

enum class stored_fmt { CLEAR, NATIVE_HASH, SHA2_HASH };
enum class transport { TLS, PLAIN_RSA, PLAIN_NO_KEY };

const char* fmt_str(stored_fmt f) {
	switch (f) {
		case stored_fmt::CLEAR: return "clear_text";
		case stored_fmt::NATIVE_HASH: return "native_hash";
		case stored_fmt::SHA2_HASH: return "sha2_hash";
	}
	return "?";
}

const char* tr_str(transport t) {
	switch (t) {
		case transport::TLS: return "TLS";
		case transport::PLAIN_RSA: return "plain+RSA";
		case transport::PLAIN_NO_KEY: return "plain,no-key";
	}
	return "?";
}

// Every account this test creates starts with this per-run prefix, so the test never
// touches a pre-existing account and the cleanup removes exactly what it created.
const string USER_PREFIX { "cu4618_" + std::to_string(getpid() % 100000) + "_" };
const string SRC_USER { USER_PREFIX + "src" };
const string SRC_PASS { "cu4618_src_pass" };
const string TG_PASS { "cu4618-Secret" };
const string WRONG_PASS { "cu4618-Wrong" };

int run_admin(MYSQL* admin, const string& q) {
	if (mysql_query(admin, q.c_str())) {
		diag("Admin query failed   query='%s' err='%s'", q.c_str(), mysql_error(admin));
		return EXIT_FAILURE;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (res) { mysql_free_result(res); }
	return EXIT_SUCCESS;
}

int admin_scalar(MYSQL* admin, const string& q, string& out) {
	if (mysql_query(admin, q.c_str())) {
		diag("Admin query failed   query='%s' err='%s'", q.c_str(), mysql_error(admin));
		return EXIT_FAILURE;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
	int rc = EXIT_FAILURE;
	if (row && row[0]) {
		out = row[0];
		rc = EXIT_SUCCESS;
	}
	if (res) { mysql_free_result(res); }
	return rc;
}

string stored_value(MYSQL* admin, stored_fmt f, const string& pass) {
	string v {};
	switch (f) {
		case stored_fmt::CLEAR:
			return pass;
		case stored_fmt::NATIVE_HASH:
			admin_scalar(admin, "SELECT MYSQL_NATIVE_PASSWORD('" + pass + "')", v);
			return v;
		case stored_fmt::SHA2_HASH:
			admin_scalar(admin, "SELECT CACHING_SHA2_PASSWORD('" + pass + "','46181618461816184618')", v);
			return v;
	}
	return v;
}

/**
 * @brief (Re)creates a frontend user with a fresh runtime entry; a fresh entry carries no
 *   cached clear-text password, so hashed passwords really require full authentication.
 */
int create_user(MYSQL* admin, const string& user, const string& stored) {
	if (run_admin(admin, "DELETE FROM mysql_users WHERE username='" + user + "'")) return EXIT_FAILURE;
	if (run_admin(admin, "LOAD MYSQL USERS TO RUNTIME")) return EXIT_FAILURE;
	if (run_admin(admin,
		"INSERT INTO mysql_users (username,password,active,default_hostgroup) VALUES ('" +
			user + "','" + stored + "',1,0)"
	)) return EXIT_FAILURE;
	return run_admin(admin, "LOAD MYSQL USERS TO RUNTIME");
}

int set_variable(MYSQL* admin, const string& name, const string& value) {
	if (run_admin(admin, "SET " + name + "='" + value + "'")) return EXIT_FAILURE;
	return run_admin(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
}

int set_default_plugin(MYSQL* admin, const string& plugin) {
	return set_variable(admin, "mysql-default_authentication_plugin", plugin);
}

/**
 * @brief Memory and runtime value of a global variable, restored by 'restore_variable()'.
 */
struct var_snapshot_t {
	string name;
	string mem;
	string rt;
	bool valid;
};

var_snapshot_t snapshot_variable(MYSQL* admin, const string& name) {
	var_snapshot_t s { name, {}, {}, false };
	s.valid =
		admin_scalar(admin,
			"SELECT variable_value FROM global_variables WHERE variable_name='" + name + "'", s.mem
		) == EXIT_SUCCESS &&
		admin_scalar(admin,
			"SELECT variable_value FROM runtime_global_variables WHERE variable_name='" + name + "'", s.rt
		) == EXIT_SUCCESS;
	return s;
}

/**
 * @brief Restores the runtime value first, then the memory value, so an unsaved runtime
 *   value is not replaced by the memory one.
 */
void restore_variable(MYSQL* admin, const var_snapshot_t& s) {
	if (!s.valid) { return; }
	set_variable(admin, s.name, s.rt);
	run_admin(admin, "SET " + s.name + "='" + s.mem + "'");
}

enum class compression { NONE, ZLIB, ZSTD };

const char* comp_str(compression c) {
	switch (c) {
		case compression::NONE: return "";
		case compression::ZLIB: return " compress=zlib";
		case compression::ZSTD: return " compress=zstd";
	}
	return "?";
}

MYSQL* connect_src(const CommandLine& cl, transport t, compression comp) {
	MYSQL* proxy = mysql_init(NULL);
	mysql_options(proxy, MYSQL_DEFAULT_AUTH, "caching_sha2_password");

	enum mysql_ssl_mode ssl_mode = t == transport::TLS ? SSL_MODE_REQUIRED : SSL_MODE_DISABLED;
	mysql_options(proxy, MYSQL_OPT_SSL_MODE, &ssl_mode);

	if (t == transport::PLAIN_RSA) {
		bool get_key = true;
		mysql_options(proxy, MYSQL_OPT_GET_SERVER_PUBLIC_KEY, &get_key);
	}
	if (comp == compression::ZLIB) {
		mysql_options(proxy, MYSQL_OPT_COMPRESS, NULL);
	} else if (comp == compression::ZSTD) {
		mysql_options(proxy, MYSQL_OPT_COMPRESSION_ALGORITHMS, "zstd");
	}

	if (!mysql_real_connect(
			proxy, cl.host, SRC_USER.c_str(), SRC_PASS.c_str(), NULL, cl.port, NULL, 0
	)) {
		diag("Source connection failed   err='%s'", mysql_error(proxy));
		mysql_close(proxy);
		return nullptr;
	}

	return proxy;
}

/**
 * @brief Returns the frontend username of the session, as seen by ProxySQL itself.
 */
string session_username(MYSQL* proxy) {
	if (mysql_query(proxy, "PROXYSQL INTERNAL SESSION")) {
		diag("'PROXYSQL INTERNAL SESSION' failed   err='%s'", mysql_error(proxy));
		return {};
	}
	MYSQL_RES* res = mysql_store_result(proxy);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
	string user {};
	if (row && row[0]) {
		try {
			json j = json::parse(row[0]);
			user = j.at("client").at("userinfo").at("username").get<string>();
		} catch (const std::exception& ex) {
			diag("Failed to parse session JSON   err='%s'", ex.what());
		}
	}
	if (res) { mysql_free_result(res); }
	return user;
}

struct case_t {
	string def_plugin;
	stored_fmt fmt;
	transport tr;
	compression comp;
	bool exp_ok;
};

int user_seq = 0;

string next_user() {
	return USER_PREFIX + std::to_string(user_seq++);
}

/**
 * @brief One COM_CHANGE_USER with correct password, and one with a wrong password, against
 *   two freshly created users with the requested stored-password format.
 */
void run_case(MYSQL* admin, const CommandLine& cl, const case_t& c) {
	const string desc {
		"def_plugin=" + c.def_plugin + " stored=" + fmt_str(c.fmt) + " transport=" + tr_str(c.tr) +
		comp_str(c.comp)
	};

	if (set_default_plugin(admin, c.def_plugin)) {
		ok(0, "Setup failed   %s", desc.c_str());
		ok(0, "Setup failed   %s", desc.c_str());
		return;
	}

	// Correct password
	{
		const string tg_user { next_user() };
		const string stored { stored_value(admin, c.fmt, TG_PASS) };
		MYSQL* proxy = nullptr;

		if (stored.empty() || create_user(admin, tg_user, stored) ||
			(proxy = connect_src(cl, c.tr, c.comp)) == nullptr) {
			ok(0, "Setup failed   %s", desc.c_str());
		} else {
			const int rc = mysql_change_user(proxy, tg_user.c_str(), TG_PASS.c_str(), NULL);
			const string err { rc ? mysql_error(proxy) : "" };
			const string sess_user { rc ? "" : session_username(proxy) };

			if (c.exp_ok) {
				ok(
					rc == 0 && sess_user == tg_user,
					"COM_CHANGE_USER with the correct password should succeed   %s"
					" rc=%d err='%s' session_user='%s' exp_user='%s'",
					desc.c_str(), rc, err.c_str(), sess_user.c_str(), tg_user.c_str()
				);
			} else {
				ok(
					rc != 0,
					"COM_CHANGE_USER should be rejected (full auth impossible on this transport)   %s"
					" rc=%d err='%s'",
					desc.c_str(), rc, err.c_str()
				);
			}
		}
		if (proxy) { mysql_close(proxy); }
	}

	// Wrong password
	{
		const string tg_user { next_user() };
		const string stored { stored_value(admin, c.fmt, TG_PASS) };
		MYSQL* proxy = nullptr;

		if (stored.empty() || create_user(admin, tg_user, stored) ||
			(proxy = connect_src(cl, c.tr, c.comp)) == nullptr) {
			ok(0, "Setup failed   %s", desc.c_str());
		} else {
			const int rc = mysql_change_user(proxy, tg_user.c_str(), WRONG_PASS.c_str(), NULL);
			const unsigned int err_no = mysql_errno(proxy);
			// When full authentication is impossible on the transport the client gives up
			// before sending any password (CR_AUTH_PLUGIN_ERR 2061), as on a fresh connect.
			ok(
				rc != 0 && (err_no == ER_ACCESS_DENIED_ERROR || !c.exp_ok),
				"COM_CHANGE_USER with a wrong password should fail%s   %s"
				" rc=%d errno=%u err='%s'",
				c.exp_ok ? " with 1045" : "", desc.c_str(), rc, err_no, mysql_error(proxy)
			);
		}
		if (proxy) { mysql_close(proxy); }
	}
}

/**
 * @brief Two consecutive COM_CHANGE_USER on the same connection: first to a user needing
 *   full authentication, then to a user verified by fast authentication, then back to the
 *   source user. Detects auth state leaking from one exchange into the next.
 */
void run_chained(MYSQL* admin, const CommandLine& cl, transport t) {
	const string desc { string { "transport=" } + tr_str(t) };

	const string full_user { next_user() };
	const string fast_user { next_user() };
	MYSQL* proxy = nullptr;

	if (
		set_default_plugin(admin, "caching_sha2_password") ||
		create_user(admin, full_user, stored_value(admin, stored_fmt::SHA2_HASH, TG_PASS)) ||
		create_user(admin, fast_user, TG_PASS) ||
		(proxy = connect_src(cl, t, compression::NONE)) == nullptr
	) {
		ok(0, "Setup failed   %s", desc.c_str());
		if (proxy) { mysql_close(proxy); }
		return;
	}

	vector<std::pair<string,string>> steps {
		{ full_user, TG_PASS }, { fast_user, TG_PASS }, { SRC_USER, SRC_PASS }, { full_user, TG_PASS }
	};
	string trace {};
	bool all_ok = true;

	for (const auto& step : steps) {
		const int rc = mysql_change_user(proxy, step.first.c_str(), step.second.c_str(), NULL);
		const string sess_user { rc ? "" : session_username(proxy) };
		trace += step.first + ":" + (rc ? string { "ERR(" } + mysql_error(proxy) + ")" : sess_user) + " ";
		if (rc || sess_user != step.first) {
			all_ok = false;
			break;
		}
	}

	ok(all_ok, "Consecutive COM_CHANGE_USER on one connection should all succeed   %s trace='%s'",
		desc.c_str(), trace.c_str());

	mysql_close(proxy);
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("File %s, line %d, Error: %s", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// RSA key exchange for plain connections is a v3.1+ feature; detect it at runtime.
	string rsa_auto_gen {};
	const bool have_rsa =
		admin_scalar(admin,
			"SELECT variable_value FROM global_variables"
			" WHERE variable_name='mysql-caching_sha2_password_auto_generate_rsa_keys'",
			rsa_auto_gen
		) == EXIT_SUCCESS;
	const vector<var_snapshot_t> snapshots {
		snapshot_variable(admin, "mysql-default_authentication_plugin"),
		snapshot_variable(admin, "mysql-have_ssl"),
		snapshot_variable(admin, "mysql-have_compress"),
	};

	vector<case_t> cases {};
	const vector<stored_fmt> fmts { stored_fmt::CLEAR, stored_fmt::NATIVE_HASH, stored_fmt::SHA2_HASH };

	// Reproducer from #4618 plus all stored formats, over TLS and over plain+RSA.
	for (const stored_fmt f : fmts) {
		cases.push_back({ "caching_sha2_password", f, transport::TLS, compression::NONE, true });
	}
	if (have_rsa) {
		for (const stored_fmt f : fmts) {
			cases.push_back({ "caching_sha2_password", f, transport::PLAIN_RSA, compression::NONE, true });
		}
	}
	// Clear text needs no full authentication: fast auth works on any transport.
	cases.push_back({ "caching_sha2_password", stored_fmt::CLEAR, transport::PLAIN_NO_KEY, compression::NONE, true });
	// A 'caching_sha2_password' hash needs full auth; a plain connection that does not
	// request the server key cannot carry it, exactly as for a fresh connection.
	cases.push_back({ "caching_sha2_password", stored_fmt::SHA2_HASH, transport::PLAIN_NO_KEY, compression::NONE, false });
	// Same for a 'mysql_native_password' hash: with 'caching_sha2_password' advertised it is
	// verified through full auth, as for a fresh connection (before #4618 this case went
	// through a 'mysql_native_password' switch).
	cases.push_back({ "caching_sha2_password", stored_fmt::NATIVE_HASH, transport::PLAIN_NO_KEY, compression::NONE, false });
	// Compressed connections. The next command after the switch must still be readable,
	// which 'session_username()' checks. zstd also checks that the auth continuation
	// packets (fast auth, full auth) keep the negotiated algorithm.
	for (const compression comp : { compression::ZLIB, compression::ZSTD }) {
		cases.push_back({ "caching_sha2_password", stored_fmt::SHA2_HASH, transport::TLS, comp, true });
		cases.push_back({ "caching_sha2_password", stored_fmt::CLEAR, transport::TLS, comp, true });
		// 'mysql_native_password' switch on a compressed connection.
		cases.push_back({ "mysql_native_password", stored_fmt::CLEAR, transport::TLS, comp, true });
	}
	// ProxySQL advertising 'mysql_native_password' must keep working.
	cases.push_back({ "mysql_native_password", stored_fmt::CLEAR, transport::TLS, compression::NONE, true });
	cases.push_back({ "mysql_native_password", stored_fmt::NATIVE_HASH, transport::TLS, compression::NONE, true });
	cases.push_back({ "mysql_native_password", stored_fmt::CLEAR, transport::PLAIN_NO_KEY, compression::NONE, true });

	const size_t chained = have_rsa ? 2 : 1;
	plan(cases.size() * 2 + chained);

	diag("RSA key exchange available: %s", have_rsa ? "yes" : "no (skipping plain+RSA cases)");

	// The TLS cases must not depend on the state left by earlier tests.
	// Source user: clear text password, so the initial connect works on every transport.
	if (
		set_variable(admin, "mysql-have_ssl", "true") ||
		set_variable(admin, "mysql-have_compress", "true") ||
		create_user(admin, SRC_USER, SRC_PASS)
	) {
		for (const var_snapshot_t& s : snapshots) { restore_variable(admin, s); }
		mysql_close(admin);
		return exit_status();
	}

	for (const case_t& c : cases) {
		run_case(admin, cl, c);
	}

	run_chained(admin, cl, transport::TLS);
	if (have_rsa) {
		run_chained(admin, cl, transport::PLAIN_RSA);
	}

	// Cleanup
	// Cleanup: only the accounts created by this run ('USER_PREFIX' has no LIKE wildcard
	// other than '_', escaped below).
	string like_prefix {};
	for (const char ch : USER_PREFIX) {
		if (ch == '_' || ch == '%' || ch == '\\') { like_prefix += '\\'; }
		like_prefix += ch;
	}
	run_admin(admin, "DELETE FROM mysql_users WHERE username LIKE '" + like_prefix + "%' ESCAPE '\\'");
	run_admin(admin, "LOAD MYSQL USERS TO RUNTIME");
	for (const var_snapshot_t& s : snapshots) { restore_variable(admin, s); }

	mysql_close(admin);

	return exit_status();
}
