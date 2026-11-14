/**
 * @file mysql_users_rejected_attributes_unit-t.cpp
 * @brief 'mysql_users' rows whose 'attributes' SQLite accepts but nlohmann
 *   rejects (issue #6413).
 *
 * The admin table only requires 'JSON_VALID(attributes) OR attributes=''', and
 * SQLite's JSON_VALID accepts text nlohmann::json::parse() rejects. For such a
 * row v3.0.11 used attributes='' and the user kept working. These tests check:
 * - the user keeps working: PASSWORD backend policy, effective attributes '';
 * - a rejected text that configures 'backend_auth' still fails closed (v4.0;
 *   v3.0/v3.1 ignore 'backend_auth', so the row is PASSWORD there);
 * - runtime never holds a value that breaks the admin table CHECK:
 *   runtime_mysql_users and SAVE MYSQL USERS FROM RUNTIME round-trip the
 *   configured text and leave no row active=0.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "MySQL_Authentication.hpp"
#include "MySQL_Backend_Auth.h"
#include "ProxySQL_Statistics.hpp"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "proxysql_admin.h"
#include "sqlite3db.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

extern MySQL_Authentication *GloMyAuth;
extern ProxySQL_Statistics *GloProxyStats;

namespace {

struct rejected_case_t {
	const char* username;
	std::string attributes;
	const char* description;
};

// Accepted by SQLite JSON_VALID, rejected by nlohmann::json::parse().
const std::vector<rejected_case_t>& rejected_cases() {
	static const std::vector<rejected_case_t> cases {
		{ "u_big_number", R"({"a":1e400})", "out-of-range number" },
		{ "u_lone_surrogate", R"({"a":"\ud800"})", "lone surrogate escape" },
		{ "u_invalid_utf8", std::string("{\"a\":\"") + '\xff' + "\"}", "invalid UTF-8 byte" },
	};
	return cases;
}

/**
 * @brief Whether 'policy' is what a backend row whose rejected attributes
 *   configure 'backend_auth' resolves to: INVALID (fail closed) with
 *   PROXYSQL40; PASSWORD on v3.0/v3.1, where AWS IAM is not available and
 *   'backend_auth' is ignored as in v3.0.11.
 */
bool is_rejected_backend_auth_policy(const MySQLBackendAuthPolicy& policy) {
#ifdef PROXYSQL40
	return policy.type == MySQLBackendAuthType::INVALID && policy.failure_code == "attributes_not_object";
#else
	return policy.type == MySQLBackendAuthType::PASSWORD && policy.failure_code.empty();
#endif // PROXYSQL40
}

// Rejected as above, but the text configures 'backend_auth'.
const std::string k_rejected_backend_auth { R"({"backend_auth":{"type":"aws_iam"},"a":1e400})" };

// As above, with the key spelled with JSON escapes ("backend\u005fauth" is
// the same key as "backend_auth").
const std::vector<std::string>& rejected_escaped_backend_auth() {
	static const std::vector<std::string> cases {
		R"({"backend\u005fauth":{"type":"aws_iam"},"a":1e400})",
		R"({"\u0062ackend_auth":{"type":"aws_iam"},"a":"\ud800"})",
	};
	return cases;
}

bool add_user(const char* username, enum cred_username_type type, const std::string& attributes) {
	std::string owned_username(username);
	std::string password("pw");
	std::string empty("");
	std::string owned_attributes(attributes);
	return GloMyAuth->add(
		&owned_username[0], &password[0], type, false, 0, &empty[0], false, false, false, 100,
		&owned_attributes[0], &empty[0]);
}

std::string effective_attributes(const char* username, enum cred_username_type type) {
	account_details_t ad = GloMyAuth->lookup(const_cast<char*>(username), type, { false, false, true });
	std::string ret = ad.attributes != nullptr ? ad.attributes : "<null>";
	free_account_details(ad);
	return ret;
}

std::string dumped_attributes(const char* username, bool frontend) {
	account_details_t** ads = nullptr;
	const int n = GloMyAuth->dump_all_users(&ads);
	std::string ret = "<missing>";
	for (int i = 0; i < n; i++) {
		account_details_t* ad = ads[i];
		if (strcmp(ad->username, username) == 0 && ad->frontend_ == frontend) {
			ret = ad->attributes;
		}
		free(ad->username);
		free(ad->password);
		free(ad->default_schema);
		free(ad->comment);
		free(ad->attributes);
		free(ad);
	}
	free(ads);
	return ret;
}

std::string sql_attributes_literal(const std::string& attributes) {
	// None of the fixtures contains a single quote.
	return "'" + attributes + "'";
}

void open_admin_db(SQLite3DB& db) {
	char db_path[] { ":memory:" };
	db.open(db_path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	db.execute(ADMIN_SQLITE_TABLE_MYSQL_USERS);
	db.execute(ADMIN_SQLITE_RUNTIME_MYSQL_USERS);
}

void test_fixtures_are_storable() {
	SQLite3DB db;
	open_admin_db(db);
	for (const auto& c : rejected_cases()) {
		const std::string q = "SELECT JSON_VALID(" + sql_attributes_literal(c.attributes) + ")";
		ok(db.return_one_int(q.c_str()) == 1,
			"fixture '%s' (%s) satisfies the mysql_users CHECK", c.username, c.description);
	}
}

void test_rejected_backend_rows_keep_working() {
	for (const auto& c : rejected_cases()) {
		ok(add_user(c.username, USERNAME_BACKEND, c.attributes),
			"backend row with %s attributes is loaded", c.description);
		ok(effective_attributes(c.username, USERNAME_BACKEND).empty(),
			"backend row with %s attributes has no effective attributes (v3.0.11)", c.description);
		const MySQLBackendAuthPolicy policy = resolve_mysql_backend_auth_policy(*GloMyAuth, c.username);
		ok(policy.type == MySQLBackendAuthType::PASSWORD && policy.failure_code.empty(),
			"backend row with %s attributes uses PASSWORD authentication", c.description);
		ok(dumped_attributes(c.username, false) == c.attributes,
			"backend row with %s attributes dumps the configured text", c.description);
	}
}

void test_rejected_frontend_rows_keep_working() {
	for (const auto& c : rejected_cases()) {
		ok(add_user(c.username, USERNAME_FRONTEND, c.attributes),
			"frontend row with %s attributes is loaded", c.description);
		ok(effective_attributes(c.username, USERNAME_FRONTEND).empty(),
			"frontend row with %s attributes has no effective attributes (v3.0.11)", c.description);
		ok(dumped_attributes(c.username, true) == c.attributes,
			"frontend row with %s attributes dumps the configured text", c.description);
	}
}

void test_rejected_backend_auth_fails_closed() {
	ok(add_user("u_rejected_iam", USERNAME_BACKEND, k_rejected_backend_auth),
		"backend row with rejected attributes configuring backend_auth is loaded");
	const MySQLBackendAuthPolicy policy = resolve_mysql_backend_auth_policy(*GloMyAuth, "u_rejected_iam");
	ok(is_rejected_backend_auth_policy(policy),
		"rejected attributes configuring backend_auth fail closed (v3.x: ignored, PASSWORD)");
	ok(dumped_attributes("u_rejected_iam", false) == k_rejected_backend_auth,
		"rejected attributes configuring backend_auth dump the configured text");

	for (const auto& attributes : rejected_escaped_backend_auth()) {
		add_user("u_rejected_iam_escaped", USERNAME_BACKEND, attributes);
		const MySQLBackendAuthPolicy escaped =
			resolve_mysql_backend_auth_policy(*GloMyAuth, "u_rejected_iam_escaped");
		ok(is_rejected_backend_auth_policy(escaped),
			"rejected attributes with an escaped backend_auth key fail closed (v3.x: ignored): %s", attributes.c_str());
	}
}

void test_reload_refreshes_rejected_rows() {
	ok(add_user("u_reload", USERNAME_BACKEND, k_rejected_backend_auth) &&
		is_rejected_backend_auth_policy(resolve_mysql_backend_auth_policy(*GloMyAuth, "u_reload")),
		"reload fixture starts with rejected backend_auth attributes");
	ok(add_user("u_reload", USERNAME_BACKEND, "") &&
		resolve_mysql_backend_auth_policy(*GloMyAuth, "u_reload").type == MySQLBackendAuthType::PASSWORD &&
		dumped_attributes("u_reload", false).empty(),
		"reloading the row with attributes='' clears the rejected text");
	ok(add_user("u_reload", USERNAME_BACKEND, rejected_cases()[0].attributes) &&
		dumped_attributes("u_reload", false) == rejected_cases()[0].attributes,
		"reloading the row with other rejected attributes keeps the new text");

	// JSON keys are case-sensitive: a case-only change is a new configuration.
	const std::string upper_rejected { R"({"BACKEND_AUTH":{"type":"aws_iam"},"a":1e400})" };
	ok(add_user("u_reload_case", USERNAME_BACKEND, upper_rejected) &&
		resolve_mysql_backend_auth_policy(*GloMyAuth, "u_reload_case").type == MySQLBackendAuthType::PASSWORD,
		"rejected attributes with a differently-cased key do not configure backend_auth");
	ok(add_user("u_reload_case", USERNAME_BACKEND, k_rejected_backend_auth) &&
		is_rejected_backend_auth_policy(resolve_mysql_backend_auth_policy(*GloMyAuth, "u_reload_case")) &&
		dumped_attributes("u_reload_case", false) == k_rejected_backend_auth,
		"reloading rejected attributes with a case-only key change refreshes the row");
}

/**
 * @brief SAVE MYSQL USERS FROM RUNTIME and the runtime_mysql_users refresh.
 * @details save_mysql_users_runtime_to_database() only uses 'admindb' and
 *   GloMyAuth, so a constructed ProxySQL_Admin with an in-memory admin DB is
 *   enough.
 */
void test_save_from_runtime_round_trip() {
	GloMyAuth->reset();

	std::vector<std::pair<std::string, std::string>> users {};
	for (const auto& c : rejected_cases()) {
		users.push_back({ c.username, c.attributes });
	}
	users.push_back({ "u_rejected_iam", k_rejected_backend_auth });
	users.push_back({ "u_valid", R"({"default-transaction_isolation":"READ COMMITTED"})" });

	SQLite3DB db;
	open_admin_db(db);
	for (const auto& u : users) {
		const std::string q =
			"INSERT INTO mysql_users (username,password,attributes) VALUES ('" + u.first + "','pw'," +
			sql_attributes_literal(u.second) + ")";
		db.execute(q.c_str());
		add_user(u.first.c_str(), USERNAME_FRONTEND, u.second);
		add_user(u.first.c_str(), USERNAME_BACKEND, u.second);
	}
	ok(db.return_one_int("SELECT COUNT(*) FROM mysql_users WHERE active=1") == (int)users.size(),
		"admin table holds the configured rows");

	// The ProxySQL_Admin constructor sets GloProxyStats variables, so it needs
	// a ProxySQL_Statistics backed by an in-memory stats DB.
	char* previous_statsdb_path = GloVars.statsdb_disk;
	std::unique_ptr<char, decltype(&free)> in_memory_statsdb { strdup(":memory:"), &free };
	GloVars.statsdb_disk = in_memory_statsdb.get();
	auto proxy_stats = std::make_unique<ProxySQL_Statistics>();
	GloProxyStats = proxy_stats.get();
	GloProxyStats->init();
	// Process-scoped partial fixture: the destructor runs the production
	// admin_shutdown(), which this fixture never started, so it is not deleted.
	ProxySQL_Admin* admin = new ProxySQL_Admin(); // NOSONAR
	admin->admindb = &db;

	admin->save_mysql_users_runtime_to_database(true);
	ok(db.return_one_int("SELECT COUNT(*) FROM runtime_mysql_users") == (int)(2 * users.size()),
		"runtime_mysql_users lists every frontend and backend row");

	admin->save_mysql_users_runtime_to_database(false);
	ok(db.return_one_int("SELECT COUNT(*) FROM mysql_users WHERE active=0") == 0,
		"SAVE MYSQL USERS FROM RUNTIME leaves no row active=0");
	ok(db.return_one_int("SELECT COUNT(*) FROM mysql_users") == (int)(2 * users.size()),
		"SAVE MYSQL USERS FROM RUNTIME writes every frontend and backend row");

	for (const auto& u : users) {
		for (const char* table : { "runtime_mysql_users", "mysql_users" }) {
			const std::string q =
				std::string("SELECT COUNT(*) FROM ") + table + " WHERE username='" + u.first +
				"' AND attributes=" + sql_attributes_literal(u.second);
			ok(db.return_one_int(q.c_str()) == 2,
				"%s round-trips the configured attributes of '%s'", table, u.first.c_str());
		}
	}

	admin->admindb = nullptr;
	GloProxyStats = nullptr;
	proxy_stats.reset();
	GloVars.statsdb_disk = previous_statsdb_path;
}

} // namespace

int main() {
	const int saved_users = 5;
	plan(3 + 12 + 9 + 3 + 2 + 3 + 2 + 4 + 2 * saved_users);
	test_init_minimal();
	test_init_auth();

	test_fixtures_are_storable();
	test_rejected_backend_rows_keep_working();
	test_rejected_frontend_rows_keep_working();
	test_rejected_backend_auth_fails_closed();
	test_reload_refreshes_rejected_rows();
	test_save_from_runtime_round_trip();

	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
}
