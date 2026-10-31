/**
 * @file test_frontend_x509_passthrough-t.cpp
 * @brief Proves row-backed require_x509 is enforced before pass-through work.
 */

#include <cstdlib>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "frontend_x509_test_utils.h"

using std::map;
using std::string;
using std::vector;

static constexpr const char* PT_USER = "tap_x509_pt";
static constexpr const char* PT_TARGET = "tap_x509_pt_target";
static constexpr const char* SPIFFE_USER = "tap_x509_pt_spiffe";
static constexpr const char* PT_PASSWORD = "x509-pass-through-password";
static constexpr const char* TARGET_PASSWORD = "ordinary-target-password";
static constexpr const char* WRONG_PASSWORD = "wrong-pass-through-password";
static constexpr const char* SPIFFE_ID = "spiffe://tap/pass-through-exclusion";

static uint32_t mysql8_hg = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);

static int do_query(MYSQL* mysql, const string& query) {
	if (mysql_query(mysql, query.c_str()) == 0) return EXIT_SUCCESS;
	diag("Query failed: %s -- %s", query.c_str(), mysql_error(mysql));
	return EXIT_FAILURE;
}

static bool read_global_variable(MYSQL* admin, const char* name, string& value) {
	const string query {
		string("SELECT variable_value FROM global_variables WHERE variable_name='") + name + "'"
	};
	if (mysql_query(admin, query.c_str())) return false;
	MYSQL_RES* result = mysql_store_result(admin);
	if (!result) return false;
	MYSQL_ROW row = mysql_fetch_row(result);
	const bool found = row && row[0];
	if (found) value = row[0];
	mysql_free_result(result);
	return found;
}

static int64_t read_metric(MYSQL* admin, const char* name) {
	const string query {
		string("SELECT metric_value FROM stats_mysql_passthrough_auth_metrics WHERE metric_name='") + name + "'"
	};
	if (mysql_query(admin, query.c_str())) return -1;
	MYSQL_RES* result = mysql_store_result(admin);
	if (!result) return -1;
	MYSQL_ROW row = mysql_fetch_row(result);
	const int64_t value = (row && row[0]) ? atoll(row[0]) : -1;
	mysql_free_result(result);
	return value;
}

static int cache_entries_for(MYSQL* admin, const char* username) {
	const string query {
		string("SELECT COUNT(*) FROM stats_mysql_passthrough_auth_cache WHERE username='") + username + "'"
	};
	if (mysql_query(admin, query.c_str())) return -1;
	MYSQL_RES* result = mysql_store_result(admin);
	if (!result) return -1;
	MYSQL_ROW row = mysql_fetch_row(result);
	const int value = (row && row[0]) ? atoi(row[0]) : -1;
	mysql_free_result(result);
	return value;
}

struct server_ssl_state {
	string hostname;
	string port;
	string use_ssl;
};

static vector<server_ssl_state> read_server_ssl_states(MYSQL* admin) {
	vector<server_ssl_state> states;
	const string query {
		"SELECT hostname,port,use_ssl FROM mysql_servers WHERE hostgroup_id=" + std::to_string(mysql8_hg)
	};
	if (mysql_query(admin, query.c_str())) return states;
	MYSQL_RES* result = mysql_store_result(admin);
	if (!result) return states;
	while (MYSQL_ROW row = mysql_fetch_row(result)) {
		if (row[0] && row[1] && row[2]) states.push_back({ row[0], row[1], row[2] });
	}
	mysql_free_result(result);
	return states;
}

static string sql_quote(const string& value) {
	string quoted { "'" };
	for (const char c : value) {
		if (c == '\'') quoted += "''";
		else quoted += c;
	}
	quoted += "'";
	return quoted;
}

static int restore_server_ssl_states(MYSQL* admin, const vector<server_ssl_state>& states) {
	int rc = EXIT_SUCCESS;
	for (const auto& state : states) {
		rc |= do_query(admin,
			"UPDATE mysql_servers SET use_ssl=" + state.use_ssl +
			" WHERE hostgroup_id=" + std::to_string(mysql8_hg) +
			" AND hostname=" + sql_quote(state.hostname) + " AND port=" + state.port);
	}
	rc |= do_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	return rc;
}

static void emit_fixture_skips(int count, const char* message) {
	for (int i = 0; i != count; ++i) ok(true, "%s # SKIP fixture unavailable", message);
}

static void expect_pass_through_rejection(
	MYSQL* admin,
	const CommandLine& cl,
	const char* label,
	const client_tls_material* identity
) {
	do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
	const int64_t probes_before = read_metric(admin, "probes_attempted");
	const int cache_before = cache_entries_for(admin, PT_USER);
	const unsigned int err = try_frontend_connect(cl, PT_USER, PT_PASSWORD, true, identity);
	const int64_t probes_after = read_metric(admin, "probes_attempted");
	const int cache_after = cache_entries_for(admin, PT_USER);
	ok(err == ER_ACCESS_DENIED_ERROR, "%s returns generic 1045 (errno=%u)", label, err);
	ok(probes_before >= 0 && probes_after == probes_before, "%s leaves probes_attempted unchanged (%ld -> %ld)", label, probes_before, probes_after);
	ok(cache_before == 0 && cache_after == 0, "%s creates no pass-through cache entry (%d -> %d)", label, cache_before, cache_after);
}

static void run_pass_through_row_checks(
	MYSQL* admin,
	const CommandLine& cl,
	bool trusted_ready,
	bool untrusted_ready,
	const client_tls_material& trusted_client,
	const client_tls_material& untrusted_client
) {
	expect_pass_through_rejection(admin, cl, "Cold TLS without client certificate", nullptr);
	if (untrusted_ready) {
		expect_pass_through_rejection(
			admin, cl, "Cold TLS with untrusted client certificate", &untrusted_client);
	} else {
		emit_fixture_skips(3, "Cold untrusted-certificate controls");
	}

	if (trusted_ready) {
		do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
		const int64_t probes_before = read_metric(admin, "probes_attempted");
		const unsigned int err = try_frontend_connect(cl, PT_USER, WRONG_PASSWORD, true, &trusted_client);
		const int64_t probes_after = read_metric(admin, "probes_attempted");
		ok(err == ER_ACCESS_DENIED_ERROR, "Trusted certificate with wrong backend password returns 1045 (errno=%u)", err);
		ok(probes_before >= 0 && probes_after == probes_before + 1, "Trusted wrong-password probe increments probes_attempted exactly once (%ld -> %ld)", probes_before, probes_after);
		ok(cache_entries_for(admin, PT_USER) == 0, "Trusted wrong-password probe leaves cache empty");

		do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
		const int64_t correct_before = read_metric(admin, "probes_attempted");
		const unsigned int correct_err = try_frontend_connect(cl, PT_USER, PT_PASSWORD, true, &trusted_client);
		const int64_t correct_after = read_metric(admin, "probes_attempted");
		ok(correct_err == 0, "Trusted no-SAN certificate with correct backend password succeeds (errno=%u)", correct_err);
		ok(correct_before >= 0 && correct_after == correct_before + 1, "Trusted correct-password probe increments probes_attempted exactly once (%ld -> %ld)", correct_before, correct_after);
		ok(cache_entries_for(admin, PT_USER) == 1, "Trusted correct-password probe creates one cache entry");

		const int64_t hits_before = read_metric(admin, "cache_hits");
		const unsigned int no_cert_warm_err = try_frontend_connect(cl, PT_USER, PT_PASSWORD, true);
		const int64_t hits_after = read_metric(admin, "cache_hits");
		ok(no_cert_warm_err == ER_ACCESS_DENIED_ERROR, "Warm TLS without a client certificate returns 1045 (errno=%u)", no_cert_warm_err);
		ok(hits_before >= 0 && hits_after == hits_before, "Warm no-certificate denial leaves cache_hits unchanged (%ld -> %ld)", hits_before, hits_after);

		const int64_t trusted_hits_before = read_metric(admin, "cache_hits");
		const unsigned int trusted_warm_err = try_frontend_connect(cl, PT_USER, PT_PASSWORD, true, &trusted_client);
		const int64_t trusted_hits_after = read_metric(admin, "cache_hits");
		ok(trusted_warm_err == 0, "Warm trusted certificate succeeds (errno=%u)", trusted_warm_err);
		ok(trusted_hits_before >= 0 && trusted_hits_after == trusted_hits_before + 1, "Warm trusted certificate increments cache_hits exactly once (%ld -> %ld)", trusted_hits_before, trusted_hits_after);
	} else {
		emit_fixture_skips(10, "Trusted pass-through control");
	}
}

static void expect_spiffe_rejection(
	MYSQL* admin,
	const CommandLine& cl,
	const char* label,
	const client_tls_material* identity
) {
	const int64_t probes_before = read_metric(admin, "probes_attempted");
	const unsigned int err = try_frontend_connect(cl, SPIFFE_USER, "", true, identity);
	const int64_t probes_after = read_metric(admin, "probes_attempted");
	ok(err == ER_ACCESS_DENIED_ERROR, "%s returns generic 1045 (errno=%u)", label, err);
	ok(probes_before >= 0 && probes_after == probes_before, "%s leaves probes_attempted unchanged (%ld -> %ld)", label, probes_before, probes_after);
	ok(cache_entries_for(admin, SPIFFE_USER) == 0, "%s creates no SPIFFE cache entry", label);
}

static void run_spiffe_row_checks(
	MYSQL* admin,
	const CommandLine& cl,
	bool trusted_ready,
	bool spiffe_ready,
	const client_tls_material& trusted_client,
	const client_tls_material& spiffe_client
) {
	if (spiffe_ready) {
		const int64_t probes_before = read_metric(admin, "probes_attempted");
		const unsigned int err = try_frontend_connect(cl, SPIFFE_USER, "", true, &spiffe_client);
		const int64_t probes_after = read_metric(admin, "probes_attempted");
		ok(err == 0, "Matching SPIFFE URI-SAN with empty password succeeds (errno=%u)", err);
		ok(probes_before >= 0 && probes_after == probes_before, "Matching SPIFFE path leaves probes_attempted unchanged (%ld -> %ld)", probes_before, probes_after);
		ok(cache_entries_for(admin, SPIFFE_USER) == 0, "Matching SPIFFE path creates no cache entry");
	} else {
		emit_fixture_skips(3, "Matching SPIFFE path");
	}

	expect_spiffe_rejection(admin, cl, "SPIFFE row without client certificate", nullptr);
	if (trusted_ready) {
		expect_spiffe_rejection(
			admin, cl, "SPIFFE row with mismatching trusted no-SAN certificate", &trusted_client);
	} else {
		emit_fixture_skips(3, "Mismatching SPIFFE path");
	}
}

static void run_change_user_direction_checks(
	MYSQL* admin,
	const CommandLine& cl,
	bool trusted_ready,
	const client_tls_material& trusted_client
) {
	if (trusted_ready) {
		mysql_ptr ordinary { connect_frontend(cl, cl.username, cl.password, true, &trusted_client) };
		const int64_t probes_before = read_metric(admin, "probes_attempted");
		const int rc = ordinary ? mysql_change_user(ordinary.get(), PT_USER, PT_PASSWORD, nullptr) : -1;
		const unsigned int err = ordinary ? mysql_errno(ordinary.get()) : UINT_MAX;
		const int64_t probes_after = read_metric(admin, "probes_attempted");
		ok(rc != 0 && err == ER_ACCESS_DENIED_ERROR, "COM_CHANGE_USER to pass-through target remains generic 1045 (rc=%d errno=%u)", rc, err);
		ok(probes_before >= 0 && probes_after == probes_before, "COM_CHANGE_USER pass-through target does not create a probe (%ld -> %ld)", probes_before, probes_after);

		mysql_ptr pass_through { connect_frontend(cl, PT_USER, PT_PASSWORD, true, &trusted_client) };
		const int direction_rc = pass_through ? mysql_change_user(pass_through.get(), PT_TARGET, TARGET_PASSWORD, nullptr) : -1;
		ok(direction_rc == 0, "Pass-through-authenticated source can COM_CHANGE_USER to ordinary target (rc=%d)", direction_rc);
	} else {
		emit_fixture_skips(3, "COM_CHANGE_USER pass-through directionality");
	}
}

int main() {
	CommandLine cl;
	const char* const datadir_env = getenv("REGULAR_INFRA_DATADIR");
	if (!datadir_env || !*datadir_env) {
		diag("SKIP: REGULAR_INFRA_DATADIR is unset; run through the isolated TAP runner.");
		plan(0);
		return exit_status();
	}
	if (cl.getEnv()) {
		diag("CommandLine getEnv() failed");
		return EXIT_FAILURE;
	}

	/* 10 setup + 28 behavior checks + 2 cleanup checks. */
	plan(40);

	mysql_ptr backend { mysql_init(NULL) };
	const bool backend_connected = backend && mysql_real_connect(
		backend.get(), cl.mysql_host, cl.mysql_username, cl.mysql_password, nullptr, cl.mysql_port, nullptr, 0);
	ok(backend_connected, "Connected to backend MySQL");

	mysql_ptr admin { mysql_init(NULL) };
	const bool admin_connected = admin && mysql_real_connect(
		admin.get(), cl.host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0);
	ok(admin_connected, "Connected to ProxySQL admin");
	if (!backend_connected || !admin_connected) return exit_status();

	const char* const variable_names[] {
		"mysql-passthrough_auth_enabled",
		"mysql-passthrough_auth_empty_password",
		"mysql-passthrough_auth_unknown_users",
		"mysql-passthrough_auth_require_tls",
		"mysql-passthrough_auth_username_pattern",
		"mysql-passthrough_auth_max_failures_per_user",
		"mysql-passthrough_auth_max_failures_per_ip",
		"mysql-default_authentication_plugin"
	};
	map<string, string> saved_variables;
	bool variables_saved = true;
	for (const char* name : variable_names) {
		string value;
		const bool saved = read_global_variable(admin.get(), name, value);
		variables_saved &= saved;
		if (saved) saved_variables[name] = value;
	}
	ok(variables_saved, "Snapshotted every mutated pass-through/default-plugin variable");

	const vector<server_ssl_state> saved_server_ssl = read_server_ssl_states(admin.get());
	ok(!saved_server_ssl.empty(), "Snapshotted mysql_servers.use_ssl for the MySQL 8 hostgroup");
	if (!variables_saved || saved_server_ssl.empty()) {
		diag("Refusing to mutate pass-through configuration without complete restoration snapshots.");
		return exit_status();
	}

	int setup_rc = EXIT_SUCCESS;
	setup_rc |= do_query(backend.get(), string("DROP USER IF EXISTS '") + PT_USER + "'@'%'");
	setup_rc |= do_query(backend.get(), string("CREATE USER '") + PT_USER + "'@'%' IDENTIFIED WITH 'caching_sha2_password' BY '" + PT_PASSWORD + "'");
	setup_rc |= do_query(backend.get(), string("GRANT SELECT ON *.* TO '") + PT_USER + "'@'%'");
	ok(setup_rc == EXIT_SUCCESS, "Provisioned caching_sha2_password backend pass-through user");

	setup_rc = EXIT_SUCCESS;
	setup_rc |= do_query(admin.get(), string("DELETE FROM mysql_users WHERE username IN ('") + PT_USER + "','" + PT_TARGET + "','" + SPIFFE_USER + "')");
	setup_rc |= do_query(admin.get(), string("INSERT INTO mysql_users(username,password,default_hostgroup,active,attributes) VALUES ") +
		"('" + PT_USER + "',''," + std::to_string(mysql8_hg) + ",1,'{\"require_x509\":true}')," +
		"('" + PT_TARGET + "','" + TARGET_PASSWORD + "'," + std::to_string(mysql8_hg) + ",1,'')," +
		"('" + SPIFFE_USER + "',''," + std::to_string(mysql8_hg) + ",1,'{\"spiffe_id\":\"" + SPIFFE_ID + "\"}')");
	setup_rc |= do_query(admin.get(), "LOAD MYSQL USERS TO RUNTIME");
	ok(setup_rc == EXIT_SUCCESS, "Provisioned row-backed pass-through, ordinary target, and SPIFFE users");

	setup_rc = EXIT_SUCCESS;
	setup_rc |= do_query(admin.get(), "SET mysql-passthrough_auth_enabled='true'");
	setup_rc |= do_query(admin.get(), "SET mysql-passthrough_auth_empty_password='true'");
	setup_rc |= do_query(admin.get(), "SET mysql-passthrough_auth_unknown_users='false'");
	setup_rc |= do_query(admin.get(), "SET mysql-passthrough_auth_require_tls='true'");
	setup_rc |= do_query(admin.get(), "SET mysql-passthrough_auth_username_pattern=''");
	setup_rc |= do_query(admin.get(), "SET mysql-passthrough_auth_max_failures_per_user='10000'");
	setup_rc |= do_query(admin.get(), "SET mysql-passthrough_auth_max_failures_per_ip='10000'");
	setup_rc |= do_query(admin.get(), "SET mysql-default_authentication_plugin='caching_sha2_password'");
	setup_rc |= do_query(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");
	setup_rc |= do_query(admin.get(), "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
	setup_rc |= do_query(admin.get(), "UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id=" + std::to_string(mysql8_hg));
	setup_rc |= do_query(admin.get(), "LOAD MYSQL SERVERS TO RUNTIME");
	ok(setup_rc == EXIT_SUCCESS, "Configured isolated pass-through window and backend TLS");

	const string datadir { datadir_env };
	const string ca { datadir + "/proxysql-ca.pem" };
	const string ca_key { datadir + "/proxysql-key.pem" };
	temporary_certificate_directory certificate_directory { datadir };
	client_tls_material trusted_client;
	client_tls_material untrusted_client;
	client_tls_material spiffe_client;
	const bool trusted_ready = certificate_directory.valid() && file_is_readable(ca) && file_is_readable(ca_key) &&
		create_trusted_client_certificate(certificate_directory, ca, ca_key, trusted_client);
	const bool untrusted_ready = certificate_directory.valid() &&
		create_untrusted_client_certificate(certificate_directory, ca, untrusted_client);
	const bool spiffe_ready = certificate_directory.valid() && file_is_readable(ca) && file_is_readable(ca_key) &&
		create_spiffe_client_certificate(certificate_directory, ca, ca_key, "spiffe-passthrough", SPIFFE_ID, 5928005, spiffe_client);
	if (trusted_ready) {
		ok(true, "Generated trusted no-URI-SAN certificate");
	} else {
		ok(true, "Generated trusted no-URI-SAN certificate # SKIP custom CA cannot sign fixture");
	}
	ok(untrusted_ready, "Generated untrusted certificate");
	if (spiffe_ready) {
		ok(true, "Generated trusted SPIFFE URI-SAN certificate");
	} else {
		ok(true, "Generated trusted SPIFFE URI-SAN certificate # SKIP custom CA cannot sign fixture");
	}

	run_pass_through_row_checks(
		admin.get(), cl, trusted_ready, untrusted_ready, trusted_client, untrusted_client);
	run_spiffe_row_checks(
		admin.get(), cl, trusted_ready, spiffe_ready, trusted_client, spiffe_client);
	run_change_user_direction_checks(admin.get(), cl, trusted_ready, trusted_client);

	int cleanup_rc = EXIT_SUCCESS;
	cleanup_rc |= do_query(backend.get(), string("DROP USER IF EXISTS '") + PT_USER + "'@'%'");
	ok(cleanup_rc == EXIT_SUCCESS, "Cleanup removed backend pass-through user");

	cleanup_rc = EXIT_SUCCESS;
	cleanup_rc |= do_query(admin.get(), string("DELETE FROM mysql_users WHERE username IN ('") + PT_USER + "','" + PT_TARGET + "','" + SPIFFE_USER + "')");
	cleanup_rc |= do_query(admin.get(), "LOAD MYSQL USERS TO RUNTIME");
	cleanup_rc |= do_query(admin.get(), "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
	for (const char* name : variable_names) {
		const auto it = saved_variables.find(name);
		if (it != saved_variables.end()) {
			cleanup_rc |= do_query(admin.get(), string("SET ") + name + "=" + sql_quote(it->second));
		} else {
			cleanup_rc = EXIT_FAILURE;
		}
	}
	cleanup_rc |= do_query(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");
	cleanup_rc |= restore_server_ssl_states(admin.get(), saved_server_ssl);
	ok(cleanup_rc == EXIT_SUCCESS, "Cleanup restored ProxySQL rows, cache, variables, and mysql_servers.use_ssl");

	return exit_status();
}
