/**
 * @file reg_test_5988-caching_sha2_rsa-t.cpp
 * @brief Non-TLS caching_sha2_password authentication using ProxySQL's RSA key.
 *
 * The bundled Connector/C cannot request a server public key, so this test uses
 * an Oracle MySQL CLI when one is available. A query rule returns an OK packet
 * locally, keeping the regression independent from any backend server.
 */

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>

#include "mysql.h"

#include "command_line.h"
#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

using std::string;
using std::vector;

enum class ServerPublicKeyMode : std::uint8_t {
	NONE,
	REQUEST,
	PATH
};

static bool run_query(MYSQL* connection, const string& query) {
	if (mysql_query(connection, query.c_str()) == 0) {
		return true;
	}
	diag("Query failed: %s; query: %s", mysql_error(connection), query.c_str());
	return false;
}

static bool query_scalar(MYSQL* connection, const string& query, string& value) {
	if (!run_query(connection, query)) {
		return false;
	}
	MYSQL_RES* result = mysql_store_result(connection);
	if (result == nullptr) {
		return false;
	}
	MYSQL_ROW row = mysql_fetch_row(result);
	const bool found = row != nullptr && row[0] != nullptr;
	if (found) {
		value = row[0];
	}
	mysql_free_result(result);
	return found;
}

static string sql_literal(MYSQL* connection, const string& value) {
	string escaped(value.size() * 2 + 1, '\0');
	const unsigned long escaped_length = mysql_real_escape_string(
		connection, escaped.data(), value.data(), static_cast<unsigned long>(value.size())
	);
	escaped.resize(escaped_length);
	return "'" + escaped + "'";
}

static bool set_global_variable(MYSQL* admin, const string& name, const string& value) {
	return run_query(
		admin,
		"UPDATE global_variables SET variable_value=" + sql_literal(admin, value) +
			" WHERE variable_name=" + sql_literal(admin, name)
	);
}

static int run_mysql_cli(
	const CommandLine& cl,
	const string& username,
	const string& password,
	ServerPublicKeyMode public_key_mode,
	const string& public_key_path,
	const string& query,
	string& output
) {
	const string host_arg = "--host=" + string(cl.host);
	const string port_arg = "--port=" + std::to_string(cl.port);
	const string user_arg = "--user=" + username;
	const string password_arg = "--password=" + password;
	vector<const char*> args {
		"--no-defaults",
		"--protocol=TCP",
		host_arg.c_str(),
		port_arg.c_str(),
		user_arg.c_str(),
		password_arg.c_str(),
		"--default-auth=caching_sha2_password",
		"--ssl-mode=DISABLED",
		"--connect-timeout=5",
		"--batch",
		"--skip-column-names"
	};
	const string server_public_key_path_arg =
		"--server-public-key-path=" + public_key_path;
	if (public_key_mode == ServerPublicKeyMode::REQUEST) {
		args.push_back("--get-server-public-key");
	} else if (public_key_mode == ServerPublicKeyMode::PATH) {
		args.push_back(server_public_key_path_arg.c_str());
	}
	const string execute_arg = "--execute=" + query;
	args.push_back(execute_arg.c_str());
	string error_output;
	const to_opts_t opts { 10 * 1000 * 1000, 0, 0, 0 };
	const int rc = wexecvp("mysql", args, opts, output, error_output);
	output += error_output;
	return rc;
}

static bool unlink_if_present(const string& path) {
	if (unlink(path.c_str()) == 0 || errno == ENOENT) {
		return true;
	}
	diag("Failed to remove test key artifact '%s': errno=%d", path.c_str(), errno);
	return false;
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(13);

	string mysql_help;
	const vector<const char*> help_args { "mysql", "--help" };
	const int help_rc = execvp("mysql", help_args, mysql_help);
	if (help_rc != 0 ||
		mysql_help.find("get-server-public-key") == string::npos ||
		mysql_help.find("server-public-key-path") == string::npos ||
		mysql_help.find("ssl-mode") == string::npos) {
		skip(13,
			"Oracle MySQL CLI with RSA public-key and --ssl-mode options is unavailable");
		return exit_status();
	}
	const char* infra_datadir = getenv("REGULAR_INFRA_DATADIR");
	if (infra_datadir == nullptr || *infra_datadir == '\0') {
		skip(13, "REGULAR_INFRA_DATADIR is required to clean generated RSA key artifacts");
		return exit_status();
	}

	MYSQL* admin = mysql_init(nullptr);
	const bool admin_connected = admin != nullptr &&
		mysql_real_connect(
			admin, cl.admin_host, cl.admin_username, cl.admin_password,
			nullptr, cl.admin_port, nullptr, 0) != nullptr;
	ok(admin_connected, "Connected to ProxySQL Admin");
	if (!admin_connected) {
		skip(12, "Cannot continue without an Admin connection");
		if (admin != nullptr) {
			mysql_close(admin);
		}
		return exit_status();
	}

	const string suffix = std::to_string(static_cast<long>(getpid()));
	const string username = "tap5988_" + suffix;
	const string pinned_username = "tap5988_pinned_" + suffix;
	const string password = "issue5988-secret"; // NOSONAR(cpp:S2068): deterministic process-local E2E test credential.
	const string wrong_password = "issue5988-wrong"; // NOSONAR(cpp:S2068): deliberate authentication-rejection test credential.
	const string comment = "reg_test_5988_" + suffix;
	const long rule_id = 598800000L + (static_cast<long>(getpid()) % 100000L);
	const string test_private_key = comment + "-private.pem";
	const string test_public_key = comment + "-public.pem";
	string test_key_directory = infra_datadir;
	if (test_key_directory.back() != '/') {
		test_key_directory.push_back('/');
	}

	string original_plugin;
	string original_auto_generate;
	string original_private_key;
	string original_public_key;
	string password_hash;
	const bool have_original_plugin = query_scalar(
		admin,
		"SELECT variable_value FROM global_variables "
		"WHERE variable_name='mysql-default_authentication_plugin'",
		original_plugin);
	const bool have_original_rsa_config = query_scalar(
		admin,
		"SELECT variable_value FROM global_variables "
		"WHERE variable_name='mysql-caching_sha2_password_auto_generate_rsa_keys'",
		original_auto_generate) && query_scalar(
		admin,
		"SELECT variable_value FROM global_variables "
		"WHERE variable_name='mysql-caching_sha2_password_private_key_path'",
		original_private_key) && query_scalar(
		admin,
		"SELECT variable_value FROM global_variables "
		"WHERE variable_name='mysql-caching_sha2_password_public_key_path'",
		original_public_key);
	bool setup_ok = query_scalar(
		admin,
		"SELECT CACHING_SHA2_PASSWORD('" + password +
			"','12345678901234567890')",
		password_hash) && have_original_plugin && have_original_rsa_config;
	setup_ok = password_hash.rfind("$A$", 0) == 0 && setup_ok;
	if (setup_ok) {
		setup_ok = set_global_variable(
			admin, "mysql-default_authentication_plugin", "caching_sha2_password") &&
			set_global_variable(
				admin, "mysql-caching_sha2_password_auto_generate_rsa_keys", "true") &&
			set_global_variable(
				admin, "mysql-caching_sha2_password_private_key_path", test_private_key) &&
			set_global_variable(
				admin, "mysql-caching_sha2_password_public_key_path", test_public_key) &&
			run_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	}
	if (setup_ok) {
		setup_ok = run_query(
			admin,
			"INSERT INTO mysql_users(username,password,active,default_hostgroup) VALUES"
				"('" + username + "','" + password_hash + "',1,0),"
				"('" + pinned_username + "','" + password_hash + "',1,0)") &&
			run_query(admin, "LOAD MYSQL USERS TO RUNTIME") &&
			run_query(
				admin,
				"INSERT INTO mysql_query_rules(rule_id,active,username,match_pattern,OK_msg,apply,comment) "
				"VALUES(" + std::to_string(rule_id) + ",1,'" + username +
					"','^SELECT 5988$','rsa-auth-ok',1,'" + comment + "'),(" +
					std::to_string(rule_id + 1) + ",1,'" + pinned_username +
					"','^SELECT 5988$','rsa-auth-ok',1,'" + comment + "')") &&
			run_query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	}
	ok(setup_ok,
		"Configured hashed caching_sha2_password frontend users and local query rules");

	if (setup_ok) {
		string output;
		const int no_key_rc = run_mysql_cli(
			cl, username, password, ServerPublicKeyMode::NONE, "", "SELECT 5988", output
		);
		ok(no_key_rc != 0,
			"Non-TLS full authentication is rejected when the client does not request the public key");

		output.clear();
		const int wrong_password_rc =
			run_mysql_cli(
				cl, username, wrong_password, ServerPublicKeyMode::REQUEST, "",
				"SELECT 5988", output);
		ok(wrong_password_rc != 0,
			"RSA full authentication rejects an incorrect password");

		const bool disabled_ok = set_global_variable(
			admin, "mysql-caching_sha2_password_auto_generate_rsa_keys", "false") &&
			set_global_variable(
				admin, "mysql-caching_sha2_password_private_key_path", "") &&
			set_global_variable(
				admin, "mysql-caching_sha2_password_public_key_path", "") &&
			run_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		output.clear();
		const int unavailable_rc = disabled_ok ? run_mysql_cli(
			cl, username, password, ServerPublicKeyMode::REQUEST, "",
			"SELECT 5988", output
		) : 0;
		ok(disabled_ok && unavailable_rc != 0 &&
			output.find("RSA key exchange is unavailable") != string::npos,
			"Disabled RSA keys return the caching_sha2_password TLS-or-key 1045 hint");

		const bool rejected_update_ok =
			run_query(
				admin,
				"DELETE FROM global_variables WHERE variable_name IN "
				"('mysql-caching_sha2_password_private_key_path',"
				"'mysql-caching_sha2_password_public_key_path')"
			) &&
			set_global_variable(
				admin, "mysql-caching_sha2_password_auto_generate_rsa_keys", "true"
			) &&
			run_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		const char* rejected_update_info = mysql_info(admin);
		diag("Rejected grouped RSA LOAD info: %s",
			rejected_update_info != nullptr ? rejected_update_info : "(null)");
		// The Admin interface refreshes known variables from runtime before reading
		// global_variables, so this external LOAD submits all three grouped RSA rows.
		ok(rejected_update_ok && rejected_update_info != nullptr &&
			string(rejected_update_info).find("Rejected: 3") != string::npos,
			"Grouped RSA rejection reports all submitted configuration variables");

		string restored_runtime_auto_generate;
		ok(query_scalar(
			admin,
			"SELECT variable_value FROM runtime_global_variables WHERE "
			"variable_name='mysql-caching_sha2_password_auto_generate_rsa_keys'",
			restored_runtime_auto_generate
		) && restored_runtime_auto_generate == "false",
			"Grouped RSA rejection restores the accepted runtime configuration");

		string restored_global_auto_generate;
		string restored_global_private_key;
		string restored_global_public_key;
		ok(query_scalar(
			admin,
			"SELECT variable_value FROM global_variables WHERE "
			"variable_name='mysql-caching_sha2_password_auto_generate_rsa_keys'",
			restored_global_auto_generate
		) && restored_global_auto_generate == "false" &&
			query_scalar(
				admin,
				"SELECT variable_value FROM global_variables WHERE "
				"variable_name='mysql-caching_sha2_password_private_key_path'",
				restored_global_private_key
			) && restored_global_private_key.empty() &&
			query_scalar(
				admin,
				"SELECT variable_value FROM global_variables WHERE "
				"variable_name='mysql-caching_sha2_password_public_key_path'",
				restored_global_public_key
			) && restored_global_public_key.empty(),
			"Grouped RSA rejection persists the accepted configuration in global_variables");

		const bool enabled_ok = set_global_variable(
			admin, "mysql-caching_sha2_password_auto_generate_rsa_keys", "true") &&
			set_global_variable(
				admin, "mysql-caching_sha2_password_private_key_path", test_private_key) &&
			set_global_variable(
				admin, "mysql-caching_sha2_password_public_key_path", test_public_key) &&
			run_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		output.clear();
		const int rsa_rc = enabled_ok ? run_mysql_cli(
			cl, username, password, ServerPublicKeyMode::REQUEST, "",
			"SELECT 5988", output
		) : -1;
		ok(enabled_ok && rsa_rc == 0,
			"Non-TLS caching_sha2_password authentication succeeds with --get-server-public-key");

		const string pinned_public_key_path = test_key_directory + test_public_key;
		output.clear();
		const int pinned_wrong_password_rc = enabled_ok ? run_mysql_cli(
			cl, pinned_username, wrong_password, ServerPublicKeyMode::PATH,
			pinned_public_key_path, "SELECT 5988", output
		) : 0;
		ok(enabled_ok && pinned_wrong_password_rc != 0 &&
			output.find("ERROR 1045") != string::npos,
			"Pinned RSA full authentication rejects an incorrect password with 1045");

		output.clear();
		const int pinned_key_rc = enabled_ok ? run_mysql_cli(
			cl, pinned_username, password, ServerPublicKeyMode::PATH,
			pinned_public_key_path, "SELECT 5988", output
		) : -1;
		ok(enabled_ok && pinned_key_rc == 0,
			"Non-TLS caching_sha2_password authentication succeeds with --server-public-key-path");

		output.clear();
		const int internal_session_rc = enabled_ok ? run_mysql_cli(
			cl, username, password, ServerPublicKeyMode::REQUEST, "",
			"PROXYSQL INTERNAL SESSION", output
		) : -1;
		ok(enabled_ok && internal_session_rc == 0 && output.find(password) == string::npos,
			"RSA-authenticated internal-session output does not expose the recovered password");
	} else {
		skip(10, "Cannot run authentication assertions after setup failure");
	}

	bool cleanup_ok = run_query(
		admin, "DELETE FROM mysql_query_rules WHERE comment='" + comment + "'");
	cleanup_ok = run_query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME") && cleanup_ok;
	cleanup_ok = run_query(
		admin, "DELETE FROM mysql_users WHERE username IN ('" + username + "','" +
			pinned_username + "')") && cleanup_ok;
	cleanup_ok = run_query(admin, "LOAD MYSQL USERS TO RUNTIME") && cleanup_ok;
	if (have_original_plugin) {
		cleanup_ok = set_global_variable(
			admin, "mysql-default_authentication_plugin", original_plugin) && cleanup_ok;
	}
	if (have_original_rsa_config) {
		cleanup_ok = set_global_variable(
			admin, "mysql-caching_sha2_password_auto_generate_rsa_keys",
			original_auto_generate) && cleanup_ok;
		cleanup_ok = set_global_variable(
			admin, "mysql-caching_sha2_password_private_key_path",
			original_private_key) && cleanup_ok;
		cleanup_ok = set_global_variable(
			admin, "mysql-caching_sha2_password_public_key_path",
			original_public_key) && cleanup_ok;
	}
	cleanup_ok = run_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME") && cleanup_ok;
	cleanup_ok = unlink_if_present(test_key_directory + test_private_key) && cleanup_ok;
	cleanup_ok = unlink_if_present(test_key_directory + test_public_key) && cleanup_ok;
	cleanup_ok = unlink_if_present(test_key_directory + test_private_key + ".lock") && cleanup_ok;
	ok(cleanup_ok,
		"Removed test objects and key artifacts, then restored authentication variables");

	mysql_close(admin);
	return exit_status();
}
