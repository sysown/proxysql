#include "tap.h"
#include "test_globals.h"

#include "MySQL_Thread.h"
#include "ProxySQL_Statistics.hpp"
#include "proxysql_admin.h"
#include "proxysql_utils.h"
#include "sqlite3db.h"
#ifdef PROXYSQL31
#include "MySQL_Caching_Sha2_RSA.h"
#endif

#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <vector>

#include <unistd.h>

extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Statistics* GloProxyStats;

static void free_variables_list(char **variables) {
	if (variables != nullptr) {
		for (char **current = variables; *current != nullptr; ++current) {
			free(*current); // NOSONAR: get_variables_list() transfers strdup-owned C strings.
		}
		free(variables); // NOSONAR: get_variables_list() transfers its malloc-owned array.
	}
}

static bool contains_variable(char **variables, const char *name) {
	for (char **current = variables; current != nullptr && *current != nullptr; ++current) {
		if (strcmp(*current, name) == 0) {
			return true;
		}
	}
	return false;
}

#ifdef PROXYSQL31
static bool has_all_rejected_rsa_variables(const std::vector<std::string>& variables) {
	return variables == std::vector<std::string> {
		"caching_sha2_password_auto_generate_rsa_keys",
		"caching_sha2_password_private_key_path",
		"caching_sha2_password_public_key_path"
	};
}
#endif

#ifdef PROXYSQL31
static void test_caching_sha2_rsa_rejection_restores_database_values(MySQL_Threads_Handler& handler);
#endif

static void test_mysql_integer_variables_are_registered() {
	test_globals_init();
	MySQL_Threads_Handler handler;
	char **variables = handler.get_variables_list();

	ok(handler.get_variable_int("aws_blue_green_deployment_auto_discovery") == 1,
		"aws_blue_green_deployment_auto_discovery is registered as an integer variable");
	ok(handler.get_variable_int("session_track_variables") == 0,
		"session_track_variables is registered as an integer variable");

#ifdef PROXYSQL31
	ok(contains_variable(variables, "caching_sha2_password_auto_generate_rsa_keys"),
		"caching_sha2 RSA auto-generation variable is registered in 3.1");
	ok(contains_variable(variables, "caching_sha2_password_private_key_path"),
		"caching_sha2 RSA private-key path variable is registered in 3.1");
	ok(contains_variable(variables, "caching_sha2_password_public_key_path"),
		"caching_sha2 RSA public-key path variable is registered in 3.1");

	char auto_generate_name[] = "caching_sha2_password_auto_generate_rsa_keys";
	char private_path_name[] = "caching_sha2_password_private_key_path";
	char public_path_name[] = "caching_sha2_password_public_key_path";
	mf_unique_ptr<char> auto_generate { handler.get_variable(auto_generate_name) };
	mf_unique_ptr<char> private_path { handler.get_variable(private_path_name) };
	mf_unique_ptr<char> public_path { handler.get_variable(public_path_name) };
	ok(auto_generate != nullptr && strcmp(auto_generate.get(), "true") == 0,
		"caching_sha2 RSA auto-generation defaults to true");
	ok(private_path != nullptr && strcmp(private_path.get(), "proxysql-caching-sha2-private-key.pem") == 0,
		"caching_sha2 RSA private-key path has the compiled default");
	ok(public_path != nullptr && strcmp(public_path.get(), "proxysql-caching-sha2-public-key.pem") == 0,
		"caching_sha2 RSA public-key path has the compiled default");
#endif

	free_variables_list(variables);
#ifdef PROXYSQL31
	test_caching_sha2_rsa_rejection_restores_database_values(handler);
#endif
	test_globals_cleanup();
}

static void test_mysql_integer_boolean_aliases() {
	test_globals_init();
	MySQL_Threads_Handler handler;
	char **variables = handler.get_variables_list();
	char variable_name[] = "aws_blue_green_deployment_auto_discovery";

	ok(handler.set_variable(variable_name, "true") &&
		handler.get_variable_int(variable_name) == 1,
		"aws_blue_green_deployment_auto_discovery accepts true");
	ok(handler.set_variable(variable_name, "false") &&
		handler.get_variable_int(variable_name) == 0,
		"aws_blue_green_deployment_auto_discovery accepts false");

	free_variables_list(variables);
	test_globals_cleanup();
}

#ifdef PROXYSQL31
static void test_caching_sha2_rsa_commit_is_atomic() {
	test_globals_init();
	char path_template[] = "/tmp/proxysql-mth-caching-sha2-rsa-XXXXXX"; // NOSONAR: mkdtemp creates this test directory atomically with owner-only permissions.
	char *temporary_directory = mkdtemp(path_template);
	ok(temporary_directory != nullptr, "created an isolated handler RSA directory");
	if (temporary_directory == nullptr) {
		test_globals_cleanup();
		return;
	}
	free(GloVars.datadir); // NOSONAR: test_globals_init() initializes this legacy C-owned field.
	GloVars.datadir = strdup(temporary_directory);

	{
		MySQL_Threads_Handler handler;
		free_variables_list(handler.get_variables_list());
		char auto_name[] = "caching_sha2_password_auto_generate_rsa_keys";
		char private_name[] = "caching_sha2_password_private_key_path";
		char public_name[] = "caching_sha2_password_public_key_path";

		handler.set_variable(auto_name, "false");
		handler.set_variable(private_name, "");
		handler.set_variable(public_name, "");
		const MySQLThreadsCommitResult disabled = handler.commit();
		ok(disabled.rejected_variables.empty(),
			"commit accepts intentional RSA unavailability");
		ok(handler.caching_sha2_rsa()->acquire() == nullptr,
			"intentional RSA unavailability publishes no snapshot");

		const int previous_poll_timeout =
			handler.set_int_variable_and_commit("poll_timeout", "10");
		ok(previous_poll_timeout > 0 &&
			handler.get_variable_int("poll_timeout") == 10,
			"atomic variable update returns the previous value and commits the replacement");
		const std::string restored_poll_timeout = std::to_string(previous_poll_timeout);
		const int temporary_poll_timeout = handler.set_int_variable_and_commit(
			"poll_timeout", restored_poll_timeout.c_str()
		);
		ok(temporary_poll_timeout == 10 &&
			handler.get_variable_int("poll_timeout") == previous_poll_timeout,
			"atomic variable update restores the prior value");

		handler.set_variable(auto_name, "true");
		const MySQLThreadsCommitResult invalid_empty = handler.commit();
		ok(has_all_rejected_rsa_variables(invalid_empty.rejected_variables),
			"invalid grouped RSA reload rejects all three variables");
		ok(handler.get_variable_int(auto_name) == 0,
			"invalid grouped reload restores the accepted boolean value");
		mf_unique_ptr<char> restored_private { handler.get_variable(private_name) };
		mf_unique_ptr<char> restored_public { handler.get_variable(public_name) };
		ok(restored_private != nullptr && restored_private.get()[0] == '\0' &&
			restored_public != nullptr && restored_public.get()[0] == '\0',
			"invalid grouped reload restores both accepted paths");

		handler.set_variable(auto_name, "true");
		handler.set_variable(private_name, "rsa-private.pem");
		handler.set_variable(public_name, "rsa-public.pem");
		const MySQLThreadsCommitResult generated = handler.commit();
		const auto generated_snapshot = handler.caching_sha2_rsa()->acquire();
		ok(generated.rejected_variables.empty(),
			"commit accepts and generates a complete RSA key pair");
		ok(generated_snapshot != nullptr,
			"accepted generated pair is visible through the handler-owned manager");

		handler.set_variable(auto_name, "false");
		handler.set_variable(public_name, "missing-public.pem");
		const MySQLThreadsCommitResult missing_public = handler.commit();
		ok(has_all_rejected_rsa_variables(missing_public.rejected_variables),
			"commit rejects a partial on-disk key pair as one grouped update");
		ok(handler.caching_sha2_rsa()->acquire() == generated_snapshot,
			"rejected handler reload preserves the previously published snapshot");
		mf_unique_ptr<char> restored_public_after_partial { handler.get_variable(public_name) };
		ok(handler.get_variable_int(auto_name) == 1 &&
			restored_public_after_partial != nullptr &&
			strcmp(restored_public_after_partial.get(), "rsa-public.pem") == 0,
			"rejected handler reload restores all prior accepted runtime values");
	}

	const std::string default_private =
		std::string(temporary_directory) + "/proxysql-caching-sha2-private-key.pem";
	const int partial_fd = open(default_private.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (partial_fd >= 0) {
		close(partial_fd);
	}
	{
		MySQL_Threads_Handler handler;
		free_variables_list(handler.get_variables_list());
		const MySQLThreadsCommitResult initial_invalid = handler.commit();
		ok(partial_fd >= 0 && has_all_rejected_rsa_variables(initial_invalid.rejected_variables) &&
			handler.caching_sha2_rsa()->acquire() == nullptr,
			"initial invalid default key pair is rejected without publishing a snapshot");

		char auto_name[] = "caching_sha2_password_auto_generate_rsa_keys";
		char private_name[] = "caching_sha2_password_private_key_path";
		char public_name[] = "caching_sha2_password_public_key_path";
		mf_unique_ptr<char> fallback_private { handler.get_variable(private_name) };
		mf_unique_ptr<char> fallback_public { handler.get_variable(public_name) };
		ok(handler.get_variable_int(auto_name) == 0 &&
			fallback_private != nullptr && fallback_private.get()[0] == '\0' &&
			fallback_public != nullptr && fallback_public.get()[0] == '\0',
			"failed initial defaults adopt an explicit TLS-only runtime configuration");
	}
	unlink(default_private.c_str());

	const std::string directory = temporary_directory;
	unlink((directory + "/rsa-private.pem").c_str());
	unlink((directory + "/rsa-public.pem").c_str());
	unlink((directory + "/rsa-private.pem.lock").c_str());
	rmdir(directory.c_str());
	test_globals_cleanup();
}

static std::string query_variable(SQLite3DB* db, const char* table, const char* name) {
	char* raw_error = nullptr;
	const std::string query = std::string("SELECT variable_value FROM ") + table +
		" WHERE variable_name='" + name + "'";
	std::unique_ptr<SQLite3_result> result { db->execute_statement(query.c_str(), &raw_error) };
	mf_unique_ptr<char> error { raw_error };
	std::string value;
	if (result != nullptr && result->rows_count == 1 && result->rows[0]->fields[0] != nullptr) {
		value = result->rows[0]->fields[0];
	}
	return value;
}

static void test_caching_sha2_rsa_rejection_restores_database_values(MySQL_Threads_Handler& handler) {
	GloMTH = &handler;

	char auto_name[] = "caching_sha2_password_auto_generate_rsa_keys";
	char private_name[] = "caching_sha2_password_private_key_path";
	char public_name[] = "caching_sha2_password_public_key_path";
	handler.set_variable(auto_name, "false");
	handler.set_variable(private_name, "");
	handler.set_variable(public_name, "");
	handler.commit();

	char* previous_statsdb_path = GloVars.statsdb_disk;
	mf_unique_ptr<char> in_memory_statsdb { strdup(":memory:") };
	GloVars.statsdb_disk = in_memory_statsdb.get();
	auto proxy_stats = std::make_unique<ProxySQL_Statistics>();
	GloProxyStats = proxy_stats.get();
	GloProxyStats->init();
	ProxySQL_Admin* admin = new ProxySQL_Admin(); // NOSONAR: this process-scoped partial fixture cannot invoke the production shutdown destructor.
	auto admin_db = std::make_unique<SQLite3DB>();
	admin->admindb = admin_db.get();
	char in_memory_admin_db[] = ":memory:";
	admin->admindb->open(
		in_memory_admin_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
	);
	admin->admindb->execute(
		"CREATE TABLE global_variables (variable_name VARCHAR NOT NULL PRIMARY KEY, variable_value VARCHAR NOT NULL)"
	);
	admin->admindb->execute(
		"CREATE TABLE runtime_global_variables (variable_name VARCHAR NOT NULL PRIMARY KEY, variable_value VARCHAR NOT NULL)"
	);
	admin->admindb->execute(
		"INSERT INTO global_variables VALUES "
		"('mysql-caching_sha2_password_auto_generate_rsa_keys', 'true')"
	);
	GloAdmin = admin;

	const FlushVariableStats stats = admin->load_mysql_variables_to_runtime();
	mf_unique_ptr<char> restored_runtime_auto_generate { handler.get_variable(auto_name) };
	ok(stats.records == 1 && stats.updated == 0 && stats.rejected == 1,
		"Grouped RSA rejection counts only the submitted database variable");
	ok(restored_runtime_auto_generate != nullptr && strcmp(restored_runtime_auto_generate.get(), "false") == 0,
		"Grouped RSA rejection restores the accepted runtime value");
	ok(query_variable(
		admin->admindb, "global_variables", "mysql-caching_sha2_password_auto_generate_rsa_keys"
	) == "false",
		"Grouped RSA rejection persists the accepted value in global_variables");
	ok(query_variable(
		admin->admindb, "runtime_global_variables", "mysql-caching_sha2_password_auto_generate_rsa_keys"
	) == "false",
		"Grouped RSA rejection publishes the accepted value to runtime_global_variables");

	admin->admindb->execute("DELETE FROM global_variables");
	admin->admindb->execute(
		"INSERT INTO global_variables VALUES "
		"('mysql-caching_sha2_password_auto_generate_rsa_keys', 'not-a-boolean')"
	);
	admin->admindb->execute(
		"INSERT INTO global_variables VALUES "
		"('mysql-caching_sha2_password_public_key_path', 'rsa-public.pem')"
	);
	const FlushVariableStats invalid_boolean_stats = admin->load_mysql_variables_to_runtime();
	ok(invalid_boolean_stats.records == 2 && invalid_boolean_stats.updated == 0 &&
		invalid_boolean_stats.rejected == 2,
		"Grouped RSA rejection does not double-count an already rejected boolean");

	GloAdmin = nullptr;
	GloMTH = nullptr;
	admin->admindb = nullptr;
	admin_db.reset();
	GloProxyStats = nullptr;
	proxy_stats.reset();
	GloVars.statsdb_disk = previous_statsdb_path;
}
#endif

int main() {
#ifdef PROXYSQL31
	plan(30);
#else
	plan(4);
#endif
	test_mysql_integer_variables_are_registered();
	test_mysql_integer_boolean_aliases();
#ifdef PROXYSQL31
	test_caching_sha2_rsa_commit_is_atomic();
#endif
	return exit_status();
}
