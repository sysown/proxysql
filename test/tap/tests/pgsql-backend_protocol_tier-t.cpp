/** Native mode is absent in v3.0 and configurable in later build tiers. */
#include <cstdio>
#include <memory>
#include <sstream>
#include <string>
#include "command_line.h"
#include "pgsql_native_tier.h"

static bool exec(PGconn* admin, const std::string& sql) {
	PGresult* result = PQexec(admin, sql.c_str());
	const bool good = PQresultStatus(result) == PGRES_COMMAND_OK;
	PQclear(result);
	return good;
}

static void require_exec(PGconn* admin, const std::string& sql) {
	if (!exec(admin, sql)) BAIL_OUT("admin command failed: %s: %s", sql.c_str(), PQerrorMessage(admin));
}

static std::string scalar(PGconn* admin, const std::string& sql) {
	PGresult* result = PQexec(admin, sql.c_str());
	if (PQresultStatus(result) != PGRES_TUPLES_OK || PQntuples(result) != 1) {
		PQclear(result);
		BAIL_OUT("admin scalar query failed: %s", sql.c_str());
		return {};
	}
	const std::string value = PQgetvalue(result, 0, 0);
	PQclear(result);
	return value;
}

static std::string value(PGconn* admin, const char* table) {
	return scalar(admin, std::string("SELECT variable_value FROM ") + table +
		" WHERE variable_name='pgsql-use_native_backend_protocol'");
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	std::ostringstream conninfo;
	conninfo << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
		<< " user=" << cl.admin_username << " password=" << cl.admin_password;
	std::unique_ptr<PGconn, decltype(&PQfinish)> admin(PQconnectdb(conninfo.str().c_str()), PQfinish);
	if (PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("admin connection failed");
	const std::string version = scalar(admin.get(),
		"SELECT variable_value FROM global_variables WHERE variable_name='admin-version'");
	int major = 0, minor = 0;
	if (sscanf(version.c_str(), "%d.%d", &major, &minor) != 2 || major < 3)
		BAIL_OUT("unexpected ProxySQL version: %s", version.c_str());
	const bool supported = major > 3 || minor >= 1;
	plan(supported ? 13 : 11);
	ok(pgsql_native_supported(admin.get()) == supported, "native setting visibility matches the server tier");
	if (!supported) {
		for (const char* input : {"true", "false"}) {
			ok(!exec(admin.get(), std::string("SET pgsql-use_native_backend_protocol='") + input + "'"),
				"Stable rejects SET for the unregistered native setting (%s)", input);
		}
		// Direct table writes (including restored configuration) must not bypass registration.
		for (const char* input : {"true", "1", "TRUE", "false"}) {
			require_exec(admin.get(), std::string("INSERT OR REPLACE INTO global_variables VALUES ") +
				"('pgsql-use_native_backend_protocol','" + input + "')");
			require_exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
			for (const char* table : {"global_variables", "runtime_global_variables"}) {
				ok(scalar(admin.get(), std::string("SELECT count(*) FROM ") + table +
					" WHERE variable_name='pgsql-use_native_backend_protocol'") == "0",
					"Stable discards injected %s from %s", input, table);
			}
		}
	} else {
		const std::string saved = value(admin.get(), "global_variables");
		const std::string saved_runtime = value(admin.get(), "runtime_global_variables");
		for (bool direct_update : {false, true}) {
			for (const char* input : {"false", "true", "0", "1", "TRUE", "FALSE"}) {
				const std::string assignment = direct_update ?
					std::string("UPDATE global_variables SET variable_value='") + input +
					"' WHERE variable_name='pgsql-use_native_backend_protocol'" :
					std::string("SET pgsql-use_native_backend_protocol='") + input + "'";
				require_exec(admin.get(), assignment);
				require_exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
				const bool enabled = std::string(input) == "true" || std::string(input) == "TRUE" || std::string(input) == "1";
				ok(value(admin.get(), "runtime_global_variables") == (enabled ? "true" : "false"),
					"%s %s selects the requested backend protocol", direct_update ? "UPDATE" : "SET", input);
			}
		}
		require_exec(admin.get(), "SET pgsql-use_native_backend_protocol='" + saved_runtime + "'");
		require_exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
		require_exec(admin.get(), "SET pgsql-use_native_backend_protocol='" + saved + "'");
	}
	return exit_status();
}
