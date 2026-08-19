#include <memory>
#include <sstream>
#include <string>

#include "command_line.h"
#include "libpq-fe.h"
#include "tap.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType {
	ADMIN,
	BACKEND
};

static PGConnPtr create_new_connection(ConnType conn_type) {
	const char* host = conn_type == BACKEND ? cl.pgsql_host : cl.pgsql_admin_host;
	int port = conn_type == BACKEND ? cl.pgsql_port : cl.pgsql_admin_port;
	const char* username = conn_type == BACKEND ? cl.pgsql_username : cl.admin_username;
	const char* password = conn_type == BACKEND ? cl.pgsql_password : cl.admin_password;
	if (port <= 0) {
		port = conn_type == BACKEND ? 6133 : 6132;
	}

	std::stringstream options;
	options << "host=" << host << " port=" << port << " user=" << username << " password=" << password
		<< " sslmode=disable";
	PGconn* conn = PQconnectdb(options.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		diag("Connection failed: %s", PQerrorMessage(conn));
		PQfinish(conn);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

static bool run_admin_checked(PGconn* admin, const char* sql) {
	PGresult* result = PQexec(admin, sql);
	const bool success = result != nullptr &&
		(PQresultStatus(result) == PGRES_COMMAND_OK || PQresultStatus(result) == PGRES_TUPLES_OK);
	if (!success) {
		diag("Admin command failed [%s]: %s", sql, PQerrorMessage(admin));
	}
	if (result != nullptr) {
		PQclear(result);
	}
	return success;
}

static bool get_single_value(PGconn* conn, const char* sql, std::string& value) {
	PGresult* result = PQexec(conn, sql);
	const bool success = result != nullptr && PQresultStatus(result) == PGRES_TUPLES_OK &&
		PQntuples(result) == 1 && PQnfields(result) == 1 && !PQgetisnull(result, 0, 0);
	if (success) {
		value = PQgetvalue(result, 0, 0);
	} else {
		diag("Expected one value from [%s]: %s", sql, PQerrorMessage(conn));
	}
	if (result != nullptr) {
		PQclear(result);
	}
	return success;
}

static bool run_rewrite_case(PGconn* admin, PGconn* proxy, const char* insert_rule,
	const char* query, const char* expected, const char* label) {
	std::string value;
	const bool setup_ok =
		run_admin_checked(admin, "DELETE FROM pgsql_query_rules WHERE rule_id BETWEEN 61190 AND 61194") &&
		run_admin_checked(admin, insert_rule) &&
		run_admin_checked(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	const bool query_ok = setup_ok && get_single_value(proxy, query, value);
	ok(query_ok && value == expected, "%s (expected '%s', got '%s')", label, expected,
		query_ok ? value.c_str() : "<query failed>");
	return query_ok && value == expected;
}

static void run_negated_error_case(PGconn* admin, PGconn* proxy, const char* insert_rule) {
	std::string value;
	const bool setup_ok =
		run_admin_checked(admin, "DELETE FROM pgsql_query_rules WHERE rule_id BETWEEN 61190 AND 61194") &&
		run_admin_checked(admin, insert_rule) &&
		run_admin_checked(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	const bool matching_ok = setup_ok && get_single_value(proxy, "SELECT 8", value);
	ok(matching_ok && value == "8",
		"negated PCRE2 rule permits its matching statement (expected '8', got '%s')",
		matching_ok ? value.c_str() : "<query failed>");

	PGresult* result = setup_ok ? PQexec(proxy, "SELECT 7") : nullptr;
	const bool blocked = result != nullptr && PQresultStatus(result) == PGRES_FATAL_ERROR;
	const std::string error = result != nullptr ? PQresultErrorMessage(result) : "";
	ok(blocked && error.find("PCRE2 negated rule blocked") != std::string::npos,
		"negated PCRE2 rule blocks its non-matching statement with the configured error (got '%s')",
		result != nullptr ? error.c_str() : "<no result>");
	if (result != nullptr) {
		PQclear(result);
	}
}

int main(int, char**) {
	if (cl.getEnv()) {
		return -1;
	}

	plan(8);

	PGConnPtr admin = create_new_connection(ADMIN);
	PGConnPtr proxy = create_new_connection(BACKEND);
	if (!admin || !proxy) {
		return exit_status();
	}

	std::string original_regex;
	const bool configured =
		get_single_value(admin.get(),
			"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-query_processor_regex'",
			original_regex) &&
		run_admin_checked(admin.get(), "SET pgsql-query_processor_regex=1") &&
		run_admin_checked(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");

	if (configured) {
		run_rewrite_case(admin.get(), proxy.get(),
			"INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61190, 1, '[0-9]', '9', 'CASELESS', 1)",
			"SELECT 1 + 2", "11", "PCRE-compatible mode replaces one match");
		run_rewrite_case(admin.get(), proxy.get(),
			"INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61191, 1, '[0-9]', '9', 'CASELESS,GLOBAL', 1)",
			"SELECT 1 + 2", "18", "PCRE-compatible mode replaces all matches with GLOBAL");
		run_rewrite_case(admin.get(), proxy.get(),
			"INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61192, 1, '^SELECT ([0-9]+)$', 'SELECT ''\\0:'' || ''\\1''', 'CASELESS', 1)",
			"SELECT 1", "SELECT 1:1", "PCRE-compatible mode expands legacy whole-match and capture references");
		run_rewrite_case(admin.get(), proxy.get(),
			"INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61193, 1, 'TOKEN', '\\\\*/ + 1 /*', 'CASELESS', 1)",
			"SELECT 1 /*TOKEN*/", "2", "PCRE-compatible replacement emits a legacy literal backslash");
		run_rewrite_case(admin.get(), proxy.get(),
			"INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61194, 1, '^SELECT 7$', 'SELECT \\x', 'CASELESS', 1)",
			"SELECT 7", "7", "malformed legacy escape leaves the query unchanged");
		run_rewrite_case(admin.get(), proxy.get(),
			"INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61190, 1, '^SELECT ''[A-Z]''$', 'SELECT 9', 'CASELESS', 1)",
			"SELECT 'a'", "9", "CASELESS PCRE-compatible replacement matches different-case text");
		run_negated_error_case(admin.get(), proxy.get(),
			"INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, negate_match_pattern, error_msg, re_modifiers, apply) "
			"VALUES (61194, 1, '^SELECT 8$', 1, 'PCRE2 negated rule blocked', 'CASELESS', 1)");
	} else {
		for (int i = 0; i < 8; ++i) {
			ok(0, "could not configure pgsql-query_processor_regex for PCRE-compatible rewrite test");
		}
	}

	const bool teardown_ok =
		run_admin_checked(admin.get(), "DELETE FROM pgsql_query_rules WHERE rule_id BETWEEN 61190 AND 61194") &&
		run_admin_checked(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME") &&
		(!original_regex.empty() &&
		 run_admin_checked(admin.get(), ("SET pgsql-query_processor_regex=" + original_regex).c_str()) &&
		 run_admin_checked(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME"));
	if (!teardown_ok) {
		diag("Failed to restore PostgreSQL query-rule test state");
	}

	return exit_status();
}
