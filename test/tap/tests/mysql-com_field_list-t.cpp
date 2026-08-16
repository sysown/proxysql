#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

namespace {

struct ExpectedField {
	const char* name;
	enum enum_field_types type;
};

bool execute(MYSQL* mysql, const char* query) {
	if (mysql_query(mysql, query)) {
		diag("Query failed: %s -- %s", query, mysql_error(mysql));
		return false;
	}
	MYSQL_RES* result = mysql_store_result(mysql);
	if (result) {
		mysql_free_result(result);
	}
	return true;
}

long long translated_query_count(MYSQL* admin) {
	const char* query =
		"SELECT COALESCE(SUM(count_star), 0) FROM stats_mysql_query_digest "
		"WHERE digest_text LIKE '%com_field_list_coverage%' "
		"AND digest_text LIKE 'SELECT%'";
	if (mysql_query(admin, query)) {
		diag("Failed to read translated COM_FIELD_LIST digest: %s", mysql_error(admin));
		return -1;
	}

	MYSQL_RES* result = mysql_store_result(admin);
	if (!result) {
		diag("No result while reading translated COM_FIELD_LIST digest: %s", mysql_error(admin));
		return -1;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	const long long count = row && row[0] ? strtoll(row[0], nullptr, 10) : -1;
	mysql_free_result(result);
	return count;
}

} // namespace

int main(int, char**) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	plan(10);

	MYSQL* admin = mysql_init(nullptr);
	MYSQL* proxy = mysql_init(nullptr);
	if (!admin || !proxy) {
		diag("mysql_init failed");
		if (admin) mysql_close(admin);
		if (proxy) mysql_close(proxy);
		return exit_status();
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		diag("Admin connection failed: %s", mysql_error(admin));
		mysql_close(proxy);
		mysql_close(admin);
		return exit_status();
	}
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		diag("ProxySQL connection failed: %s", mysql_error(proxy));
		mysql_close(proxy);
		mysql_close(admin);
		return exit_status();
	}

	const bool schema_ready =
		execute(proxy, "CREATE DATABASE IF NOT EXISTS test") &&
		execute(proxy, "DROP TABLE IF EXISTS test.com_field_list_coverage") &&
		execute(proxy,
			"CREATE TABLE test.com_field_list_coverage ("
			"id INT NOT NULL, "
			"label VARCHAR(32) NOT NULL, "
			"amount DECIMAL(10,2) NOT NULL, "
			"created_at TIMESTAMP NULL"
			")");
	ok(schema_ready, "Created table used by COM_FIELD_LIST");
	if (!schema_ready) {
		mysql_close(proxy);
		mysql_close(admin);
		return exit_status();
	}

	const bool selected_schema = mysql_select_db(proxy, "test") == 0;
	ok(selected_schema, "Selected test schema before mysql_list_fields");
	if (!selected_schema) {
		diag("mysql_select_db failed: %s", mysql_error(proxy));
		mysql_close(proxy);
		mysql_close(admin);
		return exit_status();
	}

	if (!execute(admin, "TRUNCATE stats_mysql_query_digest")) {
		mysql_close(proxy);
		mysql_close(admin);
		return exit_status();
	}

	MYSQL_RES* fields = mysql_list_fields(proxy, "com_field_list_coverage", nullptr);
	ok(fields != nullptr, "mysql_list_fields without wildcard succeeds through ProxySQL");
	if (!fields) {
		diag("mysql_list_fields failed: %s", mysql_error(proxy));
		mysql_close(proxy);
		mysql_close(admin);
		return exit_status();
	}

	const ExpectedField expected_fields[] = {
		{ "id", MYSQL_TYPE_LONG },
		// COM_FIELD_LIST is translated to SELECT * ... WHERE 1=0. MySQL returns
		// VARCHAR metadata for a SELECT as MYSQL_TYPE_VAR_STRING.
		{ "label", MYSQL_TYPE_VAR_STRING },
		{ "amount", MYSQL_TYPE_NEWDECIMAL },
		{ "created_at", MYSQL_TYPE_TIMESTAMP },
	};
	const unsigned int expected_field_count = sizeof(expected_fields) / sizeof(expected_fields[0]);
	const unsigned int field_count = mysql_num_fields(fields);
	ok(field_count == expected_field_count, "COM_FIELD_LIST returns all four table fields");
	MYSQL_FIELD* actual_fields = mysql_fetch_fields(fields);
	for (unsigned int i = 0; i < expected_field_count; ++i) {
		const bool matches = i < field_count &&
			strcmp(actual_fields[i].name, expected_fields[i].name) == 0 &&
			actual_fields[i].type == expected_fields[i].type;
		ok(matches, "COM_FIELD_LIST returns %s with its expected MySQL type", expected_fields[i].name);
	}
	mysql_free_result(fields);

	fields = mysql_list_fields(proxy, "com_field_list_coverage", "lab%");
	const bool wildcard_matches = fields && mysql_num_fields(fields) == 1 &&
		strcmp(mysql_fetch_fields(fields)[0].name, "label") == 0;
	ok(wildcard_matches, "mysql_list_fields wildcard returns only the matching field");
	if (fields) {
		mysql_free_result(fields);
	}

	ok(
		translated_query_count(admin) >= 2,
		"Both COM_FIELD_LIST calls reached the backend as translated SELECT queries"
	);

	mysql_close(proxy);
	mysql_close(admin);
	return exit_status();
}
