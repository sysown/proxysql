#include <stdlib.h>
#include "tap.h"
#include "unit_test.h"
#include "gen_utils.h"

using std::string;
using std::vector;

/**
 * Unit test for strip_schema_from_query() function
 * 
 * This test validates the functionality of stripping
 * schema prefixes from SQL queries.
 */

struct Args {
	const char* query;
	const char* schema;
	vector<string> tables;
	bool ansi_quotes = false;
};

struct TestCase {
	const char* name;
	Args args;
	const char* expected;
};

int main(int argc, char** argv) {
	TestCase test_table[] = {
		{
			"Basic schema stripping",
			{
				"SELECT * FROM stats.stats_mysql_query_digest",
				"stats",
			},
			"SELECT * FROM stats_mysql_query_digest",

		},
		{
			"Multiple schema references stripped",
			{
				"SELECT * FROM stats.table1 JOIN stats.table2",
				"stats",
			},
			"SELECT * FROM table1 JOIN table2",
		},
		{
			"Quoted schema with backticks",
			{
				"SELECT * FROM `stats`.`stats_mysql_query_digest`",
				"stats",
			},
			"SELECT * FROM `stats_mysql_query_digest`",
		},
		{
			"ANSI quotes mode",
			{
				"SELECT * FROM \"stats\".\"table1\"",
				"stats",
				{},
				true
			},
			"SELECT * FROM \"table1\"",
		},
		{
			"Mixed quoted/unquoted identifiers",
			{
				"SELECT * FROM stats.`table1`, `stats`.table2",
				"stats",
			},
			"SELECT * FROM `table1`, table2",
		},
		{
			"Schema in string literal preserved",
			{
				"SELECT * FROM stats.table1 WHERE name='stats.other'",
				"stats",
			},
			"SELECT * FROM table1 WHERE name='stats.other'",
		},
		{
			"Whitespace around dot handled",
			{
				"SELECT * FROM stats . stats_mysql_query_digest",
				"stats",
			},
			"SELECT * FROM stats_mysql_query_digest",
		},
		{
			"No schema prefix, query unchanged",
			{
				"SELECT * FROM stats_mysql_query_digest",
				"stats",
			},
			"SELECT * FROM stats_mysql_query_digest",
		},
		{
			"Empty query handled",
			{
				"",
				"stats",
			},
			"",
		},
		{
			"NULL query handled safely",
			{
				nullptr,
				"stats",
			},
			"",
		},
		{
			"Empty schema name, query unchanged",
			{
				"SELECT * FROM stats.table1",
				"",
			},
			"SELECT * FROM stats.table1",

		},
		{
			"Selective table filtering (match)",
			{
				"SELECT * FROM stats.table1, stats.table2",
				"stats",
				{"table1"},
			},
			"SELECT * FROM table1, stats.table2",
		},
		{
			"Selective table filtering (no match)",
			{
				"SELECT * FROM stats.table1",
				"stats",
				{"table2"},
			},
			"SELECT * FROM stats.table1",
		},
		{
			"Schema as substring not matched",
			{
				"SELECT * FROM mystats.table1",
				"stats",
			},
			"SELECT * FROM mystats.table1",
		},
		{
			"Case insensitive schema match",
			{
				"SELECT * FROM STATS.table1",
				"stats",
			},
			"SELECT * FROM table1",
		},
	};

	int num_tests = sizeof(test_table) / sizeof(test_table[0]);
	plan(num_tests);

	for (int i = 0; i < num_tests; i++) {
		TestCase& tc = test_table[i];
		string result = strip_schema_from_query(tc.args.query, tc.args.schema, tc.args.tables, tc.args.ansi_quotes);
		ok(result == tc.expected, "%s: '%s'", tc.name, result.c_str());
	}

	return exit_status();
}
