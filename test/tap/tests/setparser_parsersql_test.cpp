/**
 * @file setparser_parsersql_test.cpp
 * @brief Validates that parsersql_parse_set_{mysql,pgsql}() produces the same
 *   output as the existing MySQL_Set_Stmt_Parser for all SET statement test
 *   cases defined in setparser_test_common.h.
 *
 * Controlled by: mysql-set_parser_algorithm = 3 / pgsql-set_parser_algorithm = 3
 *
 * Note: The AST-based parser normalizes quoting (double quotes to single quotes)
 * and whitespace, while the regex parser preserves raw text. The comparison
 * normalizes these cosmetic differences before checking equality.
 *
 * The PostgreSQL test groups (search_path multi-value, TIME ZONE alias) are
 * the regression net for ParserSQL v1.0.3's PG SET fixes — they exercise the
 * library + adapter end-to-end without needing a live backend.
 */

#include "setparser_test_common.h"
#include "Query_Processor_ParserSQL.h"

static Test parsersql_syntax_errors[] = {
  { "SET sql_mode=(SELECT CONCA(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))",
    { Expected("sql_mode", { "(SELECT CONCA(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))" } ) } },
  { "SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))",
    { Expected("sql_mode", { "(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))" } ) } },
  { "SET sql_mode=(SELCT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))",
    { Expected("sql_mode", { "SELCT" } ) } },
};

// ----------------------------------------------------------------------------
// MySQL queries from test_filtered_set_statements-t (variables that ProxySQL
// is supposed to filter out — should still parse cleanly via ParserSQL).
// ----------------------------------------------------------------------------
static Test parsersql_mysql_filtered_set[] = {
  { "SET wait_timeout=28801",                  { Expected("wait_timeout",          {"28801"}) } },
  { "SET @@wait_timeout = 28801",              { Expected("wait_timeout",          {"28801"}) } },
  { "SET SESSION wait_timeout = 28801",        { Expected("wait_timeout",          {"28801"}) } },
  { "SET `wait_timeout` = 28801",              { Expected("wait_timeout",          {"28801"}) } },
  { "SET character_set_results=latin1",        { Expected("character_set_results", {"latin1"}) } },
  { "SET autocommit=1",                        { Expected("autocommit",            {"1"}) } },
  { "SET max_join_size=18446744073709551615",  { Expected("max_join_size",         {"18446744073709551615"}) } },
};

// MySQL multi-variable SET cases sampled from set_testing-240.csv (the fixture
// driving set_testing-t). Exercises comma-separated multi-variable parsing.
static Test parsersql_mysql_set_testing[] = {
  { "SET aurora_read_replica_read_committed=Off, auto_increment_increment=320, sql_select_limit=3656, sql_quote_show_create=\"OFF\"",
    { Expected("aurora_read_replica_read_committed", {"Off"}),
      Expected("auto_increment_increment",           {"320"}),
      Expected("sql_quote_show_create",              {"OFF"}),
      Expected("sql_select_limit",                   {"3656"}) } },
  { "SET max_heap_table_size=19456, log_slow_filter=`not_using_index`",
    { Expected("log_slow_filter",     {"not_using_index"}),
      Expected("max_heap_table_size", {"19456"}) } },
  { "SET lock_wait_timeout=431, sql_safe_updates=1, aurora_read_replica_read_committed=\"ON\", max_execution_time=13940",
    { Expected("aurora_read_replica_read_committed", {"ON"}),
      Expected("lock_wait_timeout",                  {"431"}),
      Expected("max_execution_time",                 {"13940"}),
      Expected("sql_safe_updates",                   {"1"}) } },
  { "SET session_track_gtids=OWN_GTID, optimizer_switch=\"index_merge_union=off\", foreign_key_checks=`OFF`, aurora_read_replica_read_committed=OFF",
    { Expected("aurora_read_replica_read_committed", {"OFF"}),
      Expected("foreign_key_checks",                 {"OFF"}),
      Expected("optimizer_switch",                   {"index_merge_union=off"}),
      Expected("session_track_gtids",                {"OWN_GTID"}) } },
};

// ----------------------------------------------------------------------------
// PostgreSQL search_path tests — pgsql-set_parameter_validation_test-t shapes.
// Pre-ParserSQL-1.0.3 the multi-value cases silently dropped every value past
// the first; the v1.0.3 fix retains them under the same VAR_ASSIGNMENT node
// and the ProxySQL adapter walks every RHS sibling.
// ----------------------------------------------------------------------------
static Test parsersql_pgsql_search_path[] = {
  { "SET search_path TO \"$user\", public",       { Expected("search_path", {"$user", "public"}) } },
  { "SET search_path TO \"$user\",public",        { Expected("search_path", {"$user", "public"}) } },
  { "SET search_path = '\"$user\"   ,    public'", { Expected("search_path", {"\"$user\"   ,    public"}) } },
  { "SET search_path = 'public '",                { Expected("search_path", {"public "}) } },
  { "SET search_path = \"$user\"",                { Expected("search_path", {"$user"}) } },
  { "SET search_path = '$user'",                  { Expected("search_path", {"$user"}) } },
  { "SET search_path = ''",                       { Expected("search_path", {""}) } },
  { "SET search_path = public",                   { Expected("search_path", {"public"}) } },
};

// PostgreSQL TIME ZONE tests — pgsql-set_statement_test-t shapes.
// Pre-ParserSQL-1.0.3 these were parsed as `time = ZONE` and the rest of the
// statement was dropped. The v1.0.3 fix recognizes "TIME ZONE" as the PG
// alias for `SET TimeZone = ...` and walks the trailing expression.
// NOTE: `INTERVAL '7' HOUR` is captured as `INTERVAL` only — the expression
// parser does not yet consume the full interval modifier chain. The test
// reflects the *current* observable behaviour.
static Test parsersql_pgsql_time_zone[] = {
  { "SET TIME ZONE 'UTC'",                 { Expected("timezone", {"UTC"}) } },
  { "SET TIME ZONE DEFAULT",               { Expected("timezone", {"DEFAULT"}) } },
  { "SET TIME ZONE '+05:30'",              { Expected("timezone", {"+05:30"}) } },
  { "SET TIME ZONE INTERVAL '7' HOUR",     { Expected("timezone", {"INTERVAL"}) } },
};

static std::string normalize_value(const std::string& s) {
	std::string r;
	r.reserve(s.size());
	for (size_t i = 0; i < s.size(); i++) {
		char c = s[i];
		if (c == '"') c = '\'';
		if (c != ' ' && c != '\t' && c != '\n' && c != '\r') r += c;
	}
	return r;
}

static bool values_match(const std::vector<std::string>& a, const std::vector<std::string>& b) {
	if (a.size() != b.size()) return false;
	for (size_t i = 0; i < a.size(); i++) {
		if (normalize_value(a[i]) != normalize_value(b[i])) return false;
	}
	return true;
}

static bool maps_match(
	const std::map<std::string, std::vector<std::string>>& result,
	const std::map<std::string, std::vector<std::string>>& expected)
{
	if (result.size() != expected.size()) return false;
	auto ri = result.begin();
	auto ei = expected.begin();
	for (; ri != result.end() && ei != expected.end(); ++ri, ++ei) {
		if (ri->first != ei->first) return false;
		if (!values_match(ri->second, ei->second)) return false;
	}
	return true;
}

void TestParse(const Test* tests, int ntests, const std::string& title) {
	for (int i = 0; i < ntests; i++) {
		std::map<std::string, std::vector<std::string>> data;
		for (auto it = std::begin(tests[i].results); it != std::end(tests[i].results); ++it) {
			data[it->var] = it->values;
		}

		std::map<std::string, std::vector<std::string>> result = parsersql_parse_set_mysql(tests[i].query);

		bool size_ok = (result.size() == data.size());
		ok(size_ok, "[%s %d] Sizes match: %lu, %lu", title.c_str(), i, result.size(), data.size());
		if (!size_ok) {
			diag("  FAIL: sizes differ for query: %s", tests[i].query);
		}

		bool elem_ok = maps_match(result, data);
		ok(elem_ok, "[%s %d] Elements match", title.c_str(), i);
		if (!elem_ok) {
			diag("  FAIL: elements differ for query: %s", tests[i].query);
			for (auto& kv : result) {
				diag("    result[%s] = %s", kv.first.c_str(), normalize_value(kv.second.empty() ? "" : kv.second[0]).c_str());
			}
			for (auto& kv : data) {
				diag("    expected[%s] = %s", kv.first.c_str(), normalize_value(kv.second.empty() ? "" : kv.second[0]).c_str());
			}
		}
	}
}


// Parallel TestParse for PostgreSQL — same shape, dispatches to parsersql_parse_set_pgsql.
void TestParsePgsql(const Test* tests, int ntests, const std::string& title) {
	for (int i = 0; i < ntests; i++) {
		std::map<std::string, std::vector<std::string>> data;
		for (auto it = std::begin(tests[i].results); it != std::end(tests[i].results); ++it) {
			data[it->var] = it->values;
		}

		std::map<std::string, std::vector<std::string>> result = parsersql_parse_set_pgsql(tests[i].query);

		bool size_ok = (result.size() == data.size());
		ok(size_ok, "[%s %d] Sizes match: %lu, %lu", title.c_str(), i, result.size(), data.size());
		if (!size_ok) {
			diag("  FAIL: sizes differ for query: %s", tests[i].query);
		}

		bool elem_ok = maps_match(result, data);
		ok(elem_ok, "[%s %d] Elements match", title.c_str(), i);
		if (!elem_ok) {
			diag("  FAIL: elements differ for query: %s", tests[i].query);
			for (auto& kv : result) {
				std::string joined;
				for (size_t j = 0; j < kv.second.size(); j++) {
					if (j) joined += " | ";
					joined += kv.second[j];
				}
				diag("    result[%s] = [%s]", kv.first.c_str(), joined.c_str());
			}
			for (auto& kv : data) {
				std::string joined;
				for (size_t j = 0; j < kv.second.size(); j++) {
					if (j) joined += " | ";
					joined += kv.second[j];
				}
				diag("    expected[%s] = [%s]", kv.first.c_str(), joined.c_str());
			}
		}
	}
}


int main(int argc, char** argv) {
	unsigned int p = 0;
	p += arraysize(sql_mode);
	p += arraysize(time_zone);
	p += arraysize(session_track_gtids);
	p += arraysize(character_set_results);
	p += arraysize(names);
	p += arraysize(various);
	p += arraysize(multiple);
	p += arraysize(Set1_v2);
	p += arraysize(parsersql_syntax_errors);
	p += arraysize(parsersql_mysql_filtered_set);
	p += arraysize(parsersql_mysql_set_testing);
	p += arraysize(parsersql_pgsql_search_path);
	p += arraysize(parsersql_pgsql_time_zone);
	p *= 2;
	plan(p);
	TestParse(sql_mode, arraysize(sql_mode), "sql_mode");
	TestParse(time_zone, arraysize(time_zone), "time_zone");
	TestParse(session_track_gtids, arraysize(session_track_gtids), "session_track_gtids");
	TestParse(character_set_results, arraysize(character_set_results), "character_set_results");
	TestParse(names, arraysize(names), "names");
	TestParse(various, arraysize(various), "various");
	TestParse(multiple, arraysize(multiple), "multiple");
	TestParse(Set1_v2, arraysize(Set1_v2), "Set1_v2");
	TestParse(parsersql_syntax_errors, arraysize(parsersql_syntax_errors), "parsersql_syntax_errors");
	TestParse(parsersql_mysql_filtered_set, arraysize(parsersql_mysql_filtered_set), "mysql_filtered_set");
	TestParse(parsersql_mysql_set_testing, arraysize(parsersql_mysql_set_testing), "mysql_set_testing");
	TestParsePgsql(parsersql_pgsql_search_path, arraysize(parsersql_pgsql_search_path), "pgsql_search_path");
	TestParsePgsql(parsersql_pgsql_time_zone, arraysize(parsersql_pgsql_time_zone), "pgsql_time_zone");

	return exit_status();
}
