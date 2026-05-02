/**
 * @file setparser_parsersql_test.cpp
 * @brief Validates that parsersql_parse_set_mysql() produces the same output
 *   as the existing MySQL_Set_Stmt_Parser for all SET statement test cases
 *   defined in setparser_test_common.h.
 *
 * Controlled by: mysql-set_parser_algorithm = 3
 *
 * Note: The AST-based parser normalizes quoting (double quotes to single quotes)
 * and whitespace, while the regex parser preserves raw text. The comparison
 * normalizes these cosmetic differences before checking equality.
 */

#include "setparser_test_common.h"
#include "Query_Processor_ParserSQL.h"

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
	p += arraysize(syntax_errors);
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
	TestParse(syntax_errors, arraysize(syntax_errors), "syntax_errors");
	return exit_status();
}
