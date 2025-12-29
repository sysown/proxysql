/**
 * @file setparser_test.cpp
 * @brief Test file for unit testing 'SetParser' type, responsible of parsing
 *   non-trivial 'SET' statements.
 */

#include "setparser_test_common.h"

void TestParse(const Test* tests, int ntests, const std::string& title) {
  for (int i = 0; i < ntests; i++) {
    std::map<std::string, std::vector<std::string>> data;
    for(auto it = std::begin(tests[i].results); it != std::end(tests[i].results); ++it) {
      data[it->var] = it->values;
    }

	cout << "Processing query: " << tests[i].query << endl;
    MySQL_Set_Stmt_Parser parser(tests[i].query);
    std::map<std::string, std::vector<std::string>> result = parser.parse1();

	cout << endl;
    printMap("result", result);
	cout << endl;
    printMap("expected", data);
	cout << endl;

    CHECK_EQ(result.size(), data.size());
	ok(result.size() == data.size() , "Sizes match: %lu, %lu" , result.size() , data.size());
    CHECK(std::equal(std::begin(result), std::end(result), std::begin(data)));
	ok(std::equal(std::begin(result), std::end(result), std::begin(data)) == true, "Elements match");
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
	p += arraysize(Set1_v1);
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
	TestParse(Set1_v1, arraysize(Set1_v1), "Set1_v1");
	TestParse(syntax_errors, arraysize(syntax_errors), "syntax_errors");
	return exit_status();
}
