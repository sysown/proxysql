/**
 * @file setparser_test.cpp
 * @brief Test file for unit testing 'SetParser' type, responsible of parsing
 *   non-trivial 'SET' statements.
 */

#include "setparser_test_common.h"

MySQL_Set_Stmt_Parser *parser = NULL;

void TestParse(const Test* tests, int ntests, const std::string& title) {
  for (int i = 0; i < ntests; i++) {
    std::map<std::string, std::vector<std::string>> data;
    for(auto it = std::begin(tests[i].results); it != std::end(tests[i].results); ++it) {
      data[it->var] = it->values;
    }

    //SetParser parser(tests[i].query, 1);
    //std::map<std::string, std::vector<std::string>> result = parser.parse1();
    //std::map<std::string, std::vector<std::string>> result = parser.parse1v2();

	cout << "Processing query: " << tests[i].query << endl;
	parser->set_query(tests[i].query);
    std::map<std::string, std::vector<std::string>> result = parser->parse1v2();

	cout << endl;
    printMap("result", result);
	cout << endl;
    printMap("expected", data);
	cout << endl;

    check_equal(result.size(), data.size(), __FILE__, __LINE__);
	ok(result.size() == data.size() , "Sizes match: %lu, %lu" , result.size() , data.size());
    check(std::equal(std::begin(result), std::end(result), std::begin(data)), "maps are equal", __FILE__, __LINE__);
	ok(std::equal(std::begin(result), std::end(result), std::begin(data)) == true, "Elements match");
  }
}


int main(int argc, char** argv) {
	unsigned int p = 0;
	p += std::size(sql_mode);
	p += std::size(time_zone);
	p += std::size(session_track_gtids);
	p += std::size(character_set_results);
	p += std::size(names);
	p += std::size(various);
	p += std::size(multiple);
	p += std::size(Set1_v2);
	p += std::size(syntax_errors);
	p *= 2;
	plan(p);
	parser = new MySQL_Set_Stmt_Parser("", 1);
	TestParse(sql_mode, std::size(sql_mode), "sql_mode");
	TestParse(time_zone, std::size(time_zone), "time_zone");
	TestParse(session_track_gtids, std::size(session_track_gtids), "session_track_gtids");
	TestParse(character_set_results, std::size(character_set_results), "character_set_results");
	TestParse(names, std::size(names), "names");
	TestParse(various, std::size(various), "various");
	TestParse(multiple, std::size(multiple), "multiple");
	TestParse(Set1_v2, std::size(Set1_v2), "Set1_v2");
	TestParse(syntax_errors, std::size(syntax_errors), "syntax_errors");
	return exit_status();
}
