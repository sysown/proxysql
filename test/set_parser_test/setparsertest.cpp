#include "re2/re2.h"
#include "re2/regexp.h"
#include "util/test.h"
#include "set_parser.h"
#include <vector>
#include <map>
#include <algorithm>
#include <iostream>

int remove_spaces(const char *s) {
	char *inp = (char *)s, *outp = (char *)s;
	bool prev_space = false;
	bool fns = false;
	while (*inp) {
		if (isspace(*inp)) {
			if (fns) {
				if (!prev_space) {
					*outp++ = ' ';
					prev_space = true;
				}
			}
		} else {
			*outp++ = *inp;
			prev_space = false;
			if (!fns) fns=true;
		}
		++inp;
	}
	if (outp>s) {
		if (prev_space) {
			outp--;
		}
	}
	*outp = '\0';
	return strlen(s);
}

bool iequals(const string& a, const string& b)
{
    unsigned int sz = a.size();
    if (b.size() != sz)
        return false;
    for (unsigned int i = 0; i < sz; ++i)
        if (tolower(a[i]) != tolower(b[i]))
            return false;
    return true;
}

void printMap(const char* prefix, const std::map<std::string, std::vector<std::string>>& dict)
{
  std::cout << prefix << ": ";
  for(auto mapIt = begin(dict); mapIt != end(dict); ++mapIt)
  {
    std::cout << mapIt->first << " : ";

    for(auto c : mapIt->second)
    {
        std::cout << c << " ";
    }

    std::cout << std::endl;
  }
}

struct Expected {
  const char* var;
  std::vector<std::string> values;
  Expected(const char* var, std::vector<std::string> values): var(var), values(values){};
};

struct Test {
  const char* query;
  std::vector<Expected> results;
};

static Test sql_mode[] = {
  { "SET @@sql_mode = 'TRADITIONAL'", { Expected("sql_mode",  {"TRADITIONAL"}) } },
  { "SET SESSION sql_mode = 'TRADITIONAL'", { Expected("sql_mode", {"TRADITIONAL"}) } },
  { "SET @@session.sql_mode = 'TRADITIONAL'", { Expected("sql_mode",  {"TRADITIONAL"}) } },
  { "SET sql_mode = 'TRADITIONAL'", { Expected("sql_mode",  {"TRADITIONAL"}) } },
  { "SET SQL_MODE   ='TRADITIONAL'", { Expected("sql_mode",  {"TRADITIONAL"}) } },
  { "SET SQL_MODE  = \"TRADITIONAL\"", { Expected("sql_mode",  {"TRADITIONAL"}) } },
  { "SET SQL_MODE  = TRADITIONAL", { Expected("sql_mode",  {"TRADITIONAL"}) } },
  { "set sql_mode = IFNULL(NULL,\"STRICT_TRANS_TABLES\")", { Expected("sql_mode",  {"IFNULL(NULL,\"STRICT_TRANS_TABLES\")"}) } },
  { "set sql_mode = IFNULL(NULL,'STRICT_TRANS_TABLES')", { Expected("sql_mode",  {"IFNULL(NULL,'STRICT_TRANS_TABLES')"}) } },
  { "SET @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')", { Expected("sql_mode",  {"CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')"}) } },
  { "set session sql_mode = 'ONLY_FULL_GROUP_BY'" , { Expected("sql_mode",  {"ONLY_FULL_GROUP_BY"}) } },
  { "SET sql_mode = 'NO_ZERO_DATE,STRICT_ALL_TABLES,ONLY_FULL_GROUP_BY'" , { Expected("sql_mode",  {"NO_ZERO_DATE,STRICT_ALL_TABLES,ONLY_FULL_GROUP_BY"}) } },
  { "SET @@sql_mode = CONCAT(@@sql_mode, ',', 'ONLY_FULL_GROUP_BY')" , { Expected("sql_mode",  {"CONCAT(@@sql_mode, ',', 'ONLY_FULL_GROUP_BY')"}) } },
  { "SET @@sql_mode = REPLACE(REPLACE(REPLACE(@@sql_mode, 'ONLY_FULL_GROUP_BY,', ''),',ONLY_FULL_GROUP_BY', ''),'ONLY_FULL_GROUP_BY', '')" , { Expected("sql_mode",  {"REPLACE(REPLACE(REPLACE(@@sql_mode, 'ONLY_FULL_GROUP_BY,', ''),',ONLY_FULL_GROUP_BY', ''),'ONLY_FULL_GROUP_BY', '')"}) } },
  { "SET @@sql_mode = REPLACE( REPLACE( REPLACE( @@sql_mode, 'ONLY_FULL_GROUP_BY,', ''),',ONLY_FULL_GROUP_BY', ''),'ONLY_FULL_GROUP_BY', '')" , { Expected("sql_mode",  {"REPLACE( REPLACE( REPLACE( @@sql_mode, 'ONLY_FULL_GROUP_BY,', ''),',ONLY_FULL_GROUP_BY', ''),'ONLY_FULL_GROUP_BY', '')"}) } },
//	{ "SET @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')", { Expected("sql_mode",  {"CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')"}) } },
  { "SET SQL_MODE=IFNULL(@@sql_mode,'')", { Expected("sql_mode", { "IFNULL(@@sql_mode,'')" } ) } },
  { "SET SQL_MODE=IFNULL(@old_sql_mode,'')", { Expected("sql_mode", { "IFNULL(@old_sql_mode,'')" } ) } },
  { "SET SQL_MODE=IFNULL(@OLD_SQL_MODE,'')", { Expected("sql_mode", { "IFNULL(@OLD_SQL_MODE,'')" } ) } },
};

void TestParse(const Test* tests, int ntests, const string& title) {
  for (int i = 0; i < ntests; i++) {
    std::map<std::string, std::vector<std::string>> data;
    for(auto it = std::begin(tests[i].results); it != std::end(tests[i].results); ++it) {
      data[it->var] = it->values;
    }
    
    SetParser parser(tests[i].query);
    std::map<std::string, std::vector<std::string>> result = parser.parse();
    
    // printMap("result", result);
    // printMap("expected", data);

    CHECK_EQ(result.size(), data.size());
    CHECK(std::equal(std::begin(result), std::end(result), std::begin(data)));
  }
}


TEST(TestParse, SET_SQL_MODE) {
  TestParse(sql_mode, arraysize(sql_mode), "sql_mode");
}

static Test time_zone[] = {
  { "SET @@time_zone = 'Europe/Paris'", { Expected("time_zone",  {"Europe/Paris"}) } },
  { "SET @@time_zone = '+00:00'", { Expected("time_zone",  {"+00:00"}) } },
  { "SET @@time_zone = \"Europe/Paris\"", { Expected("time_zone",  {"Europe/Paris"}) } },
  { "SET @@time_zone = \"+00:00\"", { Expected("time_zone",  {"+00:00"}) } },
  { "SET @@time_zone = @OLD_TIME_ZONE", { Expected("time_zone",  {"@OLD_TIME_ZONE"}) } },
};

TEST(TestParse, SET_TIME_ZONE) {
  TestParse(time_zone, arraysize(time_zone), "time_zone");
}

static Test session_track_gtids[] = {
  { "SET @@session_track_gtids = OFF", { Expected("session_track_gtids",  {"OFF"}) } },
  { "SET @@session_track_gtids = OWN_GTID", { Expected("session_track_gtids",  {"OWN_GTID"}) } },
  { "SET @@SESSION.session_track_gtids = OWN_GTID", { Expected("session_track_gtids",  {"OWN_GTID"}) } },
  { "SET SESSION session_track_gtids = OWN_GTID", { Expected("session_track_gtids",  {"OWN_GTID"}) } },
  { "SET @@session_track_gtids = ALL_GTIDS", { Expected("session_track_gtids",  {"ALL_GTIDS"}) } },
  { "SET @@SESSION.session_track_gtids = ALL_GTIDS", { Expected("session_track_gtids",  {"ALL_GTIDS"}) } },
  { "SET SESSION session_track_gtids = ALL_GTIDS", { Expected("session_track_gtids",  {"ALL_GTIDS"}) } },
};

TEST(TestParse, SET_SESSION_TRACK_GTIDS) {
  TestParse(session_track_gtids, arraysize(session_track_gtids), "session_track_gtids");
}

static Test character_set_results[] = {
  { "SET @@character_set_results = utf8", { Expected("character_set_results",  {"utf8"}) } },
  { "SET @@character_set_results = NULL", { Expected("character_set_results",  {"NULL"}) } },
  { "SET character_set_results = NULL", { Expected("character_set_results",  {"NULL"}) } },
  { "SET @@session.character_set_results = NULL", { Expected("character_set_results",  {"NULL"}) } },
  { "SET session character_set_results = NULL", { Expected("character_set_results",  {"NULL"}) } },
};

TEST(TestParse, SET_CHARACTER_SET_RESULTS) {
  TestParse(character_set_results, arraysize(character_set_results), "character_set_results");
}

static Test names[] = {
  { "SET NAMES utf8", { Expected("names",  {"utf8"}) } },
  { "SET NAMES 'utf8'", { Expected("names",  {"utf8"}) } },
  { "SET NAMES \"utf8\"", { Expected("names",  {"utf8"}) } },
  { "SET NAMES utf8 COLLATE unicode_ci", { Expected("names",  {"utf8", "unicode_ci"}) } },
};

TEST(TestParse, SET_NAMES) {
  TestParse(names, arraysize(names), "names");
}

static Test multiple[] = {
  { "SET time_zone = 'Europe/Paris', sql_mode = 'TRADITIONAL'", { Expected("time_zone",  {"Europe/Paris"}), Expected("sql_mode", {"TRADITIONAL"}) } },
  { "SET time_zone = 'Europe/Paris', sql_mode = IFNULL(NULL,\"STRICT_TRANS_TABLES\")", { Expected("time_zone",  {"Europe/Paris"}), Expected("sql_mode", {"IFNULL(NULL,\"STRICT_TRANS_TABLES\")"}) } },
  { "SET sql_mode = 'TRADITIONAL', NAMES 'utf8 COLLATE 'unicode_ci'", { Expected("sql_mode",  {"TRADITIONAL"}), Expected("names", {"utf8", "unicode_ci"}) } },
  { "SET  @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO'),  @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483",
  { Expected("sql_mode",  {"CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO')"}), Expected("sql_auto_is_null", {"0"}),
  Expected("wait_timeout", {"2147483"}) } },
  { "set autocommit=1, sql_mode = concat(@@sql_mode,',STRICT_TRANS_TABLES')", { Expected("autocommit", {"1"}), Expected("sql_mode",  {"concat(@@sql_mode,',STRICT_TRANS_TABLES')"}) } },
  { "SET NAMES utf8, @@SESSION.sql_mode = CONCAT(REPLACE(REPLACE(REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', ''), 'STRICT_ALL_TABLES', ''), 'TRADITIONAL', ''), ',NO_AUTO_VALUE_ON_ZERO'), @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 3600",
  { Expected("names", {"utf8"}), Expected("sql_mode",  {"CONCAT(REPLACE(REPLACE(REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', ''), 'STRICT_ALL_TABLES', ''), 'TRADITIONAL', ''), ',NO_AUTO_VALUE_ON_ZERO')"}), Expected("sql_auto_is_null", {"0"}),
  Expected("wait_timeout", {"3600"}) } },
};

TEST(TestParse, MULTIPLE) {
  TestParse(multiple, arraysize(multiple), "multiple");
}
