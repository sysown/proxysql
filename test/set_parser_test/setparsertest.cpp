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
};

TEST(TestParse, SET_TIME_ZONE) {
  TestParse(time_zone, arraysize(time_zone), "time_zone");
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
  { "SET sql_mode = 'TRADITIONAL', NAMES 'utf8 COLLATE 'unicode_ci'", { Expected("sql_mode",  {"TRADITIONAL"}), Expected("names", {"utf8", "unicode_ci"}) } },
/* not supported by SetParser
  { "SET  @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO'),  @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483",
  { Expected("sql_mode",  {"CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO')"}), Expected("sql_auto_is_null", {"0"}),
  Expected("wait_timeout", {"2147483"}) } },
*/
};

TEST(TestParse, MULTIPLE) {
  TestParse(multiple, arraysize(multiple), "multiple");
}
