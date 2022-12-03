/**
 * @file setparser_test.cpp
 * @brief Test file for unit testing 'SetParser' type, responsible of parsing
 *   non-trivial 'SET' statements. This test is executed via the wrapper tap test
 *   'setparser_test-t'.
 *   This file is an extension of ../../set_parser_test/setparsertest.cpp
 */

// NOTE: Avoids the definition of 'global_variables glovars' in 'proxysql_structs.h'
#define PROXYSQL_EXTERN
// NOTE: Avoids definition of 'proxy_sqlite3_*' functions as 'extern'
#define MAIN_PROXY_SQLITE3

#include "re2/re2.h"
#include "re2/regexp.h"
#include "util/test.h"
#include "set_parser.h"
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <iostream>

// *******************************************************************************************
/**
 * TODO: This should be fixed once we have improved include hierarchy. All the following
 * includes are required to avoid the following linker error related to 'GloMyLdapAuth':
 *
 * ```
 * /usr/bin/ld: ../../../lib/libproxysql.a(ProxySQL_GloVars.oo): in function `ProxySQL_GlobalVariables::generate_global_checksum()':
 * /home/javjarfer/Projects/proxysql_v2.2.0/lib/ProxySQL_GloVars.cpp:374: undefined reference to `GloMyLdapAuth'
 * ```
 *
 * For now we just declare it locally to avoid the linking error.
 */
#include "openssl/ssl.h"
#include "proxysql_structs.h"
#include "sqlite3db.h"
#include "MySQL_LDAP_Authentication.hpp"
MySQL_LDAP_Authentication *GloMyLdapAuth = nullptr;
// ******************************************************************************************

bool iequals(const std::string& a, const std::string& b)
{
    unsigned int sz = a.size();
    if (b.size() != sz)
        return false;
    for (unsigned int i = 0; i < sz; ++i)
        if (tolower(a[i]) != tolower(b[i]))
            return false;
    return true;
}

void printMap(const std::string query, std::map<std::string, std::vector<std::string>> map) {
	std::cout << "Query: " << query << "\r\n";
	for (const auto& entry : map) {
		std::cout << "  - Key: " << entry.first << "\r\n";

		for (const auto& value : entry.second) {
			std::cout << "    + Value: " << value << "\r\n";
		}
	}

	std::cout << "\r\n";
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
  { "SET @@local.sql_mode = 'TRADITIONAL'", { Expected("sql_mode",  {"TRADITIONAL"}) } },
  { "SET sql_mode = 'TRADITIONAL'", { Expected("sql_mode",  {"TRADITIONAL"}) } },
  { "SET SQL_MODE   ='TRADITIONAL'", { Expected("sql_mode",  {"TRADITIONAL"}) } },
  { "SET SQL_MODE  = \"TRADITIONAL\"", { Expected("sql_mode",  {"TRADITIONAL"}) } },
  { "SET SQL_MODE  = TRADITIONAL", { Expected("sql_mode",  {"TRADITIONAL"}) } },
  { "set sql_mode = IFNULL(NULL,\"STRICT_TRANS_TABLES\")", { Expected("sql_mode",  {"IFNULL(NULL,\"STRICT_TRANS_TABLES\")"}) } },
  { "set sql_mode = IFNULL(NULL,'STRICT_TRANS_TABLES')", { Expected("sql_mode",  {"IFNULL(NULL,'STRICT_TRANS_TABLES')"}) } },
  { "SET @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')", { Expected("sql_mode",  {"CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')"}) } },
  { "SET @@LOCAL.sql_mode = CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')", { Expected("sql_mode",  {"CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')"}) } },
  { "set session sql_mode = 'ONLY_FULL_GROUP_BY'" , { Expected("sql_mode",  {"ONLY_FULL_GROUP_BY"}) } },
  { "SET sql_mode = 'NO_ZERO_DATE,STRICT_ALL_TABLES,ONLY_FULL_GROUP_BY'" , { Expected("sql_mode",  {"NO_ZERO_DATE,STRICT_ALL_TABLES,ONLY_FULL_GROUP_BY"}) } },
  { "SET @@sql_mode = CONCAT(@@sql_mode, ',', 'ONLY_FULL_GROUP_BY')" , { Expected("sql_mode",  {"CONCAT(@@sql_mode, ',', 'ONLY_FULL_GROUP_BY')"}) } },
  { "SET @@sql_mode = REPLACE(REPLACE(REPLACE(@@sql_mode, 'ONLY_FULL_GROUP_BY,', ''),',ONLY_FULL_GROUP_BY', ''),'ONLY_FULL_GROUP_BY', '')" , { Expected("sql_mode",  {"REPLACE(REPLACE(REPLACE(@@sql_mode, 'ONLY_FULL_GROUP_BY,', ''),',ONLY_FULL_GROUP_BY', ''),'ONLY_FULL_GROUP_BY', '')"}) } },
  { "SET @@sql_mode = REPLACE( REPLACE( REPLACE( @@sql_mode, 'ONLY_FULL_GROUP_BY,', ''),',ONLY_FULL_GROUP_BY', ''),'ONLY_FULL_GROUP_BY', '')" , { Expected("sql_mode",  {"REPLACE( REPLACE( REPLACE( @@sql_mode, 'ONLY_FULL_GROUP_BY,', ''),',ONLY_FULL_GROUP_BY', ''),'ONLY_FULL_GROUP_BY', '')"}) } },
//	{ "SET @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')", { Expected("sql_mode",  {"CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')"}) } },
  { "SET SQL_MODE=IFNULL(@@sql_mode,'')", { Expected("sql_mode", { "IFNULL(@@sql_mode,'')" } ) } },
  { "SET SQL_MODE=IFNULL(@old_sql_mode,'')", { Expected("sql_mode", { "IFNULL(@old_sql_mode,'')" } ) } },
	  { "SET SQL_MODE=IFNULL(@OLD_SQL_MODE,'')", { Expected("sql_mode", { "IFNULL(@OLD_SQL_MODE,'')" } ) } },
  // Complex queries involving 'SELECT' and surrounding parenthesis should be parsed properly
  { "SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))", { Expected("sql_mode", { "(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))" } ) } },
  { "SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION')), time_zone = '+00:00', NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
    {
      Expected("sql_mode", { "(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))" } ),
      Expected("time_zone", { "+00:00" } ),
      Expected("names",  {"utf8mb4", "utf8mb4_unicode_ci"} )
    }
  },
  // Empty set of 'sql_mode' should result into an empty value
  { "SET sql_mode=''", { Expected("sql_mode", { "" } ) } },
  // Invalid 'non-matching' versions of 'sql_mode' should result into 'non-matching'
  { "SET sql_mode=(SELECT CONCA(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))", {} },
  { "SET sql_mode=(SELECT CONCAT(@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))", {} },
  { "SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))", {} },
  { "SET sql_mode=(SELCT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))", {} }
};

void TestParse(const Test* tests, int ntests, const std::string& title) {
  for (int i = 0; i < ntests; i++) {
    std::map<std::string, std::vector<std::string>> data;
    for(auto it = std::begin(tests[i].results); it != std::end(tests[i].results); ++it) {
      data[it->var] = it->values;
    }

    SetParser parser(tests[i].query);
    std::map<std::string, std::vector<std::string>> result = parser.parse1();

    printMap("result", result);
    printMap("expected", data);

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
  { "SET @@TIME_ZONE = @OLD_TIME_ZONE", { Expected("time_zone",  {"@OLD_TIME_ZONE"}) } },
};

TEST(TestParse, SET_TIME_ZONE) {
  TestParse(time_zone, arraysize(time_zone), "time_zone");
}

static Test session_track_gtids[] = {
  { "SET @@session_track_gtids = OFF", { Expected("session_track_gtids",  {"OFF"}) } },
  { "SET @@session_track_gtids = OWN_GTID", { Expected("session_track_gtids",  {"OWN_GTID"}) } },
  { "SET @@SESSION.session_track_gtids = OWN_GTID", { Expected("session_track_gtids",  {"OWN_GTID"}) } },
  { "SET @@LOCAL.session_track_gtids = OWN_GTID", { Expected("session_track_gtids",  {"OWN_GTID"}) } },
  { "SET SESSION session_track_gtids = OWN_GTID", { Expected("session_track_gtids",  {"OWN_GTID"}) } },
  { "SET @@session_track_gtids = ALL_GTIDS", { Expected("session_track_gtids",  {"ALL_GTIDS"}) } },
  { "SET @@SESSION.session_track_gtids = ALL_GTIDS", { Expected("session_track_gtids",  {"ALL_GTIDS"}) } },
  { "SET @@LOCAL.session_track_gtids = ALL_GTIDS", { Expected("session_track_gtids",  {"ALL_GTIDS"}) } },
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
  { "SET @@local.character_set_results = NULL", { Expected("character_set_results",  {"NULL"}) } },
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
static Test various[] = {
  { "SET @@SESSION.SQL_SELECT_LIMIT= DEFAULT", { Expected("sql_select_limit",  {"DEFAULT"}) } },
  { "SET @@LOCAL.SQL_SELECT_LIMIT= DEFAULT", { Expected("sql_select_limit",  {"DEFAULT"}) } },
  { "SET @@SQL_SELECT_LIMIT= DEFAULT", { Expected("sql_select_limit",  {"DEFAULT"}) } },
  { "SET SESSION SQL_SELECT_LIMIT   = DEFAULT", { Expected("sql_select_limit",  {"DEFAULT"}) } },
  { "SET @@SESSION.SQL_SELECT_LIMIT= 1234", { Expected("sql_select_limit",  {"1234"}) } },
  { "SET @@LOCAL.SQL_SELECT_LIMIT= 1234", { Expected("sql_select_limit",  {"1234"}) } },
  { "SET @@SQL_SELECT_LIMIT= 1234", { Expected("sql_select_limit",  {"1234"}) } },
  { "SET SESSION SQL_SELECT_LIMIT   = 1234", { Expected("sql_select_limit",  {"1234"}) } },
  { "SET @@SESSION.SQL_SELECT_LIMIT= 1234", { Expected("sql_select_limit",  {"1234"}) } },
  { "SET @@LOCAL.SQL_SELECT_LIMIT= 1234", { Expected("sql_select_limit",  {"1234"}) } },
  { "SET @@SESSION.SQL_SELECT_LIMIT= @old_sql_select_limit", { Expected("sql_select_limit",  {"@old_sql_select_limit"}) } },
  { "SET @@LOCAL.SQL_SELECT_LIMIT= @old_sql_select_limit", { Expected("sql_select_limit",  {"@old_sql_select_limit"}) } },
  { "SET SQL_SELECT_LIMIT= @old_sql_select_limit", { Expected("sql_select_limit",  {"@old_sql_select_limit"}) } },
  { "SET @@SESSION.sql_auto_is_null = 0", { Expected("sql_auto_is_null",  {"0"}) } },
  { "SET @@LOCAL.sql_auto_is_null = 0", { Expected("sql_auto_is_null",  {"0"}) } },
  { "SET SESSION sql_auto_is_null = 1", { Expected("sql_auto_is_null",  {"1"}) } },
  { "SET sql_auto_is_null = OFF", { Expected("sql_auto_is_null",  {"OFF"}) } },
  { "SET @@sql_auto_is_null = ON", { Expected("sql_auto_is_null",  {"ON"}) } },
  { "SET @@SESSION.sql_safe_updates = 0", { Expected("sql_safe_updates",  {"0"}) } },
  { "SET @@LOCAL.sql_safe_updates = 0", { Expected("sql_safe_updates",  {"0"}) } },
  { "SET SESSION sql_safe_updates = 1", { Expected("sql_safe_updates",  {"1"}) } },
  { "SET SQL_SAFE_UPDATES = OFF", { Expected("sql_safe_updates",  {"OFF"}) } },
  { "SET @@sql_safe_updates = ON", { Expected("sql_safe_updates",  {"ON"}) } },
};

TEST(TestParse, SET_VARIOUS) {
  TestParse(various, arraysize(various), "various");
}

static Test multiple[] = {
  { "SET time_zone = 'Europe/Paris', sql_mode = 'TRADITIONAL'", { Expected("time_zone",  {"Europe/Paris"}), Expected("sql_mode", {"TRADITIONAL"}) } },
  { "SET time_zone = 'Europe/Paris', sql_mode = IFNULL(NULL,\"STRICT_TRANS_TABLES\")", { Expected("time_zone",  {"Europe/Paris"}), Expected("sql_mode", {"IFNULL(NULL,\"STRICT_TRANS_TABLES\")"}) } },
  { "SET sql_mode = 'TRADITIONAL', NAMES 'utf8 COLLATE 'unicode_ci'", { Expected("sql_mode",  {"TRADITIONAL"}), Expected("names", {"utf8", "unicode_ci"}) } },
  { "SET  @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO'),  @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483",
  { Expected("sql_mode",  {"CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO')"}), Expected("sql_auto_is_null", {"0"}),
  Expected("wait_timeout", {"2147483"}) } },
  { "SET  @@LOCAL.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO'),  @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483",
  { Expected("sql_mode",  {"CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO')"}), Expected("sql_auto_is_null", {"0"}),
  Expected("wait_timeout", {"2147483"}) } },
  { "set autocommit=1, sql_mode = concat(@@sql_mode,',STRICT_TRANS_TABLES')", { Expected("autocommit", {"1"}), Expected("sql_mode",  {"concat(@@sql_mode,',STRICT_TRANS_TABLES')"}) } },
  { "SET NAMES utf8, @@SESSION.sql_mode = CONCAT(REPLACE(REPLACE(REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', ''), 'STRICT_ALL_TABLES', ''), 'TRADITIONAL', ''), ',NO_AUTO_VALUE_ON_ZERO'), @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 3600",
  { Expected("names", {"utf8"}), Expected("sql_mode",  {"CONCAT(REPLACE(REPLACE(REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', ''), 'STRICT_ALL_TABLES', ''), 'TRADITIONAL', ''), ',NO_AUTO_VALUE_ON_ZERO')"}), Expected("sql_auto_is_null", {"0"}),
  Expected("wait_timeout", {"3600"}) } },
  { "SET NAMES utf8, @@LOCAL.sql_mode = CONCAT(REPLACE(REPLACE(REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', ''), 'STRICT_ALL_TABLES', ''), 'TRADITIONAL', ''), ',NO_AUTO_VALUE_ON_ZERO'), @@LOCAL.sql_auto_is_null = 0, @@LOCAL.wait_timeout = 3600",
  { Expected("names", {"utf8"}), Expected("sql_mode",  {"CONCAT(REPLACE(REPLACE(REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', ''), 'STRICT_ALL_TABLES', ''), 'TRADITIONAL', ''), ',NO_AUTO_VALUE_ON_ZERO')"}), Expected("sql_auto_is_null", {"0"}),
  Expected("wait_timeout", {"3600"}) } },
  { "set autocommit=1, session_track_schema=1, sql_mode = concat(@@sql_mode,',STRICT_TRANS_TABLES'), @@SESSION.net_write_timeout=7200", { Expected("autocommit", {"1"}), Expected("session_track_schema", {"1"}), Expected("sql_mode", {"concat(@@sql_mode,',STRICT_TRANS_TABLES')"}),
  Expected("net_write_timeout", {"7200"}) } },
  { "set autocommit=1, session_track_schema=1, sql_mode = concat(@@sql_mode,',STRICT_TRANS_TABLES'), @@LOCAL.net_write_timeout=7200", { Expected("autocommit", {"1"}), Expected("session_track_schema", {"1"}), Expected("sql_mode", {"concat(@@sql_mode,',STRICT_TRANS_TABLES')"}),
  Expected("net_write_timeout", {"7200"}) } },
  // Mutiple set queries involving 'NULL' values should be properly parsed with and without spaces
  { "set character_set_results=null, names latin7, character_set_client='utf8mb4'",
    {
      Expected("character_set_results", { "null" } ),
      Expected("names", { "latin7" } ),
      Expected("character_set_client", { "utf8mb4" } ),
    }
  },
  { "SET character_set_results=NULL, NAMES latin7, character_set_client='utf8mb4'",
    {
      Expected("character_set_results", { "NULL" } ),
      Expected("names", { "latin7" } ),
      Expected("character_set_client", { "utf8mb4" } ),
    }
  },
  { "set character_set_results=null,names latin7,character_set_client='utf8mb4'",
    {
      Expected("character_set_results", { "null" } ),
      Expected("names", { "latin7" } ),
      Expected("character_set_client", { "utf8mb4" } ),
    }
  },
  { "SET character_set_results=NULL,NAMES latin7,character_set_client='utf8mb4'",
    {
      Expected("character_set_results", { "NULL" } ),
      Expected("names", { "latin7" } ),
      Expected("character_set_client", { "utf8mb4" } ),
    }
  },
};

TEST(TestParse, MULTIPLE) {
  TestParse(multiple, arraysize(multiple), "multiple");
}
