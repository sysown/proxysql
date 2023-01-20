#include "set_parser.h"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "gen_utils.h"
#include <string>
#include <vector>
#include <map>

SetParser::SetParser(std::string nq) {
	int query_no_space_length = nq.length();
	char *query_no_space=(char *)malloc(query_no_space_length+1);
	memcpy(query_no_space,nq.c_str(),query_no_space_length);
	query_no_space[query_no_space_length]='\0';
	query_no_space_length=remove_spaces(query_no_space);
	query = std::string(query_no_space);
	free(query_no_space);
}

#define QUOTES "(?:'|\"|`)?"
#define SPACES " *"
#define NAMES "(NAMES)"
#define NAME_VALUE "((?:\\w|\\d)+)"

std::map<std::string,std::vector<std::string>> SetParser::parse1() {

	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Parsing query %s\n", query.c_str());
	re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
	opt2->set_case_sensitive(false);
	opt2->set_longest_match(false);

	re2::RE2 re0("^\\s*SET\\s+", *opt2);
	re2::RE2::Replace(&query, re0, "");

	std::map<std::string,std::vector<std::string>> result;

#define SESSION_P1 "(?:|SESSION +|@@|@@session.|@@local.)"
#define VAR_P1 "`?(@\\w+|\\w+)`?"
//#define VAR_VALUE "((?:[\\w/\\d:\\+\\-]|,)+)"
//#define VAR_VALUE "((?:CONCAT\\((?:(REPLACE|CONCAT)\\()+@@sql_mode,(?:(?:'|\\w|,| |\"|\\))+(?:\\)))|(?:[@\\w/\\d:\\+\\-]|,)+|(?:)))"

// added (?:[\\w]+=(?:on|off)|,)+ for optimizer_switch
#define VAR_VALUE_P1 "((?:\\()*(?:SELECT)*(?: )*(?:CONCAT\\()*(?:(?:(?: )*REPLACE|IFNULL|CONCAT)\\()+(?: )*(?:NULL|@OLD_SQL_MODE|@@SQL_MODE),(?:(?:'|\\w|,| |\"|\\))+(?:\\))*)(?:\\))|(?:NULL)|(?:[\\w]+=(?:on|off)|,)+|(?:[@\\w/\\d:\\+\\-]|,)+|(?:(?:'{1}|\"{1})(?:)(?:'{1}|\"{1})))"

	const std::string pattern="(?:" NAMES SPACES QUOTES NAME_VALUE QUOTES "(?: +COLLATE +" QUOTES NAME_VALUE QUOTES "|)" "|" SESSION_P1 VAR_P1 SPACES "(?:|:)=" SPACES QUOTES VAR_VALUE_P1 QUOTES ") *,? *";
VALGRIND_DISABLE_ERROR_REPORTING;
	re2::RE2 re(pattern, *opt2);
VALGRIND_ENABLE_ERROR_REPORTING;
	std::string var;
	std::string value1, value2, value3, value4, value5;
	re2::StringPiece input(query);
	while (re2::RE2::Consume(&input, re, &value1, &value2, &value3, &value4, &value5)) {
	std::vector<std::string> op;
#ifdef DEBUG
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "SET parsing: v1='%s' , v2='%s' , v3='%s' , v4='%s' , v5='%s'\n", value1.c_str(), value2.c_str(), value3.c_str(), value4.c_str(), value5.c_str());
#endif // DEBUG
    std::string key;
    if (value1 != "") {
      // NAMES
      key = value1;
      op.push_back(value2);
      if (value3 != "") {
		op.push_back(value3);
      }
    } else if (value4 != "") {
      // VARIABLE
		value5.erase(value5.find_last_not_of(" \n\r\t,")+1);
      key = value4;
      if (value5 == "''" || value5 == "\"\"") {
        op.push_back("");
      } else {
        op.push_back(value5);
      }
    }

    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
    result[key] = op;
  }
	delete opt2;
  return result;
}


std::map<std::string,std::vector<std::string>> SetParser::parse2() {

	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Parsing query %s\n", query.c_str());
	re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
	opt2->set_case_sensitive(false);
	opt2->set_longest_match(false);

	re2::RE2 re0("^\\s*SET\\s+", *opt2);
	re2::RE2::Replace(&query, re0, "");

	std::map<std::string,std::vector<std::string>> result;

// regex used:
// SET(?: +)(|SESSION +)TRANSACTION(?: +)(?:(?:(ISOLATION(?: +)LEVEL)(?: +)(REPEATABLE(?: +)READ|READ(?: +)COMMITTED|READ(?: +)UNCOMMITTED|SERIALIZABLE))|(?:(READ)(?: +)(WRITE|ONLY)))
/*
#define SESSION_P2 "(|SESSION)"
#define VAR_P2 "(ISOLATION LEVEL|READ)"
//#define VAR_VALUE "((?:[\\w/\\d:\\+\\-]|,)+)"
//#define VAR_VALUE "((?:CONCAT\\((?:(REPLACE|CONCAT)\\()+@@sql_mode,(?:(?:'|\\w|,| |\"|\\))+(?:\\)))|(?:[@\\w/\\d:\\+\\-]|,)+|(?:)))"
#define VAR_VALUE_P2 "(((?:CONCAT\\()*(?:((?: )*REPLACE|IFNULL|CONCAT)\\()+(?: )*(?:NULL|@OLD_SQL_MODE|@@sql_mode),(?:(?:'|\\w|,| |\"|\\))+(?:\\))*)|(?:[@\\w/\\d:\\+\\-]|,)+|(?:)))"
*/
	//const std::string pattern="(?:" NAMES SPACES QUOTES NAME_VALUE QUOTES "(?: +COLLATE +" QUOTES NAME_VALUE QUOTES "|)" "|" SESSION_P1 VAR_P1 SPACES "(?:|:)=" SPACES QUOTES VAR_VALUE_P1 QUOTES ") *,? *";
	const std::string pattern="(|SESSION) *TRANSACTION(?: +)(?:(?:(ISOLATION(?: +)LEVEL)(?: +)(REPEATABLE(?: +)READ|READ(?: +)COMMITTED|READ(?: +)UNCOMMITTED|SERIALIZABLE))|(?:(READ)(?: +)(WRITE|ONLY)))";
	re2::RE2 re(pattern, *opt2);
	std::string var;
	std::string value1, value2, value3, value4, value5;
	re2::StringPiece input(query);
	while (re2::RE2::Consume(&input, re, &value1, &value2, &value3, &value4, &value5)) {
		std::vector<std::string> op;
#ifdef DEBUG
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "SET parsing: v1='%s' , v2='%s' , v3='%s' , v4='%s' , v5='%s'\n", value1.c_str(), value2.c_str(), value3.c_str(), value4.c_str(), value5.c_str());
#endif // DEBUG
		std::string key;
		if (value1 != "") { // session is specified
			if (value2 != "") { // isolation level
				key = value2;
				std::transform(value3.begin(), value3.end(), value3.begin(), ::toupper);
				op.push_back(value3);
			} else {
				key = value4;
				std::transform(value5.begin(), value5.end(), value5.begin(), ::toupper);
				op.push_back(value5);
			}
		}
		std::transform(key.begin(), key.end(), key.begin(), ::tolower);
		result[key] = op;
	}

	delete opt2;
	return result;
}

std::string SetParser::parse_character_set() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Parsing query %s\n", query.c_str());
	re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
	opt2->set_case_sensitive(false);
	opt2->set_longest_match(false);

	re2::RE2 re0("^\\s*SET\\s+", *opt2);
	re2::RE2::Replace(&query, re0, "");

	std::map<std::string,std::vector<std::string>> result;

	const std::string pattern="((charset)|(character +set))(?: )(?:'?)([^'|\\s]*)(?:'?)";
	re2::RE2 re(pattern, *opt2);
	std::string var;
	std::string value1, value2, value3, value4;
	re2::StringPiece input(query);
	re2::RE2::Consume(&input, re, &value1, &value2, &value3, &value4);

	delete opt2;
	return value4;
}

