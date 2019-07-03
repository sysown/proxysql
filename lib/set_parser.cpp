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
  query = string(query_no_space);
  free(query_no_space);
}

std::map<std::string,std::vector<string>> SetParser::parse() {

	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Parsing query %s\n", query.c_str());
  re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
  opt2->set_case_sensitive(false);
  opt2->set_longest_match(false);

  re2::RE2 re0("^\\s*SET\\s+", *opt2);
  re2::RE2::Replace(&query, re0, "");

  std::map<std::string,std::vector<string>> result;

#define NAMES "(NAMES)"
#define QUOTES "(?:'|\")?"
#define NAME_VALUE "((?:\\w|\\d)+)"
#define SESSION "(?:|SESSION +|@@|@@session.)"
#define VAR "(\\w+)"
#define SPACES " *"
//#define VAR_VALUE "((?:[\\w/\\d:\\+\\-]|,)+)"
//#define VAR_VALUE "((?:CONCAT\\((?:(REPLACE|CONCAT)\\()+@@sql_mode,(?:(?:'|\\w|,| |\"|\\))+(?:\\)))|(?:[@\\w/\\d:\\+\\-]|,)+|(?:)))"
#define VAR_VALUE "(((?:CONCAT\\()*(?:((?: )*REPLACE|IFNULL|CONCAT)\\()+(?: )*(?:NULL|@@sql_mode),(?:(?:'|\\w|,| |\"|\\))+(?:\\))*)|(?:[@\\w/\\d:\\+\\-]|,)+|(?:)))"

  const string pattern="(?:" NAMES SPACES QUOTES NAME_VALUE QUOTES "(?: +COLLATE +" QUOTES NAME_VALUE QUOTES "|)" "|" SESSION VAR SPACES "(?:|:)=" SPACES QUOTES VAR_VALUE QUOTES ") *,? *";
  re2::RE2 re(pattern, *opt2);
  string var;
  string value1, value2, value3, value4, value5;
  re2::StringPiece input(query);
  while (re2::RE2::Consume(&input, re, &value1, &value2, &value3, &value4, &value5)) {
    std::vector<std::string> op;
#ifdef DEBUG
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "SET parsing: v1='%s' , v2='%s' , v3='%s' , v4='%s' , v5='%s'\n", value1.c_str(), value2.c_str(), value3.c_str(), value4.c_str(), value5.c_str());
#endif // DEBUG
    string key;
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
      op.push_back(value5);
    }

    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
    result[key] = op;
  }
  return result;
}



