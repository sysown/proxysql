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
  re2::RE2::Replace(&query, "^\\s*SET\\s+", "");

  re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
  opt2->set_case_sensitive(false);
  opt2->set_longest_match(false);

  std::map<std::string,std::vector<string>> result;

#define NAMES "(NAMES)"
#define QUOTES "(?:'||\")"
#define NAME_VALUE "((?:\\w|\\d)+)"
#define SESSION "(?:|SESSION +|@@|@@session.)"
#define VAR "(\\w+)"
#define SPACES " *"
#define VAR_VALUE "((?:[\\w/]|,)+)"

  const string pattern="(?:" NAMES SPACES QUOTES NAME_VALUE QUOTES "(?: +COLLATE +" QUOTES NAME_VALUE QUOTES "|)" "|" SESSION VAR SPACES "(?:|:)=" SPACES QUOTES VAR_VALUE QUOTES ") *,? *";
  re2::RE2 re(pattern, *opt2);
  string var;
  string value1, value2, value3, value4, value5;
  re2::StringPiece input(query);
  while (re2::RE2::Consume(&input, re, &value1, &value2, &value3, &value4, &value5)) {
    std::vector<std::string> op;

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
      key = value4;
      op.push_back(value5);
    }

    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
    result[key] = op;
  }
  return result;
}



