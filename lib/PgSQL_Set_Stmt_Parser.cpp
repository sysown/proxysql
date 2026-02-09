#include "PgSQL_Set_Stmt_Parser.h"
#include "gen_utils.h"
#include <string>
#include <vector>
#include <map>
#include <cassert>
#include <utility> // for std::pair
//#ifdef PARSERDEBUG
#include <iostream>
//#endif

#ifdef DEBUG
//#define VALGRIND_ENABLE_ERROR_REPORTING
//#define VALGRIND_DISABLE_ERROR_REPORTING
#include "valgrind.h"
#else
#define VALGRIND_ENABLE_ERROR_REPORTING
#define VALGRIND_DISABLE_ERROR_REPORTING
#endif // DEBUG

using namespace std;

#ifdef PARSERDEBUG
PgSQL_Set_Stmt_Parser::PgSQL_Set_Stmt_Parser(std::string nq, int verb) {
	verbosity = verb;
#else
PgSQL_Set_Stmt_Parser::PgSQL_Set_Stmt_Parser(std::string nq) {
#endif
	parse1v2_init = false;
	set_query(nq);
}

PgSQL_Set_Stmt_Parser::~PgSQL_Set_Stmt_Parser() {
	if (parse1v2_init == true) {
		delete parse1v2_opt2;
		delete parse1v2_re;
	}
}

void PgSQL_Set_Stmt_Parser::set_query(const std::string& nq) {
	int query_no_space_length = nq.length();
	char *query_no_space=(char *)malloc(query_no_space_length+1);
	memcpy(query_no_space,nq.c_str(),query_no_space_length);
	query_no_space[query_no_space_length]='\0';
	query_no_space_length=remove_spaces(query_no_space);
	query = std::string(query_no_space);
	free(query_no_space);
}

void PgSQL_Set_Stmt_Parser::generateRE_parse1v2() {
	
#ifdef DEBUG
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Parsing query %s\n", query.c_str());
#endif // DEBUG

	// Function Call: Check if Group 3 is populated.
	// Literal: Check if Group 4 is populated.
	const std::string pattern = R"(^\s*(?:(?:(SESSION)\s+)?((?:TIME\s+ZONE|TRANSACTION\s+ISOLATION\s+LEVEL|XML\s+OPTION|(?:(?:[^\s=]{1,4}|[^\s=]{6}|[^\s=]{8,}|(?:[^lL][^\s=]{4}|[lL][^oO][^\s=]{3}|[lL][oO][^cC][^\s=]{2}|[lL][oO][cC][^aA][^\s=]|[lL][oO][cC][aA][^lL])|(?:[^sS][^\s=]{6}|[sS][^eE][^\s=]{5}|[sS][eE][^sS][^\s=]{4}|[sS][eE][sS][^sS][^\s=]{3}|[sS][eE][sS][sS][^iI][^\s=]{2}|[sS][eE][sS][sS][iI][^oO][^\s=]|[sS][eE][sS][sS][iI][oO][^nN])))))(?:\s*(=)\s*|\s+(TO)\s+|\s+())(?:([A-Za-z_][\w$\.]*)\s*\(\s*('(?:''|[^'])*'|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[^\s();]+)\s*\)|('(?:''|[^'])*'|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|(?:(?:[^\s= T;()][^;()]*|\s+[^=T;()][^;()]*)|=[^;()]+|TO[^;()]+|T[^O;()][^;()]*|T)))\s*;?)\s*$)";

#ifdef DEBUG
VALGRIND_DISABLE_ERROR_REPORTING;
#endif // DEBUG
#ifdef PARSERDEBUG
	if (verbosity > 0) {
		cout << pattern << endl;
	}
#endif
	parse1v2_opt2 = new re2::RE2::Options(RE2::Quiet);
	parse1v2_opt2->set_case_sensitive(false);
	parse1v2_opt2->set_longest_match(false);

	parse1v2_pattern = pattern;
	parse1v2_re = new re2::RE2(parse1v2_pattern, *parse1v2_opt2);
	
	if (!parse1v2_re->ok()) {
		proxy_error("Error in RE2 regex pattern: %s\n", parse1v2_re->error().c_str());
		assert(false);
	}

	parse1v2_init = true;
}

void PgSQL_Set_Stmt_Parser::unquote_if_quoted(std::string& v) {
	if (v.length() >= 2) {
		char firstChar = v[0];
		char lastChar = v[v.length() - 1];
		if (firstChar == lastChar) {
			if (firstChar == '\'' || firstChar == '"' || firstChar == '`') {
				v.erase(v.length() - 1, 1);
				v.erase(0, 1);
			}
		}
	}
}

std::map<std::string,std::vector<std::string>> PgSQL_Set_Stmt_Parser::parse1v2() {

	std::map<std::string,std::vector<std::string>> result = {};

	if (parse1v2_init == false) {
		generateRE_parse1v2();
	}

	re2::RE2 re0("^\\s*SET\\s+", *parse1v2_opt2);
	re2::RE2::Replace(&query, re0, "");
	re2::RE2 re1("(\\s|;)+$", *parse1v2_opt2); // remove trailing spaces and semicolon
	re2::RE2::Replace(&query, re1, "");

#ifdef DEBUG
VALGRIND_ENABLE_ERROR_REPORTING;
#endif // DEBUG
	std::string var;
	std::string scope, unknown, param_name, param_val_func, equal, to, empty, param_val_func_args, param_val;
	re2::StringPiece input(query);
	while (re2::RE2::Consume(&input, *parse1v2_re, &scope, &param_name, &equal, &to, &empty, &param_val_func, &param_val_func_args, &param_val)) {
		// FIXME: verify if we reached end of query. Did we parse everything?
		std::vector<std::string> op;
#ifdef DEBUG
		std::string oper;
		if (!equal.empty()) oper = "=";
		else if (!to.empty()) oper = "TO";
		else oper = "";
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "SET parsing: scope='%s', parameter name='%s' , operator='%s' , parameter value='%s' , parameter_value_func='%s' , parameter_value_func_args='%s'\n", scope.c_str(), param_name.c_str(), oper.c_str(), param_val.c_str(), param_val_func.c_str(), param_val_func_args.c_str());
#endif // DEBUG

		if (param_val_func.empty() == false) return {};

		unquote_if_quoted(param_name);

		size_t pos = param_val.find_last_not_of(" \n\r\t,");
		if (pos != param_val.npos) {
			param_val.erase(pos + 1);
		}

		if (param_name.empty() || param_val.empty()) {
			continue;
		}
		
		op.emplace_back(param_val);

		std::transform(param_name.begin(), param_name.end(), param_name.begin(), ::tolower);
		result[param_name] = op;
	}
	if (input.size() != 0) {
#ifdef PARSERDEBUG
		if (verbosity > 0) {
			cout << "Failed to parse: " << input << endl;
		}
#endif
		result = {};
	}
	return result;
}

std::string PgSQL_Set_Stmt_Parser::remove_comments(const std::string& q) {
    std::string result = "";
    bool in_multiline_comment = false;

    for (size_t i = 0; i < query.size(); ++i) {
        char current_char = query[i];

        // Check for multiline comment start
        if (current_char == '/' && i + 1 < query.size() && query[i + 1] == '*') {
            in_multiline_comment = true;
            i++; // Skip the '*'
            continue;
        }   

        // Check for multiline comment end
        if (in_multiline_comment && current_char == '*' && i + 1 < query.size() && query[i + 1] == '/') {
            in_multiline_comment = false;
            i++; // Skip the '/'
            continue;
        }   

        // Skip characters inside multiline comment
        if (in_multiline_comment) {
            continue;
        }

        // Check for single-line comments
        if (current_char == '#' || (current_char == '-' && i + 1 < query.size() && query[i + 1] == '-')) {
            // Skip until the end of the line
            while (i < query.size() && query[i] != '\n') {
                i++;
            }
            continue;
        }

        // Append the character to the result if it's not a comment
        result += current_char;
    }

    return result;
}
