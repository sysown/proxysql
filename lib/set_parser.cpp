#include "set_parser.h"
#include "gen_utils.h"
#include <string>
#include <vector>
#include <map>
#ifdef PARSERDEBUG
#include <iostream>
#endif

using namespace std;


static void remove_quotes(string& v) {
	if (v.length() > 2) {
		char firstChar = v[0];
		char lastChar = v[v.length()-1];
		if (firstChar == lastChar) {
			if (firstChar == '\'' || firstChar == '"' || firstChar == '`') {
				v.erase(v.length()-1, 1);
				v.erase(0, 1);
			}
		}
	}
}

#ifdef PARSERDEBUG
SetParser::SetParser(std::string nq, int verb) {
	verbosity = verb;
#else
SetParser::SetParser(std::string nq) {
#endif
	parse1v2_init = false;
	set_query(nq);
}

SetParser::~SetParser() {
	if (parse1v2_init == true) {
		delete parse1v2_opt2;
		delete parse1v2_re;
	}
}

void SetParser::set_query(const std::string& nq) {
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

#define SESSION_P1 "(?:|SESSION +|@@|@@session.|@@local.)"
#define VAR_P1 "`?(@\\w+|\\w+)`?"
//#define VAR_VALUE "((?:[\\w/\\d:\\+\\-]|,)+)"
//#define VAR_VALUE "((?:CONCAT\\((?:(REPLACE|CONCAT)\\()+@@sql_mode,(?:(?:'|\\w|,| |\"|\\))+(?:\\)))|(?:[@\\w/\\d:\\+\\-]|,)+|(?:)))"

// added (?:[\\w]+=(?:on|off)|,)+ for optimizer_switch
#define VAR_VALUE_P1_1 "(?:\\()*(?:SELECT)*(?: )*(?:CONCAT\\()*(?:(?:(?: )*REPLACE|IFNULL|CONCAT)\\()+(?: )*(?:NULL|@OLD_SQL_MODE|@@SQL_MODE),(?:(?:'|\\w|,| |\"|\\))+(?:\\))*)(?:\\))"
#define VAR_VALUE_P1_2 "|(?:NULL)"
#define VAR_VALUE_P1_3 "|(?:[\\w]+=(?:on|off)|,)+"
#define VAR_VALUE_P1_4 "|(?:[@\\w/\\d:\\+\\-]|,)+"
#define VAR_VALUE_P1_5 "|(?:(?:'{1}|\"{1})(?:)(?:'{1}|\"{1}))"
#define VAR_VALUE_P1 "(" VAR_VALUE_P1_1 VAR_VALUE_P1_2 VAR_VALUE_P1_3 VAR_VALUE_P1_4 VAR_VALUE_P1_5 ")"

std::map<std::string,std::vector<std::string>> SetParser::parse1() {

	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Parsing query %s\n", query.c_str());
	re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
	opt2->set_case_sensitive(false);
	opt2->set_longest_match(false);

	re2::RE2 re0("^\\s*SET\\s+", *opt2);
	re2::RE2::Replace(&query, re0, "");
	re2::RE2 re1("(\\s|;)+$", *opt2); // remove trailing spaces and semicolon
	re2::RE2::Replace(&query, re1, "");

	std::map<std::string,std::vector<std::string>> result;

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
			if (strcasecmp("transaction_isolation", value4.c_str()) == 0) {
				value4 = "tx_isolation";
			} else if (strcasecmp("transaction_read_only", value4.c_str()) == 0) {
				value4 = "tx_read_only";
			}
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
	if (input.size() != 0) {
		result = {};
	}
	delete opt2;
	return result;
}

/*
#define VAR_VALUE_P1_1 "(?:\\()*(?:SELECT)*(?: )*(?:CONCAT\\()*(?:(?:(?: )*REPLACE|IFNULL|CONCAT)\\()+(?: )*(?:NULL|@OLD_SQL_MODE|@@SQL_MODE),(?:(?:'|\\w|,| |\"|\\))+(?:\\))*)(?:\\))"
#define VAR_VALUE_P1_2 "|(?:NULL)"
#define VAR_VALUE_P1_3 "|(?:[\\w]+=(?:on|off)|,)+"
#define VAR_VALUE_P1_4 "|(?:[@\\w/\\d:\\+\\-]|,)+"
#define VAR_VALUE_P1_5 "|(?:(?:'{1}|\"{1})(?:)(?:'{1}|\"{1}))"
#define VAR_VALUE_P1_6 "|(?: )+"
#define VAR_VALUE_P1 "(" VAR_VALUE_P1_1 VAR_VALUE_P1_2 VAR_VALUE_P1_3 VAR_VALUE_P1_4 VAR_VALUE_P1_5 VAR_VALUE_P1_6 ")"
*/


void SetParser::generateRE_parse1v2() {
	vector<string> quote_symbol = {"\"", "'", "`"};
	vector<string> var_patterns = {};
	{
		// this block needs to be added at the very beginning, otherwise REPLACE|IFNULL|CONCAT may be considered simple words
		// sw0 matches:
		// - single word, quoted or not quoted
		// - variable name , with double @ (session variable) or single @ (user defiend variable)
		// - strings that includes words, spaces and commas
		// - single quote string
		string  sw0  = "(?:\\w+|\"[\\w, ]+\"|\'[\\w, ]+\'|@(?:|@)\\w+|\'\')";
		string  mw0  = "(?:" + sw0 + "(?: *, *" + sw0 + ")*)"; // multiple words, separated by comma and random spaces
		string  fww  = "(?:(?:REPLACE|IFNULL|CONCAT)\\( *" + mw0 + "\\))"; // functions REPLACE|IFNULL|CONCAT having argument multiple words
		string rfww2 = "(?:(?:REPLACE|IFNULL|CONCAT)\\( *" + fww   + " *, *" + mw0 + "\\))"; //functions REPLACE|IFNULL|CONCAT calling the same functions
		string rfww3 = "(?:(?:REPLACE|IFNULL|CONCAT)\\( *" + rfww2 + " *, *" + mw0 + "\\))"; //functions REPLACE|IFNULL|CONCAT calling the same functions
		string rfww4 = "(?:(?:REPLACE|IFNULL|CONCAT)\\( *" + rfww3 + " *, *" + mw0 + "\\))"; //functions REPLACE|IFNULL|CONCAT calling the same functions
		// all the above function allows space after the open parenthesis
		string Selfww = "(?:\\(SELECT  *" + fww + "\\))"; // for calls like SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'));
		// FIXME: add error handling in case rfww4 is removed
#ifdef PARSERDEBUG
		if (verbosity > 0) {
			cout << fww << endl;
			cout << rfww2 << endl;
			cout << rfww3 << endl;
			cout << rfww4 << endl;
			cout << Selfww << endl;
		}
#endif
		var_patterns.push_back(rfww4); // add first function calling function , otherwise functions will be considered simple names
		var_patterns.push_back(rfww3); // add first function calling function , otherwise functions will be considered simple names
		var_patterns.push_back(rfww2); // add first function calling function
		var_patterns.push_back(fww);
		var_patterns.push_back(Selfww);
	}

	string vp = "NULL"; // NULL
	var_patterns.push_back(vp);
	//vp = "\\w+"; // single word
	//var_patterns.push_back(vp);
	{
		string vp0 = "(?:\\w|\\d)+"; // single word with letters and digits , for example utf8mb4 and latin1
	//var_patterns.push_back(vp);
/*
		string vp1 = "(?:" + vp0 + "(?:," + vp0 + ")*)"; // multiple words (letters and digits) separated by commas WITHOUT any spaces between words . Used also for sql_mode , example: ONLY_FULL_GROUP_BY,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO
		//var_patterns.push_back(vp1); // do NOT add without quote
		for (auto it = quote_symbol.begin(); it != quote_symbol.end(); it++) {
			string s = *it + vp1 + *it;
			var_patterns.push_back(s); // add with quote
		}
*/
		string vp2 = "(?:" + vp0 + "(?:-" + vp0 + ")*)"; // multiple words (letters and digits) separated by dash, WITHOUT any spaces between words . Used also for transaction isolation
		var_patterns.push_back(vp2);
		for (auto it = quote_symbol.begin(); it != quote_symbol.end(); it++) {
			string s = *it + vp2 + *it;
			var_patterns.push_back(s); // add with quote
		}
	}
	//vp = "(?:\\w|\\d)+(?:-|\\w|\\d+)*"; // multiple words (letters and digits) separated by dash, WITHOUT any spaces between words . Used ialso for transaction isolation
	//var_patterns.push_back(vp);
//	for (auto it = quote_symbol.begin(); it != quote_symbol.end(); it++) {
//		string s = *it + vp + *it;
//		var_patterns.push_back(s); // add with quote
//	}

	vp = "\\w+(?:,\\w+)+"; // multiple words separated by commas, WITHOUT any spaces between words
	// NOTE: we do not use multiple words without quotes
	for (auto it = quote_symbol.begin(); it != quote_symbol.end(); it++) {
		string s = *it + vp + *it;
		var_patterns.push_back(s); // add with quote
	}

	// regex for optimizer_switch
	{
		string v1 = "(?:on|off)"; // on|off
		string v2 = "\\w+=" + v1; // "\\w+=(?:on|off)" , example: index_merge_sort_union=on
		string v3 = v2 + "(?:," + v2 + ")*"; // "\\w+=(?:on|off)(?:,\\w+=(?:on|off))*"
				// example index_merge=on,index_merge_union=on,index_merge_sort_union=off
				// note: spaces are not allowed
		// NOTE: the whole set of flags must be quoted
		for (auto it = quote_symbol.begin(); it != quote_symbol.end(); it++) {
			string s = *it + v3 + *it;
			var_patterns.push_back(s); // add with quote
		}
	}


//	DO NOT REMOVE THIS COMMENTED CODE
//	It helps understanding how a regex was built

//	vp = "\\d+"; // a number integer  N1
//	var_patterns.push_back(vp);
//	vp = "\\d+\\.\\d+"; // a decimal  N2
//	var_patterns.push_back(vp);
//	vp = "\\d+(?:|\\.\\d+)"; // an integer or decimal N3 , merge of N1 and N2
//	var_patterns.push_back(vp);

//	vp = " *(?:\\+|\\-) *\\d+"; // a signed number integer with spaces before and after the sign . N4 = sign + N1
//	var_patterns.push_back(vp);
//	vp = " *(?:\\+|\\-) *\\d+\\.\\d+"; // a signed decimal with spaces before and after the sign . N5 = sign + N2
//	var_patterns.push_back(vp);
	
//	vp = " *(?:\\+|\\-) *\\d+(?:|\\.\\d+)"; // a signed integer or decimal , N6 = N4 + N5
//	var_patterns.push_back(vp);

	vp = "(?:| *(?:\\+|\\-) *)\\d+(?:|\\.\\d+)"; // a signed or unsigned integer or decimal , N7 = merge of N3 and N6
	var_patterns.push_back(vp);


	{
		// time_zone in numeric format:
		// - +/- sign
		// 1 or 2 digits
		// :
		// 2 digits
		string tzd =  "(?:(?:\\+|\\-)(?:|\\d)\\d:\\d\\d)";
		// time_zone in string format:
		// word / word
		string tzw =  "(?:\\w+/\\w+)";
		vp = "(?:" + tzd + "|" + tzw + ")"; // time_zone in numeric and string format
	}
	for (auto it = quote_symbol.begin(); it != quote_symbol.end(); it++) {
		string s = *it + vp + *it;
		var_patterns.push_back(s); // add with quote
	}

	// add just variable name, for example SET time_zone = @old_time_zone
	vp = "(?:@(?:|@)\\w+)";
	var_patterns.push_back(vp);


	// add empty strings , with optional spaces
	for (auto it = quote_symbol.begin(); it != quote_symbol.end(); it++) {
		string s = *it + " *" + *it;
		var_patterns.push_back(s); // add with quote
	}



	string var_value = "(";
	for (auto it = var_patterns.begin(); it != var_patterns.end(); it++) {
		string s = "(?:" + *it + ")";
		auto it2 = it;
		it2++;
		if (it2 != var_patterns.end())
			s += "|";
		var_value += s;
	}
	var_value += ")";
	

	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Parsing query %s\n", query.c_str());
	parse1v2_opt2 = new re2::RE2::Options(RE2::Quiet);
	parse1v2_opt2->set_case_sensitive(false);
	parse1v2_opt2->set_longest_match(false);




	string var_1_0 = "(?:@\\w+|\\w+)"; // @name|name
	string var_1 = "(" + var_1_0 + "|`" + var_1_0 + "`)"; // var_1_0|`var_1_0`
	var_1 = SESSION_P1 + var_1;

	string charset_name = "(?:(?:\\w|\\d)+)";
	string name_value = "(";
	for (auto it = quote_symbol.begin(); it != quote_symbol.end(); it++) {
		string s = "(?:" + *it + charset_name + *it + ")";
		//auto it2 = it;
		//it2++;
		//if (it2 != quote_symbol.end())
		s += "|";
		name_value += s;
	}
	name_value += charset_name; // without quotes
	name_value += ")";
	
#ifdef PARSERDEBUG
	if (verbosity > 0) {
		cout << var_value << endl;
		cout << name_value << endl;
	}
#endif

#ifdef PARSERDEBUG
//	delete opt2;
//	return result;
#endif
	
/*
#define QUOTES "(?:'|\"|`)?"
#define SPACES " *"
#define NAMES "(NAMES)"
#define NAME_VALUE "((?:\\w|\\d)+)"
*/

	
	//const std::string pattern="(?:" NAMES SPACES QUOTES NAME_VALUE QUOTES "(?: +COLLATE +" QUOTES NAME_VALUE QUOTES "|)" "|" SESSION_P1 VAR_P1 SPACES "(?:|:)=" SPACES QUOTES VAR_VALUE_P1 QUOTES ") *,? *";
	const std::string pattern="(?:" NAMES SPACES + name_value + "(?: +COLLATE +" + name_value + "|)" "|" + var_1 + SPACES "(?:|:)=" SPACES + var_value + ") *,? *";
	//const std::string pattern=var_1 + SPACES "(?:|:)=" SPACES + var_value;
VALGRIND_DISABLE_ERROR_REPORTING;
#ifdef PARSERDEBUG
	if (verbosity > 0) {
		cout << pattern << endl;
	}
#endif
	//re2::RE2 re(pattern, *opt2);
	parse1v2_pattern = pattern;
	parse1v2_re = new re2::RE2(parse1v2_pattern, *parse1v2_opt2);
	parse1v2_init = true;
}

std::map<std::string,std::vector<std::string>> SetParser::parse1v2() {

	std::map<std::string,std::vector<std::string>> result = {};

	if (parse1v2_init == false) {
		generateRE_parse1v2();
	}

	re2::RE2 re0("^\\s*SET\\s+", *parse1v2_opt2);
	re2::RE2::Replace(&query, re0, "");
	re2::RE2 re1("(\\s|;)+$", *parse1v2_opt2); // remove trailing spaces and semicolon
	re2::RE2::Replace(&query, re1, "");

VALGRIND_ENABLE_ERROR_REPORTING;
	std::string var;
	std::string value1, value2, value3, value4, value5;
	re2::StringPiece input(query);
	while (re2::RE2::Consume(&input, *parse1v2_re, &value1, &value2, &value3, &value4, &value5)) {
		// FIXME: verify if we reached end of query. Did we parse everything?
		std::vector<std::string> op;
#ifdef DEBUG
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "SET parsing: v1='%s' , v2='%s' , v3='%s' , v4='%s' , v5='%s'\n", value1.c_str(), value2.c_str(), value3.c_str(), value4.c_str(), value5.c_str());
#endif // DEBUG
		std::string key;
		if (value1 != "") {
			// NAMES
			key = value1;
			remove_quotes(value2);
			op.push_back(value2);
			if (value3 != "") {
				remove_quotes(value3);
				op.push_back(value3);
			}
		} else if (value4 != "") {
			// VARIABLE
			remove_quotes(value4);
			if (strcasecmp("transaction_isolation", value4.c_str()) == 0) {
				value4 = "tx_isolation";
			} else if (strcasecmp("transaction_read_only", value4.c_str()) == 0) {
				value4 = "tx_read_only";
			}
			value5.erase(value5.find_last_not_of(" \n\r\t,")+1);
			key = value4;
			if (value5 == "''" || value5 == "\"\"") {
				op.push_back("");
			} else {
				remove_quotes(value5);
				op.push_back(value5);
			}
		}

		std::transform(key.begin(), key.end(), key.begin(), ::tolower);
		result[key] = op;
	}
	if (input.size() != 0) {
#ifdef PARSERDEBUG
		if (verbosity > 0) {
			cout << "Failed to parse: " << input << endl;
		}
#endif
		result = {};
	}
	//delete opt2;
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
		//if (value1 != "") { // session is specified
			if (value2 != "") { // isolation level
				key = value1 + ":" + value2;
				std::transform(value3.begin(), value3.end(), value3.begin(), ::toupper);
				op.push_back(value3);
			} else {
				key = value1 + ":" + value4;
				std::transform(value5.begin(), value5.end(), value5.begin(), ::toupper);
				op.push_back(value5);
			}
		//}
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

