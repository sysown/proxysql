#ifndef __CLASS_SET_PARSER_H
#define __CLASS_SET_PARSER_H
#include <string>
#include <map>
#include <vector>

#include "re2/re2.h"
#include "re2/regexp.h"

//#define PARSERDEBUG

class SetParser {
	private:
	// parse1v2 variables used for compile the RE only once
	bool parse1v2_init;
	re2::RE2::Options * parse1v2_opt2;
	re2::RE2 * parse1v2_re;
	std::string parse1v2_pattern;
	std::string query;
#ifdef PARSERDEBUG
	int verbosity;
	public:
	SetParser(std::string q, int verb = 0);
#else
	public:
	SetParser(std::string q);
#endif
	// set_query() allows to change the query associated to a SetParser.
	// This allow to parse multiple queries using just a single SetParser.
	// At the moment this makes sense only when using parse1v2() because it
	// allows to compile the regular expression only once
	void set_query(const std::string& q);
	// First implementation of the general parser
	// It uses a single complex RE pattern that is hardcoded
	std::map<std::string, std::vector<std::string>> parse1();
	// Second implementation of the general parser .
	// It uses a RE pattern that is built at runtime .
	// The final pattern used by parse1v2() is a lot longer than the one used by parse1()
	// making it very difficult to read, but the code generating it should be clear
	std::map<std::string, std::vector<std::string>> parse1v2();
	void generateRE_parse1v2();
	// First implemenation of the parser for TRANSACTION ISOLATION LEVEL and TRANSACTION READ/WRITE
	std::map<std::string, std::vector<std::string>> parse2();
	std::string parse_character_set();
	std::string parse_USE_query(std::string& errmsg);
	std::string remove_comments(const std::string& q);
#ifdef DEBUG
	// built-in testing
	void test_parse_USE_query();
#endif // DEBUG
	~SetParser();
};


#endif /* __CLASS_SET_PARSER_H */
