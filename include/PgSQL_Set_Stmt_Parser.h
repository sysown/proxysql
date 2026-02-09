#ifndef __CLASS_PGSQL_SET_STMT_PARSER_H
#define __CLASS_PGSQL_SET_STMT_PARSER_H

#include <string>
#include <map>
#include <vector>

#include "re2/re2.h"
#include "re2/regexp.h"

//#define PARSERDEBUG

class PgSQL_Set_Stmt_Parser {
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
	PgSQL_Set_Stmt_Parser(std::string q, int verb = 0);
#else
	public:
	PgSQL_Set_Stmt_Parser(std::string q);
#endif
	~PgSQL_Set_Stmt_Parser();

	// set_query() allows to change the query associated to a PgSQL_Set_Stmt_Parser.
	// This allow to parse multiple queries using just a single PgSQL_Set_Stmt_Parser.
	// At the moment this makes sense only when using parse1v2() because it
	// allows to compile the regular expression only once
	void set_query(const std::string& q);
	std::map<std::string, std::vector<std::string>> parse1v2();
	void generateRE_parse1v2();
	std::string remove_comments(const std::string& q);
	static void unquote_if_quoted(std::string& v);
};

#endif /* __CLASS_PGSQL_SET_STMT_PARSER_H */
