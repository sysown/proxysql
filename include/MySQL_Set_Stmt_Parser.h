#ifndef PROXYSQL_MYSQL_SET_STMT_PARSER_H
#define PROXYSQL_MYSQL_SET_STMT_PARSER_H

#include <string>
#include <map>
#include <vector>

#include "re2/re2.h"
#include "re2/regexp.h"

//#define PARSERDEBUG

/**
 * @brief Digest-text pattern of a session-tracked SET ... TRANSACTION.
 *
 * Used case-insensitively as MySQL_Thread::match_regexes[2]: a matching digest
 * is handled by MySQL_Set_Stmt_Parser::parse2() and tracked by ProxySQL. No
 * scope or SESSION/LOCAL (synonyms in MySQL) sets the session characteristics.
 * No scope applies to the next transaction only. GLOBAL, PERSIST and
 * PERSIST_ONLY must not match: they are forwarded to the backend.
 */
#define MYSQL_SET_TRANSACTION_DIGEST_REGEX \
	"^SET(?: +)(|SESSION +|LOCAL +)TRANSACTION(?: +)(?:(?:(ISOLATION(?: +)LEVEL)(?: +)" \
	"(REPEATABLE(?: +)READ|READ(?: +)COMMITTED|READ(?: +)UNCOMMITTED|SERIALIZABLE))|(?:(READ)(?: +)(WRITE|ONLY)))"

class MySQL_Set_Stmt_Parser {
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
	MySQL_Set_Stmt_Parser(std::string q, int verb = 0);
#else
	public:
	MySQL_Set_Stmt_Parser(std::string q);
#endif
	// set_query() allows to change the query associated to a MySQL_Set_Stmt_Parser.
	// This allow to parse multiple queries using just a single MySQL_Set_Stmt_Parser.
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
	// First implemenation of the parser for TRANSACTION ISOLATION LEVEL and TRANSACTION READ/WRITE.
	// Keys are "<scope>:isolation level" or "<scope>:read", where scope is "session"
	// (SESSION or LOCAL) or "" (next transaction only).
	std::map<std::string, std::vector<std::string>> parse2();
	std::string parse_character_set();
	std::string parse_USE_query(std::string& errmsg);
	std::string remove_comments(const std::string& q);
#ifdef DEBUG
	// built-in testing
	void test_parse_USE_query();
#endif // DEBUG
	~MySQL_Set_Stmt_Parser();
};

#endif /* PROXYSQL_MYSQL_SET_STMT_PARSER_H */
