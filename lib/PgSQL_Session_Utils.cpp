#include "PgSQL_Session_Utils.h"
#include "PgSQL_Variables_Utils.h"

std::array<Session_Regex,4> pgsql_match_regexes {
	"",
	("^SET(?: +)(|SESSION +)`?(" + get_pgsql_variables_regexp() + ")`?( *)(|=|TO)( *)").c_str(),
	"^SET(?: +)(|SESSION +)TRANSACTION(?: +)(?:(?:(ISOLATION(?: +)LEVEL)(?: +)(REPEATABLE(?: +)READ|"
		"READ(?: +)COMMITTED|READ(?: +)UNCOMMITTED|SERIALIZABLE))|(?:(READ)(?: +)(WRITE|ONLY)))",
	"^SET(?: +)(|SESSION +)`?(client_encoding|names)`?( *)(|=|TO)( *)"
};
