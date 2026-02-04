#include "MySQL_Session_Utils.h"
#include "MySQL_Variables_Utils.h"

std::array<Session_Regex,4> mysql_match_regexes {
	// NOTE: historically we used match_regexes[0] for SET SQL_LOG_BIN . Not anymore
	"",
	(
		"^SET (|SESSION |@@|@@session.|@@local.)`?(" + get_mysql_variables_regexp() + ")`?( *)(:|)=( *)"
	).c_str(),
	"^SET(?: +)(|SESSION +)TRANSACTION(?: +)(?:(?:(ISOLATION(?: +)LEVEL)(?: +)(REPEATABLE(?: +)READ|"
		"READ(?: +)COMMITTED|READ(?: +)UNCOMMITTED|SERIALIZABLE))|(?:(READ)(?: +)(WRITE|ONLY)))",
	"^(set)(?: +)((charset)|(character +set))(?: )"
};
