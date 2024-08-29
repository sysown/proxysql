#ifndef __CLASS_CLIENT_SESSION_H
#define __CLASS_CLIENT_SESSION_H

#include <functional>
#include <vector>

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Variables.h"

//#include "../deps/json/json.hpp"
//using json = nlohmann::json;

#ifndef PROXYJSON
#define PROXYJSON
namespace nlohmann { class json; }
#endif // PROXYJSON

#if 0
// this code was moved into Base_Session.h
/**
 * @class Session_Regex
 * @brief Encapsulates regex operations for session handling.
 *
 * This class is used for matching patterns in SQL queries, specifically for
 * settings like sql_log_bin, sql_mode, and time_zone.
 * See issues #509 , #815 and #816
 */
class Session_Regex {
private:
	void* opt;
	void* re;
	char* s;
public:
	Session_Regex(char* p);
	~Session_Regex();
	bool match(char* m);
};
#endif // 0

std::string proxysql_session_type_str(enum proxysql_session_type session_type);

#endif /* __CLASS_CLIENT_SESSION_H */
