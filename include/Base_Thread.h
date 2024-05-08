#ifndef CLASS_BASE_THREAD_H
#define CLASS_BASE_THREAD_H

#include "proxysql.h"

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

class MySQL_Thread;
class PgSQL_Thread;

class Base_Thread {
	public:
	unsigned long long curtime;
	int shutdown;
	PtrArray *mysql_sessions;
	Session_Regex **match_regexes;
	Base_Thread();
	~Base_Thread();
	template<typename T, typename S>
	S create_new_session_and_client_data_stream(int _fd);
	template<typename T, typename S>
	void register_session(T, S, bool up_start = true);
};

#endif // CLASS_BASE_THREAD_H
