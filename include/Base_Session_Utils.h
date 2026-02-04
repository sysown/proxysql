#ifndef BASE_SESSION_UTILS_H
#define BASE_SESSION_UTILS_H

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
	Session_Regex(const char* p);
	~Session_Regex();
	bool match(const char* m);
};

#endif // BASE_SESSION_UTILS_H
