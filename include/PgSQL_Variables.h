#ifndef PGSQL_VARIABLES_H
#define PGSQL_VARIABLES_H

#include "proxysql.h"

#include <cstdint>
#include <vector>
#include <memory>

class PgSQL_Session;

extern void print_backtrace(void);

typedef bool (*pgsql_verify_var)(PgSQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash);
typedef bool (*pgsql_update_var)(PgSQL_Session* session, int idx, int &_rc);

bool validate_charset(PgSQL_Session* session, int idx, int &_rc);
bool update_server_variable(PgSQL_Session* session, int idx, int &_rc);
bool verify_server_variable(PgSQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash);
bool verify_set_names(PgSQL_Session* session);
#if 0
bool logbin_update_server_variable(PgSQL_Session* session, int idx, int &_rc);
#endif // 0

class PgSQL_Variables {
	static pgsql_verify_var verifiers[SQL_NAME_LAST_HIGH_WM];
	static pgsql_update_var updaters[SQL_NAME_LAST_HIGH_WM];

public:
	std::string variables_regexp;
	// ignore_vars is a list of all variables that proxysql will parse but ignore its value
	std::vector<std::string> ignore_vars;
public:
	PgSQL_Variables();
	~PgSQL_Variables();

	bool client_set_value(PgSQL_Session* session, int idx, const std::string& value);
	bool client_set_hash_and_value(PgSQL_Session* session, int idx, const std::string& value, uint32_t hash);
	void client_reset_value(PgSQL_Session* session, int idx);
	const char* client_get_value(PgSQL_Session* session, int idx) const;
	uint32_t client_get_hash(PgSQL_Session* session, int idx) const;

	void server_set_value(PgSQL_Session* session, int idx, const char* value);
	void server_set_hash_and_value(PgSQL_Session* session, int idx, const char* value, uint32_t hash);
	void server_reset_value(PgSQL_Session* session, int idx);
	const char* server_get_value(PgSQL_Session* session, int idx) const;
	inline uint32_t server_get_hash(PgSQL_Session* session, int idx) const;

	bool verify_variable(PgSQL_Session* session, int idx) const;
	bool update_variable(PgSQL_Session* session, session_status status, int &_rc);
	bool parse_variable_boolean(PgSQL_Session*sess, int idx, std::string &value1, bool* lock_hostgroup);
	bool parse_variable_number(PgSQL_Session*sess, int idx, std::string &value1, bool* lock_hostgroup);
};

#endif // PGSQL_VARIABLES_H

