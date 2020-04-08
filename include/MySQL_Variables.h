#ifndef MYSQL_VARIABLES_H
#define MYSQL_VARIABLES_H

#include "proxysql.h"
#include "cpp.h"

#include <cstdint>
#include <vector>
#include <memory>

class MySQL_Session;

extern const MARIADB_CHARSET_INFO * proxysql_find_charset_nr(unsigned int nr);
extern MARIADB_CHARSET_INFO * proxysql_find_charset_name(const char *name);
extern MARIADB_CHARSET_INFO * proxysql_find_charset_collate(const char *collatename);
extern void print_backtrace(void);

typedef bool (*verify_var)(MySQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash);
typedef bool (*update_var)(MySQL_Session* session, int idx, int &_rc);

bool validate_charset(MySQL_Session* session, int idx, int &_rc);
bool update_server_variable(MySQL_Session* session, int idx, int &_rc);
bool verify_server_variable(MySQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash);
bool logbin_update_server_variable(MySQL_Session* session, int idx, int &_rc);

class MySQL_Variables {
	static verify_var verifiers[SQL_NAME_LAST];
	static update_var updaters[SQL_NAME_LAST];

public:
	MySQL_Variables();

	bool is_connected_to_backend;
	virtual ~MySQL_Variables();

	bool client_set_value(MySQL_Session* session, int idx, const std::string& value);
	const char* client_get_value(MySQL_Session* session, int idx) const;
	uint32_t client_get_hash(MySQL_Session* session, int idx) const;

	void server_set_value(MySQL_Session* session, int idx, const char* value);
	const char* server_get_value(MySQL_Session* session, int idx) const;
	inline uint32_t server_get_hash(MySQL_Session* session, int idx) const;

	bool verify_variable(MySQL_Session* session, int idx) const;
	bool update_variable(MySQL_Session* session, session_status status, int &_rc);
	bool on_connect_to_backend(MySQL_Session* session, mysql_variable_st* tracked_variables);
};

#endif // #ifndef MYSQL_VARIABLES_H

