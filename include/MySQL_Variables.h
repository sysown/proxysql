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
bool verify_variable(MySQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash);
bool logbin_update_server_variable(MySQL_Session* session, int idx, int &_rc);
char* collation_id_from_charset_name_r(const char *name, char* collation_id, int length);
char* collation_id_from_collate_r(const char *collation, char* collation_id, int length);

class MySQL_Variables {
	MySQL_Session* session;

	verify_var verifiers[SQL_NAME_LAST];
	update_var updaters[SQL_NAME_LAST];

public:
	bool is_connected_to_backend;
	MySQL_Variables(MySQL_Session* session);
	virtual ~MySQL_Variables();

	bool client_set_value(int idx, const std::string& value);
	const char* client_get_value(int idx) const;
	uint32_t client_get_hash(int idx) const;

	void server_set_value(int idx, const char* value);
	const char* server_get_value(int idx) const;
	inline uint32_t server_get_hash(int idx) const;

	bool verify_variable(int idx) const;
	bool update_variable(session_status status, int &_rc);
	bool on_connect_to_backend(mysql_variable_st* tracked_variables);
};

#endif // #ifndef MYSQL_VARIABLES_H

