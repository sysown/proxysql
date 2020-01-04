#ifndef MYSQL_VARIABLES_H
#define MYSQL_VARIABLES_H

#include "proxysql.h"
#include "cpp.h"

#include <cstdint>
#include <vector>
#include <memory>

class MySQL_Session;

class Updater {
public:
	virtual bool verify_variables(MySQL_Session* session, int idx) = 0;
	virtual bool update_server_variable(MySQL_Session* session, int idx, int &_rc) = 0;
};

class Generic_Updater : public Updater {
public:
	bool verify_variables(MySQL_Session* session, int idx);
	bool update_server_variable(MySQL_Session* session, int idx, int &_rc);
};

class MySQL_Variables {
	MySQL_Session* session;
public:
	bool verify_generic_variable(uint32_t *be_int, char **be_var, char *def, uint32_t *fe_int, char *fe_var, enum session_status next_sess_status);
	static int session_statuses[SQL_NAME_LAST];
	Updater* updaters[SQL_NAME_LAST];

	MySQL_Variables(MySQL_Session* session);
	virtual ~MySQL_Variables();

	void client_set_value(int idx, const char* value);
	const char* client_get_value(int idx);
	uint32_t client_get_hash(int idx);

	void server_set_value(int idx, const char* value);
	const char* server_get_value(int idx);
	uint32_t server_get_hash(int idx);

	bool verify_generic_variable(int idx);

};

#endif // #ifndef MYSQL_VARIABLES_H

