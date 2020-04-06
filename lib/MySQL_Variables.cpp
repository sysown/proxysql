#include "MySQL_Variables.h"
#include "proxysql.h"

#include "MySQL_Session.h"
#include "MySQL_Data_Stream.h"
#include "SpookyV2.h"

#include <sstream>

extern const MARIADB_CHARSET_INFO * proxysql_find_charset_nr(unsigned int nr);
extern MARIADB_CHARSET_INFO * proxysql_find_charset_name(const char *name);

MySQL_Variables::MySQL_Variables(MySQL_Session* _session) {
	assert(_session);
	session = _session;

	for (auto i = 0; i < SQL_NAME_LAST; i++) {
		switch(i) {
		case SQL_SAFE_UPDATES:
		case SQL_SELECT_LIMIT:
		case SQL_SQL_MODE:
		case SQL_TIME_ZONE:
		case SQL_CHARACTER_SET_RESULTS:
		case SQL_CHARACTER_SET_CONNECTION:
		case SQL_CHARACTER_SET_CLIENT:
		case SQL_CHARACTER_SET_DATABASE:
		case SQL_ISOLATION_LEVEL:
		case SQL_TRANSACTION_READ:
		case SQL_SESSION_TRACK_GTIDS:
		case SQL_SQL_AUTO_IS_NULL:
		case SQL_COLLATION_CONNECTION:
		case SQL_NET_WRITE_TIMEOUT:
		case SQL_MAX_JOIN_SIZE:
			updaters[i] = new Generic_Updater();
			break;
		default:
			updaters[i] = NULL;
		}
	}
}

MySQL_Variables::~MySQL_Variables() {
	for (auto u : updaters)
		delete u;
}

void print_backtrace(void);

void MySQL_Variables::client_set_value(int idx, const std::string& value) {
	if (!session || !session->client_myds || !session->client_myds->myconn) return;
	session->client_myds->myconn->variables[idx].hash = SpookyHash::Hash32(value.c_str(),strlen(value.c_str()),10);

	switch (idx) {
	case SQL_CHARACTER_ACTION:
		// SET NAMES command from client
		if (value == "1") {
			if (session->mysql_variables->client_get_value(SQL_CHARACTER_SET)) {
				session->mysql_variables->client_set_value(SQL_CHARACTER_SET_RESULTS, session->mysql_variables->client_get_value(SQL_CHARACTER_SET));
				session->mysql_variables->client_set_value(SQL_CHARACTER_SET_CLIENT, session->mysql_variables->client_get_value(SQL_CHARACTER_SET));
				session->mysql_variables->client_set_value(SQL_CHARACTER_SET_CONNECTION, session->mysql_variables->client_get_value(SQL_CHARACTER_SET));
				session->mysql_variables->client_set_value(SQL_COLLATION_CONNECTION, session->mysql_variables->client_get_value(SQL_CHARACTER_SET));
			}
		}
		// SET CHARSET command from client
		else if (value == "2") {
			if (session->mysql_variables->client_get_value(SQL_CHARACTER_SET)) {
				session->mysql_variables->client_set_value(SQL_CHARACTER_SET_RESULTS, session->mysql_variables->client_get_value(SQL_CHARACTER_SET));
				session->mysql_variables->client_set_value(SQL_CHARACTER_SET_CLIENT, session->mysql_variables->client_get_value(SQL_CHARACTER_SET));
			}
			if (session->mysql_variables->client_get_value(SQL_CHARACTER_SET_DATABASE)) {
				session->mysql_variables->client_set_value(SQL_CHARACTER_SET_CONNECTION, session->mysql_variables->client_get_value(SQL_CHARACTER_SET_DATABASE));
				session->mysql_variables->client_set_value(SQL_COLLATION_CONNECTION, session->mysql_variables->client_get_value(SQL_CHARACTER_SET_DATABASE));
			}
		}
		// SET NAMES during handshake etc.
		else if (value == "3") {
			if (session->mysql_variables->server_get_value(SQL_CHARACTER_SET)) {
				session->mysql_variables->client_set_value(SQL_CHARACTER_SET_RESULTS, session->mysql_variables->server_get_value(SQL_CHARACTER_SET));
				session->mysql_variables->client_set_value(SQL_CHARACTER_SET_CLIENT, session->mysql_variables->server_get_value(SQL_CHARACTER_SET));
				session->mysql_variables->client_set_value(SQL_CHARACTER_SET_CONNECTION, session->mysql_variables->server_get_value(SQL_CHARACTER_SET));
				session->mysql_variables->client_set_value(SQL_COLLATION_CONNECTION, session->mysql_variables->server_get_value(SQL_CHARACTER_SET));
			}
		}
	}

	if (session->client_myds->myconn->variables[idx].value) {
		free(session->client_myds->myconn->variables[idx].value);
	}
	session->client_myds->myconn->variables[idx].value = strdup(value.c_str());
}

const char* MySQL_Variables::client_get_value(int idx) {
	if (!session || !session->client_myds || !session->client_myds->myconn) return NULL;
	return session->client_myds->myconn->variables[idx].value;
}

uint32_t MySQL_Variables::client_get_hash(int idx) {
	if (!session || !session->client_myds || !session->client_myds->myconn) return 0;
	return session->client_myds->myconn->variables[idx].hash;
}

void MySQL_Variables::server_set_value(int idx, const char* value) {
	if (!session || !session->mybe || !session->mybe->server_myds || !session->mybe->server_myds->myconn || !value) return;
	session->mybe->server_myds->myconn->variables[idx].hash = SpookyHash::Hash32(value,strlen(value),10);

	if (session->mybe->server_myds->myconn->variables[idx].value) {
		free(session->mybe->server_myds->myconn->variables[idx].value);
	}
	session->mybe->server_myds->myconn->variables[idx].value = strdup(value);
}

const char* MySQL_Variables::server_get_value(int idx) {
	if (!session || !session->mybe || !session->mybe->server_myds || !session->mybe->server_myds->myconn) return NULL;
	return session->mybe->server_myds->myconn->variables[idx].value;
}

uint32_t MySQL_Variables::server_get_hash(int idx) {
	if (!session || !session->mybe || !session->mybe->server_myds || !session->mybe->server_myds->myconn) return 0;
	return session->mybe->server_myds->myconn->variables[idx].hash;
}

bool MySQL_Variables::update_variable(session_status status, int &_rc) {
	int idx = SQL_NAME_LAST;
	for (int i=0; i<SQL_NAME_LAST; i++) {
		if (mysql_tracked_variables[i].status == status) {
			idx = i;
			break;
		}
	}
	assert(idx != SQL_NAME_LAST);
	return updaters[idx]->update_server_variable(session, idx, _rc);
}

bool MySQL_Variables::verify_variable(int idx) {
	auto ret = false;
	if (updaters[idx] && updaters[idx])
		ret = updaters[idx]->verify_variables(session, idx);
	return ret;
}

/* 
 * Updaters for different variables
 */

Updater::~Updater() {}


bool Generic_Updater::verify_variables(MySQL_Session* session, int idx) {
	if ( !session->mysql_variables->server_get_value(idx) || strcmp(session->mysql_variables->client_get_value(idx),  session->mysql_variables->server_get_value(idx))) {
		switch(session->status) { // this switch can be replaced with a simple previous_status.push(status), but it is here for readibility
			case PROCESSING_QUERY:
				session->previous_status.push(PROCESSING_QUERY);
				break;
			case PROCESSING_STMT_PREPARE:
				session->previous_status.push(PROCESSING_STMT_PREPARE);
				break;
			case PROCESSING_STMT_EXECUTE:
				session->previous_status.push(PROCESSING_STMT_EXECUTE);
				break;
			default:
				proxy_error("Wrong status %d\n", session->status);
				assert(0);
				break;
		}
		session->set_status(mysql_tracked_variables[idx].status);
		proxy_warning("TRACE: tid [%lu] setting SERVER variable %d, value %s\n", session->thread_session_id, idx, session->mysql_variables->client_get_value(idx));
		session->mysql_variables->server_set_value(idx, session->mysql_variables->client_get_value(idx));
		return true;
	}
	return false;
}

bool Generic_Updater::update_server_variable(MySQL_Session* session, int idx, int &_rc) {
	bool no_quote = true;
	if (mysql_tracked_variables[idx].quote) no_quote = false;
	bool st = mysql_tracked_variables[idx].set_transaction;
	const char * set_var_name = mysql_tracked_variables[idx].set_variable_name;
	bool ret = false;

	/* character set variables store collation id in the char* string, but we set character_set_% command
	 * uses character set name or collation name. This branch convert collation id to character set name
	 * or collation name for further execution on backend
	 */
	if (idx==SQL_CHARACTER_SET_RESULTS) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		ci = proxysql_find_charset_nr(atoi(session->mysql_variables->client_get_value(SQL_CHARACTER_SET_RESULTS)));

		/* CHARACTER_SET_RESULTS may have "NULL" and "binary" as parameter value. 
		 * -1 - NULL
		 * -2 - binary
		 *
		 *  TODO: current implementation is not nice. Think about nicer implementation
		 */
		if (!ci) {
			if (!strcmp(session->mysql_variables->client_get_value(SQL_CHARACTER_SET_RESULTS), "-1")) {
				session->mysql_variables->server_set_value(idx, session->mysql_variables->client_get_value(idx));
				ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, "NULL", no_quote, st);
			}
			else if (!strcmp(session->mysql_variables->client_get_value(SQL_CHARACTER_SET_RESULTS), "-2")) {
				session->mysql_variables->server_set_value(idx, session->mysql_variables->client_get_value(idx));
				ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, "binary", no_quote, st);
			}
		} else {
			session->mysql_variables->server_set_value(idx, session->mysql_variables->client_get_value(idx));
			ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, ci->csname, no_quote, st);
		}
	} else if (idx==SQL_COLLATION_CONNECTION) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		ci = proxysql_find_charset_nr(atoi(session->mysql_variables->client_get_value(SQL_COLLATION_CONNECTION)));

		std::stringstream ss;
		ss << ci->nr;

		session->mysql_variables->server_set_value(idx, session->mysql_variables->client_get_value(idx));
		ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, ci->name, no_quote, st);
	} else if (idx==SQL_CHARACTER_SET_CONNECTION) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		ci = proxysql_find_charset_nr(atoi(session->mysql_variables->client_get_value(SQL_CHARACTER_SET_CONNECTION)));

		unsigned int nr = ci->nr;
		std::stringstream ss;
		ss << nr;

		session->mysql_variables->server_set_value(idx, session->mysql_variables->client_get_value(idx));
		ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, ci->csname, no_quote, st);
	} else if (idx==SQL_CHARACTER_SET_CLIENT || idx==SQL_CHARACTER_SET_DATABASE) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		ci = proxysql_find_charset_nr(atoi(session->mysql_variables->client_get_value(idx)));

		std::stringstream ss;
		ss << ci->nr;
		session->mysql_variables->server_set_value(idx, session->mysql_variables->client_get_value(idx));
		ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, ci->csname, no_quote, st);
	} else {
		session->mysql_variables->server_set_value(idx, session->mysql_variables->client_get_value(idx));
		ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, session->mysql_variables->server_get_value(idx), no_quote, st);
	}
	return ret;
}


