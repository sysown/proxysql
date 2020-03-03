#include "MySQL_Variables.h"
#include "proxysql.h"

#include "MySQL_Session.h"
#include "MySQL_Data_Stream.h"
#include "SpookyV2.h"

#include <sstream>

MySQL_Variables::MySQL_Variables(MySQL_Session* _session) : session(_session), is_connected_to_backend(false) {
	assert(_session);

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
				verifiers[i] = ::verify_variable;
				updaters[i] = update_server_variable;
				break;
			case SQL_LOG_BIN:
				verifiers[i] = ::verify_variable;
				updaters[i] = logbin_update_server_variable;
				break;
			default:
				updaters[i] = NULL;
		}
	}
}

MySQL_Variables::~MySQL_Variables() {}

bool MySQL_Variables::on_connect_to_backend(mysql_variable_st *tracked_variables) {
	if (!session || !session->mybe || !session->mybe->server_myds || !session->mybe->server_myds->myconn) return false;
	auto be_version = session->mybe->server_myds->myconn->mysql->server_version;

	if (be_version[0] == '1') {
		int idx = SQL_NAME_LAST;
		for (auto i=0; i<SQL_NAME_LAST; i++) {
			if (tracked_variables[i].idx == SQL_SESSION_TRACK_GTIDS) {
				idx = i;
				break;
			}
		}
		tracked_variables[idx].special_handling = false;
	}

	is_connected_to_backend = true;
	return true;
}

bool MySQL_Variables::client_set_value(int idx, const std::string& value) {
	if (!session || !session->client_myds || !session->client_myds->myconn) {
		proxy_warning("Session validation failed\n");
		return false;
	}

	/* Process SET NAMES and SET CHARSET commands
	 * The character_set_client, character_set_results, character_set_connection variables are set here
	 * During multiplexing/query execution these values will be used to set corresponding backend variables
	 * The charset used in SET NAMES and SET CHARSET is not used in setting backend chrsets
	 */
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
			if (!session->mysql_variables->client_get_value(SQL_CHARACTER_SET_DATABASE)) {
				const MARIADB_CHARSET_INFO *ci = NULL;
				ci = proxysql_find_charset_name(mysql_tracked_variables[SQL_CHARACTER_SET_CONNECTION].default_value);

				unsigned int nr = ci->nr;
				std::stringstream ss;
				ss << nr;

				session->mysql_variables->client_set_value(SQL_CHARACTER_SET_CONNECTION, ss.str());
				ci = proxysql_find_charset_collate(mysql_tracked_variables[SQL_COLLATION_CONNECTION].default_value);

				nr = ci->nr;
				ss.str(std::string());
				ss.clear();
				ss << nr;

				session->mysql_variables->client_set_value(SQL_COLLATION_CONNECTION, ss.str());
			} else {
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

	session->client_myds->myconn->var_hash[idx] = SpookyHash::Hash32(value.c_str(),strlen(value.c_str()),10);
	if (session->client_myds->myconn->variables[idx].value) {
		free(session->client_myds->myconn->variables[idx].value);
	}
	session->client_myds->myconn->variables[idx].value = strdup(value.c_str());

	return true;
}

const char* MySQL_Variables::client_get_value(int idx) const {
	if (!session || !session->client_myds || !session->client_myds->myconn) return NULL;
	return session->client_myds->myconn->variables[idx].value;
}

uint32_t MySQL_Variables::client_get_hash(int idx) const {
	if (!session || !session->client_myds || !session->client_myds->myconn) return 0;
	return session->client_myds->myconn->var_hash[idx];
}

void MySQL_Variables::server_set_value(int idx, const char* value) {
	if (!session || !session->mybe || !session->mybe->server_myds || !session->mybe->server_myds->myconn || !value) return;
	session->mybe->server_myds->myconn->var_hash[idx] = SpookyHash::Hash32(value,strlen(value),10);

	if (session->mybe->server_myds->myconn->variables[idx].value) {
		free(session->mybe->server_myds->myconn->variables[idx].value);
	}
	session->mybe->server_myds->myconn->variables[idx].value = strdup(value);
}

const char* MySQL_Variables::server_get_value(int idx) const {
	if (!session || !session->mybe || !session->mybe->server_myds || !session->mybe->server_myds->myconn) return NULL;
	return session->mybe->server_myds->myconn->variables[idx].value;
}

uint32_t MySQL_Variables::server_get_hash(int idx) const {
	if (!session || !session->mybe || !session->mybe->server_myds || !session->mybe->server_myds->myconn) return 0;
	return session->mybe->server_myds->myconn->var_hash[idx];
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
	return updaters[idx](session, idx, _rc);
}

bool MySQL_Variables::verify_variable(int idx) const {
	auto ret = false;
	if (likely(verifiers[idx])) {
		auto client_hash = session->client_myds->myconn->var_hash[idx];
		auto server_hash = session->mybe->server_myds->myconn->var_hash[idx];
		ret = verifiers[idx](session, idx, client_hash, server_hash);
	}
	return ret;
}

bool validate_charset(MySQL_Session* session, int idx, int &_rc) {
	if (idx == SQL_CHARACTER_SET || idx == SQL_CHARACTER_SET_CLIENT || idx == SQL_CHARACTER_SET_RESULTS ||
			idx == SQL_CHARACTER_SET_CONNECTION || idx == SQL_CHARACTER_SET_DATABASE || idx == SQL_COLLATION_CONNECTION) {
		MySQL_Data_Stream *myds = session->mybe->server_myds;
		MySQL_Connection *myconn = myds->myconn;
		char msg[128];
		const MARIADB_CHARSET_INFO *ci = NULL;
		const char* replace_collation = NULL;
		const char* not_supported_collation = NULL;
		unsigned int replace_collation_nr = 0;
		std::stringstream ss;
		int charset = atoi(session->mysql_variables->client_get_value(idx));
		if (charset >= 255 && myconn->mysql->server_version[0] != '8') {
			switch(mysql_thread___handle_unknown_charset) {
				case HANDLE_UNKNOWN_CHARSET__DISCONNECT_CLIENT:
					snprintf(msg,sizeof(msg),"Can't initialize character set %s", session->mysql_variables->client_get_value(idx));
					proxy_error("Can't initialize character set on %s, %d: Error %d (%s). Closing client connection %s:%d.\n",
							myconn->parent->address, myconn->parent->port, 2019, msg, session->client_myds->addr.addr, session->client_myds->addr.port);
					myds->destroy_MySQL_Connection_From_Pool(false);
					myds->fd=0;
					_rc=-1;
					return false;
				case HANDLE_UNKNOWN_CHARSET__REPLACE_WITH_DEFAULT_VERBOSE:
					ci = proxysql_find_charset_nr(charset);
					if (!ci) {
						proxy_error("Cannot find character set [%s]\n", session->mysql_variables->client_get_value(idx));
						assert(0);
					}
					not_supported_collation = ci->name;

					if (idx == SQL_COLLATION_CONNECTION) {
						ci = proxysql_find_charset_collate(mysql_thread___default_variables[idx]);
					} else {
						ci = proxysql_find_charset_name(mysql_thread___default_variables[idx]);
					}

					if (!ci) {
						proxy_error("Cannot find character set [%s]\n", mysql_thread___default_variables[idx]);
						assert(0);
					}
					replace_collation = ci->name;
					replace_collation_nr = ci->nr;

					proxy_warning("Server doesn't support collation (%s) %s. Replacing it with the configured default (%d) %s. Client %s:%d\n",
							session->mysql_variables->client_get_value(idx), not_supported_collation, 
							replace_collation_nr, replace_collation, session->client_myds->addr.addr, session->client_myds->addr.port);

					ss << replace_collation_nr;
					session->mysql_variables->client_set_value(idx, ss.str());
					_rc=0;
					return true;
				case HANDLE_UNKNOWN_CHARSET__REPLACE_WITH_DEFAULT:
					if (idx == SQL_COLLATION_CONNECTION) {
						ci = proxysql_find_charset_collate(mysql_thread___default_variables[idx]);
					} else {
						ci = proxysql_find_charset_name(mysql_thread___default_variables[idx]);
					}

					if (!ci) {
						proxy_error("Cannot filnd charset [%s]\n", mysql_thread___default_variables[idx]);
						assert(0);
					}
					replace_collation_nr = ci->nr;

					ss << replace_collation_nr;
					session->mysql_variables->client_set_value(idx, ss.str());
					_rc=0;
					return true;
				default:
					proxy_error("Wrong configuration of the handle_unknown_charset\n");
					_rc=-1;
					return false;
			}
		}
	}
	_rc=0;
	return true;
}

bool update_server_variable(MySQL_Session* session, int idx, int &_rc) {
	bool no_quote = true;
	if (mysql_tracked_variables[idx].quote) no_quote = false;
	bool st = mysql_tracked_variables[idx].set_transaction;
	const char * set_var_name = mysql_tracked_variables[idx].set_variable_name;
	bool ret = false;

	/* Validating that charset is less than 255 for mysqld version <8.0
	 */
	if (!validate_charset(session, idx, _rc)) {
		return false;
	}

	/* character set variables store collation id in the char* string, but we set character_set_% command
	 * uses character set name or collation name. This branch convert collation id to character set name
	 * or collation name for further execution on backend
	 */
	if (idx==SQL_CHARACTER_SET_RESULTS) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		ci = proxysql_find_charset_nr(atoi(session->mysql_variables->client_get_value(SQL_CHARACTER_SET_RESULTS)));

		if (!ci) {
			if (!strcmp(session->mysql_variables->client_get_value(SQL_CHARACTER_SET_RESULTS), "NULL")) {
				session->mysql_variables->server_set_value(idx, session->mysql_variables->client_get_value(idx));
				ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, "NULL", no_quote, st);
			} else if (!strcmp(session->mysql_variables->client_get_value(SQL_CHARACTER_SET_RESULTS), "binary")) {
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

inline bool verify_variable(MySQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash) {
	if (client_hash != server_hash) {
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
		session->mysql_variables->server_set_value(idx, session->mysql_variables->client_get_value(idx));
		return true;
	}
	return false;
}

bool logbin_update_server_variable(MySQL_Session* session, int idx, int &_rc) {
	return session->handler_again___status_SETTING_SQL_LOG_BIN(&_rc);
}

