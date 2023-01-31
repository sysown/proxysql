#include "MySQL_Variables.h"
#include "proxysql.h"

#include "MySQL_Session.h"
#include "MySQL_Data_Stream.h"
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include <sstream>


static inline char is_digit(char c) {
	if(c >= '0' && c <= '9')
		return 1;
	return 0;
}


verify_var MySQL_Variables::verifiers[SQL_NAME_LAST_HIGH_WM];
update_var MySQL_Variables::updaters[SQL_NAME_LAST_HIGH_WM];


MySQL_Variables::MySQL_Variables() {
	// add here all the variables we want proxysql to recognize, but ignore
	ignore_vars.push_back("interactive_timeout");
	ignore_vars.push_back("wait_timeout");
	ignore_vars.push_back("net_read_timeout");
	ignore_vars.push_back("net_write_timeout");
	ignore_vars.push_back("net_buffer_length");
	ignore_vars.push_back("read_buffer_size");
	ignore_vars.push_back("read_rnd_buffer_size");
	// NOTE: This variable has been temporarily ignored. Check issues #3442 and #3441.
	ignore_vars.push_back("session_track_schema");
	variables_regexp = "";
	for (auto i = 0; i < SQL_NAME_LAST_HIGH_WM; i++) {
		// we initialized all the internal_variable_name if set to NULL
		if (mysql_tracked_variables[i].internal_variable_name == NULL) {
			mysql_tracked_variables[i].internal_variable_name = mysql_tracked_variables[i].set_variable_name;
		}
	}
/*
   NOTE:
	make special ATTENTION that the order in mysql_variable_name
	and mysql_tracked_variables[] is THE SAME
   NOTE:
	MySQL_Variables::MySQL_Variables() has a built-in check to make sure that the order is correct,
	and that variables are in alphabetical order
*/
	for (int i = SQL_NAME_LAST_LOW_WM; i < SQL_NAME_LAST_HIGH_WM; i++) {
		assert(i == mysql_tracked_variables[i].idx);
		if (i > SQL_NAME_LAST_LOW_WM+1) {
			assert(strcmp(mysql_tracked_variables[i].set_variable_name, mysql_tracked_variables[i-1].set_variable_name) > 0);
		}
	}
	for (auto i = 0; i < SQL_NAME_LAST_HIGH_WM; i++) {
		if (i == SQL_CHARACTER_SET || i == SQL_CHARACTER_ACTION || i == SQL_SET_NAMES) {
			MySQL_Variables::updaters[i] = NULL;
			MySQL_Variables::verifiers[i] = NULL;
		}
		else if (i == SQL_SQL_LOG_BIN) {
			MySQL_Variables::verifiers[i] = verify_server_variable;
			MySQL_Variables::updaters[i] = logbin_update_server_variable;
		} else {
			MySQL_Variables::verifiers[i] = verify_server_variable;
			MySQL_Variables::updaters[i] = update_server_variable;
		}
		if (mysql_tracked_variables[i].status == SETTING_VARIABLE) {
			variables_regexp += mysql_tracked_variables[i].set_variable_name;
			variables_regexp += "|";
		}
	}
	for (std::vector<std::string>::iterator it=ignore_vars.begin(); it != ignore_vars.end(); it++) {
		variables_regexp += *it;
		variables_regexp += "|";
	}
}

MySQL_Variables::~MySQL_Variables() {}

bool MySQL_Variables::client_set_hash_and_value(MySQL_Session* session, int idx, const std::string& value, uint32_t hash) {
	if (!session || !session->client_myds || !session->client_myds->myconn) {
		proxy_warning("Session validation failed\n");
		return false;
	}

	session->client_myds->myconn->var_hash[idx] = hash;
	if (session->client_myds->myconn->variables[idx].value) {
		free(session->client_myds->myconn->variables[idx].value);
	}
	session->client_myds->myconn->variables[idx].value = strdup(value.c_str());

	return true;
}

void MySQL_Variables::server_set_hash_and_value(MySQL_Session* session, int idx, const char* value, uint32_t hash) {
	if (!session || !session->mybe || !session->mybe->server_myds || !session->mybe->server_myds->myconn || !value) {
		proxy_warning("Session validation failed\n");
		return;
	}

	session->mybe->server_myds->myconn->var_hash[idx] = hash;
	if (session->mybe->server_myds->myconn->variables[idx].value) {
		free(session->mybe->server_myds->myconn->variables[idx].value);
	}
	session->mybe->server_myds->myconn->variables[idx].value = strdup(value);
}


/**
 * @brief Set the supplied value for the session variable specified by the supplied
 *  index into the supplied client session.
 *
 * @details There are two session variables which require special handling:
 *   - 'SET NAMES'
 *   - 'SET CHARACTER SET'
 *
 * For the second case 'SET CHARACTER SET' we forget about the values for:
 *   - 'SQL_CHARACTER_SET_CONNECTION'
 *   - 'SQL_COLLATION_CONNECTION'
 *
 * This is done because 'character_set_database' is not known when the set happens and
 * because we work under the assumption that if a client request 'SET CHARACTER SET'
 * doesn't require a specific 'collation_connection' and 'character_set_connection".
 * Furthermore, 'character_set_database' is deprecated since MySQL 5.7 and will only
 * be usable as an immutable session variable in the future. For reference see:
 *
 * - 'https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_character_set_database
 *
 * Due to this, *it's expected behavior* to see that a connection that sets 'SET CHARACTER SET'
 * has a variant 'collation_connection' and 'character_set_connection' depending on the
 * backend connection that is retrieved from the connection pool. If the 'collation_connection'
 * and 'character_set_connection' variables are relevant and should never change,
 * 'SET NAMES' should be used.
 *
 * @param session The client session which variable value is going to be modified.
 * @param idx The index of the session variable to modify.
 * @param value The session variable value to be set.
 *
 * @return 'true' in case of success, 'false' otherwise.
 */
bool MySQL_Variables::client_set_value(MySQL_Session* session, int idx, const std::string& value) {
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
			if (mysql_variables.client_get_value(session, SQL_CHARACTER_SET)) {
				const char* value = mysql_variables.client_get_value(session, SQL_CHARACTER_SET);
				uint32_t hash = mysql_variables.client_get_hash(session, SQL_CHARACTER_SET);

				mysql_variables.client_set_hash_and_value(session, SQL_CHARACTER_SET_RESULTS, value, hash);
				mysql_variables.client_set_hash_and_value(session, SQL_CHARACTER_SET_CLIENT, value, hash);
				mysql_variables.client_set_hash_and_value(session, SQL_CHARACTER_SET_CONNECTION, value, hash);
				mysql_variables.client_set_hash_and_value(session, SQL_COLLATION_CONNECTION, value, hash);
			}
		}
		// SET CHARSET command from client
		else if (value == "2") {
			if (mysql_variables.client_get_value(session, SQL_CHARACTER_SET)) {
				const char* value = mysql_variables.client_get_value(session, SQL_CHARACTER_SET);
				uint32_t hash = mysql_variables.client_get_hash(session, SQL_CHARACTER_SET);

				mysql_variables.client_set_hash_and_value(session, SQL_CHARACTER_SET_RESULTS, value, hash);
				mysql_variables.client_set_hash_and_value(session, SQL_CHARACTER_SET_CLIENT, value, hash);

				// Setting connection and collation connection to NULL
				// because we do not know database character set
				mysql_variables.client_set_hash_and_value(session, SQL_CHARACTER_SET_CONNECTION, "", 0);
				mysql_variables.client_set_hash_and_value(session, SQL_COLLATION_CONNECTION, "", 0);
			}
		}
	}

	session->client_myds->myconn->var_hash[idx] = SpookyHash::Hash32(value.c_str(),strlen(value.c_str()),10);
	if (session->client_myds->myconn->variables[idx].value) {
		free(session->client_myds->myconn->variables[idx].value);
	}
	session->client_myds->myconn->variables[idx].value = strdup(value.c_str());
	// we now regererate dynamic_variables_idx
	session->client_myds->myconn->reorder_dynamic_variables_idx();
	return true;
}

const char* MySQL_Variables::client_get_value(MySQL_Session* session, int idx) const {
	assert(session);
	assert(session->client_myds);
	assert(session->client_myds->myconn);
	return session->client_myds->myconn->variables[idx].value;
}

uint32_t MySQL_Variables::client_get_hash(MySQL_Session* session, int idx) const {
	assert(session);
	assert(session->client_myds);
	assert(session->client_myds->myconn);
	return session->client_myds->myconn->var_hash[idx];
}

void MySQL_Variables::server_set_value(MySQL_Session* session, int idx, const char* value) {
	assert(session);
	assert(session->mybe);
	assert(session->mybe->server_myds);
	assert(session->mybe->server_myds->myconn);
	if (!value) return; // FIXME: I am not sure about this implementation . If value == NULL , show the variable be reset?
	session->mybe->server_myds->myconn->var_hash[idx] = SpookyHash::Hash32(value,strlen(value),10);

	if (session->mybe->server_myds->myconn->variables[idx].value) {
		free(session->mybe->server_myds->myconn->variables[idx].value);
	}
	session->mybe->server_myds->myconn->variables[idx].value = strdup(value);
	// we now regererate dynamic_variables_idx
	session->mybe->server_myds->myconn->reorder_dynamic_variables_idx();
}

const char* MySQL_Variables::server_get_value(MySQL_Session* session, int idx) const {
	assert(session);
	assert(session->mybe);
	assert(session->mybe->server_myds);
	assert(session->mybe->server_myds->myconn);
	return session->mybe->server_myds->myconn->variables[idx].value;
}

uint32_t MySQL_Variables::server_get_hash(MySQL_Session* session, int idx) const {
	assert(session);
	assert(session->mybe);
	assert(session->mybe->server_myds);
	assert(session->mybe->server_myds->myconn);
	return session->mybe->server_myds->myconn->var_hash[idx];
}

bool MySQL_Variables::update_variable(MySQL_Session* session, session_status status, int &_rc) {
	int idx = SQL_NAME_LAST_HIGH_WM;
	if (session->status == SETTING_VARIABLE) {
		// if status is SETTING_VARIABLE , what variable needs to be changed is defined in changing_variable_idx
		idx = session->changing_variable_idx;
	} else {
		for (int i=0; i<SQL_NAME_LAST_HIGH_WM; i++) {
			if (mysql_tracked_variables[i].status == status) {
				idx = i;
				break;
			}
		}
	}
	assert(idx != SQL_NAME_LAST_HIGH_WM);
	return updaters[idx](session, idx, _rc);
}

bool MySQL_Variables::verify_variable(MySQL_Session* session, int idx) const {
	auto ret = false;
	if (likely(verifiers[idx])) {
		auto client_hash = session->client_myds->myconn->var_hash[idx];
		auto server_hash = session->mybe->server_myds->myconn->var_hash[idx];
		if (client_hash && client_hash != server_hash) {
			ret = verifiers[idx](session, idx, client_hash, server_hash);
		}
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
		int charset = atoi(mysql_variables.client_get_value(session, idx));
		if (charset >= 255 && myconn->mysql->server_version[0] != '8') {
			switch(mysql_thread___handle_unknown_charset) {
				case HANDLE_UNKNOWN_CHARSET__DISCONNECT_CLIENT:
					snprintf(msg,sizeof(msg),"Can't initialize character set %s", mysql_variables.client_get_value(session, idx));
					proxy_error("Can't initialize character set on %s, %d: Error %d (%s). Closing client connection %s:%d.\n",
							myconn->parent->address, myconn->parent->port, 2019, msg, session->client_myds->addr.addr, session->client_myds->addr.port);
					myds->destroy_MySQL_Connection_From_Pool(false);
					myds->fd=0;
					_rc=-1;
					return false;
				case HANDLE_UNKNOWN_CHARSET__REPLACE_WITH_DEFAULT_VERBOSE:
					ci = proxysql_find_charset_nr(charset);
					if (!ci) {
						// LCOV_EXCL_START
						proxy_error("Cannot find character set [%s]\n", mysql_variables.client_get_value(session, idx));
						assert(0);
						// LCOV_EXCL_STOP
					}
					not_supported_collation = ci->name;

					if (idx == SQL_COLLATION_CONNECTION) {
						ci = proxysql_find_charset_collate(mysql_thread___default_variables[idx]);
					} else {
						if (mysql_thread___default_variables[idx]) {
							ci = proxysql_find_charset_name(mysql_thread___default_variables[idx]);
						} else {
							ci = proxysql_find_charset_name(mysql_thread___default_variables[SQL_CHARACTER_SET]);
						}
					}

					if (!ci) {
						// LCOV_EXCL_START
						proxy_error("Cannot find character set [%s]\n", mysql_thread___default_variables[idx]);
						assert(0);
						// LCOV_EXCL_STOP
					}
					replace_collation = ci->name;
					replace_collation_nr = ci->nr;

					proxy_warning("Server doesn't support collation (%s) %s. Replacing it with the configured default (%d) %s. Client %s:%d\n",
							mysql_variables.client_get_value(session, idx), not_supported_collation, 
							replace_collation_nr, replace_collation, session->client_myds->addr.addr, session->client_myds->addr.port);

					ss << replace_collation_nr;
					mysql_variables.client_set_value(session, idx, ss.str());
					_rc=0;
					return true;
				case HANDLE_UNKNOWN_CHARSET__REPLACE_WITH_DEFAULT:
					if (idx == SQL_COLLATION_CONNECTION) {
						ci = proxysql_find_charset_collate(mysql_thread___default_variables[idx]);
					} else {
						if (mysql_thread___default_variables[idx]) {
							ci = proxysql_find_charset_name(mysql_thread___default_variables[idx]);
						} else {
							ci = proxysql_find_charset_name(mysql_thread___default_variables[SQL_CHARACTER_SET]);
						}
					}

					if (!ci) {
						// LCOV_EXCL_START
						proxy_error("Cannot filnd charset [%s]\n", mysql_thread___default_variables[idx]);
						assert(0);
						// LCOV_EXCL_STOP
					}
					replace_collation_nr = ci->nr;

					ss << replace_collation_nr;
					mysql_variables.client_set_value(session, idx, ss.str());
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
		ci = proxysql_find_charset_nr(atoi(mysql_variables.client_get_value(session, SQL_CHARACTER_SET_RESULTS)));

		if (!ci) {
			if (!strcmp(mysql_variables.client_get_value(session, SQL_CHARACTER_SET_RESULTS), "NULL")) {
				mysql_variables.server_set_value(session, idx, mysql_variables.client_get_value(session, idx));
				ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, "NULL", no_quote, st);
			} else if (!strcmp(mysql_variables.client_get_value(session, SQL_CHARACTER_SET_RESULTS), "binary")) {
				mysql_variables.server_set_value(session, idx, mysql_variables.client_get_value(session, idx));
				ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, "binary", no_quote, st);
			}
		} else {
			mysql_variables.server_set_value(session, idx, mysql_variables.client_get_value(session, idx));
			ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, ci->csname, no_quote, st);
		}
	} else if (idx==SQL_COLLATION_CONNECTION) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		ci = proxysql_find_charset_nr(atoi(mysql_variables.client_get_value(session, SQL_COLLATION_CONNECTION)));

		if (ci) {
			std::stringstream ss;
			ss << ci->nr;

			mysql_variables.server_set_value(session, idx, mysql_variables.client_get_value(session, idx));
			ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, ci->name, no_quote, st);
		}
	} else if (idx==SQL_CHARACTER_SET_CONNECTION) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		ci = proxysql_find_charset_nr(atoi(mysql_variables.client_get_value(session, SQL_CHARACTER_SET_CONNECTION)));

		if (ci) {
			unsigned int nr = ci->nr;
			std::stringstream ss;
			ss << nr;

			mysql_variables.server_set_value(session, idx, mysql_variables.client_get_value(session, idx));
			ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, ci->csname, no_quote, st);
		}
	} else if (idx==SQL_CHARACTER_SET_CLIENT || idx==SQL_CHARACTER_SET_DATABASE) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		ci = proxysql_find_charset_nr(atoi(mysql_variables.client_get_value(session, idx)));

		std::stringstream ss;
		ss << ci->nr;
		mysql_variables.server_set_value(session, idx, mysql_variables.client_get_value(session, idx));
		ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, ci->csname, no_quote, st);
	} else {
		mysql_variables.server_set_value(session, idx, mysql_variables.client_get_value(session, idx));
		ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, mysql_variables.server_get_value(session, idx), no_quote, st);
	}
	return ret;
}

bool verify_set_names(MySQL_Session* session) {
	uint32_t client_charset_hash = mysql_variables.client_get_hash(session, SQL_CHARACTER_SET_CLIENT);
	if (client_charset_hash == 0)
		return false;

	uint32_t results_charset_hash = mysql_variables.client_get_hash(session, SQL_CHARACTER_SET_RESULTS);
	if (client_charset_hash != results_charset_hash)
		return false;

	uint32_t connection_charset_hash = mysql_variables.client_get_hash(session, SQL_CHARACTER_SET_CONNECTION);
	if (client_charset_hash != connection_charset_hash)
		return false;

	uint32_t collation_hash = mysql_variables.client_get_hash(session, SQL_COLLATION_CONNECTION);
	if (client_charset_hash != collation_hash)
		return false;

	if (client_charset_hash != mysql_variables.server_get_hash(session, SQL_CHARACTER_SET_CLIENT) ||
			results_charset_hash != mysql_variables.server_get_hash(session, SQL_CHARACTER_SET_RESULTS) ||
			connection_charset_hash != mysql_variables.server_get_hash(session, SQL_CHARACTER_SET_CONNECTION) ||
			collation_hash != mysql_variables.server_get_hash(session, SQL_COLLATION_CONNECTION)) {

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
				// LCOV_EXCL_START
				proxy_error("Wrong status %d\n", session->status);
				assert(0);
				break;
				// LCOV_EXCL_STOP
		}
		session->set_status(SETTING_SET_NAMES);
		uint32_t hash = mysql_variables.client_get_hash(session, SQL_CHARACTER_SET_CLIENT);
		const char* value = mysql_variables.client_get_value(session, SQL_CHARACTER_SET_CLIENT);
		mysql_variables.server_set_hash_and_value(session, SQL_CHARACTER_SET_CLIENT, value, hash);
		mysql_variables.server_set_hash_and_value(session, SQL_CHARACTER_SET_RESULTS, value, hash);
		mysql_variables.server_set_hash_and_value(session, SQL_CHARACTER_SET_CONNECTION, value, hash);
		mysql_variables.server_set_hash_and_value(session, SQL_COLLATION_CONNECTION, value, hash);
		mysql_variables.client_set_hash_and_value(session, SQL_CHARACTER_SET, value, hash);
		mysql_variables.server_set_hash_and_value(session, SQL_CHARACTER_SET, value, hash);
		return true;
	}

	return false;
}

inline bool verify_server_variable(MySQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash) {
	if (client_hash && client_hash != server_hash) {
		// Edge case for set charset command, because we do not know database character set
		// for now we are setting connection and collation to empty
		if (idx == SQL_CHARACTER_SET_CONNECTION || idx == SQL_COLLATION_CONNECTION ) {
			if (mysql_variables.client_get_hash(session, idx) == 0) {
					mysql_variables.server_set_hash_and_value(session, idx, "", 0);
					return false;
			}
		}
		// this variable is relevant only if status == SETTING_VARIABLE
		session->changing_variable_idx = (enum mysql_variable_name)idx;
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
				// LCOV_EXCL_START
				proxy_error("Wrong status %d\n", session->status);
				assert(0);
				break;
				// LCOV_EXCL_STOP
		}
		session->set_status(mysql_tracked_variables[idx].status);
		mysql_variables.server_set_value(session, idx, mysql_variables.client_get_value(session, idx));
		return true;
	}
	return false;
}

bool logbin_update_server_variable(MySQL_Session* session, int idx, int &_rc) {
	return session->handler_again___status_SETTING_SQL_LOG_BIN(&_rc);
}


bool MySQL_Variables::parse_variable_boolean(MySQL_Session *sess, int idx, string& value1, bool * lock_hostgroup) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET %s value %s\n", mysql_tracked_variables[idx].set_variable_name, value1.c_str());
	int __tmp_value = -1;
	if (
		(strcasecmp(value1.c_str(),(char *)"0")==0) ||
		(strcasecmp(value1.c_str(),(char *)"false")==0) ||
		(strcasecmp(value1.c_str(),(char *)"off")==0)
	) {
		__tmp_value = 0;
	} else {
		if (
			(strcasecmp(value1.c_str(),(char *)"1")==0) ||
			(strcasecmp(value1.c_str(),(char *)"true")==0) ||
			(strcasecmp(value1.c_str(),(char *)"on")==0)
		) {
			__tmp_value = 1;
		}
	}

	if (__tmp_value >= 0) {
		proxy_debug(PROXY_DEBUG_MYSQL_COM, 7, "Processing SET %s value %s\n", mysql_tracked_variables[idx].set_variable_name, value1.c_str());
		uint32_t var_value_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
		if (mysql_variables.client_get_hash(sess, idx) != var_value_int) {
			if (__tmp_value == 0) {
				if (!mysql_variables.client_set_value(sess, idx, "OFF"))
					return false;
			} else {
				if (!mysql_variables.client_set_value(sess, idx, "ON"))
					return false;
			}
			proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing connection %s to %s\n", mysql_tracked_variables[idx].set_variable_name, value1.c_str());
		}
	} else {
		sess->unable_to_parse_set_statement(lock_hostgroup);
		return false;
	}
	return true;
}



bool MySQL_Variables::parse_variable_number(MySQL_Session *sess, int idx, string& value1, bool * lock_hostgroup) {
	int vl = strlen(value1.c_str());
	const char *v = value1.c_str();
	bool only_digit_chars = true;
	for (int i=0; i<vl && only_digit_chars==true; i++) {
		if (is_digit(v[i])==0) {
			only_digit_chars=false;
		}
	}
	if (!only_digit_chars) {
		if (
			(strcasecmp(mysql_tracked_variables[idx].set_variable_name,(char *)"sql_select_limit")==0) // sql_select_limit allows value "default"
			||
			(strcasecmp(mysql_tracked_variables[idx].set_variable_name,(char *)"max_join_size")==0) // max_join_size allows value "default"
		) {
			if (strcasecmp(v,"default")==0) {
				only_digit_chars = true;
			}
		}
	}
	if (only_digit_chars) {
		// see https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_max_join_size
		proxy_debug(PROXY_DEBUG_MYSQL_COM, 7, "Processing SET %s value %s\n", mysql_tracked_variables[idx].set_variable_name, value1.c_str());
		uint32_t var_value_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
		if (mysql_variables.client_get_hash(sess, idx) != var_value_int) {
			if (!mysql_variables.client_set_value(sess, idx, value1.c_str()))
				return false;
			proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing connection %s to %s\n", mysql_tracked_variables[idx].set_variable_name, value1.c_str());
			if (idx == SQL_MAX_JOIN_SIZE) {
				// see https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_max_join_size
				if (
					(value1 == "18446744073709551615")
					||
					(strcasecmp(v,"default")==0)
				) {
					mysql_variables.client_set_value(sess, SQL_SQL_BIG_SELECTS, "ON");
				} else {
					mysql_variables.client_set_value(sess, SQL_SQL_BIG_SELECTS, "OFF");
				}
			}
		}
		//exit_after_SetParse = true;
	} else {
		sess->unable_to_parse_set_statement(lock_hostgroup);
		return false;
	}
	return true;
}

