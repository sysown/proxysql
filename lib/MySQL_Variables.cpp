#include "MySQL_Variables.h"
#include "proxysql.h"

#include "MySQL_Session.h"
#include "MySQL_Data_Stream.h"
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include <sstream>
#include <algorithm>
#include <charconv>
#include "mysqld_error.h"


static inline char is_digit(char c) {
	if(c >= '0' && c <= '9')
		return 1;
	return 0;
}

var_track_err_st perm_track_errs[] {
	// ERROR 1210 (HY000): Variable not supported in combination with Galera:
	// - Changed by MySQL, previously 'ER_UNKNOWN_SYSTEM_VARIABLE'
	{ ER_WRONG_ARGUMENTS, "sql_generate_invisible_primary_key" }
};

bool is_perm_track_err(int err, const char* varname) {
	const size_t count = sizeof(perm_track_errs) / sizeof(var_track_err_st);

	for (size_t i = 0; i < count; i++) {
		if (perm_track_errs[i].err == err && (strcasecmp(varname, perm_track_errs[i].name) == 0)) {
			return true;
		}
	}
	return false;
}

#include "proxysql_find_charset.h"

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
	// NOTE: This variable has been temporarily ignored. Check issues #4839
	ignore_vars.push_back("session_track_system_variables");
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

void MySQL_Variables::client_reset_value(MySQL_Session* session, int idx) {
	if (!session || !session->client_myds || !session->client_myds->myconn) {
		proxy_warning("Session validation failed\n");
		return;
	}

	MySQL_Connection *client_conn = session->client_myds->myconn;

	if (client_conn->var_hash[idx] != 0) {
		client_conn->var_hash[idx] = 0;
		if (client_conn->variables[idx].value) {
			free(client_conn->variables[idx].value);
			client_conn->variables[idx].value = NULL;
		}
		// we now regererate dynamic_variables_idx
		client_conn->reorder_dynamic_variables_idx();
	}
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

	if (idx == SQL_CHARACTER_SET_DATABASE) {
		session->client_myds->myconn->user_variable_database_charset_explicit = true;
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
			auto* connection = session->client_myds->myconn;
			connection->user_variable_charset_schema = mysql_user_variable_capture_schema(connection->userinfo->schemaname);
			connection->user_variable_charset_schema_charset = connection->userinfo->schemaname_charset;
			const char* database_charset = client_get_value(session, SQL_CHARACTER_SET_DATABASE);
			connection->user_variable_charset_database_charset = connection->user_variable_database_charset_explicit &&
				database_charset && *database_charset
				? strtoul(database_charset, nullptr, 10) : 0;
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
#ifdef DEBUG
	assert(session);
	assert(session->client_myds);
	assert(session->client_myds->myconn);
#endif // DEBUG
	return session->client_myds->myconn->variables[idx].value;
}

uint32_t MySQL_Variables::client_get_hash(MySQL_Session* session, int idx) const {
#ifdef DEBUG
	assert(session);
	assert(session->client_myds);
	assert(session->client_myds->myconn);
#endif // DEBUG
	return session->client_myds->myconn->var_hash[idx];
}

void MySQL_Variables::server_set_value(MySQL_Session* session, int idx, const char* value) {
#ifdef DEBUG
	assert(session);
	assert(session->mybe);
	assert(session->mybe->server_myds);
	assert(session->mybe->server_myds->myconn);
#endif // DEBUG
	if (!value) return; // FIXME: I am not sure about this implementation . If value == NULL , show the variable be reset?
	session->mybe->server_myds->myconn->var_hash[idx] = SpookyHash::Hash32(value,strlen(value),10);

	if (session->mybe->server_myds->myconn->variables[idx].value) {
		free(session->mybe->server_myds->myconn->variables[idx].value);
	}
	session->mybe->server_myds->myconn->variables[idx].value = strdup(value);
	// we now regererate dynamic_variables_idx
	session->mybe->server_myds->myconn->reorder_dynamic_variables_idx();
}

void MySQL_Variables::server_reset_value(MySQL_Session* session, int idx) {
#ifdef DEBUG
	assert(session);
	assert(session->mybe);
	assert(session->mybe->server_myds);
	assert(session->mybe->server_myds->myconn);
#endif // DEBUG
	MySQL_Connection *backend_conn = session->mybe->server_myds->myconn;
	
	if (backend_conn->var_hash[idx] != 0) {
		backend_conn->var_hash[idx] = 0;
		if (backend_conn->variables[idx].value) {
			free(backend_conn->variables[idx].value);
			backend_conn->variables[idx].value = NULL;
		}
		// we now regererate dynamic_variables_idx
		backend_conn->reorder_dynamic_variables_idx();
	}
}

const char* MySQL_Variables::server_get_value(MySQL_Session* session, int idx) const {
#ifdef DEBUG
	assert(session);
	assert(session->mybe);
	assert(session->mybe->server_myds);
	assert(session->mybe->server_myds->myconn);
#endif // DEBUG
	return session->mybe->server_myds->myconn->variables[idx].value;
}

uint32_t MySQL_Variables::server_get_hash(MySQL_Session* session, int idx) const {
#ifdef DEBUG
	assert(session);
	assert(session->mybe);
	assert(session->mybe->server_myds);
	assert(session->mybe->server_myds->myconn);
#endif // DEBUG
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
		// Collations with id >= 255 (e.g. utf8mb4_0900_ai_ci) are a MySQL 8.0+
		// feature. They are not understood by:
		//   - MySQL < 8.0 (any major version below 8)
		//   - MariaDB (any version): MariaDB uses different collation IDs and
		//     does not implement utf8mb4_0900_ai_ci, regardless of its numeric
		//     major version (10.x, 11.x would otherwise pass an atoi() < 8 check).
		const char *sv = myconn->mysql->server_version;
		bool is_mariadb = (sv != NULL && strstr(sv, "MariaDB") != NULL);
		// `atoi(NULL)` is undefined behavior; in practice `sv` should not be
		// NULL here (validate_charset runs after a backend handshake has
		// populated server_version), but the guard is essentially free.
		int sv_major = (sv != NULL) ? atoi(sv) : 0;
		if (charset >= 255 && (is_mariadb || sv_major < 8)) {
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

namespace {

bool normalize_set_boolean(const std::string& value, std::string& normalized) {
	if (value == "0" || !strcasecmp(value.c_str(), "false") || !strcasecmp(value.c_str(), "off")) {
		normalized = "OFF";
		return true;
	}
	if (value == "1" || !strcasecmp(value.c_str(), "true") || !strcasecmp(value.c_str(), "on")) {
		normalized = "ON";
		return true;
	}
	return false;
}

bool valid_set_number(int idx, const std::string& value) {
	if (!value.empty() && std::all_of(value.begin(), value.end(),
		[](unsigned char c) { return c >= '0' && c <= '9'; })) return true;
	return (idx == SQL_SQL_SELECT_LIMIT || idx == SQL_MAX_JOIN_SIZE) &&
		!strcasecmp(value.c_str(), "default");
}

} // namespace

bool MySQL_Variables::stage_set_variable(
	const std::string& name, const std::string& input, MySQL_Session_Set_Plan& plan) const {
	if (input.find('\0') != std::string::npos) return false;
	// Stage locally first: a failure must leave both classes of tracked state
	// unchanged, even if an earlier assignment in this SET was valid.
	MySQL_Session_Set_Plan change;
	std::string value = input;
	if (name == "autocommit") {
		if (!normalize_set_boolean(input, value)) return false;
		change.autocommit.push_back(value == "ON");
	} else if (name == "wait_timeout") {
		unsigned long long seconds = 0;
		const auto parsed = std::from_chars(input.data(), input.data() + input.size(), seconds);
		if (input.empty() || parsed.ec != std::errc{} || parsed.ptr != input.data() + input.size()) return false;
		change.wait_timeout_ms = std::clamp(seconds, 1ULL, 20ULL * 24 * 3600) * 1000;
		change.requested_wait_timeout_seconds = seconds;
	} else if (name == "session_track_gtids") {
		if (!strcasecmp(input.c_str(), "ALL_GTIDS") || !strcasecmp(input.c_str(), "OWN_GTID")) {
			change.session_track_gtids = "OWN_GTID";
		} else if (!strcasecmp(input.c_str(), "OFF")) {
			change.session_track_gtids = "OFF";
		} else return false;
	} else if (name == "tx_isolation") {
		std::replace(value.begin(), value.end(), '-', ' ');
		if (strcasecmp(value.c_str(), "READ UNCOMMITTED") && strcasecmp(value.c_str(), "READ COMMITTED") &&
			strcasecmp(value.c_str(), "REPEATABLE READ") && strcasecmp(value.c_str(), "SERIALIZABLE")) return false;
		change.values.emplace_back(SQL_ISOLATION_LEVEL, value);
	} else if (name == "tx_read_only") {
		if (!normalize_set_boolean(input, value)) return false;
		change.values.emplace_back(SQL_TRANSACTION_READ, value == "ON" ? "ONLY" : "WRITE");
	} else {
		int idx = SQL_NAME_LAST_HIGH_WM;
		for (int i = 0; i < SQL_NAME_LAST_HIGH_WM; ++i) {
			if (i != SQL_NAME_LAST_LOW_WM && mysql_tracked_variables[i].status == SETTING_VARIABLE &&
				name == mysql_tracked_variables[i].set_variable_name) {
				idx = i;
				break;
			}
		}
		if (idx == SQL_NAME_LAST_HIGH_WM) {
			return std::find(ignore_vars.begin(), ignore_vars.end(), name) != ignore_vars.end();
		}
		if (idx == SQL_CHARACTER_SET_RESULTS || idx == SQL_CHARACTER_SET_CLIENT ||
			idx == SQL_CHARACTER_SET_CONNECTION || idx == SQL_CHARACTER_SET_DATABASE || idx == SQL_COLLATION_CONNECTION) {
			const auto* charset = idx == SQL_COLLATION_CONNECTION
				? proxysql_find_charset_collate(input.c_str()) : proxysql_find_charset_name(input.c_str());
			if (charset) {
				value = std::to_string(charset->nr);
				if (idx == SQL_CHARACTER_SET_CONNECTION) change.values.emplace_back(SQL_COLLATION_CONNECTION, value);
				if (idx == SQL_COLLATION_CONNECTION) change.values.emplace_back(SQL_CHARACTER_SET_CONNECTION, value);
			} else if (idx == SQL_CHARACTER_SET_RESULTS &&
				(!strcasecmp(input.c_str(), "NULL") || !strcasecmp(input.c_str(), "binary"))) {
				value = !strcasecmp(input.c_str(), "NULL") ? "NULL" : "binary";
			} else return false;
		} else if (idx == SQL_QUERY_CACHE_TYPE) {
			std::string boolean;
			if (normalize_set_boolean(input, boolean)) value = boolean == "ON" ? "1" : "0";
			else if (!strcasecmp(input.c_str(), "DEMAND")) value = "2";
			if (!valid_set_number(idx, value)) return false;
		} else if (mysql_tracked_variables[idx].is_bool) {
			if (!normalize_set_boolean(input, value)) return false;
		} else if (mysql_tracked_variables[idx].is_number) {
			if (!valid_set_number(idx, input)) return false;
		} else {
			// Session tracking accepts literals, never another variable's value.
			if (input.find('@') != std::string::npos || input.find('\0') != std::string::npos ||
				input.find_first_of("'\\") != std::string::npos || (!input.empty() && input[0] == '(') ||
				!strncasecmp(input.c_str(), "CONCAT", 6) || !strncasecmp(input.c_str(), "IFNULL", 6) ||
				!strncasecmp(input.c_str(), "REPLACE", 7)) return false;
			if (idx == SQL_TIME_ZONE && value.size() == 5 &&
				(value[0] == '+' || value[0] == '-') && value[2] == ':') value.insert(1, "0");
		}
		change.values.emplace_back(idx, value);
		if (idx == SQL_MAX_JOIN_SIZE) {
			change.values.emplace_back(SQL_SQL_BIG_SELECTS,
				(value == "18446744073709551615" || !strcasecmp(value.c_str(), "default")) ? "ON" : "OFF");
		}
	}
	plan.values.insert(plan.values.end(), change.values.begin(), change.values.end());
	plan.autocommit.insert(plan.autocommit.end(), change.autocommit.begin(), change.autocommit.end());
	if (change.wait_timeout_ms) {
		plan.wait_timeout_ms = change.wait_timeout_ms;
		plan.requested_wait_timeout_seconds = change.requested_wait_timeout_seconds;
	}
	if (change.session_track_gtids) plan.session_track_gtids = std::move(change.session_track_gtids);
	return true;
}

void MySQL_Variables::apply_set_plan(MySQL_Session* session, const MySQL_Session_Set_Plan& plan) {
	for (const auto& assignment : plan.values) {
		client_set_value(session, assignment.first, assignment.second);
		if (assignment.first == SQL_SQL_MODE) {
			session->client_myds->myconn->set_no_backslash_escapes(
				strcasestr(assignment.second.c_str(), "NO_BACKSLASH_ESCAPES") != nullptr);
		}
	}
	if (!plan.autocommit.empty()) {
		session->autocommit = plan.autocommit.back();
		session->client_myds->myconn->set_autocommit(plan.autocommit.back());
	}
	if (plan.wait_timeout_ms) {
		const auto requested_seconds = *plan.requested_wait_timeout_seconds;
		if (requested_seconds < 1 || requested_seconds > 20ULL * 24 * 3600) {
			proxy_warning("Client [%s:%d] (user: %s) requested wait_timeout = %llu seconds, clamped to %llu ms (ProxySQL limits: 1s to 20 days)\n",
				session->client_myds->addr.addr, session->client_myds->addr.port,
				session->client_myds->myconn->userinfo->username, requested_seconds, *plan.wait_timeout_ms);
		}
		if (*plan.wait_timeout_ms > static_cast<unsigned long long>(mysql_thread___wait_timeout)) {
			proxy_warning("Client [%s:%d] (user: %s) requested wait_timeout = %llu ms, exceeds the global mysql-wait_timeout = %d ms. Global timeout will still be enforced.\n",
				session->client_myds->addr.addr, session->client_myds->addr.port,
				session->client_myds->myconn->userinfo->username, *plan.wait_timeout_ms, mysql_thread___wait_timeout);
		}
		session->wait_timeout = *plan.wait_timeout_ms;
		session->thread->status_variables.stvar[st_var_set_wait_timeout_commands]++;
	}
	if (plan.session_track_gtids) {
		auto& options = session->client_myds->myconn->options;
		free(options.session_track_gtids);
		options.session_track_gtids = strdup(plan.session_track_gtids->c_str());
		options.session_track_gtids_int = SpookyHash::Hash32(
			plan.session_track_gtids->data(), plan.session_track_gtids->size(), 10);
	}
}


bool MySQL_Variables::parse_variable_boolean(MySQL_Session *sess, int idx, string& value1, bool * lock_hostgroup) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET %s value %s\n", mysql_tracked_variables[idx].set_variable_name, value1.c_str());
	std::string normalized;
	if (normalize_set_boolean(value1, normalized)) {
		proxy_debug(PROXY_DEBUG_MYSQL_COM, 7, "Processing SET %s value %s\n", mysql_tracked_variables[idx].set_variable_name, value1.c_str());
		uint32_t var_value_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
		if (mysql_variables.client_get_hash(sess, idx) != var_value_int) {
			if (!mysql_variables.client_set_value(sess, idx, normalized)) return false;
			proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing connection %s to %s\n", mysql_tracked_variables[idx].set_variable_name, value1.c_str());
		}
	} else {
		sess->unable_to_parse_set_statement(lock_hostgroup);
		return false;
	}
	return true;
}



bool MySQL_Variables::parse_variable_number(MySQL_Session *sess, int idx, string& value1, bool * lock_hostgroup) {
	const char *v = value1.c_str();
	if (valid_set_number(idx, value1)) {
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

