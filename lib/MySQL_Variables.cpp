#include "MySQL_Variables.h"
#include "proxysql.h"

#include "MySQL_Session.h"
#include "MySQL_Data_Stream.h"
#include "SpookyV2.h"

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
		case SQL_ISOLATION_LEVEL:
		case SQL_TRANSACTION_READ:
		case SQL_SESSION_TRACK_GTIDS:
		case SQL_SQL_AUTO_IS_NULL:
		case SQL_COLLATION_CONNECTION:
		case SQL_NET_WRITE_TIMEOUT:
		case SQL_MAX_JOIN_SIZE:
			updaters[i] = new Generic_Updater();
			break;
		case SQL_CHARACTER_SET:
			updaters[i] = new Charset_Updater();
			break;
		case SQL_SET_NAMES:
			updaters[i] = new Names_Updater();
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

void MySQL_Variables::client_set_value(int idx, const char* value) {
	session->client_myds->myconn->variables[idx].hash = SpookyHash::Hash32(value,strlen(value),10);

	if (session->client_myds->myconn->variables[idx].value) {
		free(session->client_myds->myconn->variables[idx].value);
	}
	session->client_myds->myconn->variables[idx].value = strdup(value);
}

void MySQL_Variables::client_set_value(int idx, const std::string& value) {
	session->client_myds->myconn->variables[idx].hash = SpookyHash::Hash32(value.c_str(),strlen(value.c_str()),10);

	if (session->client_myds->myconn->variables[idx].value) {
		free(session->client_myds->myconn->variables[idx].value);
	}
	session->client_myds->myconn->variables[idx].value = strdup(value.c_str());
}

const char* MySQL_Variables::client_get_value(int idx) {
	return session->client_myds->myconn->variables[idx].value;
}

uint32_t MySQL_Variables::client_get_hash(int idx) {
	return session->client_myds->myconn->variables[idx].hash;
}

void MySQL_Variables::server_set_value(int idx, const char* value) {
	session->mybe->server_myds->myconn->variables[idx].hash = SpookyHash::Hash32(value,strlen(value),10);

	if (session->mybe->server_myds->myconn->variables[idx].value) {
		free(session->mybe->server_myds->myconn->variables[idx].value);
	}
	session->mybe->server_myds->myconn->variables[idx].value = strdup(value);
}

const char* MySQL_Variables::server_get_value(int idx) {
	return session->mybe->server_myds->myconn->variables[idx].value;
}

uint32_t MySQL_Variables::server_get_hash(int idx) {
	return session->mybe->server_myds->myconn->variables[idx].hash;
}

bool MySQL_Variables::verify_generic_variable(uint32_t *be_int, char **be_var, char *def, uint32_t *fe_int, char *fe_var, enum session_status next_sess_status) {
	// be_int = backend int (hash)
	// be_var = backend value
	// def = default
	// fe_int = frontend int (has)
	// fe_var = frontend value
	if (*be_int == 0) {
		// it is the first time we use this backend. Set value to default
		if (*be_var) {
			free(*be_var);
			*be_var = NULL;
		}
		*be_var = strdup(def);
		uint32_t tmp_int = SpookyHash::Hash32(*be_var, strlen(*be_var), 10);
		*be_int = tmp_int;
	}
	if (*fe_int) {
		if (*fe_int != *be_int) {
			{
				*be_int = *fe_int;
				if (*be_var) {
					free(*be_var);
					*be_var = NULL;
				}
				if (fe_var) {
					*be_var = strdup(fe_var);
				}
			}
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
					assert(0);
					break;
			}
			session->set_status(next_sess_status);
			return true;
		}
	}
	return false;
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
	updaters[idx]->update_server_variable(session, idx, _rc);
}

bool MySQL_Variables::verify_variable(int idx) {
	int rc = 0;
	auto ret = false;
	if (updaters[idx] && updaters[idx])
		ret = updaters[idx]->verify_variables(session, idx);
	if (ret) {
		// FIXME
		// update_variable(mysql_tracked_variables[idx].status, rc);
	}
	return ret;
}

/* 
 * Updaters for different variables
 */

Updater::~Updater() {}


bool Generic_Updater::verify_variables(MySQL_Session* session, int idx) {
	auto ret = session->mysql_variables->verify_generic_variable(
		&session->mybe->server_myds->myconn->variables[idx].hash,
		&session->mybe->server_myds->myconn->variables[idx].value,
		mysql_thread___default_variables[idx],
		&session->client_myds->myconn->variables[idx].hash,
		session->client_myds->myconn->variables[idx].value,
		mysql_tracked_variables[idx].status
	);
	return ret;
}

bool Generic_Updater::update_server_variable(MySQL_Session* session, int idx, int &_rc) {
	bool no_quote = true;
	if (mysql_tracked_variables[idx].quote) no_quote = false;
	bool st = mysql_tracked_variables[idx].set_transaction;
	const char * set_var_name = mysql_tracked_variables[idx].set_variable_name;
	bool ret = false;
	if (idx==SQL_CHARACTER_SET_RESULTS) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		ci = proxysql_find_charset_nr(atoi(session->mysql_variables->client_get_value(SQL_CHARACTER_SET_RESULTS)));

		ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, ci->csname, no_quote, st);
	} else if (idx==SQL_COLLATION_CONNECTION) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		ci = proxysql_find_charset_nr(atoi(session->mysql_variables->client_get_value(SQL_COLLATION_CONNECTION)));


		ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, ci->name, no_quote, st);
	} else {
		ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, session->mysql_variables->server_get_value(idx), no_quote, st);
	}
	return ret;
}

bool Names_Updater::verify_variables(MySQL_Session* session, int idx) {
	if (!strcmp(session->client_myds->myconn->variables[SQL_CHARACTER_ACTION].value, "1") ||
			!strcmp(session->client_myds->myconn->variables[SQL_CHARACTER_ACTION].value, "3")) {

		auto ret = session->mysql_variables->verify_generic_variable(
				&session->mybe->server_myds->myconn->variables[SQL_CHARACTER_SET].hash,
				&session->mybe->server_myds->myconn->variables[SQL_CHARACTER_SET].value,
				mysql_thread___default_variables[SQL_CHARACTER_SET],
				&session->client_myds->myconn->variables[SQL_CHARACTER_SET].hash,
				session->client_myds->myconn->variables[SQL_CHARACTER_SET].value,
				mysql_tracked_variables[idx].status
				);

		if (ret) {
			auto should_update_results = false;
			auto server = session->mybe->server_myds->myconn->variables[SQL_CHARACTER_SET_RESULTS].value;
			auto client = session->client_myds->myconn->variables[SQL_CHARACTER_SET_RESULTS].value;

			if (server && client && !strcmp(server, client))
				should_update_results = true;

			if (should_update_results) {
				session->mysql_variables->server_set_value(SQL_CHARACTER_SET_RESULTS, session->mysql_variables->server_get_value(SQL_CHARACTER_SET));
			}

			server = session->mybe->server_myds->myconn->variables[SQL_COLLATION_CONNECTION].value;
			client = session->client_myds->myconn->variables[SQL_COLLATION_CONNECTION].value;

			if (server && client && !strcmp(server, client))
				should_update_results = true;

			if (should_update_results) {
				session->mysql_variables->server_set_value(SQL_COLLATION_CONNECTION, session->mysql_variables->server_get_value(SQL_CHARACTER_SET));
			}

			return ret;
		}

		ret = session->mysql_variables->verify_generic_variable(
				&session->mybe->server_myds->myconn->variables[SQL_CHARACTER_ACTION].hash,
				&session->mybe->server_myds->myconn->variables[SQL_CHARACTER_ACTION].value,
				mysql_thread___default_variables[SQL_CHARACTER_ACTION],
				&session->client_myds->myconn->variables[SQL_CHARACTER_ACTION].hash,
				session->client_myds->myconn->variables[SQL_CHARACTER_ACTION].value,
				mysql_tracked_variables[idx].status
				);
		return ret;
	}
	return false;
}

bool Names_Updater::update_server_variable(MySQL_Session* session, int idx, int &_rc) {
	auto ret = session->handler_again___status_CHANGING_CHARSET(&_rc);
	return ret;
}

bool Charset_Updater::verify_variables(MySQL_Session* session, int idx) {
	if (strcmp(session->client_myds->myconn->variables[SQL_CHARACTER_ACTION].value, "2"))
		return false;

	auto ret = session->mysql_variables->verify_generic_variable(
		&session->mybe->server_myds->myconn->variables[SQL_CHARACTER_SET].hash,
		&session->mybe->server_myds->myconn->variables[SQL_CHARACTER_SET].value,
		mysql_thread___default_variables[SQL_CHARACTER_SET],
		&session->client_myds->myconn->variables[SQL_CHARACTER_SET].hash,
		session->client_myds->myconn->variables[SQL_CHARACTER_SET].value,
		mysql_tracked_variables[idx].status
	);

	if (ret) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		session->mysql_variables->client_set_value(SQL_CHARACTER_SET_RESULTS, session->mysql_variables->server_get_value(SQL_CHARACTER_SET));
		return ret;
	}

	ret = session->mysql_variables->verify_generic_variable(
		&session->mybe->server_myds->myconn->variables[SQL_CHARACTER_ACTION].hash,
		&session->mybe->server_myds->myconn->variables[SQL_CHARACTER_ACTION].value,
		mysql_thread___default_variables[SQL_CHARACTER_ACTION],
		&session->client_myds->myconn->variables[SQL_CHARACTER_ACTION].hash,
		session->client_myds->myconn->variables[SQL_CHARACTER_ACTION].value,
		mysql_tracked_variables[idx].status
	);
	return ret;
}

bool Charset_Updater::update_server_variable(MySQL_Session* session, int idx, int &_rc) {
	bool no_quote = true;
	if (mysql_tracked_variables[idx].quote) no_quote = false;
	bool st = mysql_tracked_variables[idx].set_transaction;
	const char * set_var_name = mysql_tracked_variables[idx].set_variable_name;
	const MARIADB_CHARSET_INFO *ci = NULL;
	ci = proxysql_find_charset_nr(atoi(session->mysql_variables->client_get_value(SQL_CHARACTER_SET)));

	auto ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, ci->csname, no_quote, st);
	return ret;
}
