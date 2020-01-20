#include "MySQL_Variables.h"
#include "proxysql.h"

#include "MySQL_Session.h"
#include "MySQL_Data_Stream.h"
#include "SpookyV2.h"

int MySQL_Variables::var_by_session[NONE] = {
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_SQL_MODE,
	SQL_TIME_ZONE,
	SQL_ISOLATION_LEVEL,
	SQL_TRANSACTION_READ,
	SQL_CHARACTER_SET_RESULTS,
	SQL_SESSION_TRACK_GTIDS,
	SQL_SQL_AUTO_IS_NULL,
	SQL_SELECT_LIMIT,
	SQL_SAFE_UPDATES,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST,
	SQL_NAME_LAST
};

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
			updaters[i] = new Generic_Updater();
			break;
		default:
			proxy_error("Wrong variable index\n");
			assert(0);
		}
	}
}

MySQL_Variables::~MySQL_Variables() {
	for (auto u : updaters)
		delete u;
}

void MySQL_Variables::client_set_value(int idx, const char* value) {
	session->client_myds->myconn->variables[idx].hash = SpookyHash::Hash32(value,strlen(value),10);

	if (session->client_myds->myconn->variables[idx].value) {
		free(session->client_myds->myconn->variables[idx].value);
	}
	session->client_myds->myconn->variables[idx].value = strdup(value);
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

bool MySQL_Variables::update_variable(int &_rc) {
	auto idx = MySQL_Variables::var_by_session[session->status];
	updaters[idx]->update_server_variable(session, idx, _rc);
}

bool MySQL_Variables::verify_variable(int idx) {
	int rc = 0;
	auto ret = updaters[idx]->verify_variables(session, idx);
	if (ret)
		update_variable(rc);
	return ret;
}

bool Generic_Updater::verify_variables(MySQL_Session* session, int idx) {
	auto ret = session->mysql_variables->verify_generic_variable(
		&session->mybe->server_myds->myconn->variables[idx].hash,
		&session->mybe->server_myds->myconn->variables[idx].value,
		mysql_thread___default_variables[idx],
		&session->client_myds->myconn->variables[idx].hash,
		session->client_myds->myconn->variables[idx].value,
		mysql_tracked_variables[idx].status
	);
}

bool Generic_Updater::update_server_variable(MySQL_Session* session, int idx, int &_rc) {
	bool q = mysql_tracked_variables[idx].quote;
	bool st = mysql_tracked_variables[idx].set_transaction;
	const char * set_var_name = mysql_tracked_variables[idx].set_variable_name;
	auto ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, session->mysql_variables->server_get_value(idx), q, st);
	return ret;
}
