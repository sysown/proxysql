#include "MySQL_Variables.h"
#include "proxysql.h"

#include "MySQL_Session.h"
#include "MySQL_Data_Stream.h"
#include "SpookyV2.h"

int MySQL_Variables::session_statuses[SQL_NAME_LAST] = {
	SETTING_SQL_SAFE_UPDATES,
	SETTING_SQL_SELECT_LIMIT
};

MySQL_Variables::MySQL_Variables(MySQL_Session* _session) {
	assert(_session);
	session = _session;

	for (auto i = 0; i < SQL_NAME_LAST; i++) {
		switch(i) {
		case SQL_SAFE_UPDATES:
		case SQL_SELECT_LIMIT:
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

bool MySQL_Variables::verify_generic_variable(int idx) {
	return updaters[idx]->verify_variables(session, idx);
}

bool Generic_Updater::verify_variables(MySQL_Session* session, int idx) {
	auto ret = session->mysql_variables->verify_generic_variable(
		&session->mybe->server_myds->myconn->variables[idx].hash,
		&session->mybe->server_myds->myconn->variables[idx].value,
		mysql_thread___default_sql_safe_updates,
		&session->client_myds->myconn->variables[idx].hash,
		session->client_myds->myconn->variables[idx].value,
		static_cast<session_status>(MySQL_Variables::session_statuses[idx])
	);
}

bool Generic_Updater::update_server_variable(MySQL_Session* session, int idx, int &_rc) {
}
