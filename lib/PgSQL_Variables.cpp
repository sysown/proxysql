#include "PgSQL_Variables.h"
#include "proxysql.h"

#include "PgSQL_Session.h"
#include "PgSQL_Data_Stream.h"
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include <sstream>

pgsql_verify_var PgSQL_Variables::verifiers[PGSQL_NAME_LAST_HIGH_WM];
pgsql_update_var PgSQL_Variables::updaters[PGSQL_NAME_LAST_HIGH_WM];

PgSQL_Variables::PgSQL_Variables() {
	// add here all the variables we want proxysql to recognize, but ignore
	ignore_vars.push_back("application_name");
	// NOTE: This variable has been temporarily ignored. Check issues #3442 and #3441.
	//ignore_vars.push_back("session_track_schema");
	variables_regexp = "";

	/*
	   NOTE:
		make special ATTENTION that the order in pgsql_variable_name
		and pgsqll_tracked_variables[] is THE SAME
	   NOTE:
		PgSQL_Variables::PgSQL_Variables() has a built-in check to make sure that the order is correct,
		and that variables are in alphabetical order
	*/
	for (auto i = 0; i < PGSQL_NAME_LAST_HIGH_WM; i++) {
		//Array index and enum value (idx) should be same
		assert(i == pgsql_tracked_variables[i].idx);

		if (i > PGSQL_NAME_LAST_LOW_WM + 1) {
			assert(strcmp(pgsql_tracked_variables[i].set_variable_name, pgsql_tracked_variables[i - 1].set_variable_name) > 0);
		}

		// we initialized all the internal_variable_name if set to NULL
		if (pgsql_tracked_variables[i].internal_variable_name == NULL) {
			pgsql_tracked_variables[i].internal_variable_name = pgsql_tracked_variables[i].set_variable_name;
		}

		PgSQL_Variables::verifiers[i] = verify_server_variable;
		PgSQL_Variables::updaters[i] = update_server_variable;

		if (pgsql_tracked_variables[i].status == SETTING_VARIABLE) {
			variables_regexp += pgsql_tracked_variables[i].set_variable_name;
			variables_regexp += "|";

			int idx = 0;
			while (pgsql_tracked_variables[i].alias[idx]) {
				variables_regexp += pgsql_tracked_variables[i].alias[idx];
				variables_regexp += "|";
				idx++;
			}
		}
	}

	for (std::vector<std::string>::iterator it=ignore_vars.begin(); it != ignore_vars.end(); it++) {
		variables_regexp += *it;
		variables_regexp += "|";
	}

	// Check if the last character is '|'
	if (!variables_regexp.empty() && variables_regexp.back() == '|') {
		variables_regexp.pop_back(); // Remove the last character
	}
}

PgSQL_Variables::~PgSQL_Variables() {}

bool PgSQL_Variables::client_set_hash_and_value(PgSQL_Session* session, int idx, const std::string& value, uint32_t hash) {
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

void PgSQL_Variables::client_reset_value(PgSQL_Session* session, int idx, bool reorder_dynamic_variables_idx) {
	if (!session || !session->client_myds || !session->client_myds->myconn) {
		proxy_warning("Session validation failed\n");
		return;
	}

	PgSQL_Connection *client_conn = session->client_myds->myconn;

	if (client_conn->var_hash[idx] != 0) {
		client_conn->var_hash[idx] = 0;
		if (client_conn->variables[idx].value) {
			free(client_conn->variables[idx].value);
			client_conn->variables[idx].value = NULL;
		}
		if (reorder_dynamic_variables_idx && idx > PGSQL_NAME_LAST_LOW_WM) {
			// we now regererate dynamic_variables_idx
			client_conn->reorder_dynamic_variables_idx();
		}
	}
}
void PgSQL_Variables::server_set_hash_and_value(PgSQL_Session* session, int idx, const char* value, uint32_t hash) {
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

bool PgSQL_Variables::client_set_value(PgSQL_Session* session, int idx, const std::string& value, bool reorder_dynamic_variables_idx) {
	if (!session || !session->client_myds || !session->client_myds->myconn) {
		proxy_warning("Session validation failed\n");
		return false;
	}

	session->client_myds->myconn->var_hash[idx] = SpookyHash::Hash32(value.c_str(),strlen(value.c_str()),10);
	if (session->client_myds->myconn->variables[idx].value) {
		free(session->client_myds->myconn->variables[idx].value);
	}
	session->client_myds->myconn->variables[idx].value = strdup(value.c_str());

	if (reorder_dynamic_variables_idx && idx > PGSQL_NAME_LAST_LOW_WM) {
		// we now regererate dynamic_variables_idx
		session->client_myds->myconn->reorder_dynamic_variables_idx();
	}
	return true;
}

const char* PgSQL_Variables::client_get_value(PgSQL_Session* session, int idx) const {
	assert(session);
	assert(session->client_myds);
	assert(session->client_myds->myconn);
	return session->client_myds->myconn->variables[idx].value;
}

uint32_t PgSQL_Variables::client_get_hash(PgSQL_Session* session, int idx) const {
	assert(session);
	assert(session->client_myds);
	assert(session->client_myds->myconn);
	return session->client_myds->myconn->var_hash[idx];
}

void PgSQL_Variables::server_set_value(PgSQL_Session* session, int idx, const char* value, bool reorder_dynamic_variables_idx) {
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

	if (reorder_dynamic_variables_idx && idx > PGSQL_NAME_LAST_LOW_WM) {
		// we now regererate dynamic_variables_idx
		session->mybe->server_myds->myconn->reorder_dynamic_variables_idx();
	}
}

void PgSQL_Variables::server_reset_value(PgSQL_Session* session, int idx, bool reorder_dynamic_variables_idx) {
	assert(session);
	assert(session->mybe);
	assert(session->mybe->server_myds);
	assert(session->mybe->server_myds->myconn);

	PgSQL_Connection *backend_conn = session->mybe->server_myds->myconn;
	
	if (backend_conn->var_hash[idx] != 0) {
		backend_conn->var_hash[idx] = 0;
		if (backend_conn->variables[idx].value) {
			free(backend_conn->variables[idx].value);
			backend_conn->variables[idx].value = NULL;
		}
		if (reorder_dynamic_variables_idx && idx > PGSQL_NAME_LAST_LOW_WM) {
			// we now regererate dynamic_variables_idx
			backend_conn->reorder_dynamic_variables_idx();
		}
	}
}

const char* PgSQL_Variables::server_get_value(PgSQL_Session* session, int idx) const {
	assert(session);
	assert(session->mybe);
	assert(session->mybe->server_myds);
	assert(session->mybe->server_myds->myconn);
	return session->mybe->server_myds->myconn->variables[idx].value;
}

uint32_t PgSQL_Variables::server_get_hash(PgSQL_Session* session, int idx) const {
	assert(session);
	assert(session->mybe);
	assert(session->mybe->server_myds);
	assert(session->mybe->server_myds->myconn);
	return session->mybe->server_myds->myconn->var_hash[idx];
}

bool PgSQL_Variables::update_variable(PgSQL_Session* session, session_status status, int &_rc) {
	int idx = PGSQL_NAME_LAST_HIGH_WM;
	if (session->status == SETTING_VARIABLE) {
		// if status is SETTING_VARIABLE , what variable needs to be changed is defined in changing_variable_idx
		idx = session->changing_variable_idx;
	} else {
		for (int i=0; i<PGSQL_NAME_LAST_HIGH_WM; i++) {
			if (pgsql_tracked_variables[i].status == status) {
				idx = i;
				break;
			}
		}
	}
	assert(idx != PGSQL_NAME_LAST_HIGH_WM);
	return updaters[idx](session, idx, _rc);
}

bool PgSQL_Variables::verify_variable(PgSQL_Session* session, int idx) const {
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

bool update_server_variable(PgSQL_Session* session, int idx, int &_rc) {
	bool no_quote = true;
	if (IS_PGTRACKED_VAR_OPTION_SET_QUOTE(pgsql_tracked_variables[idx])) no_quote = false;
	bool st = IS_PGTRACKED_VAR_OPTION_SET_SET_TRANSACTION(pgsql_tracked_variables[idx]);
	const char *set_var_name = pgsql_tracked_variables[idx].set_variable_name;
	bool ret = false;

	const char* value = pgsql_variables.client_get_value(session, idx);
	pgsql_variables.server_set_value(session, idx, value, true);
	ret = session->handler_again___status_SETTING_GENERIC_VARIABLE(&_rc, set_var_name, value, no_quote, st);
	return ret;
}

inline bool verify_server_variable(PgSQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash) {
	if (client_hash && client_hash != server_hash) {
		// Edge case for set charset command, because we do not know database character set
		// for now we are setting connection and collation to empty
		//if (idx == SQL_CHARACTER_SET_CONNECTION || idx == SQL_COLLATION_CONNECTION ) {
		//	if (pgsql_variables.client_get_hash(session, idx) == 0) {
		//			pgsql_variables.server_set_hash_and_value(session, idx, "", 0);
		//			return false;
		//	}
		//}
		// this variable is relevant only if status == SETTING_VARIABLE
		session->changing_variable_idx = (enum pgsql_variable_name)idx;
		switch(session->status) { // this switch can be replaced with a simple previous_status.push(status), but it is here for readibility
			case PROCESSING_QUERY:
				session->previous_status.push(PROCESSING_QUERY);
				break;
			case PROCESSING_STMT_PREPARE:
				session->previous_status.push(PROCESSING_STMT_PREPARE);
				break;
			case PROCESSING_STMT_DESCRIBE:
				session->previous_status.push(PROCESSING_STMT_DESCRIBE);
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
		session->set_status(pgsql_tracked_variables[idx].status);
		pgsql_variables.server_set_value(session, idx, pgsql_variables.client_get_value(session, idx), true);
		return true;
	}
	return false;
}
