#ifndef MYSQL_VARIABLES_H
#define MYSQL_VARIABLES_H

#include <cstdint>
#include <vector>
#include <memory>
#include <optional>
#include <string>
#include <utility>

/** Frontend changes prepared without acquiring or modifying a backend. */
struct MySQL_Session_Set_Plan {
	std::vector<std::pair<int, std::string>> values;
	// Retain intermediate transitions: ON followed by OFF still commits.
	std::vector<bool> autocommit;
	std::optional<unsigned long long> wait_timeout_ms;
	std::optional<unsigned long long> requested_wait_timeout_seconds;
	std::optional<std::string> session_track_gtids;
};

#include "proxysql.h"
#include "cpp.h"

class MySQL_Session;

extern void print_backtrace(void);

typedef bool (*verify_var)(MySQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash);
typedef bool (*update_var)(MySQL_Session* session, int idx, int &_rc);

bool validate_charset(MySQL_Session* session, int idx, int &_rc);
bool update_server_variable(MySQL_Session* session, int idx, int &_rc);
bool verify_server_variable(MySQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash);
bool verify_set_names(MySQL_Session* session);
bool logbin_update_server_variable(MySQL_Session* session, int idx, int &_rc);
bool is_perm_track_err(int err, const char* varname);

class MySQL_Variables {
	static verify_var verifiers[SQL_NAME_LAST_HIGH_WM];
	static update_var updaters[SQL_NAME_LAST_HIGH_WM];

public:
	std::string variables_regexp;
	// ignore_vars is a list of all variables that proxysql will parse but ignore its value
	std::vector<std::string> ignore_vars;
public:
	MySQL_Variables();

	virtual ~MySQL_Variables();

	bool client_set_value(MySQL_Session* session, int idx, const std::string& value);
	bool client_set_hash_and_value(MySQL_Session* session, int idx, const std::string& value, uint32_t hash);
	void client_reset_value(MySQL_Session* session, int idx);
	const char* client_get_value(MySQL_Session* session, int idx) const;
	uint32_t client_get_hash(MySQL_Session* session, int idx) const;

	void server_set_value(MySQL_Session* session, int idx, const char* value);
	void server_set_hash_and_value(MySQL_Session* session, int idx, const char* value, uint32_t hash);
	void server_reset_value(MySQL_Session* session, int idx);
	const char* server_get_value(MySQL_Session* session, int idx) const;
	inline uint32_t server_get_hash(MySQL_Session* session, int idx) const;

	bool verify_variable(MySQL_Session* session, int idx) const;
	bool update_variable(MySQL_Session* session, session_status status, int &_rc);
	bool parse_variable_boolean(MySQL_Session *sess, int idx, std::string &value1, bool* lock_hostgroup);
	bool parse_variable_number(MySQL_Session *sess, int idx, std::string &value1, bool* lock_hostgroup);
	/** @brief Validate one session assignment and append its frontend changes. */
	bool stage_set_variable(const std::string& name, const std::string& value,
		MySQL_Session_Set_Plan& plan) const;
	/** @brief Commit a validated SET plan to the frontend only. */
	void apply_set_plan(MySQL_Session* session, const MySQL_Session_Set_Plan& plan);
};

#endif // #ifndef MYSQL_VARIABLES_H

