#ifndef MYSQL_VARIABLES_H
#define MYSQL_VARIABLES_H

#include "proxysql.h"
#include "cpp.h"

#include <cstdint>
#include <vector>
#include <memory>

class MySQL_Session;

/* These declarations might be moved to a header file */
extern const MARIADB_CHARSET_INFO * proxysql_find_charset_nr(unsigned int nr);
extern MARIADB_CHARSET_INFO * proxysql_find_charset_name(const char *name);
extern MARIADB_CHARSET_INFO * proxysql_find_charset_collate(const char *collatename);
extern void print_backtrace(void);

/* Each variable should be verified (if client and server side values are different) and
 * server side variable is updated when it is not equal to client
 * Different variables may have different algorithms for verification and update.
 * These are function pointer types that are stored in the array for each variable. Each
 * variable has own implementation of the verification and updater.
 */
typedef bool (*verify_var)(MySQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash);
typedef bool (*update_var)(MySQL_Session* session, int idx, int &_rc);

/* Calls handler_again___status_SETTING_GENERIC_VARIABLE to set MySQL variable.
 * Also updates server connection variables. There is if/elseif/else per variable type
 * inside this function, so function might be split per variable. This is updater function which is
 * called through the function pointer for specific variable.
 */
bool update_server_variable(MySQL_Session* session, int idx, int &_rc);
/* This is veru generic function used for all variables. It just comapres variables hashes
 * of the client side and server side connections. Its name is clashes with MySQL_Variables::verify_variable
 * and might be better changed to a more generic like generic_verifier
 */
bool verify_server_variable(MySQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash);
bool verify_set_names(MySQL_Session* session);
/* This is updater function used for SQL_LOG_BIN variable only.
 * It is called using a function pointer.
 */
bool logbin_update_server_variable(MySQL_Session* session, int idx, int &_rc);

/* This function validates if the charset in variable is supported by the backend.
 * Some old backends like MySQL 5.7 supports UTF8 but newer version MySQL 8.0
 * support UTF8MB4. The behavior of this function depends on the global variable
 * mysql-handle_unknown_charset. May be I should rename this function to make its name
 * more verbose.
 */
bool validate_charset(MySQL_Session* session, int idx, int &_rc);

/* Now we process COLLATION_CONNECTION variable and we need these two methods to set its value
 * These fucntions along with other charset functions might be moved to separate file.
 */
char* collation_id_from_charset_name_r(const char *name, char* collation_id, int length);
char* collation_id_from_collate_r(const char *collation, char* collation_id, int length);

/* This function processes variables value received from client. It is called as a function pointer
 * from the map of variables names
 */
bool process_on_off(MySQL_Session& session, enum variable_name var, const std::string& value, bool* lock_hostgroup);

/* This struct represents a value in the map of the variable names. The struct is necessary to have a variable_name var
 * along with std::function (pointer ot a function). During a call var is passed to std::function so it knows for which
 * variable it is called, and can use var for calling client/server getters and setters.
 */
struct Query_Handler {
	Query_Handler(enum variable_name _var, std::function<bool(MySQL_Session& session, enum variable_name, const std::string&, bool*)> _function) :
		var(_var), function(_function) {}
	enum variable_name var;
	std::function<bool(MySQL_Session& session, enum variable_name, const std::string&, bool*)> function;
};

class MySQL_Variables {
	static verify_var verifiers[SQL_NAME_LAST];
	static update_var updaters[SQL_NAME_LAST];

public:
	MySQL_Variables();

	virtual ~MySQL_Variables();

	/* client side variables/hashes setters and getters */
	bool client_set_value(MySQL_Session* session, int idx, const std::string& value);
	bool client_set_hash_and_value(MySQL_Session* session, int idx, const std::string& value, uint32_t hash);
	const char* client_get_value(MySQL_Session* session, int idx) const;
	uint32_t client_get_hash(MySQL_Session* session, int idx) const;

	/* server side variables/hashes setters and getters */
	void server_set_value(MySQL_Session* session, int idx, const char* value);
	void server_set_hash_and_value(MySQL_Session* session, int idx, const char* value, uint32_t hash);
	const char* server_get_value(MySQL_Session* session, int idx) const;
	inline uint32_t server_get_hash(MySQL_Session* session, int idx) const;

	/* This method is called from the session handler where all variables are processed in the loop
	 * This is just an entry point for verification of the variable. Changes state of the state machine
	 * and returns true if variable has to be changed.
	 *
	 * It make sense to rename this method to avoid clash with function
	 */
	bool verify_variable(MySQL_Session* session, int idx) const;
	/* This method is called from the session handler where SETTIIONG_* state is handled.
	 * This is an entry point for updating server variable. Returns true if variable was successfully updated.
	 */
	bool update_variable(MySQL_Session* session, session_status status, int &_rc);
	/* This function is implemented as event handler and it is called from places where session gets a
	 * new connection to backend (MySQL server).
	 *
	 * When processing connection event it checks the MySQL server version and disables variables that
	 * are not handled by this server version. For example, if session connects to MySQL 5.7 then WSREP_SYNC_WAIT
	 * is disabled.
	 *
	 * This method (connect event handler) also sets is_connected_to_backend flag which allows verification
	 * and update of the backend variables.
	 */
	bool on_connect_to_backend(MySQL_Session* session);

	/* This map maps variable names as they parsed to function pointers that process values assigned to the variable.
	 *
	 * This map is used in the QPO handler where set variable is recognized by regexp.
	 * Basically this variable is used to refactor (reduce in size) this method
	 * bool MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(PtrSize_t *pkt, bool *lock_hostgroup, bool prepared)
	 */
	static const std::map<std::string, Query_Handler> functions;
};

#endif // #ifndef MYSQL_VARIABLES_H

