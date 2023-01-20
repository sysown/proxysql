#ifndef __CLASS_MYSQL_AUTHENTICATION_H
#define __CLASS_MYSQL_AUTHENTICATION_H

#include "proxysql.h"
#include "cpp.h"

#define PROXYSQL_AUTH_PTHREAD_MUTEX

#ifndef ACCOUNT_DETAILS_T
#define ACCOUNT_DETAILS_T
typedef struct _account_details_t {
	char *username;
	char *password;
	void *sha1_pass;
	bool use_ssl;
	int default_hostgroup;
	char *default_schema;
	bool schema_locked;
	bool transaction_persistent;
	bool fast_forward;
	int max_connections;
	int num_connections_used;
	bool __frontend;	// this is used only during the dump
	bool __backend;	// this is used only during the dump
	bool __active;
	char *attributes;
	char *comment;
} account_details_t;

typedef std::map<uint64_t, account_details_t *> umap_auth;
#endif // ACCOUNT_DETAILS_T

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define MYSQL_AUTHENTICATION_VERSION "0.2.0902" DEB


class PtrArray;

#ifndef CREDS_GROUPS_T
#define CREDS_GROUPS_T
typedef struct _creds_group_t {
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_t lock;
#else
	rwlock_t lock;
#endif
	umap_auth bt_map;
	PtrArray *cred_array;
} creds_group_t;
#endif // CREDS_GROUPS_T

class MySQL_Authentication {
	private:
	/**
	 * @brief Holds the current value for 'runtime_mysql_users' used by 'ProxySQL_Admin' to reply to
	 *  'CLUSTER_QUERY_MYSQL_USERS'.
	 */
	std::unique_ptr<SQLite3_result> mysql_users_resultset { nullptr };
	creds_group_t creds_backends;
	creds_group_t creds_frontends;
	bool _reset(enum cred_username_type usertype);
	uint64_t _get_runtime_checksum(enum cred_username_type usertype);
	public:
	MySQL_Authentication();
	~MySQL_Authentication();
	bool add(char *username, char *password, enum cred_username_type usertype, bool use_ssl, int default_hostgroup, char *default_schema, bool schema_locked, bool transaction_persistent, bool fast_forward, int max_connections, char* attributes, char *comment);
	bool del(char *username, enum cred_username_type usertype, bool set_lock=true);
	bool reset();
	void print_version();
	bool exists(char *username);
	char * lookup(char *username, enum cred_username_type usertype, bool *use_ssl, int *default_hostgroup, char **default_schema, bool *schema_locked, bool *transaction_persistent, bool *fast_forward, int *max_connections, void **sha1_pass, char **attributes);
	int dump_all_users(account_details_t ***, bool _complete=true);
	int increase_frontend_user_connections(char *username, int *mc=NULL);
	void decrease_frontend_user_connections(char *username);
	void set_all_inactive(enum cred_username_type usertype);
	void remove_inactives(enum cred_username_type usertype);
	bool set_SHA1(char *username, enum cred_username_type usertype, void *sha_pass);
	unsigned int memory_usage();
	uint64_t get_runtime_checksum();
	/**
	 * @brief Computes the checksum for the 'mysql_users' table contained in the supplied resultset.
	 *  It's UNSAFE to call this function with another resultset than the specified in @param doc.
	 * @param resultset Assumed to be the result of hte following query against the Admin interface:
	 *   - '"SELECT username, password, active, use_ssl, default_hostgroup, default_schema,
	 *     schema_locked, transaction_persistent, fast_forward, backend, frontend, max_connections,
	 *     attributes, comment FROM runtime_mysql_users"'
	 *   The order isn't relevant in the query itself because ordering is performed while processing.
	 * @param mysql_users A 'unique_ptr' to be filled with the 'frontend' and 'backend' users found in the
	 *  provided resulset.
	 * @return The computed hash for the provided resultset.
	 */
	uint64_t get_runtime_checksum(MYSQL_RES* resultset, unique_ptr<SQLite3_result>& mysql_users);
	/**
	 * @brief Takes ownership of the supplied resultset and stores it in 'mysql_users_resultset' field.
	 * @param users Holds the current value for 'runtime_mysql_users'.
	 */
	void save_mysql_users(std::unique_ptr<SQLite3_result>&& users);
	/**
	 * @brief Return a pointer to internally managed 'mysql_users_resultset' field. DO NOT FREE.
	 * @return A pointer to the internally managed 'mysql_users_resultset'.
	 */
	SQLite3_result* get_current_mysql_users();
};

#endif /* __CLASS_MYSQL_AUTHENTICATION_H */
