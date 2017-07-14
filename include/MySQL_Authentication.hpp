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
	creds_group_t creds_backends;
	creds_group_t creds_frontends;
	bool _reset(enum cred_username_type usertype);
	uint64_t _get_runtime_checksum(enum cred_username_type usertype);
	public:
	MySQL_Authentication();
	~MySQL_Authentication();
	bool add(char *username, char *password, enum cred_username_type usertype, bool use_ssl, int default_hostgroup, char *default_schema, bool schema_locked, bool transaction_persistent, bool fast_forward, int max_connections);
	bool del(char *username, enum cred_username_type usertype, bool set_lock=true);
	bool reset();
	void print_version();
	char * lookup(char *username, enum cred_username_type usertype, bool *use_ssl, int *default_hostgroup, char **default_schema, bool *schema_locked, bool *transaction_persistent, bool *fast_forward, int *max_connections, void **sha1_pass);
	int dump_all_users(account_details_t ***, bool _complete=true);
	int increase_frontend_user_connections(char *username, int *mc=NULL);
	void decrease_frontend_user_connections(char *username);
	void set_all_inactive(enum cred_username_type usertype);
	void remove_inactives(enum cred_username_type usertype);
	bool set_SHA1(char *username, enum cred_username_type usertype, void *sha_pass);
	unsigned int memory_usage();
	uint64_t get_runtime_checksum();
};

#endif /* __CLASS_MYSQL_AUTHENTICATION_H */
