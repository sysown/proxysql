#ifndef CLASS_PROXYSQL_CLICKHOUSE_AUTHENTICATION_H
#define CLASS_PROXYSQL_CLICKHOUSE_AUTHENTICATION_H

#include "proxysql.h"
#include "cpp.h"

#define PROXYSQL_AUTH_PTHREAD_MUTEX

#ifndef CH_ACCOUNT_DETAILS_T
#define CH_ACCOUNT_DETAILS_T
typedef struct _ch_account_details_t {
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
	bool __frontend;  // this is used only during the dump
	bool __backend;   // this is used only during the dump
	bool __active;
} ch_account_details_t;

typedef std::map<uint64_t, ch_account_details_t *> ch_umap_auth;
#endif  // CH_ACCOUNT_DETAILS_T

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_CLICKHOUSE_AUTHENTICATION_VERSION "0.1.0702" DEB

class PtrArray;

#ifndef CH_CREDS_GROUPS_T
#define CH_CREDS_GROUPS_T
typedef struct _ch_creds_group_t {
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_t lock;
#else
	rwlock_t lock;
#endif
	ch_umap_auth bt_map;
	PtrArray *cred_array;
} ch_creds_group_t;
#endif  // CH_CREDS_GROUPS_T

class ClickHouse_Authentication {
   private:
	ch_creds_group_t creds_backends;
	ch_creds_group_t creds_frontends;
	bool _reset(enum cred_username_type usertype);

   public:
	ClickHouse_Authentication();
	~ClickHouse_Authentication();
	bool add(char *username, char *password, enum cred_username_type usertype,
	         bool use_ssl, int default_hostgroup, char *default_schema,
	         bool schema_locked, bool transaction_persistent, bool fast_forward,
	         int max_connections);
	bool del(char *username, enum cred_username_type usertype,
	         bool set_lock = true);
	bool reset();
	void print_version();
//	bool exists(char *username);
	char *lookup(char *username, enum cred_username_type usertype,
	             bool *use_ssl, int *default_hostgroup, char **default_schema,
	             bool *schema_locked, bool *transaction_persistent,
	             bool *fast_forward, int *max_connections, void **sha1_pass);
	int dump_all_users(ch_account_details_t ***, bool _complete = true);
	int increase_frontend_user_connections(char *username, int *mc = NULL);
	void decrease_frontend_user_connections(char *username);
	void set_all_inactive(enum cred_username_type usertype);
	void remove_inactives(enum cred_username_type usertype);
//	bool set_SHA1(char *username, enum cred_username_type usertype,
//	              void *sha_pass);
};

#endif  // CLASS_PROXYSQL_CLICKHOUSE_AUTHENTICATION_H
