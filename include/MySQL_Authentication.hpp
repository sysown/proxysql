#ifndef __CLASS_MYSQL_AUTHENTICATION_H
#define __CLASS_MYSQL_AUTHENTICATION_H

#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"


typedef struct _account_details_t {
	char *username;
	char *password;
	bool use_ssl;
	int default_hostgroup;
	char *default_schema;
	bool schema_locked;
	bool transaction_persistent;
	bool fast_forward;
} account_details_t;

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define MYSQL_AUTHENTICATION_VERSION "0.1.0706" DEB

typedef btree::btree_map<uint64_t, account_details_t *> BtMap_auth;

class PtrArray;

typedef struct _creds_group_t {
	rwlock_t lock;
	BtMap_auth bt_map;
	PtrArray *cred_array;
} creds_group_t;

class MySQL_Authentication {
	private:
	creds_group_t creds_backends;
	creds_group_t creds_frontends;
	bool _reset(enum cred_username_type usertype);
	public:
	MySQL_Authentication();
	~MySQL_Authentication();
	bool add(char *username, char *password, enum cred_username_type usertype, bool use_ssl, int default_hostgroup, char *default_schema, bool schema_locked, bool transaction_persistent, bool fast_forward);
	bool del(char *username, enum cred_username_type usertype);
	bool reset();
	void print_version();
	char * lookup(char *username, enum cred_username_type usertype, bool *use_ssl, int *default_hostgroup, char **default_schema, bool *schema_locked, bool *transaction_persistent, bool *fast_forward);
};

#endif /* __CLASS_MYSQL_AUTHENTICATION_H */
