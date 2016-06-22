#ifndef __CLASS_MYSQL_AUTHENTICATION_H
#define __CLASS_MYSQL_AUTHENTICATION_H

#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"


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
} account_details_t;

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define MYSQL_AUTHENTICATION_VERSION "0.2.0902" DEB

/*
#define AUTH_TABLE_MYSQL_USERS "CREATE TABLE mysql_users ( username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0, default_hostgroup INT NOT NULL DEFAULT 0, default_schema VARCHAR, schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0, transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 0, fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0, backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1, frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1, PRIMARY KEY (username, backend), UNIQUE (username, frontend))"
#define AUTH_TABLE_MYSQL_USERS_INCOMING "CREATE TABLE mysql_users_incoming ( username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0, default_hostgroup INT NOT NULL DEFAULT 0, default_schema VARCHAR, schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0, transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 0, fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0, backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1, frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1, PRIMARY KEY (username, backend), UNIQUE (username, frontend))"
*/


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
//	SQLite3DB *authdb;
//  rwlock_t rwlock;
	public:
	MySQL_Authentication();
	~MySQL_Authentication();
	bool add(char *username, char *password, enum cred_username_type usertype, bool use_ssl, int default_hostgroup, char *default_schema, bool schema_locked, bool transaction_persistent, bool fast_forward, int max_connections);
	bool del(char *username, enum cred_username_type usertype);
	bool reset();
	void print_version();
	char * lookup(char *username, enum cred_username_type usertype, bool *use_ssl, int *default_hostgroup, char **default_schema, bool *schema_locked, bool *transaction_persistent, bool *fast_forward, int *max_connections, void **sha1_pass);
	int dump_all_users(account_details_t ***);
	int increase_frontend_user_connections(char *username);
	void decrease_frontend_user_connections(char *username);
	bool set_SHA1(char *username, enum cred_username_type usertype, void *sha_pass);
//	void rdlock();
//	void rdunlock();
//	void wrlock();
//	void wrunlock();
};

#endif /* __CLASS_MYSQL_AUTHENTICATION_H */
