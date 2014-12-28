#ifndef __CLASS_MYSQL_AUTHENTICATION_H
#define __CLASS_MYSQL_AUTHENTICATION_H

#include "proxysql.h"
#include "cpp.h"

enum cred_username_type { USERNAME_BACKEND, USERNAME_FRONTEND };

class MySQL_Authentication {
	public:
	MySQL_Authentication() {};
	virtual ~MySQL_Authentication() {};
	//virtual bool add(char *username, char *password, enum cred_username_type usertype, bool use_ssl) { return false; };
	virtual bool add(char *username, char *password, enum cred_username_type usertype, bool use_ssl, int default_hostgroup) { return false; };
	virtual bool del(char *username, enum cred_username_type usertype) { return false; };
//	virtual bool reset(unsigned char *) { return false; };
	virtual bool reset() { return false; };
//	virtual bool refresh() { return false; };
	virtual void print_version() {};
//	virtual char * lookup(char *username, enum cred_username_type usertype, bool *use_ssl) {return NULL; };
	virtual char * lookup(char *username, enum cred_username_type usertype, bool *use_ssl, int *default_hostgroup) {return NULL; };
};

typedef MySQL_Authentication * create_MySQL_Authentication_t();
typedef void destroy_MyAuth_t(MySQL_Authentication *);

#endif /* __CLASS_MYSQL_AUTHENTICATION_H */
