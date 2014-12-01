#ifndef __CLASS_MYSQL_AUTHENTICATION_H
#define __CLASS_MYSQL_AUTHENTICATION_H

#include "proxysql.h"
#include "cpp.h"


class MySQL_Authentication {
	public:
	MySQL_Authentication() {};
	virtual ~MySQL_Authentication() {};
	virtual bool add(char *, char *, char *) { return false; };
	virtual bool del(char *, char *) { return false; };
//	virtual bool reset(unsigned char *) { return false; };
	virtual bool reset() { return false; };
//	virtual bool refresh() { return false; };
	virtual void print_version() {};
	virtual char * lookup(char *, char *) {return NULL; };
};

typedef MySQL_Authentication * create_MySQL_Authentication_t();
typedef void destroy_MyAuth_t(MySQL_Authentication *);

#endif /* __CLASS_MYSQL_AUTHENTICATION_H */
