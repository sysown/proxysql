#ifndef __CLASS_PROXYSQL_ADMIN_H
#define __CLASS_PROXYSQL_ADMIN_H
#include "proxysql.h"
#include "cpp.h"


class ProxySQL_Admin {
	public:
	ProxySQL_Admin() {};
	virtual ~ProxySQL_Admin() {};
	virtual const char *version() {return NULL;};
	virtual void print_version() {};
	virtual bool init() {return false;};
	virtual void admin_shutdown() {};
};


typedef ProxySQL_Admin * create_ProxySQL_Admin_t();

#endif /* __CLASS_PROXYSQL_ADMIN_H */

