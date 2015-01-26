#ifndef __CLASS_MYSQL_CONNECTION_H
#define __CLASS_MYSQL_CONNECTION_H

#include "proxysql.h"
#include "cpp.h"

class MySQL_Connection {
	private:
	MyConnArray *MCA;
	bool is_expired(unsigned long long timeout);
	unsigned long long inserted_into_pool;
	public:
	int fd;
	MySrvC *parent;
//	void * operator new(size_t);
//	void operator delete(void *);
	MySQL_Data_Stream *myds;
	MYSQL myconn;
	MySQL_Hostgroup_Entry *mshge;
	bool reusable;
	MySQL_Connection();
	~MySQL_Connection();
	int assign_mshge(unsigned int);
	void set_mshge(MySQL_Hostgroup_Entry *);
	void free_mshge();
	MyConnArray *set_MCA(MySQL_Connection_Pool *_MyConnPool, const char *hostname, const char *username, const char *password, const char *db, unsigned int port);
	bool return_to_connection_pool();
	friend class MyConnArray;
};
#endif /* __CLASS_MYSQL_CONNECTION_H */
