#ifndef __CLASS_MYSQL_CONNECTION_H
#define __CLASS_MYSQL_CONNECTION_H

#include "proxysql.h"
#include "cpp.h"

class MySQL_Connection {
	public:
	void * operator new(size_t);
	void operator delete(void *);
	MyConnArray *MCA;
	MySQL_Data_Stream *myds;
	MYSQL myconn;
	MySQL_Hostgroup_Entry *mshge;
	unsigned long long expire;
  bool reusable;
	MySQL_Connection();
	~MySQL_Connection();
	int assign_mshge(unsigned int);
	void set_mshge(MySQL_Hostgroup_Entry *);
	void free_mshge();
};
#endif /* __CLASS_MYSQL_CONNECTION_H */
