#ifndef __CLASS_MYSQL_CONNECTION_POOL_H
#define __CLASS_MYSQL_CONNECTION_POOL_H
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_atomic.h"

/*
typedef struct _mysql_conns_array_t MCA_t;
struct _mysql_conns_array_t {
    char *hostname;
    char *username;
    char *password;
    char *db;
    unsigned int port;
	//GPtrArray *free_conns;
	PtrArray *free_conns;
};
*/

class MyConnArray {
	private:
    char *hostname;
    char *username;
    char *password;
    char *db;
    unsigned int port;
	//GPtrArray *free_conns;
	PtrArray *free_conns;
	public:
	MyConnArray(const char *__hostname, const char *__username, const char *__password, const char *__db, unsigned int __port);
	~MyConnArray();
	MyConnArray * match(const char *__hostname, const char *__username, const char *__password, const char *__db, unsigned int __port);
	void add(MySQL_Connection *);
};

class MySQL_Connection_Pool {
	private:
	int shared;
	spinlock mutex;
	//GPtrArray *MyConnArrays;
	PtrArray *MyConnArrays;
	MyConnArray * MyConnArray_find(const char *hostname, const char *username, const char *password, const char *db, unsigned int port);
	MyConnArray * MyConnArray_create(const char *hostname, const char *username, const char *password, const char *db, unsigned int port);
	public:
	MySQL_Connection_Pool(int _shared=0);
	~MySQL_Connection_Pool();
	MyConnArray * MyConnArray_lookup(const char *hostname, const char *username, const char *password, const char *db, unsigned int port);
};

#endif /* __CLASS_MYSQL_CONNECTION_POOL_H */
