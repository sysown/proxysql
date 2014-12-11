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
	PtrArray *free_conns;
	MyConnArray * match(const char *__hostname, const char *__username, const char *__password, const char *__db, unsigned int __port);
	void add(MySQL_Connection *);
	MySQL_Connection * MyConn_find();
	public:
	MyConnArray(const char *__hostname, const char *__username, const char *__password, const char *__db, unsigned int __port);
	~MyConnArray();
	friend class MySQL_Connection_Pool;
};

class MySQL_Connection_Pool {
	private:
	bool shared; //< TRUE for shared connection pool
	spinlock mutex; //< used only for shared connection pool
	PtrArray *MyConnArrays; //< Pointers array
	MyConnArray * MyConnArray_find(const char *hostname, const char *username, const char *password, const char *db, unsigned int port);
	MyConnArray * MyConnArray_create(const char *hostname, const char *username, const char *password, const char *db, unsigned int port);
	public:
	MySQL_Connection_Pool(bool _shared=false);
	~MySQL_Connection_Pool();
	MyConnArray * MyConnArray_lookup(const char *hostname, const char *username, const char *password, const char *db, unsigned int port);
	MySQL_Connection * MySQL_Connection_lookup(MyConnArray *MCA);
	MySQL_Connection * MySQL_Connection_lookup(const char *hostname, const char *username, const char *password, const char *db, unsigned int port);

};

#endif /* __CLASS_MYSQL_CONNECTION_POOL_H */
