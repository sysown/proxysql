#ifndef __CLASS_MYSQL_CONNECTION_H
#define __CLASS_MYSQL_CONNECTION_H

#include "proxysql.h"
#include "cpp.h"

class MySQL_Connection_userinfo {
	private:
	uint64_t compute_hash();
  public:
	char *username;
	char *password;
	char *schemaname;
	uint64_t hash;
	MySQL_Connection_userinfo();
	~MySQL_Connection_userinfo();
	void set(char *, char *, char *);
	void set(MySQL_Connection_userinfo *);
	bool set_schemaname(char *, int);
};



class MySQL_Connection {
	private:
	MyConnArray *MCA;
	bool is_expired(unsigned long long timeout);
	unsigned long long inserted_into_pool;
	public:
	int fd;
	char scramble_buff[40];
	struct {
		uint32_t max_allowed_pkt;
		uint32_t server_capabilities;
		char *server_version;
		uint8_t protocol_version;
		uint8_t charset;
	} options;
	unsigned long long last_time_used;
	MySrvC *parent;
//	void * operator new(size_t);
//	void operator delete(void *);
	MySQL_Connection_userinfo *userinfo;
	MySQL_Data_Stream *myds;
	//MYSQL myconn;
	//MySQL_Hostgroup_Entry *mshge;
	bool reusable;
	MySQL_Connection();
	~MySQL_Connection();
//	int assign_mshge(unsigned int);
	//void set_mshge(MySQL_Hostgroup_Entry *);
//	void free_mshge();
	MyConnArray *set_MCA(MySQL_Connection_Pool *_MyConnPool, const char *hostname, const char *username, const char *password, const char *db, unsigned int port);
	bool return_to_connection_pool();
	uint8_t set_charset(uint8_t);
	friend class MyConnArray;
};
#endif /* __CLASS_MYSQL_CONNECTION_H */
