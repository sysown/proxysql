#ifndef __CLASS_MYSQL_CONNECTION_H
#define __CLASS_MYSQL_CONNECTION_H

#include "proxysql.h"
#include "cpp.h"

#define STATUS_MYSQL_CONNECTION_TRANSACTION          0x00000001
#define STATUS_MYSQL_CONNECTION_COMPRESSION          0x00000002
#define STATUS_MYSQL_CONNECTION_USER_VARIABLE        0x00000004
#define STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT   0x00000008


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
		unsigned int compression_min_length;
	} options;
	uint32_t status_flags;
	unsigned long long last_time_used;
	uint8_t compression_pkt_id;
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

	void set_status_transaction(bool);
	void set_status_compression(bool);
	void set_status_prepared_statement(bool);
	void set_status_user_variable(bool);
	bool get_status_transaction();
	bool get_status_compression();
	bool get_status_prepared_statement();
	bool get_status_user_variable();

	friend class MyConnArray;
};
#endif /* __CLASS_MYSQL_CONNECTION_H */
