#ifndef __CLASS_MYSQL_SESSION_H
#define __CLASS_MYSQL_SESSION_H
#include "proxysql.h"
#include "cpp.h"

class MySQL_Session_userinfo {
	public:
  char *username;
  char *password;
  char *schemaname;
	MySQL_Session_userinfo();
	~MySQL_Session_userinfo();
	void set(char *, char *, char *);
	void set(MySQL_Session_userinfo *);
	bool set_schemaname(char *, int);
};

class Query_Info {
	public:
	unsigned long long start_time;
	unsigned long long end_time;
	void *QueryParserArgs;
	enum MYSQL_COM_QUERY_command MyComQueryCmd;
	unsigned char *QueryPointer;
	int QueryLength;
	void init(unsigned char *_p, int len, bool mysql_header=false);
	void query_parser_init(); 
	enum MYSQL_COM_QUERY_command query_parser_command_type(); 
	void query_parser_free(); 
	unsigned long long query_parser_update_counters();
};

class MySQL_Session
{
	public:
	void * operator new(size_t);
	void operator delete(void *);
	MySQL_Thread *thread;
	MySQL_Connection_Pool *MyConnPool;
//	enum session_states sess_states;
	QP_out_t *qpo;
	int healthy;
	bool admin;
	bool stats;
	void (*admin_func) (MySQL_Session *arg, ProxySQL_Admin *, PtrSize_t *pkt);
	int client_fd;
	int server_fd;
	enum session_status status;
	int current_hostgroup;
	int default_hostgroup;
	int active_transactions;
	bool transaction_persistent;
	int to_process;
	Query_Info CurrentQuery;
	//void *query_parser_args;
	unsigned long long pause;
	MySQL_Session_userinfo userinfo_client;
	MySQL_Session_userinfo userinfo_server;
//	char *username;
//	char *password;
//	char *schema_name;
//	char *schema_cur;
//	char *schema_new;
	//int net_failure;
	MySQL_Data_Stream *client_myds;
	MySQL_Data_Stream *server_myds;

	//GPtrArray *mybes;
	MySQL_Backend *mybe;
	PtrArray *mybes;

	MySQL_Session();
	MySQL_Session(int);
	~MySQL_Session();


	MySQL_Protocol myprot_client;
	MySQL_Protocol myprot_server;
	int handler();

	MySQL_Backend * find_backend(int);
	MySQL_Backend * create_backend(int, MySQL_Data_Stream *_myds=NULL);
	MySQL_Backend * find_or_create_backend(int, MySQL_Data_Stream *_myds=NULL);
	void reset_all_backends();
	void writeout();

};

#endif /* __CLASS_MYSQL_SESSION_H */
