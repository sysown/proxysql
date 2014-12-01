#ifndef __CLASS_SESSION_H
#define __CLASS_SESSION_H
#include "proxysql.h"
#include "cpp.h"


class ProxySQL_Session
{
	public:
//	virtual void * operator new(size_t) {return NULL;}
//	virtual void operator delete(void *) {};
	MySQL_Thread *thread;
//	enum session_states sess_states;
	QP_out_t *qpo;
	int healthy;
	int admin;
	int client_fd;
	int server_fd;
	enum session_status status;
	int to_process;
	unsigned long long pause;
	char *username;
	char *password;
	char *schema_name;
//	char *schema_cur;
//	char *schema_new;
	int net_failure;
	MySQL_Data_Stream *client_myds;
	MySQL_Data_Stream *server_myds;

	//GPtrArray *mybes;
	PtrArray *mybes;

	ProxySQL_Session();
	ProxySQL_Session(int) {};
	virtual ~ProxySQL_Session() {};


	MySQL_Protocol prot;
	virtual int handler() {return 0;};

	virtual int find_backend(int) {return 0;};
	virtual void reset_all_backends() {};
	virtual void writeout() {};

};

#endif /* __CLASS_SESSION_H */
