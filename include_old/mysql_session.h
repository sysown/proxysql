#ifndef __CLASS_MYSQL_SESSION_H
#define __CLASS_MYSQL_SESSION_H
#include "proxysql.h"
#include "cpp.h"

class MySQL_Session
{
	public:
	enum session_states sess_states;
	int healthy;
	int admin;
	int client_fd;
	int server_fd;
	int status;
	char *username;
	char *password;
	char *schema_cur;
	char *schema_new;
	int net_failure;
	MySQL_Data_Stream *client_myds;
	MySQL_Data_Stream *server_myds;

	GPtrArray *mybes;

	MySQL_Session();
	MySQL_Session(int);
	~MySQL_Session();


	int find_backend(int);
	void reset_all_backends();
	void writeout();

};

#endif /* __CLASS_MYSQL_SESSION_H */
