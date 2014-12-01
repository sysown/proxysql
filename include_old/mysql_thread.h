#ifndef __CLASS_MYSQL_THREAD_H
#define __CLASS_MYSQL_THREAD_H
#include "proxysql.h"
#include "cpp.h"

#define MYSQL_THREAD_EPOLL_MAXEVENTS 1000

class MySQL_Thread
{
	private:
	int epoll_maxevents;
	struct epoll_event *events;
	int nfds;
	
	public:
	int shutdown;
	int epollfd;
	GPtrArray *mysql_sessions;
/*
	int hostgroup_id;
	MySQL_Data_Stream *server_myds;
  mysql_cp_entry_t *server_mycpe;
  bytes_stats_t server_bytes_at_cmd;
*/
	MySQL_Thread();
	void init();
	int init_epoll(int);
	void epoll_listener_add(int);
	void run(); // main loop
};

#endif /* __CLASS_MYSQL_THREAD_H */
