#ifndef __CLASS_PROXYSQL_HTTP_H
#define __CLASS_PROXYSQL_HTTP_H

class MySQL_Thread;

class ProxySQL_HTTP {
	private:
	MySQL_Thread * mysql_thr;
	unsigned short port;
	struct mg_mgr * mgr;
	struct mg_connection *HTTP_nc;
	struct mg_connection *telnet_nc;
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	public:
	ProxySQL_HTTP();
	~ProxySQL_HTTP();
	bool init();
	void run();
	void run2();
	//void ev_handler(struct mg_connection *nc, int ev, void *ev_data);
	void ev_handler();
};

#endif /* __CLASS_PROXYSQL_HTTP_H */
