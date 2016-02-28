#ifndef __CLASS_PROXYSQL_HTTP_H
#define __CLASS_PROXYSQL_HTTP_H


class ProxySQL_HTTP {
	private:
	unsigned short port;
	struct mg_mgr * mgr;
	struct mg_connection *HTTP_nc;
	struct mg_connection *telnet_nc;
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
