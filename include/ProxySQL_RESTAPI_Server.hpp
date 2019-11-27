#ifndef CLASS_PROXYSQL_RESTAPI_SERVER_H
#define CLASS_PROXYSQL_RESTAPI_SERVER_H
#include "proxysql.h"
#include "cpp.h"
#include <string>

#include "httpserver.hpp"

class ProxySQL_RESTAPI_Server {
	private:
	//httpserver::webserver *ws;
	httpserver::webserver * ws;
	int port;
	pthread_t thread_id;
	httpserver::http_resource *hr;
	public:
	ProxySQL_RESTAPI_Server(int p);
	~ProxySQL_RESTAPI_Server();
	void init();
	void print_version();
};
#endif /* CLASS_PROXYSQL_RESTAPI_SERVER */
