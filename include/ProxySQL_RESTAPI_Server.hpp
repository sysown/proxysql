#ifndef CLASS_PROXYSQL_RESTAPI_SERVER_H
#define CLASS_PROXYSQL_RESTAPI_SERVER_H
#include "proxysql.h"
#include "cpp.h"
#include <string>

#include "httpserver.hpp"

class ProxySQL_RESTAPI_Server {
	private:
	std::unique_ptr<httpserver::webserver> ws;
	int port;
	pthread_t thread_id;
	std::unique_ptr<httpserver::http_resource> endpoint;
	public:
	ProxySQL_RESTAPI_Server(int p);
	~ProxySQL_RESTAPI_Server();
	void init();
	void print_version();
};
#endif /* CLASS_PROXYSQL_RESTAPI_SERVER */
