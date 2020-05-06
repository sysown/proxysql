#ifndef CLASS_PROXYSQL_RESTAPI_SERVER_H
#define CLASS_PROXYSQL_RESTAPI_SERVER_H
#include "proxysql.h"
#include "cpp.h"
#include <string>
#include <memory>
#include <functional>

#include "httpserver.hpp"

class ProxySQL_RESTAPI_Server {
	private:
	std::unique_ptr<httpserver::webserver> ws;
	int port;
	pthread_t thread_id;
	std::unique_ptr<httpserver::http_resource> endpoint;
	std::vector<std::pair<std::string, std::unique_ptr<httpserver::http_resource>>> _endpoints {};
	public:
	ProxySQL_RESTAPI_Server(
		int p,
		std::vector<
			std::pair<
				std::string,
				std::function<std::shared_ptr<httpserver::http_response>(const httpserver::http_request&)>>
		> endpoints =
			std::vector<
				std::pair<
					std::string,
					std::function<std::shared_ptr<httpserver::http_response>(const httpserver::http_request&)>>> {}
	);
	~ProxySQL_RESTAPI_Server();
	void init();
	void print_version();
};
#endif /* CLASS_PROXYSQL_RESTAPI_SERVER */
