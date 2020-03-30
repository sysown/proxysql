#include "proxysql.h"
#include "cpp.h"
#include "httpserver.hpp"

#include <functional>
#include <sstream>


#include "ProxySQL_RESTAPI_Server.hpp"
using namespace httpserver;


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_RESTAPI_SERVER_VERSION "2.0.1121" DEB

extern ProxySQL_Admin *GloAdmin;

class sync_resource : public http_resource {
private:
	void add_headers(std::shared_ptr<http_response> &response) {
		response->with_header("Content-Type", "application/json");
		response->with_header("Access-Control-Allow-Origin", "*");
	}

	const std::shared_ptr<http_response> find_script(const http_request& req, std::string& script, int &interval_ms) {
		char *error=NULL;
		std::stringstream ss;
		ss << "SELECT * FROM runtime_restapi_routes WHERE uri='" << req.get_path_piece(1) << "' and method='" << req.get_method() << "' and active=1";
		std::unique_ptr<SQLite3_result> resultset = std::unique_ptr<SQLite3_result>(GloAdmin->admindb->execute_statement(ss.str().c_str(), &error));
		if (!resultset) {
			proxy_error("Cannot query script for given method [%s] and uri [%s]\n", req.get_method().c_str(), req.get_path_piece(1).c_str());
			std::stringstream ss;
			if (error) {
				ss << "{\"error\":\"The script for method [" << req.get_method() << "] and route [" << req.get_path() << "] was not found. Error: " << error << "Error: \"}";
				proxy_error("Path %s, error %s\n", req.get_path().c_str(), error);
			}
			else {
				ss << "{\"error\":\"The script for method [" << req.get_method() << "] and route [" << req.get_path() << "] was not found.\"}";
				proxy_error("Path %s\n", req.get_path().c_str());
			}
			auto response = std::shared_ptr<http_response>(new string_response(ss.str()));
			add_headers(response);
			return response;
		}
		if (resultset && resultset->rows_count != 1) {
			std::stringstream ss;
			ss << "{\"error\":\"The script for method [" << req.get_method() << "] and route [" << req.get_path() << "] was not found. Rows count returned [" << resultset->rows_count << "]\" }";
			proxy_error("Script for method [%s] and route [%s] was not found\n", req.get_method().c_str(), req.get_path().c_str());
			auto response = std::shared_ptr<http_response>(new string_response(ss.str()));
			add_headers(response);
			return response;
		}
		script = resultset->rows[0]->fields[5];
		interval_ms = atoi(resultset->rows[0]->fields[2]);
		return std::shared_ptr<http_response>(nullptr);
	}

    const std::shared_ptr<http_response> process_request(const http_request& req, const std::string& _params) {
		std::string params = req.get_content();
		if (params.empty())
			params = _params;
		if (params.empty()) {
			proxy_error("Empty parameters\n");

			auto response = std::shared_ptr<http_response>(new string_response("{\"error\":\"Empty parameters\"}"));
			add_headers(response);
			return response;
		}

		try {
			nlohmann::json valid=nlohmann::json::parse(params);
		}
		catch(nlohmann::json::exception& e) {
			std::stringstream ss;
			ss << "{\"type\":\"in\", \"error\":\"" << e.what() << "\"}";
			proxy_error("Error parsing input json parameters. %s\n", ss.str().c_str());

			auto response = std::shared_ptr<http_response>(new string_response(ss.str()));
			add_headers(response);
			return response;
		}

		std::string script;
		int interval_ms;
		auto result=find_script(req, script, interval_ms);

		// result == nullpts means that script was found and we can execute it. continue.
		if (nullptr!=result)
			return result;

		int pipefd[2];
		if (pipe(pipefd) == -1) {
			proxy_error("Cannot create pipe\n");

			auto response = std::shared_ptr<http_response>(new string_response("{\"error\":\"Cannot create pipe.\"}"));
			add_headers(response);
			return response;
		}

		pid_t pid;
		if ((pid=fork()) == -1) {
			proxy_error("Cannot fork\n");

			auto response = std::shared_ptr<http_response>(new string_response("{\"error\":\"Cannot fork.\"}"));
			add_headers(response);
			return response;
		}

		char buf[65536] = {0};
		if (pid == 0) {
			dup2(pipefd[1], STDOUT_FILENO);
			close(pipefd[0]);
			close(pipefd[1]);

			char* const args[] = {const_cast<char* const>(script.c_str()), const_cast<char* const>(params.c_str()), NULL};
			if (execve(script.c_str(), args, NULL) == -1) {
				char path_buffer[PATH_MAX];
				char* cwd = getcwd(path_buffer, sizeof(path_buffer)-1);
				std::stringstream ss;
				ss << "{\"error\":\"Error calling execve().\", \"cwd\":\"" << cwd << "\", \"file\":\"" << script << "\"}";
				proxy_error("%s\n", ss.str().c_str());

				auto response = std::shared_ptr<http_response>(new string_response(ss.str()));
				add_headers(response);
				return response;
			}
			exit(EXIT_SUCCESS);
		}
		else {
			close(pipefd[1]);

			fd_set set;

			FD_ZERO(&set);
			FD_SET(pipefd[0], &set);

			struct timeval timeout;
			timeout.tv_sec=interval_ms/1000;
			timeout.tv_usec=(interval_ms%1000)*1000;

			int rv = select(pipefd[0]+1,&set,NULL,NULL,&timeout);
			if (rv == -1) {
				proxy_error("Error calling select for path %s\n", req.get_path().c_str());
				std::stringstream ss;
				ss << "{\"error\":\"Error calling select().\", \"path\":\"" << req.get_path() << "\"}";

				auto response = std::shared_ptr<http_response>(new string_response(ss.str()));
				add_headers(response);
				return response;
			}
			else if (rv == 0) {
				proxy_error("Timeout reading script output %s\n", script.c_str());
				std::stringstream ss;
				ss << "{\"error\":\"Timeout reading script output. Script file: " << script << "\"}";

				auto response = std::shared_ptr<http_response>(new string_response(ss.str()));
				add_headers(response);
				return response;
			}
			else {
				int nbytes = read(pipefd[0], buf, sizeof(buf) - 1);
				if (nbytes == -1) {
					proxy_error("Error reading pipe\n");

					auto response = std::shared_ptr<http_response>(new string_response("{\"error\":\"Error reading pipe.\"}"));
					add_headers(response);
					return response;
				}

				// validate json correctness
				try {
					nlohmann::json j=nlohmann::json::parse(buf);
				}
				catch(nlohmann::json::exception& e) {
					std::stringstream ss;
					ss << "{\"type\":\"out\", \"error\":\"" << e.what() << "\"}";
					proxy_error("Error parsing script output. %s\n", buf);

					auto response = std::shared_ptr<http_response>(new string_response(ss.str()));
					add_headers(response);
					return response;
				}
			}
			close(pipefd[0]);

			int status;
			waitpid(pid, &status, 0);
		}
        auto response = std::shared_ptr<http_response>(new string_response(buf));
        add_headers(response);
        return response;
    }

public:
	const std::shared_ptr<http_response> render(const http_request& req) {
		proxy_info("Render generic request with method %s for uri %s\n", req.get_method().c_str(), req.get_path().c_str());
		std::stringstream ss;
		ss << "{\"error\":\"HTTP method " << req.get_method().c_str() << " is not implemented\"}";

        auto response = std::shared_ptr<http_response>(new string_response(ss.str().c_str()));
        response->with_header("Content-Type", "application/json");
        response->with_header("Access-Control-Allow-Origin", "*");
        return response;
    }

	const std::shared_ptr<http_response> render_GET(const http_request& req) {
		auto args = req.get_args();

		size_t last = 0;
		std::stringstream params;
		params << "{";
		for (auto arg : args) {
			params << "\"" << arg.first << "\":\"" << arg.second << "\"";
			if (last < args.size()-1) {
				params << ",";
				last++;
			}
		}
		params << "}";

		return process_request(req, params.str());
	}

	const std::shared_ptr<http_response> render_POST(const http_request& req) {
		std::string params=req.get_content();
		return process_request(req, params);
	}

};

class gen_get_endpoint : public http_resource {
private:
	std::function<std::shared_ptr<http_response>(const http_request&)> _get_fn {};
public:
	gen_get_endpoint(std::function<std::shared_ptr<http_response>(const http_request&)> get_fn) :
		_get_fn(get_fn)
	{}

	const std::shared_ptr<http_response> render_GET(const http_request& req) override {
		return this->_get_fn(req);
	}
};

void * restapi_server_thread(void *arg) {
	httpserver::webserver * ws = (httpserver::webserver *)arg;
    ws->start(true);
	return NULL;
}

using std::vector;
using std::pair;
using std::function;
using std::shared_ptr;

ProxySQL_RESTAPI_Server::ProxySQL_RESTAPI_Server(
	int p,
	vector<pair<std::string, function<shared_ptr<http_response>(const http_request&)>>> endpoints
) {
	ws = std::unique_ptr<httpserver::webserver>(new webserver(create_webserver(p)));
	auto sr = new sync_resource();

	endpoint = std::unique_ptr<httpserver::http_resource>(sr);

    ws->register_resource("/sync", endpoint.get(), true);
	if (pthread_create(&thread_id, NULL, restapi_server_thread, ws.get()) !=0 ) {
		perror("Thread creation");
		exit(EXIT_FAILURE);
	}

	for (const auto& id_endpoint : endpoints) {
		const auto& endpoint_route { id_endpoint.first };
		auto endpoint_fn { id_endpoint.second };
		auto endpoint_res {
			std::unique_ptr<httpserver::http_resource>(
				new gen_get_endpoint(endpoint_fn)
			)
		};

		ws->register_resource(endpoint_route, endpoint_res.get(), true);
		_endpoints.push_back({endpoint_route, std::move(endpoint_res)});
	}
}

ProxySQL_RESTAPI_Server::~ProxySQL_RESTAPI_Server() {
	if (ws) {
    	ws->stop();
		pthread_join(thread_id, NULL);
	}
}

void ProxySQL_RESTAPI_Server::init() {
}

void ProxySQL_RESTAPI_Server::print_version() {
    fprintf(stderr,"Standard ProxySQL REST API Server Handler rev. %s -- %s -- %s\n", PROXYSQL_RESTAPI_SERVER_VERSION, __FILE__, __TIMESTAMP__);
}

