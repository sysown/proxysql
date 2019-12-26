#include "proxysql.h"
#include "cpp.h"
#include "httpserver.hpp"

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
	const std::shared_ptr<http_response> find_script(const http_request& req, std::string& script, int &interval_ms) {
		SQLite3_result *resultset=NULL;
		int affected_rows;
		int cols;
		char *error=NULL;
		std::stringstream ss;
		ss << "SELECT * FROM restapi_routes WHERE uri='" << req.get_path_piece(1) << "' and active=1";
		bool rc=GloAdmin->admindb->execute_statement(ss.str().c_str(), &error, &cols, &affected_rows, &resultset);
		if (!rc) {
			proxy_error("Cannot query script for given path [%s]\n", req.get_path_piece(1));
			std::stringstream ss;
			if (error) {
				ss << "{\"error\":\"The script for route [" << req.get_path() << "] was not found. Error: " << error << "Error: \"}";
				proxy_error("Path %s, error %s\n", req.get_path().c_str(), error);
			}
			else {
				ss << "{\"error\":\"The script for route [" << req.get_path() << "] was not found.\"}";
				proxy_error("Path %s\n", req.get_path().c_str());
			}
			return std::shared_ptr<http_response>(new string_response(ss.str()));
		}
		if (resultset && resultset->rows_count != 1) {
			std::stringstream ss;
			ss << "{\"error\":\"The script for route [" << req.get_path() << "] was not found. count = " << resultset->rows_count << "\" }";
			proxy_error("Script for route %s was not found\n", req.get_path().c_str());
			return std::shared_ptr<http_response>(new string_response(ss.str()));
		}
		script = resultset->rows[0]->fields[4];
		interval_ms = atoi(resultset->rows[0]->fields[2]);
		if (resultset) {delete resultset; resultset=NULL;}
		return std::shared_ptr<http_response>(nullptr);
	}

    const std::shared_ptr<http_response> process_request(const http_request& req, const std::string& _params) {
		std::string params = req.get_content();
		if (params.empty())
			params = _params;
		if (params.empty()) {
			proxy_error("Empty parameters\n");
			return std::shared_ptr<http_response>(new string_response("{\"error\":\"Empty parameters\"}"));
		}

		try {
			nlohmann::json valid=nlohmann::json::parse(params);
		}
		catch(nlohmann::json::exception& e) {
			std::stringstream ss;
			ss << "{\"type\":\"in\", \"error\":\"" << e.what() << "\"}";
			proxy_error("Error parsing input json parameters. %s\n", ss.str().c_str());
			return std::shared_ptr<http_response>(new string_response(ss.str()));
		}

		std::string script;
		int interval_ms;
		auto result=find_script(req, script, interval_ms);
		if (nullptr!=result)
			return result;

		int pipefd[2];
        if (pipe(pipefd) == -1) {
			proxy_error("Cannot create pipe\n");
            return std::shared_ptr<http_response>(new string_response("{\"error\":\"Cannot create pipe.\"}"));
        }

		pid_t pid;
		if ((pid=fork()) == -1) {
			proxy_error("Cannot fork\n");
			return std::shared_ptr<http_response>(new string_response("{\"error\":\"Cannot fork.\"}"));
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
				return std::shared_ptr<http_response>(new string_response(ss.str()));
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
				return std::shared_ptr<http_response>(new string_response(ss.str()));
			}
			else if (rv == 0) {
				proxy_error("Timeout reading script output %s\n", script.c_str());
				std::stringstream ss;
				ss << "{\"error\":\"Timeout reading script output. Script file: " << script << "\"}";
				return std::shared_ptr<http_response>(new string_response(ss.str()));
			}
			else {
				int nbytes = read(pipefd[0], buf, sizeof(buf) - 1);
				if (nbytes == -1) {
					proxy_error("Error reading pipe\n");
					return std::shared_ptr<http_response>(new string_response("{\"error\":\"Error reading pipe.\"}"));
				}

				// validate json correctness
				try {
					nlohmann::json j=nlohmann::json::parse(buf);
				}
				catch(nlohmann::json::exception& e) {
					std::stringstream ss;
					ss << "{\"type\":\"out\", \"error\":\"" << e.what() << "\"}";
					proxy_error("Error parsing script output. %s\n", buf);
					return std::shared_ptr<http_response>(new string_response(ss.str()));
				}
			}
			close(pipefd[0]);

			int status;
			waitpid(pid, &status, 0);
		}
        return std::shared_ptr<http_response>(new string_response(buf));
    }

public:
	const std::shared_ptr<http_response> render(const http_request& req) {
		proxy_info("Render generic request with method %s for uri %s\n", req.get_method().c_str(), req.get_path().c_str());
		std::stringstream ss;
		ss << "{\"error\":\"HTTP method " << req.get_method().c_str() << " is not implemented\"}";
        return std::shared_ptr<http_response>(new string_response(ss.str().c_str()));
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

void * restapi_server_thread(void *arg) {
	httpserver::webserver * ws = (httpserver::webserver *)arg;
    ws->start(true);
	return NULL;
}

ProxySQL_RESTAPI_Server::ProxySQL_RESTAPI_Server(int p) {
	ws = std::unique_ptr<httpserver::webserver>(new webserver(create_webserver(p)));
	auto sr = new sync_resource();

	endpoint = std::unique_ptr<httpserver::http_resource>(sr);

    ws->register_resource("/sync", endpoint.get(), true);
	if (pthread_create(&thread_id, NULL, restapi_server_thread, ws.get()) !=0 ) {
		perror("Thread creation");
		exit(EXIT_FAILURE);
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

