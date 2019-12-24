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

class hello_world_resource : public http_resource {
public:
    const std::shared_ptr<http_response> render_GET(const http_request& req) {
        return std::shared_ptr<http_response>(new string_response("GET: Hello, World!\n"));
    }

    const std::shared_ptr<http_response> render_POST(const http_request& req) {
        //TODO : validate json correctness in the req

        int pipefd[2];
        if (pipe(pipefd) == -1) {
            return std::shared_ptr<http_response>(new string_response("{\"error\":\"Cannot create pipe.\"}"));
        }

		pid_t pid;
		if ((pid=fork()) == -1) {
			return std::shared_ptr<http_response>(new string_response("{\"error\":\"Cannot fork.\"}"));
		}

		// validate json correctness
		try {
			nlohmann::json valid=nlohmann::json::parse(req.get_content());
		}
		catch(nlohmann::json::exception& e) {
			std::stringstream ss;
			ss << "{\"type\":\"in\", \"error\":\"" << e.what() << "\"}";
			return std::shared_ptr<http_response>(new string_response(ss.str()));
		}


		char buf[1024] = {0};
		if (pid == 0) {
			dup2(pipefd[1], STDOUT_FILENO);
			close(pipefd[0]);
			close(pipefd[1]);

			SQLite3_result *resultset=NULL;
			int affected_rows;
			int cols;
			char *error=NULL;
			std::stringstream ss;
			ss << "SELECT * FROM restapi_routes WHERE uri='" << req.get_path_piece(1) << "'";
			bool rc=GloAdmin->admindb->execute_statement(ss.str().c_str(), &error, &cols, &affected_rows, &resultset);
			if (!rc) {
				proxy_error("Cannot query script for given path [%s]\n", req.get_path_piece(1));
			}
			if (!resultset || resultset->rows_count == 0) {
				std::stringstream ss;
				ss << "{\"error\":\"The script for route [" << req.get_path() << "] was not found.\"}";
				return std::shared_ptr<http_response>(new string_response(ss.str()));
			}
			std::string script = resultset->rows[0]->fields[4];
			char* const args[] = {const_cast<char* const>("a"), const_cast<char* const>(req.get_content().c_str()), NULL};
			if (execve(resultset->rows[0]->fields[4], args, NULL) == -1) {
				char path_buffer[PATH_MAX];
				char* cwd = getcwd(path_buffer, sizeof(path_buffer)-1);
				std::stringstream ss;
				ss << "{\"error\":\"Error calling execve().\", \"cwd\":\"" << cwd << "\", \"file\":\"" << resultset->rows[0]->fields[4] << "\"}";
				return std::shared_ptr<http_response>(new string_response(ss.str()));
			}
			exit(EXIT_SUCCESS);
		}
		else {
			close(pipefd[1]);
			int nbytes = read(pipefd[0], buf, sizeof(buf) - 1);
			if (nbytes == -1) {
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

			close(pipefd[0]);
			wait(NULL);
		}
        return std::shared_ptr<http_response>(new string_response(buf));
    }
};

void * restapi_server_thread(void *arg) {
	httpserver::webserver * ws = (httpserver::webserver *)arg;
    ws->start(true);
	return NULL;
}

ProxySQL_RESTAPI_Server::ProxySQL_RESTAPI_Server(int p) {

	// for now, this is COMPLETELY DISABLED
	// just adding a POC
//	return;

	//ws = NULL;
	port = p;
	ws = new webserver(create_webserver(p));
	//hello_world_resource hwr;
	hr = new hello_world_resource();

    //ws->register_resource("/hello", &hwr);
    ws->register_resource("/hello", hr, true);
	if (pthread_create(&thread_id, NULL, restapi_server_thread, ws) !=0 ) {
            perror("Thread creation");
            exit(EXIT_FAILURE);
	}
	//webserver ws2 = create_webserver(8080);
	//webserws = create_webserver(8080);
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

