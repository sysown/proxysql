#include "proxysql.h"
#include "cpp.h"
#include "httpserver.hpp"

#include "ProxySQL_RESTAPI_Server.hpp"
using namespace httpserver;


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_RESTAPI_SERVER_VERSION "2.0.1121" DEB

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

		char buf[1024];
		if (pid == 0) {
			dup2(pipefd[1], STDOUT_FILENO);
			close(pipefd[0]);
			close(pipefd[1]);
			char* args[] = {"a", (char*)req.get_content().data(), NULL};
			if (execve("/home/val/workspace/script.py", args, NULL) == -1) {
				return std::shared_ptr<http_response>(new string_response("{\"error\":\"Error calling execve().\"}"));
			}
			exit(EXIT_SUCCESS);
		}
		else {
			close(pipefd[1]);
			int nbytes = read(pipefd[0], buf, sizeof(buf) - 1);
			if (nbytes == -1) {
				return std::shared_ptr<http_response>(new string_response("{\"error\":\"Error reading pipe.\"}"));
			}
			//TODO : validate json correctness in the buf
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
    ws->register_resource("/hello", hr);
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

