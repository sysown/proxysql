#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "cpp.h"
#include "ProxySQL_RESTAPI_Server.hpp"

#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

static int find_free_port() {
	int fd = ::socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return 18080;
	sockaddr_in addr {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (::bind(fd, (sockaddr*)&addr, sizeof(addr)) != 0) {
		::close(fd);
		return 18080;
	}
	socklen_t len = sizeof(addr);
	::getsockname(fd, (sockaddr*)&addr, &len);
	int port = ntohs(addr.sin_port);
	::close(fd);
	return port;
}

static void test_lifecycle_and_endpoint() {
	int port = find_free_port();
	ok(port > 0, "RESTAPI: found free port %d", port);

	bool hit = false;
	std::vector<std::pair<std::string, std::function<std::shared_ptr<httpserver::http_response>(const httpserver::http_request&)>>> endpoints;
	endpoints.push_back({
		"/api/unit-test-ping",
		[&hit](const httpserver::http_request&) -> std::shared_ptr<httpserver::http_response> {
			hit = true;
			return std::shared_ptr<httpserver::http_response>(
				new httpserver::string_response("{\"ok\":true}", httpserver::http::http_utils::http_ok)
			);
		}
	});

	// Intentionally not deleted: ~ProxySQL_RESTAPI_Server() joins the
	// server thread and can hang when stop() does not unblock start()
	// under the unit-test harness. Process exit cleans up the thread.
	ProxySQL_RESTAPI_Server* server = new ProxySQL_RESTAPI_Server(port, endpoints);
	ok(server != nullptr, "RESTAPI: constructor with custom endpoint succeeds");

	server->init();
	ok(1, "RESTAPI: init() completes without crash");

	server->print_version();
	ok(1, "RESTAPI: print_version() completes without crash");

	usleep(300000);

	char url[128];
	snprintf(url, sizeof(url), "http://127.0.0.1:%d/api/unit-test-ping", port);
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "curl -s -o /dev/null -w '%%{http_code}' --max-time 2 '%s' 2>/dev/null", url);
	FILE* fp = popen(cmd, "r");
	int http_code = 0;
	if (fp) {
		char buf[16] = {0};
		if (fgets(buf, sizeof(buf), fp)) {
			http_code = atoi(buf);
		}
		pclose(fp);
	}
	ok(http_code == 200, "RESTAPI: custom GET endpoint returns HTTP 200 (got %d)", http_code);
	ok(hit == true, "RESTAPI: custom endpoint handler was invoked");
}

int main() {
	plan(7);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_lifecycle_and_endpoint();

	test_cleanup_minimal();
	return exit_status();
}
