#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "cpp.h"
#include "ProxySQL_RESTAPI_Server.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <thread>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

static int find_free_port() {
	int fd = ::socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	sockaddr_in addr {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (::bind(fd, (sockaddr*)&addr, sizeof(addr)) != 0) {
		::close(fd);
		return -1;
	}
	socklen_t len = sizeof(addr);
	::getsockname(fd, (sockaddr*)&addr, &len);
	int port = ntohs(addr.sin_port);
	::close(fd);
	return port;
}

static int curl_http_code(const char* url) {
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "curl -s -o /dev/null -w '%%{http_code}' --max-time 1 '%s' 2>/dev/null", url);
	FILE* fp = popen(cmd, "r");
	int http_code = 0;
	if (fp) {
		char buf[16] = {0};
		if (fgets(buf, sizeof(buf), fp)) {
			http_code = atoi(buf);
		}
		pclose(fp);
	}
	return http_code;
}

static void test_lifecycle_and_endpoint() {
	int port = find_free_port();
	if (port <= 0) {
		ok(0, "RESTAPI: failed to find free port");
		skip(5, "RESTAPI port unavailable");
		return;
	}
	ok(port > 0, "RESTAPI: found free port %d", port);

	// shared_ptr by value: callback outlives this stack frame (server not deleted)
	auto hit = std::make_shared<std::atomic<bool>>(false);
	std::vector<std::pair<std::string, std::function<std::shared_ptr<httpserver::http_response>(const httpserver::http_request&)>>> endpoints;
	endpoints.push_back({
		"/api/unit-test-ping",
		[hit](const httpserver::http_request&) -> std::shared_ptr<httpserver::http_response> {
			hit->store(true, std::memory_order_release);
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

	char url[128];
	snprintf(url, sizeof(url), "http://127.0.0.1:%d/api/unit-test-ping", port);

	/* Poll until ready — constructor starts the listener asynchronously. */
	int http_code = 0;
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (std::chrono::steady_clock::now() < deadline) {
		http_code = curl_http_code(url);
		if (http_code == 200) break;
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}

	ok(http_code == 200, "RESTAPI: custom GET endpoint returns HTTP 200 (got %d)", http_code);
	ok(hit->load(std::memory_order_acquire) == true, "RESTAPI: custom endpoint handler was invoked");
}

int main() {
	plan(7);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_lifecycle_and_endpoint();

	test_cleanup_minimal();
	return exit_status();
}
