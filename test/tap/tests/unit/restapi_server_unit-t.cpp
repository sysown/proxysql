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

struct startup_probe_state {
	std::string url;
	bool armed = false;
	int http_code_during_registration = 0;
};

// std::function copies its callable while the constructor builds each resource.
// Hold that phase open while checking the real listener: serving a request here
// would allow it to read the routing table while later resources are registered.
struct startup_probe {
	std::shared_ptr<startup_probe_state> state;

	explicit startup_probe(std::shared_ptr<startup_probe_state> s) : state(std::move(s)) {}
	startup_probe(const startup_probe& other) : state(other.state) {
		if (!state->armed) return;
		state->armed = false;
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
		do {
			state->http_code_during_registration = curl_http_code(state->url.c_str());
			if (state->http_code_during_registration != 0) break;
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		} while (std::chrono::steady_clock::now() < deadline);
	}

	std::shared_ptr<httpserver::http_response> operator()(const httpserver::http_request&) const {
		return std::make_shared<httpserver::string_response>("ready", httpserver::http::http_utils::http_ok);
	}
};

static void test_lifecycle_and_endpoint() {
	int port = find_free_port();
	if (port <= 0) {
		ok(0, "RESTAPI: failed to find free port");
		skip(7, "RESTAPI port unavailable");
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
	char url[128];
	snprintf(url, sizeof(url), "http://127.0.0.1:%d/api/unit-test-ping", port);
	auto probe = std::make_shared<startup_probe_state>();
	probe->url = url;
	endpoints.push_back({"/api/unit-test-startup-probe", startup_probe(probe)});
	probe->armed = true;

	// Intentionally not deleted: ~ProxySQL_RESTAPI_Server() joins the
	// server thread and can hang when stop() does not unblock start()
	// under the unit-test harness. Process exit cleans up the thread.
	// Move the vector so the armed callable is first copied inside the server.
	ProxySQL_RESTAPI_Server* server = new ProxySQL_RESTAPI_Server(port, std::move(endpoints));
	ok(server != nullptr, "RESTAPI: constructor with custom endpoint succeeds");
	ok(!probe->armed && probe->http_code_during_registration == 0,
		"RESTAPI: listener starts after all custom resources are constructed (got %d)",
		probe->http_code_during_registration);

	server->init();
	ok(1, "RESTAPI: init() completes without crash");

	server->print_version();
	ok(1, "RESTAPI: print_version() completes without crash");

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
	snprintf(url, sizeof(url), "http://127.0.0.1:%d/api/unit-test-startup-probe", port);
	http_code = curl_http_code(url);
	ok(http_code == 200, "RESTAPI: last custom endpoint is ready when listener starts (got %d)", http_code);
}

int main() {
	plan(9);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_lifecycle_and_endpoint();

	test_cleanup_minimal();
	return exit_status();
}
