#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "ProxySQL_HTTP_Server.hpp"

#include <cstring>

static void test_constructor() {
	ProxySQL_HTTP_Server* server = new ProxySQL_HTTP_Server();
	ok(server != nullptr, "HTTP Server: constructor succeeds");
	ok(server->variables.proxysql_latest_version == NULL,
		"HTTP Server: proxysql_latest_version initialized to NULL");
	delete server;
}

static void test_init() {
	ProxySQL_HTTP_Server server;
	server.init();
	ok(1, "HTTP Server: init() completes without crash");
}

static void test_multiple_instances() {
	ProxySQL_HTTP_Server* s1 = new ProxySQL_HTTP_Server();
	ProxySQL_HTTP_Server* s2 = new ProxySQL_HTTP_Server();
	ok(s1 != s2, "HTTP Server: multiple instances are distinct");
	ok(s1->variables.proxysql_latest_version == NULL,
		"HTTP Server: instance 1 version is NULL");
	ok(s2->variables.proxysql_latest_version == NULL,
		"HTTP Server: instance 2 version is NULL");
	delete s1;
	delete s2;
}

static void test_destructor_with_version() {
	ProxySQL_HTTP_Server* server = new ProxySQL_HTTP_Server();
	server->variables.proxysql_latest_version = strdup("2.5.0");
	ok(server->variables.proxysql_latest_version != NULL,
		"HTTP Server: can set proxysql_latest_version");
	delete server;
	ok(1, "HTTP Server: destructor handles non-null version without crash");
}

static void test_destructor_with_null_version() {
	ProxySQL_HTTP_Server* server = new ProxySQL_HTTP_Server();
	ok(server->variables.proxysql_latest_version == NULL,
		"HTTP Server: version starts as NULL");
	delete server;
	ok(1, "HTTP Server: destructor handles null version without crash");
}

int main() {
	plan(11);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_constructor();
	test_init();
	test_multiple_instances();
	test_destructor_with_version();
	test_destructor_with_null_version();

	test_cleanup_minimal();
	return exit_status();
}
