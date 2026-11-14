/**
 * @file plugin_raw_backend_unit-t.cpp
 * @brief Focused real-HGM coverage for the ABI-18 raw TCP backend service.
 *
 * Every acquisition below goes through the real MySQL/PostgreSQL hostgroup
 * managers.  The service must register a fresh protocol object in the actual
 * selected server's ConnectionsUsed list, account obvious capacity/counters
 * without a fabricated SQL session, and destroy that exact object once.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "ProxySQL_Plugin.h"
#include "ProxySQL_PluginRawBackend.h"
#include "MySQL_HostGroups_Manager.h"
#include "PgSQL_HostGroups_Manager.h"
#include "MySQL_Thread.h"
#include "PgSQL_Thread.h"
#include "MySQL_Monitor.hpp"
#include "PgSQL_Monitor.hpp"
#include "mysql_connection.h"
#include "PgSQL_Connection.h"
#include "proxysql.h"
#include "cpp.h"
#include "sqlite3db.h"

#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <thread>

extern MySQL_HostGroups_Manager *MyHGM;
extern PgSQL_HostGroups_Manager *PgHGM;
extern PgSQL_Threads_Handler *GloPTH;
extern MySQL_Monitor *GloMyMon;
extern PgSQL_Monitor *GloPgMon;

namespace {
std::atomic<int> g_fail_new_countdown { -1 };
}

void* operator new(std::size_t size) {
	const int remaining = g_fail_new_countdown.load(std::memory_order_relaxed);
	if (remaining == 0) {
		g_fail_new_countdown.store(-1, std::memory_order_relaxed);
		throw std::bad_alloc();
	}
	if (remaining > 0) {
		g_fail_new_countdown.fetch_sub(1, std::memory_order_relaxed);
	}
	void* memory = std::malloc(size == 0 ? 1 : size);
	if (memory == nullptr) throw std::bad_alloc();
	return memory;
}

void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }

namespace {

int add_mysql_server(uint32_t hg, const char* addr, uint16_t port,
	int64_t weight = 1, int64_t max_conns = 100) {
	srv_info_t info;
	info.addr = addr;
	info.port = port;
	info.kind = "raw-test";

	srv_opts_t opts;
	opts.weigth = weight;
	opts.max_conns = max_conns;
	opts.use_ssl = 0;

	MyHGM->wrlock();
	const int rc = MyHGM->create_new_server_in_hg(hg, info, opts);
	MyHGM->wrunlock();
	return rc;
}

int add_pgsql_server(uint32_t hg, const char* addr, uint16_t port,
	int64_t weight = 1, int64_t max_conns = 100) {
	PgSQL_srv_info_t info;
	info.addr = addr;
	info.port = port;
	info.kind = "raw-test";

	PgSQL_srv_opts_t opts;
	opts.weigth = weight;
	opts.max_conns = max_conns;
	opts.use_ssl = 0;

	PgHGM->wrlock();
	const int rc = PgHGM->create_new_server_in_hg(hg, info, opts);
	PgHGM->wrunlock();
	return rc;
}

MySrvC* find_mysql_server(uint32_t hg, const char* addr) {
	MyHGC* hgc = MyHGM->MyHGC_find(hg);
	if (hgc == nullptr) return nullptr;
	for (unsigned int i = 0; i < hgc->mysrvs->cnt(); ++i) {
		MySrvC* server = hgc->mysrvs->idx(i);
		if (std::strcmp(server->address, addr) == 0) return server;
	}
	return nullptr;
}

PgSQL_SrvC* find_pgsql_server(uint32_t hg, const char* addr) {
	PgSQL_HGC* hgc = PgHGM->MyHGC_find(hg);
	if (hgc == nullptr) return nullptr;
	for (unsigned int i = 0; i < hgc->mysrvs->cnt(); ++i) {
		PgSQL_SrvC* server = hgc->mysrvs->idx(i);
		if (std::strcmp(server->address, addr) == 0) return server;
	}
	return nullptr;
}

unsigned int mysql_used(MySrvC* server) {
	MyHGM->wrlock();
	const unsigned int used = server->ConnectionsUsed->conns_length();
	MyHGM->wrunlock();
	return used;
}

unsigned int pgsql_used(PgSQL_SrvC* server) {
	PgHGM->wrlock();
	const unsigned int used = server->ConnectionsUsed->conns_length();
	PgHGM->wrunlock();
	return used;
}

int mysql_error_rows(uint32_t hg, const char* host, uint16_t port, int err_no) {
	std::unique_ptr<SQLite3_result> rows(MyHGM->get_mysql_errors(false));
	int matches = 0;
	for (const auto* row : rows->rows) {
		if (std::atoi(row->fields[0]) == static_cast<int>(hg) &&
			std::strcmp(row->fields[1], host) == 0 &&
			std::atoi(row->fields[2]) == port &&
			std::atoi(row->fields[6]) == err_no &&
			std::atoi(row->fields[7]) == 1) {
			++matches;
		}
	}
	return matches;
}

int pgsql_error_rows(uint32_t hg, const char* host, uint16_t port, const char* sqlstate) {
	std::unique_ptr<SQLite3_result> rows(PgHGM->get_pgsql_errors(false));
	int matches = 0;
	for (const auto* row : rows->rows) {
		if (std::atoi(row->fields[0]) == static_cast<int>(hg) &&
			std::strcmp(row->fields[1], host) == 0 &&
			std::atoi(row->fields[2]) == port &&
			std::strcmp(row->fields[6], sqlstate) == 0 &&
			std::atoi(row->fields[7]) == 1) {
			++matches;
		}
	}
	return matches;
}

const ProxySQL_RawBackendServiceV2* service() {
	return proxysql_raw_backend_service();
}

bool valid_service(const ProxySQL_RawBackendServiceV2* svc) {
	return svc != nullptr && svc->version == 2 && svc->acquire != nullptr &&
		svc->connect_result != nullptr && svc->account_io != nullptr &&
		svc->offline_hard != nullptr && svc->destroy != nullptr;
}

void set_mysql_header_defaults(int latency_ms) {
	pthread_mutex_lock(&GloVars.global.ext_glomth_mutex);
	if (GloMTH != nullptr) {
		GloMTH->wrlock();
		GloMTH->variables.default_max_latency_ms = latency_ms;
		GloMTH->wrunlock();
	}
	pthread_mutex_unlock(&GloVars.global.ext_glomth_mutex);
}

void set_pgsql_header_defaults(int latency_ms) {
	pthread_mutex_lock(&GloVars.global.ext_glopth_mutex);
	if (GloPTH != nullptr) {
		GloPTH->wrlock();
		GloPTH->variables.default_max_latency_ms = latency_ms;
		GloPTH->wrunlock();
	}
	pthread_mutex_unlock(&GloVars.global.ext_glopth_mutex);
}

void set_mysql_latency_awareness_min(int minimum) {
	pthread_mutex_lock(&GloVars.global.ext_glomth_mutex);
	if (GloMTH != nullptr) {
		GloMTH->wrlock();
		GloMTH->variables.min_num_servers_lantency_awareness = minimum;
		GloMTH->wrunlock();
	}
	pthread_mutex_unlock(&GloVars.global.ext_glomth_mutex);
}

void set_pgsql_latency_awareness_min(int minimum) {
	pthread_mutex_lock(&GloVars.global.ext_glopth_mutex);
	if (GloPTH != nullptr) {
		GloPTH->wrlock();
		GloPTH->variables.min_num_servers_lantency_awareness = minimum;
		GloPTH->wrunlock();
	}
	pthread_mutex_unlock(&GloVars.global.ext_glopth_mutex);
}

int get_mysql_latency_awareness_min() {
	int minimum = 0;
	pthread_mutex_lock(&GloVars.global.ext_glomth_mutex);
	if (GloMTH != nullptr) {
		GloMTH->wrlock();
		minimum = GloMTH->variables.min_num_servers_lantency_awareness;
		GloMTH->wrunlock();
	}
	pthread_mutex_unlock(&GloVars.global.ext_glomth_mutex);
	return minimum;
}

int get_pgsql_latency_awareness_min() {
	int minimum = 0;
	pthread_mutex_lock(&GloVars.global.ext_glopth_mutex);
	if (GloPTH != nullptr) {
		GloPTH->wrlock();
		minimum = GloPTH->variables.min_num_servers_lantency_awareness;
		GloPTH->wrunlock();
	}
	pthread_mutex_unlock(&GloVars.global.ext_glopth_mutex);
	return minimum;
}

void test_mysql_real_hgm() {
	const uint32_t hg = 9601;
	const char* host = "127.0.0.1";
	const uint16_t port = 33061;
	ok(add_mysql_server(hg, host, port, 1, 1) == 0, "MySQL raw fixture server is created");
	MySrvC* server = find_mysql_server(hg, host);
	ok(server != nullptr, "MySQL raw fixture server is addressable");
	if (server == nullptr) return;

	const auto* svc = service();
	ok(valid_service(svc), "ABI-18 raw backend service exposes the frozen V2 callback table");

	ProxySQL_RawBackendEndpoint endpoint;
	std::string error = "stale";
	const unsigned long get_before = MyHGM->status.myconnpoll_get;
	const unsigned long get_ok_before = MyHGM->status.myconnpoll_get_ok;
	const unsigned long created_before = MyHGM->status.server_connections_created;
	const unsigned int connect_ok_before = server->connect_OK;
	const unsigned long long queries_before = server->queries_sent;

	ProxySQL_RawBackend* first = svc->acquire(ProxySQL_RawBackendProtocol::mysql, hg, endpoint, error);
	ok(first != nullptr && error.empty() && endpoint.address == host && endpoint.port == port,
		"MySQL acquire returns the selected numeric endpoint");
	ok(first != nullptr && mysql_used(server) == 1 &&
		server->ConnectionsFree->conns_length() == 0,
		"MySQL acquire registers exactly one object in actual ConnectionsUsed, never Free");
	ok(first != nullptr && MyHGM->status.myconnpoll_get == get_before + 1 &&
		MyHGM->status.myconnpoll_get_ok == get_ok_before + 1 &&
		MyHGM->status.server_connections_created == created_before + 1,
		"MySQL acquire preserves normal pool_get/get_ok/created counters");
	ok(first != nullptr && server->max_connections_used == 1,
		"MySQL acquire updates the normal max_connections_used watermark");

	MySQL_Connection* first_object = nullptr;
	MyHGM->wrlock();
	if (server->ConnectionsUsed->conns_length() == 1) {
		first_object = server->ConnectionsUsed->index(0);
	}
	MyHGM->wrunlock();
	ok(first_object != nullptr && first_object->parent == server &&
		first_object->send_quit == false && first_object->reusable == false &&
		first_object->fd == -1 && first_object->mysql == nullptr,
		"MySQL raw object is a fresh in-use protocol wrapper with no socket/protocol state");

	ok(first != nullptr && svc->acquire(ProxySQL_RawBackendProtocol::mysql, hg, endpoint, error) == nullptr &&
		error.find("no eligible") != std::string::npos && mysql_used(server) == 1,
		"MySQL raw handles share the actual max_connections capacity with normal selection");

	const unsigned long connected_before = MyHGM->status.server_connections_connected;
	if (first != nullptr) {
		svc->connect_result(first, 0);
		svc->connect_result(first, 0);
	}
	ok(first != nullptr && server->connect_OK == connect_ok_before + 1 &&
		MyHGM->status.server_connections_connected == connected_before + 1,
		"MySQL connect outcome success is counted exactly once");

	if (first != nullptr) {
		svc->account_io(first, 11, 7);
		svc->account_io(first, 5, 3);
	}
	MyHGM->wrlock();
	const unsigned long long parent_sent = server->bytes_sent;
	const unsigned long long parent_recv = server->bytes_recv;
	const unsigned long long object_sent = first_object != nullptr ? first_object->bytes_info.bytes_sent : 0;
	const unsigned long long object_recv = first_object != nullptr ? first_object->bytes_info.bytes_recv : 0;
	const unsigned long long queries_after = server->queries_sent;
	const unsigned long long object_questions = first_object != nullptr ? first_object->statuses.questions : 1;
	MyHGM->wrunlock();
	ok(parent_sent == 16 && parent_recv == 10 && object_sent == 16 && object_recv == 10,
		"MySQL account_io records exact wire directions on both server and object");
	ok(queries_after == queries_before && object_questions == 0,
		"MySQL raw bytes do not fabricate SQL query/authentication counters");

	const unsigned long destroy_before = MyHGM->status.myconnpoll_destroy;
	const bool mysql_first_final_hard = first != nullptr ? svc->destroy(first) : true;
	ok(mysql_used(server) == 0 && MyHGM->status.myconnpoll_destroy == destroy_before + 1 &&
		MyHGM->status.server_connections_connected == connected_before &&
		!mysql_first_final_hard,
		"MySQL destroy removes Used once, balances connected and reports fresh final HARD false");

	error = "stale";
	ProxySQL_RawBackend* second = svc->acquire(ProxySQL_RawBackendProtocol::mysql, hg, endpoint, error);
	ok(second != nullptr && mysql_used(server) == 1 && error.empty(),
		"MySQL acquire after destroy gets a fresh in-use object within shared capacity");
	MySQL_Connection* second_object = nullptr;
	MyHGM->wrlock();
	if (server->ConnectionsUsed->conns_length() == 1) {
		second_object = server->ConnectionsUsed->index(0);
	}
	MyHGM->wrunlock();
	ok(second_object != nullptr &&
		second_object->bytes_info.bytes_sent == 0 && second_object->bytes_info.bytes_recv == 0 &&
		second_object->send_quit == false && second_object->reusable == false &&
		second_object->fd == -1 && second_object->mysql == nullptr,
		"MySQL fresh acquisition resets the in-use object's accounting/protocol state");
	const bool mysql_second_final_hard = second != nullptr ? svc->destroy(second) : true;
	ok(mysql_used(server) == 0 && !mysql_second_final_hard,
		"MySQL second fresh destroy leaves Used empty and reports final HARD false");
}

void test_pgsql_real_hgm() {
	const uint32_t hg = 9602;
	const char* host = "127.0.0.1";
	const uint16_t port = 15432;
	ok(add_pgsql_server(hg, host, port, 1, 1) == 0, "PgSQL raw fixture server is created");
	PgSQL_SrvC* server = find_pgsql_server(hg, host);
	ok(server != nullptr, "PgSQL raw fixture server is addressable");
	if (server == nullptr) return;

	const auto* svc = service();
	ProxySQL_RawBackendEndpoint endpoint;
	std::string error = "stale";
	const unsigned long get_before = PgHGM->status.pgconnpoll_get;
	const unsigned long get_ok_before = PgHGM->status.pgconnpoll_get_ok;
	const unsigned long created_before = PgHGM->status.server_connections_created;
	const unsigned int connect_ok_before = server->connect_OK;
	const unsigned long long queries_before = server->queries_sent;

	ProxySQL_RawBackend* first = svc->acquire(ProxySQL_RawBackendProtocol::pgsql, hg, endpoint, error);
	ok(first != nullptr && error.empty() && endpoint.address == host && endpoint.port == port,
		"PgSQL acquire returns the selected numeric endpoint");
	ok(first != nullptr && pgsql_used(server) == 1 &&
		server->ConnectionsFree->conns_length() == 0,
		"PgSQL acquire registers exactly one object in actual ConnectionsUsed, never Free");
	ok(first != nullptr && PgHGM->status.pgconnpoll_get == get_before + 1 &&
		PgHGM->status.pgconnpoll_get_ok == get_ok_before + 1 &&
		PgHGM->status.server_connections_created == created_before + 1,
		"PgSQL acquire preserves normal pool_get/get_ok/created counters");

	PgSQL_Connection* first_object = nullptr;
	PgHGM->wrlock();
	if (server->ConnectionsUsed->conns_length() == 1) {
		first_object = server->ConnectionsUsed->index(0);
	}
	PgHGM->wrunlock();
	ok(first_object != nullptr && first_object->parent == server &&
		first_object->send_quit == false && first_object->reusable == false &&
		first_object->fd == -1 && first_object->pgsql_conn == nullptr,
		"PgSQL raw object is a fresh in-use protocol wrapper with no socket/protocol state");

	ok(first != nullptr && svc->acquire(ProxySQL_RawBackendProtocol::pgsql, hg, endpoint, error) == nullptr &&
		error.find("no eligible") != std::string::npos && pgsql_used(server) == 1,
		"PgSQL raw handles share the actual max_connections capacity with normal selection");

	const unsigned long connected_before = PgHGM->status.server_connections_connected;
	if (first != nullptr) {
		svc->connect_result(first, 0);
		svc->connect_result(first, 0);
	}
	ok(first != nullptr && server->connect_OK == connect_ok_before + 1 &&
		PgHGM->status.server_connections_connected == connected_before + 1,
		"PgSQL connect outcome success is counted exactly once");

	if (first != nullptr) {
		svc->account_io(first, 13, 17);
	}
	PgHGM->wrlock();
	const unsigned long long parent_sent = server->bytes_sent;
	const unsigned long long parent_recv = server->bytes_recv;
	const unsigned long long object_sent = first_object != nullptr ? first_object->bytes_info.bytes_sent : 0;
	const unsigned long long object_recv = first_object != nullptr ? first_object->bytes_info.bytes_recv : 0;
	PgHGM->wrunlock();
	ok(parent_sent == 13 && parent_recv == 17 && object_sent == 13 && object_recv == 17,
		"PgSQL account_io records exact wire directions on both server and object");

	const unsigned long destroy_before = PgHGM->status.pgconnpoll_destroy;
	const bool pgsql_first_final_hard = first != nullptr ? svc->destroy(first) : true;
	ok(pgsql_used(server) == 0 && PgHGM->status.pgconnpoll_destroy == destroy_before + 1 &&
		PgHGM->status.server_connections_connected == connected_before &&
		!pgsql_first_final_hard,
		"PgSQL destroy removes Used once, balances connected and reports fresh final HARD false");
}

void test_failures_do_not_fabricate() {
	const auto* svc = service();
	ProxySQL_RawBackendEndpoint endpoint;
	std::string error = "stale";
	ok(svc->acquire(ProxySQL_RawBackendProtocol::mysql, 9699, endpoint, error) == nullptr &&
		error.find("hostgroup") != std::string::npos,
		"missing MySQL hostgroup fails with a clear diagnostic");

	const uint32_t hg = 9603;
	const char* host = "raw-cache-miss.invalid";
	ok(add_mysql_server(hg, host, 33063, 1, 10) == 0, "MySQL DNS-miss fixture server is created");
	MySrvC* server = find_mysql_server(hg, host);
	if (server == nullptr) {
		ok(false, "MySQL DNS-miss fixture server is addressable");
		return;
	}
	const unsigned int connect_err_before = server->connect_ERR;
	const int errors_before = mysql_error_rows(hg, host, 33063, 2003);
	error = "stale";
	ProxySQL_RawBackend* failed = svc->acquire(ProxySQL_RawBackendProtocol::mysql, hg, endpoint, error);
	ok(failed == nullptr && error.find("DNS") != std::string::npos &&
		mysql_used(server) == 0,
		"MySQL DNS cache miss releases the reserved object and explains the failure");
	ok(server->connect_ERR == connect_err_before &&
		mysql_error_rows(hg, host, 33063, 2003) == errors_before,
		"MySQL pre-connect DNS failure fabricates no connect error or errors-map row");

	const uint32_t pg_hg = 9604;
	const char* pg_host = "raw-cache-miss.invalid";
	ok(add_pgsql_server(pg_hg, pg_host, 15433, 1, 10) == 0, "PgSQL DNS-miss fixture server is created");
	PgSQL_SrvC* pg_server = find_pgsql_server(pg_hg, pg_host);
	if (pg_server == nullptr) {
		ok(false, "PgSQL DNS-miss fixture server is addressable");
		return;
	}
	const unsigned int pg_connect_err_before = pg_server->connect_ERR;
	const int pg_errors_before = pgsql_error_rows(pg_hg, pg_host, 15433, "08001");
	error = "stale";
	ProxySQL_RawBackend* pg_failed = svc->acquire(ProxySQL_RawBackendProtocol::pgsql, pg_hg, endpoint, error);
	ok(pg_failed == nullptr && error.find("DNS") != std::string::npos &&
		pgsql_used(pg_server) == 0,
		"PgSQL DNS cache miss releases the reserved object and explains the failure");
	ok(pg_server->connect_ERR == pg_connect_err_before &&
		pgsql_error_rows(pg_hg, pg_host, 15433, "08001") == pg_errors_before,
		"PgSQL pre-connect DNS failure fabricates no connect error or errors-map row");
}

void test_connect_error_once_and_map() {
	const auto* svc = service();
	ProxySQL_RawBackendEndpoint endpoint;
	std::string error;

	const uint32_t hg = 9605;
	const char* host = "127.0.0.1";
	const uint16_t port = 33065;
	ok(add_mysql_server(hg, host, port, 1, 10) == 0, "MySQL connect-error fixture server is created");
	MySrvC* server = find_mysql_server(hg, host);
	if (server == nullptr) {
		ok(false, "MySQL connect-error fixture server is addressable");
		return;
	}
	ProxySQL_RawBackend* handle = svc->acquire(ProxySQL_RawBackendProtocol::mysql, hg, endpoint, error);
	const unsigned int err_before = server->connect_ERR;
	const unsigned long aborted_before = MyHGM->status.server_connections_aborted;
	const int map_before = mysql_error_rows(hg, host, port, 2003);
	if (handle != nullptr) {
		svc->connect_result(handle, ECONNREFUSED);
		svc->connect_result(handle, ECONNREFUSED);
	}
	ok(handle != nullptr && server->connect_ERR == err_before + 1 &&
		MyHGM->status.server_connections_aborted == aborted_before + 1,
		"MySQL connect failure increments normal error/aborted machinery exactly once");
	ok(mysql_error_rows(hg, host, port, 2003) == map_before + 1,
		"MySQL connect failure records one code-2003 errors-map row");
	if (handle != nullptr) svc->destroy(handle);
	ok(mysql_used(server) == 0, "MySQL failed handle destroy removes the in-use object");

	const uint32_t pg_hg = 9606;
	const char* pg_host = "127.0.0.1";
	const uint16_t pg_port = 15435;
	ok(add_pgsql_server(pg_hg, pg_host, pg_port, 1, 10) == 0, "PgSQL connect-error fixture server is created");
	PgSQL_SrvC* pg_server = find_pgsql_server(pg_hg, pg_host);
	if (pg_server == nullptr) {
		ok(false, "PgSQL connect-error fixture server is addressable");
		return;
	}
	ProxySQL_RawBackend* pg_handle = svc->acquire(ProxySQL_RawBackendProtocol::pgsql, pg_hg, endpoint, error);
	const unsigned int pg_err_before = pg_server->connect_ERR;
	const unsigned long pg_aborted_before = PgHGM->status.server_connections_aborted;
	const int pg_map_before = pgsql_error_rows(pg_hg, pg_host, pg_port, "08001");
	if (pg_handle != nullptr) {
		svc->connect_result(pg_handle, ECONNREFUSED);
		svc->connect_result(pg_handle, ECONNREFUSED);
	}
	ok(pg_handle != nullptr && pg_server->connect_ERR == pg_err_before + 1 &&
		PgHGM->status.server_connections_aborted == pg_aborted_before + 1,
		"PgSQL connect failure increments normal error/aborted machinery exactly once");
	ok(pgsql_error_rows(pg_hg, pg_host, pg_port, "08001") == pg_map_before + 1,
		"PgSQL connect failure records one SQLSTATE-08001 errors-map row");
	if (pg_handle != nullptr) svc->destroy(pg_handle);
	ok(pgsql_used(pg_server) == 0, "PgSQL failed handle destroy removes the in-use object");
}

void test_status_and_hard_latch() {
	const auto* svc = service();
	ProxySQL_RawBackendEndpoint endpoint;
	std::string error;

	const uint32_t hg = 9607;
	const char* host = "127.0.0.1";
	const uint16_t port = 33067;
	ok(add_mysql_server(hg, host, port, 1, 10) == 0, "MySQL status fixture server is created");
	MySrvC* server = find_mysql_server(hg, host);
	if (server == nullptr) {
		ok(false, "MySQL status fixture server is addressable");
		return;
	}
	ProxySQL_RawBackend* old_handle = svc->acquire(ProxySQL_RawBackendProtocol::mysql, hg, endpoint, error);
	MyHGM->wrlock();
	server->set_status(MYSQL_SERVER_STATUS_OFFLINE_HARD);
	server->set_status(MYSQL_SERVER_STATUS_ONLINE);
	MyHGM->wrunlock();
	ok(old_handle != nullptr && svc->offline_hard(old_handle),
		"MySQL HARD transition stays latched on the old handle after HARD->ONLINE");
	ProxySQL_RawBackend* new_handle = svc->acquire(ProxySQL_RawBackendProtocol::mysql, hg, endpoint, error);
	ok(new_handle != nullptr && !svc->offline_hard(new_handle),
		"MySQL newly acquired handle after HARD->ONLINE is not latched");
	MyHGM->wrlock();
	server->set_status(MYSQL_SERVER_STATUS_SHUNNED);
	MyHGM->wrunlock();
	ok(new_handle != nullptr && !svc->offline_hard(new_handle),
		"MySQL SHUNNED established stream is not closed by offline_hard");
	MyHGM->wrlock();
	server->set_status(MYSQL_SERVER_STATUS_OFFLINE_SOFT);
	MyHGM->wrunlock();
	ok(new_handle != nullptr && !svc->offline_hard(new_handle),
		"MySQL OFFLINE_SOFT established stream is not closed by offline_hard");
	MyHGM->wrlock();
	server->set_status(MYSQL_SERVER_STATUS_OFFLINE_HARD);
	MyHGM->wrunlock();
	ok(new_handle != nullptr && svc->offline_hard(new_handle),
		"MySQL current OFFLINE_HARD is reported without relying on a prior latch");
	if (old_handle != nullptr) svc->destroy(old_handle);
	if (new_handle != nullptr) svc->destroy(new_handle);

	MyHGM->wrlock();
	server->set_status(MYSQL_SERVER_STATUS_ONLINE);
	MyHGM->wrunlock();
	ProxySQL_RawBackend* pinned = svc->acquire(ProxySQL_RawBackendProtocol::mysql, hg, endpoint, error);
	ok(pinned != nullptr && mysql_used(server) == 1,
		"MySQL removal fixture has one pinned in-use raw handle");
	MyHGM->wrlock();
	const int removed = MyHGM->remove_server_in_hg(hg, std::string(host), port);
	MyHGM->wrunlock();
	ok(removed == 0 && pinned != nullptr && mysql_used(server) == 1 &&
		svc->offline_hard(pinned) && std::strcmp(server->address, host) == 0,
		"MySQL removal pins the original server object and latches HARD for its established handle");
	ok(svc->acquire(ProxySQL_RawBackendProtocol::mysql, hg, endpoint, error) == nullptr,
		"MySQL removed hostgroup cannot select a replacement identity for the old stream");
	if (pinned != nullptr) svc->destroy(pinned);

	const uint32_t pg_hg = 9608;
	const char* pg_host = "127.0.0.1";
	const uint16_t pg_port = 15437;
	ok(add_pgsql_server(pg_hg, pg_host, pg_port, 1, 10) == 0, "PgSQL status fixture server is created");
	PgSQL_SrvC* pg_server = find_pgsql_server(pg_hg, pg_host);
	if (pg_server == nullptr) {
		ok(false, "PgSQL status fixture server is addressable");
		return;
	}
	ProxySQL_RawBackend* pg_old = svc->acquire(ProxySQL_RawBackendProtocol::pgsql, pg_hg, endpoint, error);
	PgHGM->wrlock();
	const int pg_removed = PgHGM->remove_server_in_hg(pg_hg, std::string(pg_host), pg_port);
	pg_server->status = MYSQL_SERVER_STATUS_ONLINE;
	PgHGM->wrunlock();
	ok(pg_removed == 0 && pg_old != nullptr && svc->offline_hard(pg_old),
		"PgSQL HARD transition stays latched on the old handle after HARD->ONLINE");
	ProxySQL_RawBackend* pg_new = svc->acquire(ProxySQL_RawBackendProtocol::pgsql, pg_hg, endpoint, error);
	ok(pg_new != nullptr && !svc->offline_hard(pg_new),
		"PgSQL newly acquired handle after HARD->ONLINE is not latched");
	PgHGM->wrlock();
	pg_server->status = MYSQL_SERVER_STATUS_SHUNNED;
	PgHGM->wrunlock();
	ok(pg_new != nullptr && !svc->offline_hard(pg_new),
		"PgSQL SHUNNED established stream is not closed by offline_hard");
	PgHGM->wrlock();
	pg_server->status = MYSQL_SERVER_STATUS_OFFLINE_SOFT;
	PgHGM->wrunlock();
	ok(pg_new != nullptr && !svc->offline_hard(pg_new),
		"PgSQL OFFLINE_SOFT established stream is not closed by offline_hard");
	PgHGM->wrlock();
	const int pg_hard_again = PgHGM->remove_server_in_hg(pg_hg, std::string(pg_host), pg_port);
	PgHGM->wrunlock();
	ok(pg_new != nullptr && pg_hard_again == 0 && svc->offline_hard(pg_new),
		"PgSQL actual HARD transition latches the established handle by atomic fact alone");
	if (pg_old != nullptr) svc->destroy(pg_old);
	if (pg_new != nullptr) svc->destroy(pg_new);
}

void test_worker_thread_policy_refresh_and_restore() {
	const auto* svc = service();
	const uint32_t hg = 9609;
	const char* host = "127.0.0.1";
	const uint16_t port = 33069;
	ok(add_mysql_server(hg, host, port, 1, 10) == 0, "MySQL latency fixture server is created");
	MySrvC* server = find_mysql_server(hg, host);
	if (server == nullptr) {
		ok(false, "MySQL latency fixture server is addressable");
		return;
	}
	MyHGM->wrlock();
	server->current_latency_us = 500000;
	MyHGM->wrunlock();
	set_mysql_header_defaults(1000);

	const int saved_default = mysql_thread___default_max_latency_ms;
	const int saved_shun_recovery = mysql_thread___shun_recovery_time_sec;
	const int saved_timeout_max = mysql_thread___connect_timeout_server_max;
	const int saved_unshun = mysql_thread___unshun_algorithm;
	const int saved_retries = mysql_thread___connect_retries_on_failure;
	const int saved_shun = mysql_thread___shun_on_failures;
	const int saved_throttle = mysql_thread___throttle_connections_per_sec_to_hostgroup;
	const bool saved_aws = mysql_thread___aws_locality_awareness;
	const int saved_session_track = mysql_thread___session_track_variables;

	bool acquired = false;
	bool restored = false;
	std::string worker_error;
	std::thread worker([&] {
		mysql_thread___default_max_latency_ms = 7;
		mysql_thread___shun_recovery_time_sec = 17;
		mysql_thread___connect_timeout_server_max = 27;
		mysql_thread___unshun_algorithm = 37;
		mysql_thread___connect_retries_on_failure = 47;
		mysql_thread___shun_on_failures = 57;
		mysql_thread___throttle_connections_per_sec_to_hostgroup = 67;
		mysql_thread___aws_locality_awareness = false;
		mysql_thread___session_track_variables = session_track_variables::ENFORCED;

		ProxySQL_RawBackendEndpoint endpoint;
		ProxySQL_RawBackend* handle = svc->acquire(ProxySQL_RawBackendProtocol::mysql, hg,
			endpoint, worker_error);
		acquired = handle != nullptr;
		if (handle != nullptr) svc->destroy(handle);
		restored = mysql_thread___default_max_latency_ms == 7 &&
			mysql_thread___shun_recovery_time_sec == 17 &&
			mysql_thread___connect_timeout_server_max == 27 &&
			mysql_thread___unshun_algorithm == 37 &&
			mysql_thread___connect_retries_on_failure == 47 &&
			mysql_thread___shun_on_failures == 57 &&
			mysql_thread___throttle_connections_per_sec_to_hostgroup == 67 &&
			mysql_thread___aws_locality_awareness == false &&
			mysql_thread___session_track_variables == session_track_variables::ENFORCED &&
			proxysql_raw_backend_latency_awareness_min_servers() == 0;
	});
	worker.join();
	ok(acquired, "MySQL raw acquire on a custom worker refreshes live latency policy and tolerates null session in ENFORCED mode");
	ok(restored, "MySQL raw acquire restores every exact native thread policy field on the worker");

	MyHGM->wrlock();
	server->current_latency_us = 2000000;
	MyHGM->wrunlock();
	ProxySQL_RawBackendEndpoint endpoint;
	std::string error = "stale";
	ProxySQL_RawBackend* too_slow = svc->acquire(ProxySQL_RawBackendProtocol::mysql, hg, endpoint, error);
	ok(too_slow == nullptr && error.find("no eligible") != std::string::npos,
		"MySQL live default_max_latency_ms excludes an over-latency server instead of leaving all servers ineligible");
	if (too_slow != nullptr) svc->destroy(too_slow);

	mysql_thread___default_max_latency_ms = saved_default;
	mysql_thread___shun_recovery_time_sec = saved_shun_recovery;
	mysql_thread___connect_timeout_server_max = saved_timeout_max;
	mysql_thread___unshun_algorithm = saved_unshun;
	mysql_thread___connect_retries_on_failure = saved_retries;
	mysql_thread___shun_on_failures = saved_shun;
	mysql_thread___throttle_connections_per_sec_to_hostgroup = saved_throttle;
	mysql_thread___aws_locality_awareness = saved_aws;
	mysql_thread___session_track_variables = saved_session_track;
}

void test_pgsql_worker_thread_policy_refresh_and_restore() {
	const auto* svc = service();
	const uint32_t hg = 9625;
	const char* host = "127.0.0.1";
	const uint16_t port = 15445;
	ok(add_pgsql_server(hg, host, port, 1, 10) == 0, "PgSQL latency fixture server is created");
	PgSQL_SrvC* server = find_pgsql_server(hg, host);
	if (server == nullptr) {
		ok(false, "PgSQL latency fixture server is addressable");
		return;
	}
	PgHGM->wrlock();
	server->current_latency_us = 500000;
	PgHGM->wrunlock();
	set_pgsql_header_defaults(1000);

	const int saved_default = pgsql_thread___default_max_latency_ms;
	const int saved_shun_recovery = pgsql_thread___shun_recovery_time_sec;
	const int saved_timeout_max = pgsql_thread___connect_timeout_server_max;
	const int saved_unshun = pgsql_thread___unshun_algorithm;
	const int saved_retries = pgsql_thread___connect_retries_on_failure;
	const int saved_shun = pgsql_thread___shun_on_failures;
	const int saved_throttle = pgsql_thread___throttle_connections_per_sec_to_hostgroup;

	bool acquired = false;
	bool restored = false;
	std::string worker_error;
	std::thread worker([&] {
		pgsql_thread___default_max_latency_ms = 7;
		pgsql_thread___shun_recovery_time_sec = 17;
		pgsql_thread___connect_timeout_server_max = 27;
		pgsql_thread___unshun_algorithm = 37;
		pgsql_thread___connect_retries_on_failure = 47;
		pgsql_thread___shun_on_failures = 57;
		pgsql_thread___throttle_connections_per_sec_to_hostgroup = 67;

		ProxySQL_RawBackendEndpoint endpoint;
		ProxySQL_RawBackend* handle = svc->acquire(ProxySQL_RawBackendProtocol::pgsql, hg,
			endpoint, worker_error);
		acquired = handle != nullptr;
		if (handle != nullptr) svc->destroy(handle);
		restored = pgsql_thread___default_max_latency_ms == 7 &&
			pgsql_thread___shun_recovery_time_sec == 17 &&
			pgsql_thread___connect_timeout_server_max == 27 &&
			pgsql_thread___unshun_algorithm == 37 &&
			pgsql_thread___connect_retries_on_failure == 47 &&
			pgsql_thread___shun_on_failures == 57 &&
			pgsql_thread___throttle_connections_per_sec_to_hostgroup == 67 &&
			proxysql_raw_backend_latency_awareness_min_servers() == 0;
	});
	worker.join();
	ok(acquired, "PgSQL raw acquire on a custom worker refreshes live latency policy");
	ok(restored, "PgSQL raw acquire restores every exact native thread policy field on the worker");

	PgHGM->wrlock();
	server->current_latency_us = 2000000;
	PgHGM->wrunlock();
	ProxySQL_RawBackendEndpoint endpoint;
	std::string error = "stale";
	ProxySQL_RawBackend* too_slow = svc->acquire(ProxySQL_RawBackendProtocol::pgsql, hg, endpoint, error);
	ok(too_slow == nullptr && error.find("no eligible") != std::string::npos,
		"PgSQL live default_max_latency_ms excludes an over-latency server");
	if (too_slow != nullptr) svc->destroy(too_slow);

	pgsql_thread___default_max_latency_ms = saved_default;
	pgsql_thread___shun_recovery_time_sec = saved_shun_recovery;
	pgsql_thread___connect_timeout_server_max = saved_timeout_max;
	pgsql_thread___unshun_algorithm = saved_unshun;
	pgsql_thread___connect_retries_on_failure = saved_retries;
	pgsql_thread___shun_on_failures = saved_shun;
	pgsql_thread___throttle_connections_per_sec_to_hostgroup = saved_throttle;
}

void test_creation_throttle_override() {
	const auto* svc = service();
	ProxySQL_RawBackendEndpoint endpoint;
	std::string error;

	const uint32_t mysql_hg = 9621;
	const char* mysql_host = "127.0.0.1";
	const uint16_t mysql_port = 33071;
	ok(add_mysql_server(mysql_hg, mysql_host, mysql_port, 1, 10) == 0,
		"MySQL throttle fixture server is created");
	MySrvC* mysql_server = find_mysql_server(mysql_hg, mysql_host);
	MyHGC* mysql_hgc = MyHGM->MyHGC_find(mysql_hg);
	if (mysql_server == nullptr || mysql_hgc == nullptr) {
		ok(false, "MySQL throttle fixture server is addressable");
		return;
	}
	MyHGM->wrlock();
	mysql_hgc->attributes.configured = true;
	mysql_hgc->attributes.throttle_connections_per_sec = 0;
	mysql_hgc->current_time_now = 0;
	mysql_hgc->new_connections_now = 0;
	MyHGM->wrunlock();
	const unsigned long delayed_before = MyHGM->status.server_connections_delayed;
	const unsigned int err_before = mysql_server->connect_ERR;
	const int map_before = mysql_error_rows(mysql_hg, mysql_host, mysql_port, 2003);
	error = "stale";
	ProxySQL_RawBackend* throttled = svc->acquire(ProxySQL_RawBackendProtocol::mysql,
		mysql_hg, endpoint, error);
	ok(throttled == nullptr && error.find("throttled") != std::string::npos &&
		MyHGM->status.server_connections_delayed == delayed_before + 1 &&
		mysql_used(mysql_server) == 0 && mysql_server->connect_ERR == err_before &&
		mysql_error_rows(mysql_hg, mysql_host, mysql_port, 2003) == map_before,
		"MySQL hostgroup throttle override rejects admission, increments delayed and fabricates no connect error");
	if (throttled != nullptr) svc->destroy(throttled);
	MyHGM->wrlock();
	mysql_hgc->attributes.configured = false;
	MyHGM->wrunlock();

	const uint32_t pg_hg = 9622;
	const char* pg_host = "127.0.0.1";
	const uint16_t pg_port = 15446;
	ok(add_pgsql_server(pg_hg, pg_host, pg_port, 1, 10) == 0,
		"PgSQL throttle fixture server is created");
	PgSQL_SrvC* pg_server = find_pgsql_server(pg_hg, pg_host);
	PgSQL_HGC* pg_hgc = PgHGM->MyHGC_find(pg_hg);
	if (pg_server == nullptr || pg_hgc == nullptr) {
		ok(false, "PgSQL throttle fixture server is addressable");
		return;
	}
	PgHGM->wrlock();
	pg_hgc->attributes.configured = true;
	pg_hgc->attributes.throttle_connections_per_sec = 0;
	pg_hgc->current_time_now = 0;
	pg_hgc->new_connections_now = 0;
	PgHGM->wrunlock();
	const unsigned long pg_delayed_before = PgHGM->status.server_connections_delayed;
	const unsigned int pg_err_before = pg_server->connect_ERR;
	const int pg_map_before = pgsql_error_rows(pg_hg, pg_host, pg_port, "08001");
	error = "stale";
	ProxySQL_RawBackend* pg_throttled = svc->acquire(ProxySQL_RawBackendProtocol::pgsql,
		pg_hg, endpoint, error);
	ok(pg_throttled == nullptr && error.find("throttled") != std::string::npos &&
		PgHGM->status.server_connections_delayed == pg_delayed_before + 1 &&
		pgsql_used(pg_server) == 0 && pg_server->connect_ERR == pg_err_before &&
		pgsql_error_rows(pg_hg, pg_host, pg_port, "08001") == pg_map_before,
		"PgSQL hostgroup throttle override rejects admission, increments delayed and fabricates no connect error");
	if (pg_throttled != nullptr) svc->destroy(pg_throttled);
	PgHGM->wrlock();
	pg_hgc->attributes.configured = false;
	PgHGM->wrunlock();
}

void test_dns_cache_hits() {
	const auto* svc = service();
	ProxySQL_RawBackendEndpoint endpoint;
	std::string error;

	if (GloMyMon == nullptr) {
		GloMyMon = new MySQL_Monitor();
	}
	if (GloPgMon == nullptr) {
		GloPgMon = new PgSQL_Monitor();
	}
	const char* mysql_host = "raw-cache-hit.invalid";
	const char* pg_host = "raw-cache-hit.invalid";
	const char* mysql_ip = "127.0.0.2";
	const char* pg_ip = "127.0.0.3";
	ok(GloMyMon->dns_cache->add(mysql_host, { mysql_ip }) &&
		GloPgMon->dns_cache->add(pg_host, { pg_ip }),
		"existing monitor DNS caches accept synthetic cache-only records");

	const uint32_t mysql_hg = 9623;
	const uint16_t mysql_port = 33073;
	ok(add_mysql_server(mysql_hg, mysql_host, mysql_port, 1, 10) == 0,
		"MySQL DNS-cache fixture server is created");
	MySrvC* mysql_server = find_mysql_server(mysql_hg, mysql_host);
	ProxySQL_RawBackend* mysql_handle = svc->acquire(ProxySQL_RawBackendProtocol::mysql,
		mysql_hg, endpoint, error);
	ok(mysql_server != nullptr && mysql_handle != nullptr && error.empty() &&
		endpoint.address == mysql_ip && endpoint.port == mysql_port &&
		mysql_used(mysql_server) == 1,
		"MySQL acquire resolves a cached hostname to its numeric monitor IP");
	if (mysql_handle != nullptr) svc->destroy(mysql_handle);

	const uint32_t pg_hg = 9624;
	const uint16_t pg_port = 15447;
	ok(add_pgsql_server(pg_hg, pg_host, pg_port, 1, 10) == 0,
		"PgSQL DNS-cache fixture server is created");
	PgSQL_SrvC* pg_server = find_pgsql_server(pg_hg, pg_host);
	ProxySQL_RawBackend* pg_handle = svc->acquire(ProxySQL_RawBackendProtocol::pgsql,
		pg_hg, endpoint, error);
	ok(pg_server != nullptr && pg_handle != nullptr && error.empty() &&
		endpoint.address == pg_ip && endpoint.port == pg_port &&
		pgsql_used(pg_server) == 1,
		"PgSQL acquire resolves a cached hostname to its numeric monitor IP");
	if (pg_handle != nullptr) svc->destroy(pg_handle);
}

void test_errors_helpers_unlock_on_bad_alloc() {
	char user[] = "";
	char address[] = "unknown";
	char schema[] = "";
	char message[] = "injected allocation failure";
	char mysql_host[] = "raw-oom-node.invalid";
	char mysql_map_host[] = "raw-oom-map.invalid";
	char pg_host[] = "raw-oom-pg.invalid";

	bool mysql_node_threw = false;
	g_fail_new_countdown.store(0, std::memory_order_relaxed);
	try {
		MyHGM->add_mysql_errors(9701, mysql_host, 1, user, address, schema, 2003, message);
	} catch (const std::bad_alloc&) {
		mysql_node_threw = true;
	}
	g_fail_new_countdown.store(-1, std::memory_order_relaxed);
	ok(mysql_node_threw, "MySQL errors helper propagates a node allocation failure");
	ok(mysql_error_rows(9701, mysql_host, 1, 2003) == 0,
		"failed MySQL stats-node allocation leaves no orphan row");
	MyHGM->add_mysql_errors(9701, mysql_host, 1, user, address, schema, 2003, message);
	ok(mysql_error_rows(9701, mysql_host, 1, 2003) == 1,
		"MySQL errors helper remains usable after unlocking on allocation failure");

	bool mysql_map_threw = false;
	g_fail_new_countdown.store(1, std::memory_order_relaxed);
	try {
		MyHGM->add_mysql_errors(9702, mysql_map_host, 2, user, address, schema, 2003, message);
	} catch (const std::bad_alloc&) {
		mysql_map_threw = true;
	}
	g_fail_new_countdown.store(-1, std::memory_order_relaxed);
	ok(mysql_map_threw, "MySQL errors helper propagates a map insertion allocation failure");
	ok(mysql_error_rows(9702, mysql_map_host, 2, 2003) == 0,
		"failed MySQL map insertion leaves no orphan stats node");
	MyHGM->add_mysql_errors(9702, mysql_map_host, 2, user, address, schema, 2003, message);
	ok(mysql_error_rows(9702, mysql_map_host, 2, 2003) == 1,
		"MySQL errors map is usable after an insertion allocation failure");

	bool pg_node_threw = false;
	g_fail_new_countdown.store(0, std::memory_order_relaxed);
	try {
		PgHGM->add_pgsql_errors(9703, pg_host, 3, user, address, schema, "08001", message);
	} catch (const std::bad_alloc&) {
		pg_node_threw = true;
	}
	g_fail_new_countdown.store(-1, std::memory_order_relaxed);
	ok(pg_node_threw, "PgSQL errors helper propagates a node allocation failure");
	ok(pgsql_error_rows(9703, pg_host, 3, "08001") == 0,
		"failed PgSQL stats-node allocation leaves no orphan row");
	PgHGM->add_pgsql_errors(9703, pg_host, 3, user, address, schema, "08001", message);
	ok(pgsql_error_rows(9703, pg_host, 3, "08001") == 1,
		"PgSQL errors helper remains usable after unlocking on allocation failure");

	char pg_map_host[] = "raw-oom-pg-map.invalid";
	bool pg_map_threw = false;
	g_fail_new_countdown.store(1, std::memory_order_relaxed);
	try {
		PgHGM->add_pgsql_errors(9704, pg_map_host, 4, user, address, schema, "08001", message);
	} catch (const std::bad_alloc&) {
		pg_map_threw = true;
	}
	g_fail_new_countdown.store(-1, std::memory_order_relaxed);
	ok(pg_map_threw, "PgSQL errors helper propagates a map insertion allocation failure");
	ok(pgsql_error_rows(9704, pg_map_host, 4, "08001") == 0,
		"failed PgSQL map insertion leaves no orphan stats node");
	PgHGM->add_pgsql_errors(9704, pg_map_host, 4, user, address, schema, "08001", message);
	ok(pgsql_error_rows(9704, pg_map_host, 4, "08001") == 1,
		"PgSQL errors map is usable after an insertion allocation failure");
}

void test_final_hard_destroy_fence() {
	const auto* svc = service();
	ProxySQL_RawBackendEndpoint endpoint;
	std::string error;

	const uint32_t mysql_hg = 9626;
	const char* mysql_host = "127.0.0.1";
	const uint16_t mysql_port = 33076;
	ok(add_mysql_server(mysql_hg, mysql_host, mysql_port, 1, 10) == 0,
		"MySQL final-HARD fixture server is created");
	MySrvC* mysql_server = find_mysql_server(mysql_hg, mysql_host);
	ProxySQL_RawBackend* mysql_handle = svc->acquire(ProxySQL_RawBackendProtocol::mysql,
		mysql_hg, endpoint, error);
	ok(mysql_server != nullptr && mysql_handle != nullptr && !svc->offline_hard(mysql_handle),
		"MySQL fresh handle observes HARD false before the real transition");
	MyHGM->wrlock();
	mysql_server->set_status(MYSQL_SERVER_STATUS_OFFLINE_HARD);
	mysql_server->set_status(MYSQL_SERVER_STATUS_ONLINE);
	MyHGM->wrunlock();
	const bool mysql_final_hard = mysql_handle != nullptr ? svc->destroy(mysql_handle) : false;
	ok(mysql_final_hard && mysql_used(mysql_server) == 0,
		"MySQL destroy returns the final HARD latch after HARD->ONLINE without another status poll");
	ProxySQL_RawBackend* mysql_fresh = svc->acquire(ProxySQL_RawBackendProtocol::mysql,
		mysql_hg, endpoint, error);
	const bool mysql_fresh_hard = mysql_fresh != nullptr ? svc->destroy(mysql_fresh) : true;
	ok(!mysql_fresh_hard && mysql_used(mysql_server) == 0,
		"MySQL newly acquired then destroyed handle reports final HARD false");

	const uint32_t pg_hg = 9627;
	const char* pg_host = "127.0.0.1";
	const uint16_t pg_port = 15457;
	ok(add_pgsql_server(pg_hg, pg_host, pg_port, 1, 10) == 0,
		"PgSQL final-HARD fixture server is created");
	PgSQL_SrvC* pg_server = find_pgsql_server(pg_hg, pg_host);
	ProxySQL_RawBackend* pg_handle = svc->acquire(ProxySQL_RawBackendProtocol::pgsql,
		pg_hg, endpoint, error);
	ok(pg_server != nullptr && pg_handle != nullptr && !svc->offline_hard(pg_handle),
		"PgSQL fresh handle observes HARD false before the real transition");
	PgHGM->wrlock();
	const int pg_removed = PgHGM->remove_server_in_hg(pg_hg, std::string(pg_host), pg_port);
	pg_server->status = MYSQL_SERVER_STATUS_ONLINE;
	PgHGM->wrunlock();
	const bool pg_final_hard = pg_handle != nullptr ? svc->destroy(pg_handle) : false;
	ok(pg_removed == 0 && pg_final_hard && pgsql_used(pg_server) == 0,
		"PgSQL destroy returns the final HARD latch after HARD->ONLINE without another status poll");
	ProxySQL_RawBackend* pg_fresh = svc->acquire(ProxySQL_RawBackendProtocol::pgsql,
		pg_hg, endpoint, error);
	const bool pg_fresh_hard = pg_fresh != nullptr ? svc->destroy(pg_fresh) : true;
	ok(!pg_fresh_hard && pgsql_used(pg_server) == 0,
		"PgSQL newly acquired then destroyed handle reports final HARD false");
}

void test_comparative_latency_policy() {
	const auto* svc = service();
	ProxySQL_RawBackendEndpoint endpoint;
	const int saved_mysql_min = get_mysql_latency_awareness_min();
	const int saved_pgsql_min = get_pgsql_latency_awareness_min();

	const uint32_t mysql_hg = 9628;
	const char* mysql_fast_host = "127.0.0.1";
	const char* mysql_slow_host = "127.0.0.2";
	const uint16_t mysql_fast_port = 33078;
	const uint16_t mysql_slow_port = 33079;
	ok(add_mysql_server(mysql_hg, mysql_fast_host, mysql_fast_port, 1, 10) == 0 &&
		add_mysql_server(mysql_hg, mysql_slow_host, mysql_slow_port, 1, 10) == 0,
		"MySQL comparative-latency fixture servers are created");
	MySrvC* mysql_fast = find_mysql_server(mysql_hg, mysql_fast_host);
	MySrvC* mysql_slow = find_mysql_server(mysql_hg, mysql_slow_host);
	if (mysql_fast == nullptr || mysql_slow == nullptr) {
		ok(false, "MySQL comparative-latency fixture servers are addressable");
		return;
	}
	MyHGM->wrlock();
	mysql_fast->current_latency_us = 1000;
	mysql_slow->current_latency_us = 9000;
	MyHGM->wrunlock();
	set_mysql_header_defaults(1000);
	set_mysql_latency_awareness_min(2);

	int mysql_fast_hits = 0;
	int mysql_slow_hits = 0;
	int mysql_leaks = 0;
	for (int i = 0; i < 64; ++i) {
		std::string error;
		ProxySQL_RawBackend* handle = svc->acquire(ProxySQL_RawBackendProtocol::mysql,
			mysql_hg, endpoint, error);
		if (handle == nullptr) {
			++mysql_leaks;
			continue;
		}
		MyHGM->wrlock();
		const unsigned int fast_used = mysql_fast->ConnectionsUsed->conns_length();
		const unsigned int slow_used = mysql_slow->ConnectionsUsed->conns_length();
		MyHGM->wrunlock();
		if (fast_used == 1) ++mysql_fast_hits;
		if (slow_used == 1) ++mysql_slow_hits;
		svc->destroy(handle);
	}
	ok(mysql_leaks == 0 && mysql_fast_hits == 64 && mysql_slow_hits == 0,
		"MySQL raw selection reuses native comparative latency policy and excludes the slower backend");

	set_mysql_latency_awareness_min(0);
	int mysql_slow_control_hits = 0;
	for (int i = 0; i < 64; ++i) {
		std::string error;
		ProxySQL_RawBackend* handle = svc->acquire(ProxySQL_RawBackendProtocol::mysql,
			mysql_hg, endpoint, error);
		if (handle == nullptr) continue;
		MyHGM->wrlock();
		const unsigned int slow_used = mysql_slow->ConnectionsUsed->conns_length();
		MyHGM->wrunlock();
		if (slow_used == 1) ++mysql_slow_control_hits;
		svc->destroy(handle);
	}
	ok(mysql_slow_control_hits > 0 &&
		proxysql_raw_backend_latency_awareness_min_servers() == 0,
		"MySQL disabled comparative policy permits both backends and restores helper TLS to default");
	set_mysql_latency_awareness_min(saved_mysql_min);

	const uint32_t pg_hg = 9629;
	const char* pg_fast_host = "127.0.0.1";
	const char* pg_slow_host = "127.0.0.2";
	const uint16_t pg_fast_port = 15458;
	const uint16_t pg_slow_port = 15459;
	ok(add_pgsql_server(pg_hg, pg_fast_host, pg_fast_port, 1, 10) == 0 &&
		add_pgsql_server(pg_hg, pg_slow_host, pg_slow_port, 1, 10) == 0,
		"PgSQL comparative-latency fixture servers are created");
	PgSQL_SrvC* pg_fast = find_pgsql_server(pg_hg, pg_fast_host);
	PgSQL_SrvC* pg_slow = find_pgsql_server(pg_hg, pg_slow_host);
	if (pg_fast == nullptr || pg_slow == nullptr) {
		ok(false, "PgSQL comparative-latency fixture servers are addressable");
		return;
	}
	PgHGM->wrlock();
	pg_fast->current_latency_us = 1000;
	pg_slow->current_latency_us = 9000;
	PgHGM->wrunlock();
	set_pgsql_header_defaults(1000);
	set_pgsql_latency_awareness_min(2);

	int pg_fast_hits = 0;
	int pg_slow_hits = 0;
	int pg_leaks = 0;
	for (int i = 0; i < 64; ++i) {
		std::string error;
		ProxySQL_RawBackend* handle = svc->acquire(ProxySQL_RawBackendProtocol::pgsql,
			pg_hg, endpoint, error);
		if (handle == nullptr) {
			++pg_leaks;
			continue;
		}
		PgHGM->wrlock();
		const unsigned int fast_used = pg_fast->ConnectionsUsed->conns_length();
		const unsigned int slow_used = pg_slow->ConnectionsUsed->conns_length();
		PgHGM->wrunlock();
		if (fast_used == 1) ++pg_fast_hits;
		if (slow_used == 1) ++pg_slow_hits;
		svc->destroy(handle);
	}
	ok(pg_leaks == 0 && pg_fast_hits == 64 && pg_slow_hits == 0,
		"PgSQL raw selection reuses native comparative latency policy and excludes the slower backend");

	set_pgsql_latency_awareness_min(0);
	int pg_slow_control_hits = 0;
	for (int i = 0; i < 64; ++i) {
		std::string error;
		ProxySQL_RawBackend* handle = svc->acquire(ProxySQL_RawBackendProtocol::pgsql,
			pg_hg, endpoint, error);
		if (handle == nullptr) continue;
		PgHGM->wrlock();
		const unsigned int slow_used = pg_slow->ConnectionsUsed->conns_length();
		PgHGM->wrunlock();
		if (slow_used == 1) ++pg_slow_control_hits;
		svc->destroy(handle);
	}
	ok(pg_slow_control_hits > 0 &&
		proxysql_raw_backend_latency_awareness_min_servers() == 0,
		"PgSQL disabled comparative policy permits both backends and restores helper TLS to default");
	set_pgsql_latency_awareness_min(saved_pgsql_min);
}

} // namespace

int main() {
	plan(NO_PLAN);
	if (test_init_minimal() != 0) {
		BAIL_OUT("test_init_minimal() failed");
	}
	if (test_init_query_processor() != 0) {
		BAIL_OUT("test_init_query_processor() failed");
	}
	if (test_init_hostgroups() != 0) {
		BAIL_OUT("test_init_hostgroups() failed");
	}

	ok(valid_service(service()), "raw backend service is available before any hostgroup work");
	test_mysql_real_hgm();
	test_pgsql_real_hgm();
	test_failures_do_not_fabricate();
	test_connect_error_once_and_map();
	test_status_and_hard_latch();
	test_final_hard_destroy_fence();
	test_worker_thread_policy_refresh_and_restore();
	test_pgsql_worker_thread_policy_refresh_and_restore();
	test_creation_throttle_override();
	test_dns_cache_hits();
	test_comparative_latency_policy();
	test_errors_helpers_unlock_on_bad_alloc();
	return exit_status();
}
