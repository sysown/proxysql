/**
 * @file gtid_local_cache_unit-t.cpp
 * @brief GTID-qualified checkout must reuse eligible thread-local connections.
 *
 * Calls the real worker lookup and real HGM GTID lookup with in-memory GTID
 * data. The linker wrapper only counts lookups; it forwards every call to the
 * production implementation without changing its arguments or result.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "GTID_Server_Data.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_Logger.hpp"

#include <cstring>
#include <map>
#include <memory>
#include <string>

extern MySQL_HostGroups_Manager* MyHGM;
extern MySQL_Threads_Handler* GloMTH;
extern MySQL_Logger* GloMyLogger;

namespace {

constexpr unsigned int kHostgroup = 6436;
char kUuid[] = "aaaaaaaa000011112222aaaaaaaaaaaa";
std::map<MySrvC*, unsigned int> gtid_calls;

MySrvC* create_server(const char* address) {
	srv_info_t info;
	info.addr = address;
	info.port = 3306;
	info.kind = "gtid-local-cache-unit";
	srv_opts_t options;
	options.weigth = 1;
	options.max_conns = 100;
	options.use_ssl = 0;

	MyHGM->wrlock();
	const int result = MyHGM->create_new_server_in_hg(kHostgroup, info, options);
	MyHGC* hostgroup = MyHGM->MyHGC_find(kHostgroup);
	MySrvC* server = nullptr;
	if (hostgroup != nullptr) {
		for (unsigned int i = 0; i < hostgroup->mysrvs->cnt(); ++i) {
			MySrvC* candidate = hostgroup->mysrvs->idx(i);
			if (std::strcmp(candidate->address, address) == 0) {
				server = candidate;
				break;
			}
		}
	}
	MyHGM->wrunlock();
	if (result != 0 || server == nullptr) BAIL_OUT("failed to create GTID server fixture");
	return server;
}

void set_userinfo(MySQL_Connection* connection) {
	char username[] = "gtid_cache_user";
	char password[] = "password";
	char schema[] = "gtid_cache_schema";
	connection->userinfo->set(username, password, schema, nullptr);
#ifdef PROXYSQL40
	connection->set_backend_auth_type(MySQLBackendAuthType::PASSWORD);
#endif // PROXYSQL40
}

MySQL_Connection* cache_connection(MySQL_Thread& worker, MySrvC* server) {
	auto connection = std::make_unique<MySQL_Connection>();
	connection->mysql = mysql_init(nullptr);
	if (connection->mysql == nullptr) BAIL_OUT("mysql_init() failed");
	connection->ret_mysql = connection->mysql;
	connection->mysql->charset = mariadb_get_charset_by_name("utf8mb4");
	if (connection->mysql->charset == nullptr) BAIL_OUT("connector charset is unavailable");
	connection->parent = server;
	set_userinfo(connection.get());
	connection->healthy = true;
	connection->reusable = true;
	connection->send_quit = false;
	connection->async_state_machine = ASYNC_IDLE;
	server->ConnectionsUsed->add(connection.get());
	worker.push_MyConn_local(connection.get());
	return connection.release();
}

class SessionFixture {
public:
	explicit SessionFixture(MySQL_Thread& worker) : session(new MySQL_Session()) {
		session->thread = &worker;
		session->connections_handler = true;
		stream = new MySQL_Data_Stream();
		stream->init(MYDS_FRONTEND, session.get(), -1);
		auto* frontend = new MySQL_Connection();
		stream->attach_connection(frontend);
		stream->myprot.init(&stream, frontend->userinfo, session.get());
		session->client_myds = stream;
		set_userinfo(frontend);
	}

	std::unique_ptr<MySQL_Session> session;
	MySQL_Data_Stream* stream = nullptr;
};

class GtidFixture {
public:
	GtidFixture(MySrvC* server, const char* gtid)
		: endpoint(std::string(server->address) + ":3306"),
		  data(nullptr, server->address, 0, server->port) {
		if (!data.add_gtid_from_ok(gtid)) BAIL_OUT("failed to seed GTID fixture");
		MyHGM->gtid_map.emplace(endpoint, &data);
	}

	~GtidFixture() { MyHGM->gtid_map.erase(endpoint); }

private:
	std::string endpoint;
	GTID_Server_Data data;
};

MySQL_Connection* checkout(MySQL_Thread& worker, SessionFixture& fixture, char* uuid = kUuid) {
	gtid_calls.clear();
	return worker.get_MyConn_local(kHostgroup, fixture.session.get(), uuid, 42, -1);
}

void return_selected(MySQL_Connection* selected) {
	if (selected != nullptr) MyHGM->push_MyConn_to_pool(selected);
}

void test_matching_parent(MySQL_Thread& worker, SessionFixture& session, MySrvC* matching) {
	MySQL_Connection* expected = cache_connection(worker, matching);
	MySQL_Connection* selected = checkout(worker, session);
	ok(selected == expected, "a cached connection whose server has the GTID is returned");
	ok(gtid_calls[matching] == 1, "a matching server is checked once through the real GTID lookup");
	return_selected(selected);
	selected = checkout(worker, session);
	ok(selected == nullptr && gtid_calls.empty(), "the returned GTID connection is removed from the local cache");
	return_selected(selected);
	worker.return_local_connections();
}

void test_missing_parent(MySQL_Thread& worker, SessionFixture& session, MySrvC* missing) {
	MySQL_Connection* first = cache_connection(worker, missing);
	MySQL_Connection* second = cache_connection(worker, missing);
	MySQL_Connection* selected = checkout(worker, session);
	ok(selected == nullptr, "connections whose server lacks the requested GTID remain in the cache");
	ok(gtid_calls[missing] == 1, "two cached connections to a missing server cause only one GTID lookup");
	return_selected(selected);
	selected = checkout(worker, session, nullptr);
	ok(selected == first && gtid_calls.empty(), "a GTID miss preserves the first connection for ordinary checkout");
	return_selected(selected);
	selected = checkout(worker, session, nullptr);
	ok(selected == second && gtid_calls.empty(), "a GTID miss preserves the second connection for ordinary checkout");
	return_selected(selected);
	worker.return_local_connections();
}

void test_mixed_parents(MySQL_Thread& worker, SessionFixture& session,
	MySrvC* missing, MySrvC* matching) {
	cache_connection(worker, missing);
	cache_connection(worker, missing);
	MySQL_Connection* expected = cache_connection(worker, matching);
	MySQL_Connection* selected = checkout(worker, session);
	ok(selected == expected, "lookup skips a missing server and returns a later GTID-qualified parent");
	ok(gtid_calls[missing] == 1 && gtid_calls[matching] == 1 && gtid_calls.size() == 2,
		"mixed parents are evaluated once each despite duplicate cached connections");
	return_selected(selected);
	selected = checkout(worker, session);
	ok(selected == nullptr && gtid_calls[missing] == 1 && gtid_calls.size() == 1,
		"server exclusions are rebuilt on each checkout, checking a missing server once again");
	return_selected(selected);
	worker.return_local_connections();
}

} // namespace

#ifdef __linux__
extern "C" bool __real__ZN24MySQL_HostGroups_Manager11gtid_existsEP6MySrvCPcm(
	MySQL_HostGroups_Manager*, MySrvC*, char*, uint64_t);

extern "C" bool __wrap__ZN24MySQL_HostGroups_Manager11gtid_existsEP6MySrvCPcm(
	MySQL_HostGroups_Manager* manager, MySrvC* server, char* uuid, uint64_t trxid) {
	++gtid_calls[server];
	return __real__ZN24MySQL_HostGroups_Manager11gtid_existsEP6MySrvCPcm(
		manager, server, uuid, trxid);
}
#endif

int main() {
#ifndef __linux__
	plan(1);
	skip(1, "requires GNU ld --wrap support");
	return exit_status();
#else
	plan(10);
	if (test_init_minimal() != 0 || test_init_query_processor() != 0 ||
		test_init_hostgroups() != 0) {
		BAIL_OUT("failed to initialize unit-test globals");
	}
	GloMyLogger = new MySQL_Logger();
	GloMTH->num_threads = 1;
#ifdef PROXYSQL40
	GloMTH->set_variable("aws_locality_awareness", "false");
#endif
	{
		MySQL_Thread worker;
		if (!worker.init()) BAIL_OUT("MySQL_Thread::init() failed");
		SessionFixture session(worker);
		MySrvC* matching = create_server("gtid-matching");
		MySrvC* missing = create_server("gtid-missing");
		GtidFixture matching_gtid(matching, "aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:42");
		GtidFixture missing_gtid(missing, "aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:41");
		test_matching_parent(worker, session, matching);
		test_missing_parent(worker, session, missing);
		test_mixed_parents(worker, session, missing, matching);
	}
	test_cleanup_hostgroups();
	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
#endif
}
