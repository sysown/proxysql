#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Session.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Connection.h"
#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Extended_Query_Message.h"
#include <fcntl.h>
#include <unistd.h>
extern PgSQL_HostGroups_Manager* PgHGM;
using namespace pgsql_lsn;

static void pg_append_typed_msg(std::vector<unsigned char>& wire, char type, const unsigned char* data, size_t size) {
	const uint32_t length = size + 4;
	wire.insert(wire.end(), {static_cast<unsigned char>(type), static_cast<unsigned char>(length >> 24),
		static_cast<unsigned char>(length >> 16), static_cast<unsigned char>(length >> 8), static_cast<unsigned char>(length)});
	wire.insert(wire.end(), data, data + size);
}

static std::vector<unsigned char> bootstrap_response(const char* start, bool finish) {
	std::vector<unsigned char> wire;
	const unsigned char fields[] = {0,2};
	pg_append_typed_msg(wire, 'T', fields, sizeof(fields));
	std::vector<unsigned char> row{0,2};
	for (const char* value : {start, "f"}) {
		uint32_t length = strlen(value);
		row.insert(row.end(), {static_cast<unsigned char>(length>>24), static_cast<unsigned char>(length>>16),
			static_cast<unsigned char>(length>>8), static_cast<unsigned char>(length)});
		row.insert(row.end(), value, value + length);
	}
	pg_append_typed_msg(wire, 'D', row.data(), row.size());
	if (finish) {
		pg_append_typed_msg(wire, 'C', reinterpret_cast<const unsigned char*>("SELECT 1"), 9);
		const unsigned char idle = 'I'; pg_append_typed_msg(wire, 'Z', &idle, 1);
	}
	return wire;
}

int main() {
	plan(NO_PLAN);
	test_init_minimal(); test_init_query_processor(); test_init_hostgroups();
	auto& manager = PgHGM->lsn_manager();
	Endpoint writer{"writer",5432};
	PgHGM->reconcile_lsn_policies({{10,20,true,{writer},{}}});
	ServerToken source{manager.snapshot(writer).generation,writer,{{123,1},1000},Role::Writer};
	manager.publish_progress({source,1,0x100,{},true,1,1,{}});
	{
		PgSQL_Session session;
		session.connections_handler = true;
		PgSQL_Data_Stream stream;
		stream.sess = &session;
		PgSQL_HGC hostgroup(10);
		PgSQL_SrvC server(const_cast<char*>("writer"), 5432, 1, MYSQL_SERVER_STATUS_ONLINE,
			0, 100, 0, 0, 0, const_cast<char*>(""));
		server.myhgc = &hostgroup;
		PgSQL_Connection connection(false);
		connection.parent = &server;
		connection.myds = &stream;
		connection.lsn_stamp = source;
		PgSQL_Protocol protocol;
		PgSQL_Query_Result result;
		result.init(&protocol, &stream, &connection);
		const unsigned char idle = 'I', transaction = 'T', failed = 'E';
		result.add_native_backend_message('Z', &idle, 1);
		ok(manager.snapshot(writer).completions == 0, "internal idle response does not enroll application work");
		connection.lsn_begin_application_cycle();
		result.add_ready_status(PQTRANS_IDLE);
		ok(manager.snapshot(writer).completions == 1 && !session.lsn_dependencies.empty(), "libpq completion enrolls before result becomes available");
		connection.lsn_on_ready_for_query('I');
		ok(manager.snapshot(writer).completions == 1, "duplicate status update cannot enroll twice");
		connection.lsn_begin_application_cycle();
		result.add_native_backend_message('Z', &transaction, 1);
		connection.lsn_begin_application_cycle();
		result.add_native_backend_message('Z', &failed, 1);
		ok(manager.snapshot(writer).completions == 1, "active and failed transactions do not create completion batches");
		connection.lsn_begin_application_cycle();
		result.add_native_backend_message('C', reinterpret_cast<const unsigned char*>("ROLLBACK\0"), 9);
		ok(manager.snapshot(writer).completions == 1, "CommandComplete alone does not close an application cycle");
		result.add_native_backend_message('Z', &idle, 1);
		ok(manager.snapshot(writer).completions == 2, "native rollback-to-idle preserves conservative dependency");
		connection.lsn_begin_application_cycle();
		connection.set_ready_for_query_status('I');
		ok(manager.snapshot(writer).completions == 3, "suppressed native ReadyForQuery enrolls before buffer flush");
		connection.lsn_begin_application_cycle();
		result.add_native_backend_message('C', reinterpret_cast<const unsigned char*>("COMMIT\0"), 7);
		const unsigned char error[] = "SERROR\0C22012\0Mdivision by zero\0\0";
		result.add_native_backend_message('E', error, sizeof(error)-1);
		result.add_native_backend_message('Z', &idle, 1);
		ok(manager.snapshot(writer).completions == 4, "error after earlier commit still enrolls the completed cycle");
		connection.lsn_begin_application_cycle();
		connection.lsn_begin_application_cycle();
		result.add_native_backend_message('1', nullptr, 0);
		result.add_native_backend_message('2', nullptr, 0);
		ok(manager.snapshot(writer).completions == 4, "Parse and Bind acknowledgements before Sync do not enroll");
		connection.set_ready_for_query_status('I');
		ok(manager.snapshot(writer).completions == 5, "one Sync enrolls the whole extended cycle once");
		connection.async_free_result();
		connection.myds = nullptr;
		ok(!session.lsn_dependencies.empty(), "backend result release retains frontend dependency");
		if (!session.lsn_dependencies.empty()) {
			auto ticket = manager.seal_writer_batch(writer);
			ok(ticket && manager.complete_writer_sample(*ticket, {source,1,0x200,{},true,2,1,{}}), "observed cycles share the next writer sample");
			ok(manager.resolve(session.lsn_dependencies.at(writer)).required_lsn == 0x200, "frontend owns the resolved LSN after backend detach");
		}
		connection.myds = &stream;
		const auto before_error = manager.snapshot(writer).completions;
		connection.lsn_begin_application_cycle();
		connection.query_result = &result;
		connection.native_result_protocol_violation("unit-test malformed backend response");
		connection.query_result = nullptr;
		ok(manager.snapshot(writer).completions == before_error, "synthetic error ReadyForQuery cannot certify an actual backend completion");
		session.backend_connection_detached(&connection);
		ok(session.lsn_errors.count(writer) == 1, "losing an unanswered writer cycle poisons its frontend dependency");
		ok(session.lsn_route_sources.count(10) && session.lsn_route_sources.at(10)==writer,
			"unknown writer outcome retains routing origin independently of tracker identity");
		{
			PgSQL_Session reset_session;
			reset_session.connections_handler = true;
			stream.sess = &reset_session;
			connection.set_ready_for_query_status('I');
			ok(reset_session.lsn_dependencies.empty() && manager.snapshot(writer).completions == before_error,
				"internal reset on a different session cannot inherit the previous application's cycle");
		}
		stream.sess = &session;
		connection.lsn_begin_application_cycle();
		connection.native_result_fatal("08006", "unit-test connection loss");
		ok(!connection.lsn_stamp && connection.lsn_outcome_unknown && session.lsn_errors.count(writer),
			"physical socket loss clears its stamp while retaining unknown-outcome and frontend error state");
		connection.myds = nullptr;
		stream.sess = nullptr;
	}
	{
		PgSQL_HGC hostgroup(10);
		PgSQL_SrvC server(const_cast<char*>("writer"), 5432, 1, MYSQL_SERVER_STATUS_ONLINE,
			0, 100, 0, 0, 0, const_cast<char*>(""));
		server.myhgc = &hostgroup;
		PgSQL_Connection connection(false);
		connection.parent = &server;
		connection.native_mode = true; connection.native_connected = true;
		int sockets[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
		for (int fd : sockets) fcntl(fd, F_SETFL, O_NONBLOCK);
		connection.fd = sockets[0];
		ok(connection.async_validate_lsn_incarnation(POLLOUT) == 1 && !connection.lsn_stamp,
			"new backend must wait for its one-time incarnation bootstrap");
		char query[1024]; const auto size = recv(sockets[1], query, sizeof(query), 0);
		ok(size > 0 && std::string(query, size).find("pg_postmaster_start_time") != std::string::npos,
			"bootstrap queries postmaster incarnation on the selected application socket");
		auto wire = bootstrap_response("1000", false);
		connection.native_framer.feed(wire.data(), wire.size());
		ok(connection.async_validate_lsn_incarnation(POLLIN) == 1 && !connection.lsn_stamp,
			"partial bootstrap row cannot certify a connection before ReadyForQuery");
		wire.clear();
		pg_append_typed_msg(wire, 'C', reinterpret_cast<const unsigned char*>("SELECT 1"), 9);
		const unsigned char idle = 'I'; pg_append_typed_msg(wire, 'Z', &idle, 1);
		connection.native_framer.feed(wire.data(), wire.size());
		ok(connection.async_validate_lsn_incarnation(POLLIN) == 0 && connection.lsn_stamp && *connection.lsn_stamp == source,
			"matching postmaster and role stamp the application connection");
		ok(!connection.query_result, "hidden bootstrap never creates frontend response packets");
		ok(connection.async_validate_lsn_incarnation(0) == 0 && recv(sockets[1], query, sizeof(query), 0) < 0,
			"already stamped backend sends no additional bootstrap query");
		auto dependency = manager.observe_completion(source, {});
		connection.lsn_stamp.reset();
		ok(connection.async_validate_lsn_incarnation(POLLOUT) == 1, "bootstrap can validate an unstamped pooled connection");
		recv(sockets[1], query, sizeof(query), 0);
		wire = bootstrap_response("1001", true);
		connection.native_framer.feed(wire.data(), wire.size());
		ok(connection.async_validate_lsn_incarnation(POLLIN) == -1 && !connection.lsn_stamp && !connection.reusable,
			"postmaster mismatch refuses and retires the application connection");
		ok(manager.resolve(dependency).state == DependencyState::Invalid,
			"observed writer incarnation mismatch invalidates earlier frontend dependencies");
		close(sockets[1]);
	}
	{
		// The endpoint is tracked through HG10, but HG99 has no causal policy.
		PgSQL_HGC unprotected(99);
		PgSQL_SrvC server(const_cast<char*>("writer"),5432,1,MYSQL_SERVER_STATUS_ONLINE,
			0,100,0,0,0,const_cast<char*>(""));
		server.myhgc=&unprotected;
		PgSQL_Connection connection(false); connection.parent=&server;
		connection.native_mode=true; connection.native_connected=true;
		ok(connection.async_validate_lsn_incarnation(0)==0 && !connection.lsn_bootstrap_active,
			"unprotected hostgroup sharing an endpoint does not require monitor certification");
	}
	{
		PgSQL_Session session; session.connections_handler=true;
		PgSQL_Data_Stream stream; stream.sess=&session;
		PgSQL_Connection connection(false); connection.myds=&stream;
		connection.lsn_stamp=source;
		connection.lsn_begin_application_cycle();
		PgHGM->reconcile_lsn_policies({{10,20,true,{},{}}});
		connection.lsn_on_ready_for_query('I');
		ok(session.lsn_dependencies.count(writer) && manager.resolve(session.lsn_dependencies.at(writer)).state==DependencyState::Invalid,
			"completion racing endpoint removal retains an invalid dependency instead of becoming clean");
		connection.myds=nullptr; stream.sess=nullptr;
	}
	test_cleanup_hostgroups(); test_cleanup_query_processor(); test_cleanup_minimal();
	return exit_status();
}
