#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Session.h"
#include "PgSQL_Backend.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Connection.h"
#include "PgSQL_HostGroups_Manager.h"
#include <fcntl.h>
#include <unistd.h>

int main() {
	plan(NO_PLAN);
	test_init_minimal(); test_init_query_processor(); test_init_hostgroups();
#ifdef PROXYSQL31
	{
		PgSQL_Session session;
		auto* source = session.find_or_create_backend(10);
		PgSQL_Data_Stream stream; stream.sess = &session;
		PgSQL_HGC hg10(10), hg20(20);
		PgSQL_SrvC a(const_cast<char*>("a"),5432,1,MYSQL_SERVER_STATUS_ONLINE,0,100,0,0,0,const_cast<char*>(""));
		PgSQL_SrvC b(const_cast<char*>("b"),5433,1,MYSQL_SERVER_STATUS_ONLINE,0,100,0,0,0,const_cast<char*>(""));
		a.myhgc=&hg10; b.myhgc=&hg10;
		PgSQL_Connection conn(false); conn.parent=&a; conn.myds=&stream; conn.native_mode=true;
		PgSQL_Protocol protocol; PgSQL_Query_Result result; result.init(&protocol,&stream,&conn);
		const unsigned char idle='I', tx='T', failed='E';
		result.add_native_backend_message('Z',&idle,1);
		ok(source->last_execution.completed_at==0,"internal ReadyForQuery does not record an application completion");
		session.record_lsn_completion(conn,100);
		ok(source->last_execution.endpoint.address=="a" && source->last_execution.completed_at==100,"completion stores actual endpoint and time in source hostgroup");
		conn.parent=&b; session.record_lsn_completion(conn,200);
		ok(source->last_execution.endpoint.address=="b" && source->last_execution.endpoint.port==5433 && source->last_execution.completed_at==200,"last server replaces previous server without retaining dependencies");
		b.myhgc=&hg20; session.find_or_create_backend(20); session.record_lsn_completion(conn,300);
		ok(source->last_execution.completed_at==200 && session.find_backend(20)->last_execution.completed_at==300,"hostgroups retain separate last-execution records");
		b.myhgc=&hg10;
		conn.lsn_begin_application_cycle();
		result.add_native_backend_message('C',reinterpret_cast<const unsigned char*>("COMMIT\0"),7);
		ok(source->last_execution.completed_at==200,"CommandComplete alone does not record a cycle boundary");
		const auto before=monotonic_time();
		result.add_native_backend_message('Z',&idle,1);
		const auto after=source->last_execution.completed_at;
		ok(after>=before && after<=monotonic_time(),"real completion uses a fresh monotonic timestamp before exposing ReadyForQuery");
		conn.set_ready_for_query_status('I');
		ok(source->last_execution.completed_at==after,"duplicate ReadyForQuery observation cannot update completion twice");
		for (auto status : {tx,failed}) {
			session.record_lsn_completion(conn,1); conn.lsn_begin_application_cycle();
			result.add_native_backend_message('Z',&status,1);
			ok(source->last_execution.completed_at>1,"transactional/error application cycle records latest actual execution");
		}
		session.record_lsn_completion(conn,1); conn.lsn_begin_application_cycle();
		conn.set_ready_for_query_status('I');
		ok(source->last_execution.completed_at>1,"suppressed native ReadyForQuery records completion");
		session.record_lsn_completion(conn,1); conn.lsn_begin_application_cycle();
		conn.query_result=&result; conn.native_result_protocol_violation("malformed response test"); conn.query_result=nullptr;
		ok(source->last_execution.completed_at==1,"synthetic error ReadyForQuery does not record a backend completion");
		conn.lsn_application_owner=nullptr; conn.lsn_application_cycle_active=false;
		int sockets[2]; socketpair(AF_UNIX,SOCK_STREAM,0,sockets);
		fcntl(sockets[1],F_SETFL,O_NONBLOCK);
		conn.fd=sockets[0]; stream.DSS=STATE_READY; stream.wait_until=12345;
		conn.lsn_begin_application_cycle(); conn.set_ready_for_query_status('I');
		char byte;
		ok(recv(sockets[1],&byte,1,MSG_DONTWAIT)<0 && (errno==EAGAIN || errno==EWOULDBLOCK),"completion bookkeeping sends no application bytes");
		ok(stream.DSS==STATE_READY && stream.wait_until==12345 && !conn.options.init_connect_sent,"bookkeeping preserves connection initialization and deadline");
		close(sockets[1]);
		const auto retained=source->last_execution.completed_at;
		source->reset();
		ok(source->last_execution.completed_at==retained && source->last_execution.endpoint.address=="b","last execution survives physical backend reset/detach");
		conn.myds=nullptr; stream.sess=nullptr;
	}
#else
	ok(true,"v3.0 omits native LSN completion bookkeeping");
#endif
	test_cleanup_hostgroups(); test_cleanup_query_processor(); test_cleanup_minimal();
	return exit_status();
}
