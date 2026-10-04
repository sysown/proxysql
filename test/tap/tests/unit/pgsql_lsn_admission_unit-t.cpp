#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Session.h"
#include "PgSQL_Thread.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Backend.h"
#include "PgSQL_Logger.hpp"
#include "PgSQL_Query_Cache.h"
#include "PgSQL_Query_Processor.h"
#include "PgSQL_Extended_Query_Message.h"
#include <unistd.h>
extern PgSQL_HostGroups_Manager* PgHGM;
extern PgSQL_Logger* GloPgSQL_Logger;
extern PgSQL_Threads_Handler* GloPTH;
extern PgSQL_Query_Cache* GloPgQC;
#ifdef PROXYSQL31
using namespace pgsql_lsn;
class PgSQL_LSN_Admission_Test {
public:
	static void seed_frame(PgSQL_Session& s) {
		s.extended_query_phase=EXTQ_PHASE_EXECUTING_SYNC_CLIENT|EXTQ_PHASE_PROCESSING_BIND;
		s.extended_query_frame.emplace(std::unique_ptr<PgSQL_Execute_Message>{});
		s.pending_named_bind.active=true;
		s.pending_named_bind.portal_name="pending";
		s.closing_portal_name="closing";
		s.extq_backend_used=true;
	}
	static bool clean_frame(PgSQL_Session& s) {
		return s.extended_query_frame.empty() && s.extended_query_phase==EXTQ_PHASE_IDLE &&
			!s.pending_named_bind.active && s.pending_named_bind.portal_name.empty() &&
			s.closing_portal_name.empty() && !s.extq_backend_used;
	}
	static void portal(PgSQL_Session& s, const char* name, const PgSQL_Connection* conn) {
		s.named_portals[name].bound_conn=conn;
	}
	static bool has_portal(const PgSQL_Session& s, const char* name) { return s.named_portals.count(name); }
	static bool poisoned(const PgSQL_Session& s) { return s.tx_poisoned; }
	static bool acquire(PgSQL_Session& s) { int rc=0; return s.handler_again___status_CONNECTING_SERVER(&rc); }
	static bool cache(PgSQL_Session& s, PtrSize_t& packet) {
		bool lock=false;
		return s.handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_QUERY_qpo(
			&packet,&lock,PGSQL_EXTENDED_QUERY_TYPE_NOT_SET);
	}
};
static void frontend(PgSQL_Session& session,PgSQL_Thread& worker) {
	session.thread=&worker;
	session.client_myds=new PgSQL_Data_Stream(); session.client_myds->init(MYDS_FRONTEND,&session,-1);
	session.client_myds->myconn=new PgSQL_Connection(true);
	session.client_myds->myconn->userinfo->username=strdup("unit");
	session.client_myds->myconn->userinfo->set_dbname("unit");
	session.client_myds->myprot.init(&session.client_myds,session.client_myds->myconn->userinfo,&session);
}
static PtrSize_t cache_query(PgSQL_Session& session) {
	const char sql[]="SELECT n FROM lsn_test";
	PtrSize_t packet{}; packet.size=sizeof(sql)+5; packet.ptr=l_alloc(packet.size);
	auto* bytes=static_cast<unsigned char*>(packet.ptr);
	memcpy(bytes,"Q\0\0\0",4); bytes[4]=sizeof(sql)+4; memcpy(bytes+5,sql,sizeof(sql));
	session.CurrentQuery.begin(bytes,packet.size,true);
	session.qpo->destination_hostgroup=20; session.qpo->cache_ttl=10000;
	session.qpo->lsn_from_hostgroup=10;
	return packet;
}
#endif
int main() {
	plan(NO_PLAN);
	test_init_minimal(); test_init_query_processor(); test_init_hostgroups();
#ifdef PROXYSQL31
	GloPgSQL_Logger=new PgSQL_Logger(); GloPgQC=new PgSQL_Query_Cache();
	{
		auto& manager=PgHGM->lsn_manager();
		Endpoint a{"source-a",5432}, b{"source-b",5432}, replica{"replica",5432};
		manager.reconcile_endpoints({a,b,replica});
		manager.publish({a,{123,1},1000,{100,200},true});
		manager.publish({b,{123,1},2000,{100,150},true});
		manager.publish({replica,{123,1},3000,{100,150},true});
		PgSQL_HGC hgr(20);
		PgSQL_SrvC rs(const_cast<char*>("replica"),5432,1,MYSQL_SERVER_STATUS_ONLINE,0,100,0,0,0,const_cast<char*>("")); rs.myhgc=&hgr;
		PgSQL_Connection connection(false); connection.parent=&rs;
		PgSQL_Session session; session.current_hostgroup=20;
		auto* source=session.find_or_create_backend(10); source->last_execution={a,150};
		ok(session.lsn_prepare_request()==PgSQL_LSN_PrepareResult::Disabled && session.lsn_backend_allowed(connection),"unset rule follows ordinary selection despite recorded source");
		session.lsn_request={}; session.qpo->lsn_from_hostgroup=0;
		ok(session.lsn_prepare_request()==PgSQL_LSN_PrepareResult::Disabled,"source HG without prior execution has no dependency");
		session.find_or_create_backend(0)->last_execution={a,150}; session.lsn_request={};
		ok(session.lsn_prepare_request()==PgSQL_LSN_PrepareResult::Pending && !session.lsn_server_allowed(rs),"HG zero is valid and sample started before completion cannot satisfy it");
		session.qpo->lsn_from_hostgroup=10; session.lsn_request={};
		ok(session.lsn_prepare_request()==PgSQL_LSN_PrepareResult::Pending,"existing source with no later sample stays pending");
		manager.publish({a,{123,1},1000,{200,210},true});
		ok(session.lsn_prepare_request()==PgSQL_LSN_PrepareResult::Ready && session.lsn_request.required->lsn==210,"first later source sample fixes required LSN");
		manager.publish({a,{123,1},1000,{300,220},true});
		ok(session.lsn_prepare_request()==PgSQL_LSN_PrepareResult::Ready && session.lsn_request.required->lsn==210,"later polls do not move an in-flight target");
		ok(!session.lsn_backend_allowed(connection) && session.current_hostgroup==20,"lagging attached server rejected without changing destination");
		manager.publish({replica,{123,1},3000,{200,210},true});
		ok(session.lsn_backend_allowed(connection),"candidate in same history at target qualifies without a connection stamp");
		manager.withdraw(replica);
		ok(!session.lsn_backend_allowed(connection),"withdrawn progress immediately prevents dispatch");
		source->last_execution={b,150}; session.lsn_request={};
		manager.publish({b,{123,1},2000,{200,150},true});
		ok(session.lsn_prepare_request()==PgSQL_LSN_PrepareResult::Ready && session.lsn_request.required->lsn==150,"last server B replaces stronger prior dependency from A");
		manager.prune_before(1000);
		ok(session.lsn_prepare_request()==PgSQL_LSN_PrepareResult::Ready && session.lsn_request.required->lsn==150,"pruning leaves copied requirement intact on retry");
		manager.withdraw(b);
		ok(session.lsn_prepare_request()==PgSQL_LSN_PrepareResult::Ready && session.lsn_request.required->lsn==150,"source withdrawal does not erase an already resolved target");
		manager.publish({b,{123,2},4000,{400,300},true});
		ok(session.lsn_prepare_request()==PgSQL_LSN_PrepareResult::Error,"source history change invalidates an already fixed request requirement");
		session.lsn_request={};
		ok(session.lsn_prepare_request()==PgSQL_LSN_PrepareResult::Error,"observed history change rejects old source completion");
		PgSQL_Thread worker; if (!worker.init()) BAIL_OUT("worker init failed"); worker.curtime=1000000;
		{
			PgSQL_Session cached; frontend(cached,worker); cached.current_hostgroup=20;
			cached.find_or_create_backend(10)->last_execution={a,900000};
			manager.withdraw(a);
			auto packet=cache_query(cached);
			auto* value=static_cast<unsigned char*>(malloc(6)); memcpy(value,"Z\0\0\0\5I",6);
			GloPgQC->set(cached.client_myds->myconn->userinfo->hash,cached.CurrentQuery.QueryPointer,cached.CurrentQuery.QueryLength,value,6,1000,1000,11000,1,0);
			ok(PgSQL_LSN_Admission_Test::cache(cached,packet) && cached.client_myds->PSarrayOUT->len>0,"LSN-configured query still returns an existing cache hit");
			ok(!cached.lsn_request.initialized && cached.find_backend(10)->last_execution.completed_at==900000,"cache hit performs no LSN preparation and preserves backend execution record");
		}
		{
			PgSQL_Session refused; frontend(refused,worker); refused.mybe=refused.find_or_create_backend(20);
			auto packet=cache_query(refused); refused.status=PROCESSING_STMT_BIND;
			PgSQL_LSN_Admission_Test::seed_frame(refused);
			refused.lsn_fail_request("test refusal");
			ok(PgSQL_LSN_Admission_Test::clean_frame(refused),"LSN refusal discards queued extended messages and pending Bind before next Sync");
			l_free(packet.size,packet.ptr);
		}
		{
			PgSQL_Session timed; frontend(timed,worker); timed.current_hostgroup=20;
			timed.mybe=timed.find_or_create_backend(20);
			timed.find_or_create_backend(10)->last_execution={a,900000};
			auto packet=cache_query(timed);
			ok(timed.lsn_prepare_request()==PgSQL_LSN_PrepareResult::Pending,"timeout regression starts with a missing source sample");
			PgSQL_LSN_Admission_Test::seed_frame(timed);
			timed.status=CONNECTING_SERVER; timed.previous_status.push(PROCESSING_STMT_BIND);
			timed.client_myds->setDSS_STATE_QUERY_SENT_NET();
			timed.mybe->server_myds->max_connect_time=worker.curtime-1;
			PgSQL_LSN_Admission_Test::acquire(timed);
			ok(PgSQL_LSN_Admission_Test::clean_frame(timed) && timed.status==WAITING_CLIENT_DATA && timed.previous_status.empty(),
				"causal acquisition timeout discards queued extended messages and pending operations");
			std::string wire;
			for (unsigned i=0;i<timed.client_myds->PSarrayOUT->len;++i) {
				const auto& response=timed.client_myds->PSarrayOUT->pdata[i];
				wire.append(static_cast<const char*>(response.ptr),response.size);
			}
			ok(wire.find("08001")!=std::string::npos && wire.find("Max connect timeout reached while reaching hostgroup 20")!=std::string::npos &&
				wire.size()>=6 && wire.compare(wire.size()-6,6,std::string("Z\0\0\0\5I",6))==0,
				"causal timeout preserves ordinary acquisition SQLSTATE, message, and ReadyForQuery");
			l_free(packet.size,packet.ptr);
		}
		for (bool kill_session : {false,true}) {
			PgSQL_Session cancelled; frontend(cancelled,worker); cancelled.current_hostgroup=20;
			cancelled.mybe=cancelled.find_or_create_backend(20);
			cancelled.find_or_create_backend(10)->last_execution={a,900000};
			auto packet=cache_query(cancelled); PgSQL_LSN_Admission_Test::seed_frame(cancelled);
			cancelled.status=CONNECTING_SERVER; cancelled.killed=kill_session;
			cancelled.mybe->server_myds->cancel_query=!kill_session;
			ok(!cancelled.lsn_route_request() && PgSQL_LSN_Admission_Test::clean_frame(cancelled) &&
				cancelled.status==WAITING_CLIENT_DATA && !cancelled.mybe->server_myds->myconn,
				"%s abandons pending causal acquisition and its extended frame",kill_session?"session kill":"query cancellation");
			const auto& response=cancelled.client_myds->PSarrayOUT->pdata[0];
			ok(std::string(static_cast<const char*>(response.ptr),response.size).find("57014")!=std::string::npos,
				"%s retains query-canceled SQLSTATE during acquisition",kill_session?"session kill":"query cancellation");
			l_free(packet.size,packet.ptr);
		}
		{
			PgSQL_Session multi;
			auto* unrelated=multi.find_or_create_backend(10); auto* actual=multi.find_or_create_backend(20);
			PgSQL_Connection idle(false), transaction(false);
			idle.native_mode=true; transaction.native_mode=true;
			idle.set_ready_for_query_status('I'); idle.set_status(true,STATUS_PGSQL_CONNECTION_NO_MULTIPLEX);
			transaction.set_ready_for_query_status('T');
			unrelated->server_myds->myconn=&idle; actual->server_myds->myconn=&transaction; multi.mybe=actual;
			ok(multi.lsn_pinned_backend()==&transaction,"refusal selects current transaction before unrelated idle nonmultiplexed backend");
			PgSQL_LSN_Admission_Test::portal(multi,"referenced",&idle);
			multi.CurrentQuery.extended_query_info.stmt_client_portal_name="referenced";
			ok(multi.lsn_pinned_backend()==&idle,"referenced portal selects its owning backend before current transaction");
			multi.CurrentQuery.extended_query_info.stmt_client_portal_name=nullptr;
			multi.backend_connection_detached(&idle);
			actual->server_myds->myconn=nullptr;
			ok(multi.lsn_pinned_backend()==nullptr,"unrelated idle nonmultiplexed backend does not constrain another hostgroup");
			idle.set_ready_for_query_status('T');
			ok(multi.lsn_pinned_backend()==&idle,"active transaction remains pinned when current mybe points elsewhere");
			unrelated->server_myds->myconn=nullptr;
		}
		PgHGM->wrlock(); PgHGM->create_new_server_in_hg(20,{"replica",5432,"unit"},{1,100,0}); auto* server=PgHGM->find_server_in_hg(20,"replica",5432); PgHGM->wrunlock();
		{
			PgSQL_Session refused; frontend(refused,worker); refused.current_hostgroup=20;
			int peers[3];
			auto attach = [&](int hg, char txn, int& peer) {
				PgHGM->wrlock();
				PgHGM->create_new_server_in_hg(hg,{"teardown",5432,"unit"},{1,100,0});
				auto* parent=PgHGM->find_server_in_hg(hg,"teardown",5432);
				PgHGM->wrunlock();
				int sockets[2]; if (socketpair(AF_UNIX,SOCK_STREAM,0,sockets)) BAIL_OUT("socketpair failed");
				peer=sockets[1];
				auto* be=refused.find_or_create_backend(hg);
				auto* conn=new PgSQL_Connection(false); conn->parent=parent; conn->native_mode=true;
				conn->fd=sockets[0]; conn->async_state_machine=ASYNC_IDLE;
				conn->set_ready_for_query_status(txn); parent->ConnectionsUsed->add(conn);
				be->server_myds->attach_connection(conn); be->server_myds->fd=sockets[0];
				worker.mypolls.add(POLLIN|POLLOUT,sockets[0],be->server_myds,worker.curtime);
				return be;
			};
			auto* idle=attach(10,'I',peers[0]); auto* active=attach(20,'T',peers[1]); auto* other=attach(30,'T',peers[2]);
			idle->server_myds->myconn->set_status(true,STATUS_PGSQL_CONNECTION_NO_MULTIPLEX);
			PgSQL_LSN_Admission_Test::portal(refused,"unrelated",idle->server_myds->myconn);
			PgSQL_LSN_Admission_Test::portal(refused,"aborted",active->server_myds->myconn);
			refused.mybe=active; refused.transaction_persistent_hostgroup=20;
			auto packet=cache_query(refused); refused.status=PROCESSING_QUERY;
			refused.lsn_fail_request("test transaction refusal");
			ok(!active->server_myds->myconn && !other->server_myds->myconn && idle->server_myds->myconn,
				"global poison destroys all active transactions and retains unrelated idle backend");
			char byte;
			ok(recv(peers[1],&byte,1,MSG_DONTWAIT)==0 && recv(peers[2],&byte,1,MSG_DONTWAIT)==0,
				"refusal closes both transaction sockets so a later local ROLLBACK cannot preserve work");
			ok(PgSQL_LSN_Admission_Test::poisoned(refused) && refused.transaction_persistent_hostgroup==-1 && refused.NumActiveTransactions()==0,
				"refusal poisons frontend and clears transaction ownership before recovery");
			ok(PgSQL_LSN_Admission_Test::has_portal(refused,"unrelated") && !PgSQL_LSN_Admission_Test::has_portal(refused,"aborted"),
				"teardown removes only portals belonging to destroyed backends");
			l_free(packet.size,packet.ptr);
			for (auto* be : {idle,active,other}) if (be->server_myds->myconn) be->server_myds->destroy_MySQL_Connection_From_Pool(false);
			for (int peer : peers) close(peer);
		}
		{
			PgSQL_Session pooled; frontend(pooled,worker); pooled.current_hostgroup=20;
			pooled.qpo->lsn_from_hostgroup=10;
			pooled.find_or_create_backend(10)->last_execution={a,150};
			manager.publish({a,{123,1},1000,{400,250},true});
			manager.publish({replica,{123,1},3000,{300,210},true});
			pooled.lsn_prepare_request();
			auto* checked=PgHGM->get_MyConn_from_pool(20,&pooled,true,nullptr,0,-1);
			ok(!checked,"new-connection pool path excludes lagging candidate before selection");
			if(checked) PgHGM->destroy_MyConn_from_pool(checked);
			auto* local=new PgSQL_Connection(false); local->parent=server; local->async_state_machine=ASYNC_IDLE; local->reusable=true; local->userinfo->set(pooled.client_myds->myconn->userinfo); server->ConnectionsUsed->add(local);
			GloPTH->num_threads=1; worker.push_MyConn_local(local);
			checked=worker.get_MyConn_local(20,&pooled,nullptr,0,-1);
			ok(!checked,"worker-local pool also excludes lagging candidate");
			if(checked) worker.push_MyConn_local(checked);
			manager.publish({replica,{123,1},3000,{400,250},true});
			checked=worker.get_MyConn_local(20,&pooled,nullptr,0,-1);
			ok(checked==local,"same pooled connection becomes eligible after progress publication");
			if(checked) PgHGM->destroy_MyConn_from_pool(checked);
			worker.return_local_connections();
		}
	}
	delete GloPgQC; GloPgQC=nullptr; delete GloPgSQL_Logger; GloPgSQL_Logger=nullptr;
#else
	ok(true,"v3.0 omits LSN admission");
#endif
	test_cleanup_hostgroups(); test_cleanup_query_processor(); test_cleanup_minimal();
	return exit_status();
}
