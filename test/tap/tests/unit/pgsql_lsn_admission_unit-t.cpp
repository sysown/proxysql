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
#include "PgSQL_ExplicitTxnStateMgr.h"
extern PgSQL_HostGroups_Manager* PgHGM;
extern PgSQL_Logger* GloPgSQL_Logger;
extern PgSQL_Threads_Handler* GloPTH;
extern PgSQL_Query_Cache* GloPgQC;
using namespace pgsql_lsn;

class PgSQL_LSN_Admission_Test {
public:
	static bool cache(PgSQL_Session& s, PtrSize_t& packet) {
		bool lock=false;
		return s.handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_QUERY_qpo(
			&packet,&lock,PGSQL_EXTENDED_QUERY_TYPE_NOT_SET);
	}
};

static PtrSize_t cache_query(PgSQL_Session& session) {
	const char sql[]="SELECT n FROM lsn_test";
	PtrSize_t packet{};
	packet.size=sizeof(sql)+5; packet.ptr=l_alloc(packet.size);
	auto* bytes=static_cast<unsigned char*>(packet.ptr);
	memcpy(bytes,"Q\0\0\0",4); bytes[4]=sizeof(sql)+4;
	memcpy(bytes+5,sql,sizeof(sql));
	session.CurrentQuery.begin(bytes,packet.size,true);
	session.qpo->destination_hostgroup=20; session.qpo->cache_ttl=10000;
	return packet;
}

int main() {
	plan(NO_PLAN);
	test_init_minimal(); test_init_query_processor(); test_init_hostgroups();
	GloPgSQL_Logger = new PgSQL_Logger();
	GloPgQC = new PgSQL_Query_Cache();
	{
	auto& manager = PgHGM->lsn_manager();
	Endpoint writer{"writer",5432}, replica{"replica",5432};
	PgSQL_Session old;
	old.connections_handler = false;
	PgHGM->reconcile_lsn_policies({{10,20,true,{writer},{replica}}});
	ServerToken source{manager.snapshot(writer).generation,writer,{{123,1},1000},Role::Writer};
	ServerToken reader{manager.snapshot(replica).generation,replica,{{123,1},2000},Role::Replica};
	manager.publish_progress({source,1,0x100,{},true,1,1,{}});
	manager.publish_progress({reader,1,{},0x100,true,1,1,{}});
	pgsql_thread___lsn_wait_timeout = 100;
	pgsql_thread___lsn_poll_interval = 10;
	pgsql_thread___default_query_timeout = 1000;
	ok(old.lsn_admit(20,1000) == LsnAdmission::Error && old.lsn_request.error == Reason::TrackingNotInitialized,
		"session predating activation cannot use untracked history");
	ok(!old.lsn_cache_allowed(20), "activation guard applies before cache lookup");
	{
		PgHGM->reconcile_lsn_policies({{10,20,true,{writer},{replica}},
			{30,40,true,{writer},{replica}},{50,60,true,{writer},{writer,replica}}});
		PgSQL_Session shared; shared.connections_handler=false;
		shared.lsn_dependencies[writer]=manager.observe_completion(source,{});
		ok(manager.snapshots().size()==2,"three hostgroup policies share two physical trackers");
		ok(shared.lsn_admit(40,1000)==LsnAdmission::Wait,
			"dependency follows physical writer into a different hostgroup policy");
		shared.lsn_finish_request();
		ok(shared.lsn_admit(60,1000)==LsnAdmission::Proceed,
			"originating physical writer remains eligible when listed in a reader hostgroup");
		shared.lsn_finish_request();
		Endpoint replacement{"replacement",5432};
		PgHGM->reconcile_lsn_policies({{10,20,true,{writer},{replica}},
			{30,40,true,{replacement},{replica}},{50,60,true,{writer},{writer,replica}}});
		ServerToken changed{manager.snapshot(replacement).generation,replacement,{{123,2},3000},Role::Writer};
		manager.publish_progress({changed,1,0x500,{},true,1,1,{}});
		ok(!shared.lsn_cache_allowed(40),"membership change cannot erase shared dependency before cache lookup");
		ok(shared.lsn_admit(40,1001)==LsnAdmission::Error && shared.lsn_request.error==Reason::HistoryChanged,
			"policy retains an inferred physical source when its writer membership changes");
		shared.lsn_finish_request();
		PgHGM->reconcile_lsn_policies({{10,20,true,{writer},{replica}}});
		ok(manager.resolve(shared.lsn_dependencies.at(writer)).state==DependencyState::Pending &&
			manager.snapshot(writer).generation==source.generation,
			"removing duplicate policies preserves server generation and dependency");
	}
	{
		PgSQL_Session session; session.connections_handler = false;
		ok(session.lsn_admit(20,1000) == LsnAdmission::Proceed, "new clean session can use a certified reader");
		ok(session.lsn_cache_allowed(20), "clean session keeps ordinary cache eligibility");
		session.lsn_finish_request();
		session.lsn_dependencies[writer] = manager.observe_completion(source, {});
		ok(!session.lsn_cache_allowed(20), "unresolved dependency bypasses cache");
		ok(session.lsn_admit(20,1000) == LsnAdmission::Wait, "reader request waits for sealed writer sample");
		const auto deadline = session.lsn_request.deadline;
		ok(deadline == 101000 && session.lsn_admit(20,50000) == LsnAdmission::Wait && session.lsn_request.deadline == deadline,
			"admission retries retain one monotonic deadline");
		auto ticket = manager.seal_writer_batch(writer);
		manager.complete_writer_sample(*ticket, {source,1,0x200,{},true,2,1,{}});
		ok(session.lsn_admit(20,60000) == LsnAdmission::Wait, "resolved target still waits for replay");
		manager.publish_progress({reader,1,{},0x200,true,3,1,{}});
		ok(session.lsn_admit(20,70000) == LsnAdmission::Proceed, "reader admitted when its certified replay reaches the target");
		ok(!session.lsn_cache_allowed(20), "resolved dependency still bypasses cache");
		PgSQL_HGC hgr(20), hgw(10);
		PgSQL_SrvC rs(const_cast<char*>("replica"),5432,1,MYSQL_SERVER_STATUS_ONLINE,0,100,0,0,0,const_cast<char*>(""));
		PgSQL_SrvC ws(const_cast<char*>("writer"),5432,1,MYSQL_SERVER_STATUS_ONLINE,0,100,0,0,0,const_cast<char*>(""));
		rs.myhgc=&hgr; ws.myhgc=&hgw;
		PgSQL_Connection backend(false); backend.parent=&rs; backend.lsn_stamp=reader;
		ok(session.lsn_backend_allowed(backend), "matching application socket is eligible");
		backend.lsn_stamp->incarnation.postmaster_start_us++;
		ok(!session.lsn_backend_allowed(backend), "old attached socket fails incarnation check");
		backend.lsn_stamp.reset();
		ok(!session.lsn_backend_allowed(backend) && session.lsn_backend_allowed(backend,true),
			"unstamped connection requires bootstrap before dispatch");
		manager.publish_progress({reader,1,{},0x1ff,true,4,1,{}});
		session.lsn_admit(20,80000);
		ok(!session.lsn_server_allowed(rs), "lagging server excluded before pool weighting");
		ok(session.lsn_admit(20,deadline) == LsnAdmission::UseWriter && session.lsn_request.route_hostgroup==10,
			"expired wait falls back to originating writer");
		ok(session.lsn_server_allowed(ws) && !session.lsn_server_allowed(rs), "fallback pool predicate accepts only originating writer");
		ok(session.lsn_admit(20,deadline+1) == LsnAdmission::Proceed && session.lsn_request.fallback,
			"fallback happens at most once");
		session.lsn_finish_request();
		pgsql_thread___lsn_wait_timeout=0;
		ok(session.lsn_admit(20,200000) == LsnAdmission::UseWriter, "zero wait performs immediate valid writer fallback");
		session.lsn_finish_request();
		manager.publish_progress({reader,1,{},0x200,true,5,1,{}});
		ok(session.lsn_admit(20,200000) == LsnAdmission::Proceed, "zero wait permits a ready reader on initial eligibility check");
		session.lsn_request.waiting_for_pool=true;
		ok(session.lsn_admit(20,200001) == LsnAdmission::UseWriter, "pool checkout shares the same zero wait deadline");
		session.lsn_finish_request();
		pgsql_thread___lsn_wait_timeout=100;
		manager.publish_progress({reader,1,{},0x100,true,6,1,{}});
		session.lsn_admit(20,300000);
		session.lsn_request.query_deadline=300001;
		ok(session.lsn_admit(20,300001)==LsnAdmission::Error && session.lsn_request.cancelled,
			"earlier query deadline wins over causal fallback");
		session.lsn_finish_request();
		backend.parent=&ws; backend.lsn_stamp=source; backend.native_mode=true;
		backend.set_ready_for_query_status('T');
		session.mybe=session.find_or_create_backend(10);
		session.mybe->server_myds->myconn=&backend;
		session.transaction_persistent=false;
		ok(session.lsn_admit(20,310000)==LsnAdmission::Proceed && session.lsn_request.route_hostgroup==10 &&
			session.lsn_pinned_backend()==&backend,"transaction stays on writer despite reader rule and transaction_persistent=false");
		session.lsn_finish_request();
		ok(session.lsn_admit(99,310001)==LsnAdmission::Error,"protected snapshot cannot migrate to an unrelated hostgroup");
		session.lsn_finish_request();
		backend.set_ready_for_query_status('I'); backend.native_unsynced_work=true;
		ok(session.lsn_admit(20,310002)==LsnAdmission::Proceed && session.lsn_request.route_hostgroup==10,
			"unsynchronized extended cycle retains backend affinity");
		backend.native_unsynced_work=false;
		session.mybe->server_myds->myconn=nullptr;
		session.mybe=nullptr;
		session.lsn_finish_request();
		session.session_fast_forward=SESSION_FORWARD_TYPE_PERMANENT;
		ok(session.lsn_admit(20,310003)==LsnAdmission::Error,"protected reader fast-forward route is refused");
		session.session_fast_forward=SESSION_FORWARD_TYPE_NONE;
		session.lsn_finish_request();
		session.lsn_admit(20,400000);
		PgHGM->reconcile_lsn_policies({});
		ok(session.lsn_admit(20,400001)==LsnAdmission::Error, "disable cannot silently relax an in-flight protected request");
		session.lsn_finish_request();
		ok(session.lsn_admit(20,400002)==LsnAdmission::Proceed && session.lsn_cache_allowed(20),
			"new request observes disabled policy");
	}
	PgHGM->reconcile_lsn_policies({{10,20,true,{writer},{replica}}});
	source.generation = manager.snapshot(writer).generation;
	reader.generation = manager.snapshot(replica).generation;
	manager.publish_progress({source,1,0x300,{},true,7,1,{}});
	manager.publish_progress({reader,1,{},0x100,true,7,1,{}});
	{
		PgSQL_Thread worker;
		if (!worker.init()) BAIL_OUT("worker init failed");
		worker.curtime=1000000;
		pgsql_thread___lsn_wait_timeout=100;
		auto* first = new PgSQL_Session(); first->thread=&worker;
		first->lsn_dependencies[writer]=manager.observe_completion(source,{});
		first->lsn_admit(20,worker.curtime);
		first->to_process=0;
		worker.lsn_waiter_enter(first);
		ok(worker.lsn_waiter_count==1, "worker owns separate LSN waiter node");
		first->to_process=1;
		worker.lsn_waiter_enter(first);
		ok(first->to_process==0,"registering an unchanged wait clears stale runnable state to avoid a busy loop");
#ifdef PROXYSQL31
		ok(worker.waiter_lists.empty(), "LSN waiting does not enter vanilla pool wait queue");
#endif
		ok(worker.lsn_poll_timeout(2000,worker.curtime)==100, "worker poll honors earliest causal deadline");
		auto* second = new PgSQL_Session(); second->thread=&worker;
		second->lsn_dependencies=first->lsn_dependencies;
		second->lsn_admit(20,worker.curtime);
		second->to_process=0;
		auto ticket=manager.seal_writer_batch(writer);
		manager.complete_writer_sample(*ticket,{source,1,0x300,{},true,8,1,{}});
		worker.lsn_waiter_enter(second);
		ok(second->to_process==1, "register then recheck catches publication before insertion");
		worker.process_lsn_waiters(worker.curtime);
		ok(first->to_process==1, "publication after insertion wakes existing waiter");
		first->to_process=0; second->to_process=0; second->killed=true;
		worker.process_lsn_waiters(worker.curtime);
		ok(second->to_process==1, "cancelled waiter behind unready waiter is inspected");
		first->lsn_finish_request();
		ok(worker.lsn_waiter_count==1 && !first->lsn_waiter_node.owner, "request cleanup unlinks only its own waiter");
		delete first; delete second;
		ok(worker.lsn_waiter_count==0, "frontend teardown leaves no dangling LSN wait node");
		// Actual shared and worker-local checkout, including a new socket.
		PgHGM->wrlock();
		PgHGM->create_new_server_in_hg(20,{"replica",5432,"unit"},{1,100,0});
		auto* server=PgHGM->find_server_in_hg(20,"replica",5432);
		PgHGM->wrunlock();
		if (!server) BAIL_OUT("server init failed");
		PgSQL_Session session; session.thread=&worker;
		session.client_myds=new PgSQL_Data_Stream(); session.client_myds->init(MYDS_FRONTEND,&session,-1);
		session.client_myds->myconn=new PgSQL_Connection(true);
		session.client_myds->myconn->userinfo->username=strdup("unit");
		session.client_myds->myconn->userinfo->set_dbname("unit");
		session.lsn_dependencies[writer]=manager.observe_completion(source,{});
		session.lsn_admit(20,worker.curtime);
		auto* checked=PgHGM->get_MyConn_from_pool(20,&session,false,nullptr,0,-1);
		ok(!checked,"shared pool cannot create a socket on an ineligible replica");
		if (checked) PgHGM->destroy_MyConn_from_pool(checked);
		auto* cached=new PgSQL_Connection(false); cached->parent=server;
		cached->async_state_machine=ASYNC_IDLE; cached->reusable=true;
		cached->userinfo->set(session.client_myds->myconn->userinfo);
		cached->lsn_stamp=reader; server->ConnectionsUsed->add(cached);
		GloPTH->num_threads=1;
		worker.push_MyConn_local(cached);
		checked=worker.get_MyConn_local(20,&session,nullptr,0,-1);
		ok(!checked,"worker-local checkout rejects unresolved LSN dependency");
		if (checked) worker.push_MyConn_local(checked);
		ticket=manager.seal_writer_batch(writer);
		manager.complete_writer_sample(*ticket,{source,1,0x400,{},true,9,1,{}});
		manager.publish_progress({reader,1,{},0x400,true,9,1,{}});
		session.lsn_admit(20,worker.curtime+1);
		checked=worker.get_MyConn_local(20,&session,nullptr,0,-1);
		ok(checked==cached,"caught-up certified local connection becomes eligible");
		if (checked) PgHGM->destroy_MyConn_from_pool(checked);
		worker.return_local_connections();
		checked=PgHGM->get_MyConn_from_pool(20,&session,true,nullptr,0,-1);
		ok(checked && !checked->lsn_stamp,"eligible shared pool can create an unstamped socket for bootstrap");
		if (checked) PgHGM->destroy_MyConn_from_pool(checked);
		cached=new PgSQL_Connection(false); cached->parent=server;
		cached->async_state_machine=ASYNC_IDLE; cached->reusable=true;
		cached->userinfo->set(session.client_myds->myconn->userinfo);
		cached->lsn_stamp=reader; ++cached->lsn_stamp->incarnation.postmaster_start_us;
		server->ConnectionsFree->add(cached);
		checked=PgHGM->get_MyConn_from_pool(20,&session,false,nullptr,0,-1);
		ok(checked && !checked->lsn_stamp,"shared checkout retires mismatched physical stamp and creates a socket for bootstrap");
		if (checked) PgHGM->destroy_MyConn_from_pool(checked);
		session.mybe=session.find_or_create_backend(20);
		session.mybe->server_myds->cancel_query=true;
		ok(session.lsn_admit(20,worker.curtime+2)==LsnAdmission::Error && session.lsn_request.cancelled,
			"query cancellation wins even when a replica has become eligible");
		session.mybe->server_myds->cancel_query=false;
		session.lsn_finish_request();
		session.current_hostgroup=99;
		auto packet=cache_query(session);
		auto* value=static_cast<unsigned char*>(malloc(6)); memcpy(value,"Z\0\0\0\5I",6);
		GloPgQC->set(session.client_myds->myconn->userinfo->hash,session.CurrentQuery.QueryPointer,
			session.CurrentQuery.QueryLength,value,6,1000,1000,11000,1,0);
		ok(!PgSQL_LSN_Admission_Test::cache(session,packet) && session.current_hostgroup==20 &&
			session.client_myds->PSarrayOUT->len==0,"actual simple-cache path resolves reader rule then rejects stale preseeded entry");
		l_free(packet.size,packet.ptr); session.CurrentQuery.end();
		{
			PgSQL_Session clean; clean.thread=&worker;
			clean.client_myds=new PgSQL_Data_Stream(); clean.client_myds->init(MYDS_FRONTEND,&clean,-1);
			clean.client_myds->myconn=new PgSQL_Connection(true);
			clean.client_myds->myconn->userinfo->set(session.client_myds->myconn->userinfo);
			packet=cache_query(clean);
			ok(PgSQL_LSN_Admission_Test::cache(clean,packet) && clean.client_myds->PSarrayOUT->len>0,
				"independent clean frontend can hit the same cache entry");
		}
		PgHGM->wrlock();
		PgHGM->create_new_server_in_hg(10,{"writer",5432,"unit"},{1,100,0});
		auto* writer_server=PgHGM->find_server_in_hg(10,"writer",5432);
		PgHGM->wrunlock();
		for (bool explicit_txn : {true,false}) {
			PgSQL_Session guarded; guarded.thread=&worker;
			guarded.client_myds=new PgSQL_Data_Stream(); guarded.client_myds->init(MYDS_FRONTEND,&guarded,-1);
			guarded.client_myds->myconn=new PgSQL_Connection(true);
			guarded.client_myds->myconn->userinfo->set(session.client_myds->myconn->userinfo);
			guarded.client_myds->myprot.init(&guarded.client_myds,guarded.client_myds->myconn->userinfo,&guarded);
			guarded.mybe=guarded.find_or_create_backend(10);
			auto* stream=guarded.mybe->server_myds;
			auto* active=new PgSQL_Connection(false); active->parent=writer_server; active->myds=stream;
			active->native_mode=true; active->native_connected=true; active->healthy=true; active->async_state_machine=ASYNC_IDLE;
			active->lsn_stamp=source; active->set_ready_for_query_status(explicit_txn ? 'T' : 'I');
			active->native_unsynced_work=!explicit_txn;
			writer_server->ConnectionsUsed->add(active); stream->myconn=active;
			packet=cache_query(guarded); guarded.current_hostgroup=10; guarded.status=PROCESSING_QUERY;
			manager.invalidate_endpoint(writer,Reason::NoSafeBackend);
			ok(!guarded.lsn_route_request(),"withdrawn certification refuses a pinned %s",explicit_txn ? "transaction" : "extended cycle");
			ok(!stream->myconn && guarded.tx_poisoned==explicit_txn,
				"causal refusal discards uncommitted work and preserves explicit aborted-transaction state");
			char ready=0;
			for (unsigned i=0;i<guarded.client_myds->PSarrayOUT->len;++i) {
				auto* output=guarded.client_myds->PSarrayOUT->index(i);
				const auto* bytes=static_cast<const unsigned char*>(output->ptr);
				if (output->size>=6 && bytes[output->size-6]=='Z') ready=bytes[output->size-1];
			}
			ok(ready==(explicit_txn ? 'E' : 'I'),"causal refusal reports the correct ReadyForQuery transaction state");
			l_free(packet.size,packet.ptr);
			manager.publish_progress({source,1,0x400,{},true,10,1,{}});
		}

	}
	}
	delete GloPgQC; GloPgQC=nullptr;
	delete GloPgSQL_Logger; GloPgSQL_Logger=nullptr;
	test_cleanup_hostgroups(); test_cleanup_query_processor(); test_cleanup_minimal();
	return exit_status();
}
