#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Session.h"
#include "PgSQL_Thread.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Backend.h"
#include "PgSQL_Query_Processor.h"
#include <algorithm>
#include <limits>
#include <climits>
extern PgSQL_HostGroups_Manager* PgHGM;
using namespace pgsql_lsn;

namespace {
Micros after_ms(Micros now, uint64_t ms) {
	const auto max = std::numeric_limits<Micros>::max();
	return ms > (max-now)/1000 ? max : now+ms*1000;
}
bool eligible(const PgSQL_LSN_Request& request, const Progress& progress) {
	const auto& token = progress.server;
	if (!progress.valid || token.group != *request.group || token.generation != request.snapshot.generation)
		return false;
	if (request.route_hostgroup == request.snapshot.config.writer_hostgroup) {
		const auto& source = request.view.source ? request.view.source : request.snapshot.writer;
		return source && token.role == Role::Writer && token == *source;
	}
	if (token.role != Role::Replica || !request.snapshot.writer ||
		!(token.incarnation.history == request.snapshot.writer->incarnation.history)) return false;
	if (request.view.state == DependencyState::Clean) return true;
	return replica_satisfies(request.view, progress, token);
}
}

const PgSQL_Connection* PgSQL_Session::lsn_pinned_backend() const {
	if (!mybes) return nullptr;
	for (unsigned i=0; i<mybes->len; ++i) {
		auto* backend = static_cast<PgSQL_Backend*>(mybes->index(i));
		auto* conn = backend->server_myds ? backend->server_myds->myconn : nullptr;
		if (!conn || !conn->lsn_stamp) continue;
		if (conn->lsn_application_cycle_active || conn->last_ready_for_query_status() != 'I' ||
			conn->native_unsynced_work || (conn->is_connected() && conn->is_pipeline_active()) ||
			session_fast_forward != SESSION_FORWARD_TYPE_NONE) return conn;
		for (const auto& portal : named_portals)
			if (portal.second.bound_conn == conn) return conn;
	}
	return nullptr;
}

LsnAdmission PgSQL_Session::lsn_admit(uint32_t destination, Micros now) {
	auto& request = lsn_request;
	if (!PgHGM || connections_handler || mirror) return LsnAdmission::Proceed;
	auto& manager = PgHGM->lsn_manager();
	auto fail = [&](Reason reason) { request.error = reason; return LsnAdmission::Error; };
	if (!request.initialized) {
		request.initialized = true;
		request.requested_hostgroup = request.route_hostgroup = destination;
		request.group = manager.group_for_hostgroup(destination);
		if (const auto* pinned = lsn_pinned_backend()) request.group = pinned->lsn_stamp->group;
		if (!request.group) return LsnAdmission::Proceed;
		request.snapshot = manager.snapshot(*request.group);
		request.entered_at = now;
		request.deadline = after_ms(now, std::max(0, pgsql_thread___lsn_wait_timeout));
		const int group_timeout = PgHGM->lsn_query_timeout(destination);
		const int timeout = qpo && qpo->timeout > 0 ? qpo->timeout :
			(group_timeout > 0 ? group_timeout : pgsql_thread___default_query_timeout);
		if (timeout > 0) request.query_deadline = after_ms(now, timeout);
		auto dependency = lsn_dependencies.find(*request.group);
		if (dependency != lsn_dependencies.end()) request.dependency = dependency->second;
	}
	if (!request.group) return LsnAdmission::Proceed;
	if (destination != request.snapshot.config.writer_hostgroup && destination != request.snapshot.config.reader_hostgroup)
		return fail(Reason::NoSafeBackend);
	if (request.error != Reason::None) return LsnAdmission::Error;
	if (killed || (mybe && mybe->server_myds && mybe->server_myds->cancel_query) ||
		(request.query_deadline && now >= request.query_deadline)) {
		request.cancelled = true;
		return LsnAdmission::Error;
	}
	const auto current = manager.snapshot(*request.group);
	if (!current.config.enabled || current.generation != request.snapshot.generation)
		return fail(Reason::HistoryChanged);
	request.snapshot = current;
	if (current.activation_epoch > lsn_birth_epoch) return fail(Reason::TrackingNotInitialized);
	auto error = lsn_errors.find(*request.group);
	if (error != lsn_errors.end()) return fail(error->second);
	request.view = manager.resolve(request.dependency);
	if (request.view.state == DependencyState::Invalid) return fail(request.view.reason);
	if (request.view.source && (request.view.source->generation != current.generation ||
		(current.writer && !(*request.view.source == *current.writer)))) return fail(Reason::HistoryChanged);
	if (session_fast_forward != SESSION_FORWARD_TYPE_NONE && destination != current.config.writer_hostgroup)
		return fail(Reason::NoSafeBackend);
	if (const auto* pinned = lsn_pinned_backend()) {
		if (pinned->lsn_stamp->group != *request.group) return fail(Reason::NoSafeBackend);
		request.route_hostgroup = pinned->parent->myhgc->hid;
		// The snapshot was admitted before the transaction/cycle began. Continuing
		// it must not move to another backend or acquire a second snapshot.
		for (const auto& progress : current.servers)
			if (progress.valid && progress.server == *pinned->lsn_stamp) return LsnAdmission::Proceed;
		return fail(Reason::NoSafeBackend);
	}
	bool available = false;
	for (const auto& progress : current.servers) available |= eligible(request, progress);
	if (available && (!request.waiting_for_pool || now < request.deadline || request.fallback))
		return LsnAdmission::Proceed;
	if (request.fallback) return fail(Reason::NoSafeBackend);
	if (now < request.deadline) return LsnAdmission::Wait;
	request.route_hostgroup = current.config.writer_hostgroup;
	if (locked_on_hostgroup >= 0 && static_cast<uint32_t>(locked_on_hostgroup) != request.route_hostgroup)
		return fail(Reason::NoSafeBackend);
	for (const auto& progress : current.servers) {
		if (eligible(request, progress)) {
			request.fallback = true; request.waiting_for_pool = false;
			return LsnAdmission::UseWriter;
		}
	}
	return fail(Reason::NoSafeBackend);
}

bool PgSQL_Session::lsn_server_allowed(const PgSQL_SrvC& server) const {
	const auto& request = lsn_request;
	if (!request.group) return true;
	if (request.error != Reason::None || request.cancelled || !server.myhgc ||
		server.myhgc->hid != request.route_hostgroup) return false;
	if (const auto* pinned = lsn_pinned_backend()) return pinned->parent == &server;
	for (const auto& progress : request.snapshot.servers)
		if (progress.server.endpoint == Endpoint{server.address,server.port} && eligible(request,progress)) return true;
	return false;
}
bool PgSQL_Session::lsn_backend_allowed(const PgSQL_Connection& conn, bool allow_unstamped) const {
	if (!lsn_request.group) return true;
	if (!conn.parent || !lsn_server_allowed(*conn.parent)) return false;
	if (const auto* pinned = lsn_pinned_backend()) return pinned == &conn;
	if (!conn.lsn_stamp) return allow_unstamped;
	for (const auto& progress : lsn_request.snapshot.servers)
		if (progress.server == *conn.lsn_stamp && eligible(lsn_request,progress)) return true;
	return false;
}
bool PgSQL_Session::lsn_cache_allowed(int destination) const {
	if (!PgHGM || destination < 0) return true;
	auto& manager = PgHGM->lsn_manager();
	const auto group = lsn_request.group ? lsn_request.group : manager.group_for_hostgroup(destination);
	if (!group) return true;
	if (lsn_request.group && (lsn_request.error != Reason::None || lsn_request.cancelled)) return false;
	if (manager.snapshot(*group).activation_epoch > lsn_birth_epoch || lsn_errors.count(*group) ||
		lsn_pinned_backend()) return false;
	const auto dependency = lsn_dependencies.find(*group);
	return dependency == lsn_dependencies.end() || manager.resolve(dependency->second).state == DependencyState::Clean;
}
void PgSQL_Session::lsn_finish_request() {
	if (thread) thread->lsn_waiter_leave(this);
	lsn_request = {};
}
bool PgSQL_Session::lsn_route_request() {
	if (!thread || current_hostgroup < 0 || connections_handler || mirror) return true;
	// Once sent, consume the current application response. Re-admission is for
	// the next snapshot, and must not interrupt an already running statement.
	auto* stream = mybe ? mybe->server_myds : nullptr;
	auto* conn = stream ? stream->myconn : nullptr;
	if (conn && conn->lsn_application_cycle_active && conn->async_state_machine != ASYNC_IDLE)
		return true;
	auto action = lsn_admit(current_hostgroup, thread->curtime);
	if (!lsn_request.group) return true;
	auto refuse = [&]() {
		const auto code = lsn_request.cancelled ? PGSQL_ERROR_CODES::ERRCODE_QUERY_CANCELED :
			PGSQL_ERROR_CODES::ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE;
		const char* message = lsn_request.cancelled ? "canceling statement while waiting for causal LSN admission" :
			reason_code(lsn_request.error);
		const bool permanent_forward = session_fast_forward != SESSION_FORWARD_TYPE_NONE &&
			!(session_fast_forward & SESSION_FORWARD_TYPE_TEMPORARY);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true,true,message,code,permanent_forward,true);
		if (permanent_forward) healthy=0;
		if (stream && stream->myconn && (stream->myconn->lsn_bootstrap_active ||
			!stream->myconn->healthy || stream->myconn->async_state_machine != ASYNC_IDLE))
			stream->destroy_MySQL_Connection_From_Pool(false);
		while (!previous_status.empty()) previous_status.pop();
		if (status != PROCESSING_QUERY && !permanent_forward) reset_extended_query_frame();
		RequestEnd(stream,true);
		if (stream) { stream->cancel_query=false; stream->wait_until=0; }
		return false;
	};
	if (action == LsnAdmission::Error) return refuse();
	if (action == LsnAdmission::Wait) {
		to_process=0;
		thread->lsn_waiter_enter(this);
		return false;
	}
	const auto route=lsn_request.route_hostgroup;
	if (locked_on_hostgroup >= 0 && static_cast<unsigned>(locked_on_hostgroup) != route) {
		lsn_request.error=Reason::NoSafeBackend;
		return refuse();
	}
	if (mybe && static_cast<unsigned>(mybe->hostgroup_id) != route) {
		if (conn && (conn->MultiplexDisabled(false) || lsn_pinned_backend())) {
			lsn_request.error=Reason::NoSafeBackend;
			return refuse();
		}
		if (conn) stream->destroy_MySQL_Connection_From_Pool(false);
		auto* next=find_or_create_backend(route);
		if (stream && stream != next->server_myds) {
			auto* target=next->server_myds;
			assert(!target->pgsql_real_query.QueryPtr);
			target->pgsql_real_query=stream->pgsql_real_query;
			stream->pgsql_real_query.reset();
			target->query_retries_on_failure=stream->query_retries_on_failure;
			target->connect_retries_on_failure=stream->connect_retries_on_failure;
			target->max_connect_time=stream->max_connect_time;
		}
		mybe=next; stream=next->server_myds; conn=stream->myconn;
	}
	current_hostgroup=route;
	if (conn && !lsn_backend_allowed(*conn,true)) {
		if (lsn_pinned_backend() || conn->MultiplexDisabled(false)) {
			lsn_request.error=Reason::NoSafeBackend;
			return refuse();
		}
		stream->destroy_MySQL_Connection_From_Pool(false);
		stream->DSS=STATE_NOT_INITIALIZED;
	}
	if (lsn_request.waiting_for_pool) thread->lsn_waiter_enter(this);
	else thread->lsn_waiter_leave(this);
	return true;
}
void PgSQL_Thread::lsn_waiter_enter(PgSQL_Session* session) {
	if (!session->lsn_request.group) return;
	session->to_process=0;
	auto& node = session->lsn_waiter_node;
	if (!node.owner) {
		node.session = session; node.hid = *session->lsn_request.group;
		lsn_waiters.push_back(node); ++lsn_waiter_count;
	}
	// Register before rechecking publication: a notification racing this call
	// either wakes this worker or is observed by the revision comparison.
	if (PgHGM->lsn_manager().snapshot(node.hid).revision != session->lsn_request.snapshot.revision)
		session->to_process = 1;
}
void PgSQL_Thread::lsn_waiter_leave(PgSQL_Session* session) {
	auto& node = session->lsn_waiter_node;
	if (node.owner != &lsn_waiters) return;
	lsn_waiters.unlink(node); node.session=nullptr; --lsn_waiter_count;
}
void PgSQL_Thread::process_lsn_waiters(Micros now) {
	lsn_waiters.for_each_hid([&](unsigned group, PgSQL_LSN_Waiter_Node* head) {
		const auto revision = PgHGM->lsn_manager().snapshot(group).revision;
		for (auto* node=head; node; node=node->next) {
			auto* session = static_cast<PgSQL_Session*>(node->session);
			const auto& request=session->lsn_request;
			if (revision != request.snapshot.revision || session->killed ||
				(session->mybe && session->mybe->server_myds && session->mybe->server_myds->cancel_query) ||
				(!request.fallback && now >= request.deadline) ||
				(request.query_deadline && now >= request.query_deadline) || request.waiting_for_pool) {
				session->to_process=1; session->pause_until=0;
			}
		}
	});
}
int PgSQL_Thread::lsn_poll_timeout(int ms, Micros now) const {
	// The list structure is not modified by iteration; it is owned by this worker.
	const_cast<PgSQL_LSN_Waiter_List&>(lsn_waiters).for_each_hid([&](unsigned, PgSQL_LSN_Waiter_Node* head) {
		for (auto* node=head; node; node=node->next) {
			const auto* session=static_cast<const PgSQL_Session*>(node->session);
			const auto& request=session->lsn_request;
			Micros deadline=request.fallback ? 0 : request.deadline;
			if (request.query_deadline && (!deadline || request.query_deadline<deadline)) deadline=request.query_deadline;
			if (deadline) ms=std::min(ms, int(std::min<Micros>(deadline>now ? (deadline-now+999)/1000 : 0, INT_MAX)));
			if (request.waiting_for_pool) ms=std::min(ms,std::max(1,pgsql_thread___lsn_poll_interval));
			if (session->to_process || session->killed) ms=0;
		}
	});
	return ms;
}
