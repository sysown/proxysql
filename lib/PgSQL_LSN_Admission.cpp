#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Session.h"
#include "PgSQL_Thread.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Backend.h"
#include "PgSQL_Query_Processor.h"
#include "PgSQL_ExplicitTxnStateMgr.h"
#include "PgSQL_Extended_Query_Message.h"

#ifdef PROXYSQL31
extern PgSQL_HostGroups_Manager* PgHGM;
using namespace pgsql_lsn;

namespace {
bool lsn_has_transaction_work(const PgSQL_Connection& conn) {
	return conn.last_ready_for_query_status() != 'I' || conn.native_unsynced_work ||
		conn.lsn_application_cycle_active;
}
}

void PgSQL_Session::record_lsn_completion(const PgSQL_Connection& conn, Micros completed_at) {
	if (!conn.parent || !conn.parent->myhgc) return;
	auto* backend = find_backend(conn.parent->myhgc->hid);
	if (!backend) return;
	auto& record = backend->last_execution;
	// Ordinary completions allocate only when the physical endpoint changes.
	if (record.endpoint.address != conn.parent->address)
		record.endpoint.address = conn.parent->address;
	record.endpoint.port = conn.parent->port;
	record.completed_at = completed_at;
}

PgSQL_LSN_PrepareResult PgSQL_Session::lsn_prepare_request() {
	auto& request = lsn_request;
	if (!request.initialized) {
		request.initialized = true;
		if (!qpo || qpo->lsn_from_hostgroup < 0 || connections_handler || mirror ||
			(session_fast_forward != SESSION_FORWARD_TYPE_NONE &&
			 !(session_fast_forward & SESSION_FORWARD_TYPE_TEMPORARY)))
			return PgSQL_LSN_PrepareResult::Disabled;
		request.source_hostgroup = qpo->lsn_from_hostgroup;
		if (auto* backend = find_backend(request.source_hostgroup))
			request.source = backend->last_execution;
	}
	if (!lsn_has_dependency()) return PgSQL_LSN_PrepareResult::Disabled;
	if (request.error) return PgSQL_LSN_PrepareResult::Error;
	if (!PgHGM) return request.required ? PgSQL_LSN_PrepareResult::Ready : PgSQL_LSN_PrepareResult::Pending;
	const auto result = PgHGM->lsn_manager().lookup_after(request.source.endpoint, request.source.completed_at);
	if (result.state == LookupState::HistoryChanged) {
		request.error = "LSN_HISTORY_CHANGED: source server history changed after the recorded execution";
		return PgSQL_LSN_PrepareResult::Error;
	}
	// Keep the copied target through pruning/withdrawal, but honor an observed
	// source history reset even when this request resolved on an earlier retry.
	if (request.required) return PgSQL_LSN_PrepareResult::Ready;
	if (result.state != LookupState::Ready || !result.required)
		return PgSQL_LSN_PrepareResult::Pending;
	request.required = result.required;
	return PgSQL_LSN_PrepareResult::Ready;
}

bool PgSQL_Session::lsn_server_allowed(const PgSQL_SrvC& server) const {
	if (!lsn_has_dependency()) return true;
	if (!PgHGM || !lsn_request.required || lsn_request.error) return false;
	const auto progress = PgHGM->lsn_manager().latest({server.address, server.port});
	return progress && progress->valid &&
		progress->history == lsn_request.required->history &&
		progress->sample.lsn >= lsn_request.required->lsn;
}

bool PgSQL_Session::lsn_backend_allowed(const PgSQL_Connection& conn) const {
	if (!lsn_has_dependency()) return true;
	return conn.parent && lsn_server_allowed(*conn.parent);
}

const PgSQL_Connection* PgSQL_Session::lsn_pinned_backend() const {
	if (!mybes) return nullptr;
	const char* portal_name = CurrentQuery.extended_query_info.stmt_client_portal_name;
	if (portal_name && *portal_name) {
		const auto portal = named_portals.find(portal_name);
		if (portal != named_portals.end() && portal->second.bound_conn)
			return portal->second.bound_conn;
	}
	const auto has_portal = [this](const PgSQL_Connection* conn) {
		for (const auto& portal : named_portals)
			if (portal.second.bound_conn == conn) return true;
		return false;
	};
	if (transaction_persistent_hostgroup >= 0) {
		for (unsigned i=0; i<mybes->len; ++i) {
			const auto* backend = static_cast<const PgSQL_Backend*>(mybes->index(i));
			if (backend->hostgroup_id == transaction_persistent_hostgroup && backend->server_myds &&
				backend->server_myds->myconn) return backend->server_myds->myconn;
		}
	}
	auto* current = mybe && mybe->server_myds ? mybe->server_myds->myconn : nullptr;
	if (current && (lsn_has_transaction_work(*current) || current->MultiplexDisabled() || has_portal(current)))
		return current;
	// A live transaction or portal still owns its backend when routing chose another HG.
	// An unrelated idle nonmultiplexed connection does not own this request.
	for (unsigned i=0; i<mybes->len; ++i) {
		const auto* backend = static_cast<const PgSQL_Backend*>(mybes->index(i));
		auto* conn = backend->server_myds ? backend->server_myds->myconn : nullptr;
		if (!conn) continue;
		if (lsn_has_transaction_work(*conn) || has_portal(conn)) return conn;
	}
	return nullptr;
}

void PgSQL_Session::lsn_fail_request(const char* message, bool cancelled) {
	const auto* pinned = lsn_pinned_backend();
	bool explicit_txn = is_in_transaction() ||
		(pinned && pinned->last_ready_for_query_status() != 'I');
	for (unsigned i=0; mybes && i<mybes->len; ++i) {
		const auto* backend = static_cast<const PgSQL_Backend*>(mybes->index(i));
		const auto* conn = backend->server_myds ? backend->server_myds->myconn : nullptr;
		if (conn && conn->last_ready_for_query_status() != 'I') explicit_txn = true;
	}
	// Poison recovery answers ROLLBACK locally. No transaction it aborts may survive
	// on another hostgroup; unrelated idle connections and their portals stay intact.
	for (unsigned i=0; mybes && i<mybes->len; ++i) {
		auto* backend = static_cast<PgSQL_Backend*>(mybes->index(i));
		auto* stream = backend->server_myds;
		auto* conn = stream ? stream->myconn : nullptr;
		if (conn && (conn == pinned || (explicit_txn && lsn_has_transaction_work(*conn)))) {
			stream->destroy_MySQL_Connection_From_Pool(false);
			if (transaction_persistent_hostgroup == backend->hostgroup_id)
				transaction_persistent_hostgroup = -1;
		}
	}
	if (explicit_txn) {
		if (!tx_poisoned && thread) ++thread->status_variables.tx_poisoned_total;
		tx_poisoned = true;
	}
	if ((pinned || explicit_txn) && transaction_state_manager) transaction_state_manager->reset_state();
	active_transactions = NumActiveTransactions();
	if (!active_transactions) transaction_started_at = 0;
	if (thread) thread->leave_waiter(this);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	client_myds->myprot.generate_error_packet(true, false, message,
		cancelled ? PGSQL_ERROR_CODES::ERRCODE_QUERY_CANCELED :
		PGSQL_ERROR_CODES::ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE, false, true);
	client_myds->myprot.generate_ready_for_query_packet(true, explicit_txn ? 'E' : 'I');
	RequestEnd(mybe ? mybe->server_myds : nullptr, true);
	// RequestEnd logs names borrowed from the pending Bind and portal entries.
	// Discard their owners only after it has finished reading those pointers.
	reset_extended_query_frame();
	pending_named_bind.bind_msg.reset();
	pending_named_bind.stmt_info.reset();
	pending_named_bind.portal_name.clear();
	pending_named_bind.active = false;
	closing_portal_name.clear();
	while (!previous_status.empty()) previous_status.pop();
	if (mybe && mybe->server_myds) mybe->server_myds->max_connect_time = 0;
	status = WAITING_CLIENT_DATA;
	client_myds->DSS = STATE_SLEEP;
}

bool PgSQL_Session::lsn_route_request() {
	auto* stream = mybe ? mybe->server_myds : nullptr;
	auto* conn = stream ? stream->myconn : nullptr;
	// Finish an already dispatched operation through the normal state machine.
	if (conn && conn->async_state_machine != ASYNC_IDLE) return true;
	const auto prepared = lsn_prepare_request();
	if (prepared == PgSQL_LSN_PrepareResult::Disabled) return true;
	if (killed || (stream && stream->cancel_query)) {
		lsn_fail_request("canceling statement while acquiring an LSN-eligible backend", true);
		return false;
	}
	if (prepared == PgSQL_LSN_PrepareResult::Error) {
		lsn_fail_request(lsn_request.error);
		return false;
	}
	if (const auto* pinned = lsn_pinned_backend()) {
		if (pinned != conn || !lsn_backend_allowed(*pinned)) {
			lsn_fail_request("LSN_NO_SAFE_BACKEND: pinned backend cannot satisfy the source execution");
			return false;
		}
	}
	if (conn && !lsn_backend_allowed(*conn)) {
		// Retry ordinary acquisition in the same HG; the request's target survives.
		stream->return_MySQL_Connection_To_Pool();
		stream->DSS = STATE_NOT_INITIALIZED;
	}
	return true;
}
#endif
