/*
 * ProxySQL_Raft.cpp — Raft leader-election implementation for ProxySQL clustering
 *
 * Election-only Raft using NuRaft. No application data flows through Raft;
 * it is used solely for leader election and heartbeats. On becoming leader,
 * epoch values are bumped on all config modules so the existing checksum-based
 * cluster sync mechanism propagates configuration from the new leader.
 */

#include "proxysql.h"
#include "cpp.h"
#include "ProxySQL_Raft.h"

#include <cstring>
#include <ctime>

// ===================================================================
// ProxySQL_Raft_StateMachine
// ===================================================================

nuraft::ptr<nuraft::buffer> ProxySQL_Raft_StateMachine::commit(
		const nuraft::ulong log_idx, nuraft::buffer& /*data*/) {
	last_committed_idx_.store(log_idx);
	return nullptr;
}

bool ProxySQL_Raft_StateMachine::apply_snapshot(nuraft::snapshot& /*s*/) {
	return true;
}

nuraft::ptr<nuraft::snapshot> ProxySQL_Raft_StateMachine::last_snapshot() {
	return nullptr;
}

nuraft::ulong ProxySQL_Raft_StateMachine::last_commit_index() {
	return last_committed_idx_.load();
}

void ProxySQL_Raft_StateMachine::create_snapshot(
		nuraft::snapshot& /*s*/,
		nuraft::async_result<bool>::handler_type& when_done) {
	nuraft::ptr<std::exception> except(nullptr);
	bool ret = true;
	when_done(ret, except);
}

// ===================================================================
// ProxySQL_Raft_LogStore
// ===================================================================

ProxySQL_Raft_LogStore::ProxySQL_Raft_LogStore()
	: start_idx_(1)
{
	// NuRaft convention: dummy entry at index 0
	nuraft::ptr<nuraft::buffer> buf = nuraft::buffer::alloc(sizeof(nuraft::ulong));
	buf->put(static_cast<nuraft::ulong>(0));
	buf->pos(0);
	auto dummy = nuraft::cs_new<nuraft::log_entry>(
		0, buf, nuraft::log_val_type::app_log);
	logs_[0] = dummy;
}

nuraft::ulong ProxySQL_Raft_LogStore::next_slot() const {
	std::lock_guard<std::mutex> lock(logs_lock_);
	if (logs_.empty()) {
		return start_idx_;
	}
	return logs_.rbegin()->first + 1;
}

nuraft::ulong ProxySQL_Raft_LogStore::start_index() const {
	return start_idx_;
}

nuraft::ptr<nuraft::log_entry> ProxySQL_Raft_LogStore::last_entry() const {
	std::lock_guard<std::mutex> lock(logs_lock_);
	if (logs_.empty()) {
		// Return a dummy entry with term 0 and null buffer
		return nuraft::cs_new<nuraft::log_entry>(
			0, nuraft::ptr<nuraft::buffer>(nullptr));
	}
	return make_clone(logs_.rbegin()->second);
}

nuraft::ulong ProxySQL_Raft_LogStore::append(
		nuraft::ptr<nuraft::log_entry>& entry) {
	std::lock_guard<std::mutex> lock(logs_lock_);
	nuraft::ulong idx = logs_.empty() ? start_idx_ : logs_.rbegin()->first + 1;
	logs_[idx] = make_clone(entry);
	return idx;
}

void ProxySQL_Raft_LogStore::write_at(
		nuraft::ulong index,
		nuraft::ptr<nuraft::log_entry>& entry) {
	std::lock_guard<std::mutex> lock(logs_lock_);
	// Truncate all entries from index onward
	auto it = logs_.lower_bound(index);
	while (it != logs_.end()) {
		it = logs_.erase(it);
	}
	logs_[index] = make_clone(entry);
}

nuraft::ptr<std::vector<nuraft::ptr<nuraft::log_entry>>>
ProxySQL_Raft_LogStore::log_entries(nuraft::ulong start, nuraft::ulong end) {
	auto result = nuraft::cs_new<std::vector<nuraft::ptr<nuraft::log_entry>>>();
	std::lock_guard<std::mutex> lock(logs_lock_);
	for (nuraft::ulong i = start; i < end; i++) {
		auto it = logs_.find(i);
		if (it != logs_.end()) {
			result->push_back(make_clone(it->second));
		}
	}
	return result;
}

nuraft::ptr<nuraft::log_entry> ProxySQL_Raft_LogStore::entry_at(
		nuraft::ulong index) {
	std::lock_guard<std::mutex> lock(logs_lock_);
	auto it = logs_.find(index);
	if (it != logs_.end()) {
		return make_clone(it->second);
	}
	return nullptr;
}

nuraft::ulong ProxySQL_Raft_LogStore::term_at(nuraft::ulong index) {
	std::lock_guard<std::mutex> lock(logs_lock_);
	auto it = logs_.find(index);
	if (it != logs_.end()) {
		return it->second->get_term();
	}
	return 0;
}

nuraft::ptr<nuraft::buffer> ProxySQL_Raft_LogStore::pack(
		nuraft::ulong index, nuraft::int32 cnt) {
	std::lock_guard<std::mutex> lock(logs_lock_);

	// Calculate total buffer size
	std::vector<nuraft::ptr<nuraft::buffer>> serialized;
	size_t total_size = sizeof(nuraft::int32); // count header

	for (nuraft::int32 i = 0; i < cnt; i++) {
		auto it = logs_.find(index + i);
		if (it == logs_.end()) break;
		nuraft::ptr<nuraft::buffer> buf = it->second->serialize();
		total_size += sizeof(nuraft::int32) + buf->size();
		serialized.push_back(buf);
	}

	nuraft::ptr<nuraft::buffer> result = nuraft::buffer::alloc(total_size);
	result->put(static_cast<nuraft::int32>(serialized.size()));
	for (auto& buf : serialized) {
		result->put(static_cast<nuraft::int32>(buf->size()));
		result->put(*buf);
	}
	result->pos(0);
	return result;
}

void ProxySQL_Raft_LogStore::apply_pack(
		nuraft::ulong index, nuraft::buffer& pack) {
	std::lock_guard<std::mutex> lock(logs_lock_);

	pack.pos(0);
	nuraft::int32 cnt = pack.get_int();
	for (nuraft::int32 i = 0; i < cnt; i++) {
		nuraft::int32 buf_size = pack.get_int();
		nuraft::ptr<nuraft::buffer> buf = nuraft::buffer::alloc(buf_size);
		pack.get(buf);
		auto entry = nuraft::log_entry::deserialize(*buf);
		logs_[index + i] = entry;
	}
}

bool ProxySQL_Raft_LogStore::compact(nuraft::ulong last_log_index) {
	std::lock_guard<std::mutex> lock(logs_lock_);
	auto it = logs_.begin();
	while (it != logs_.end()) {
		if (it->first <= last_log_index) {
			it = logs_.erase(it);
		} else {
			break;
		}
	}
	if (start_idx_ <= last_log_index) {
		start_idx_ = last_log_index + 1;
	}
	return true;
}

bool ProxySQL_Raft_LogStore::flush() {
	// In-memory store: nothing to flush
	return true;
}

nuraft::ptr<nuraft::log_entry> ProxySQL_Raft_LogStore::make_clone(
		const nuraft::ptr<nuraft::log_entry>& entry) {
	nuraft::ptr<nuraft::buffer> cloned_buf = nullptr;
	if (!entry->is_buf_null()) {
		cloned_buf = nuraft::buffer::clone(entry->get_buf());
	}
	return nuraft::cs_new<nuraft::log_entry>(
		entry->get_term(), cloned_buf, entry->get_val_type());
}

// ===================================================================
// ProxySQL_Raft_StateManager
// ===================================================================

ProxySQL_Raft_StateManager::ProxySQL_Raft_StateManager(
		int node_id,
		const std::string& my_raft_addr,
		const std::vector<ProxySQL_Raft_Node>& cluster_nodes)
	: node_id_(node_id)
	, my_raft_addr_(my_raft_addr)
	, cluster_nodes_(cluster_nodes)
	, log_store_(nuraft::cs_new<ProxySQL_Raft_LogStore>())
{
}

nuraft::ptr<nuraft::cluster_config> ProxySQL_Raft_StateManager::load_config() {
	auto config = nuraft::cs_new<nuraft::cluster_config>();
	for (const auto& node : cluster_nodes_) {
		std::string endpoint = node.hostname + ":" + std::to_string(node.raft_port);
		auto srv = nuraft::cs_new<nuraft::srv_config>(node.id, endpoint);
		config->get_servers().push_back(srv);
	}
	return config;
}

void ProxySQL_Raft_StateManager::save_config(
		const nuraft::cluster_config& /*config*/) {
	// No-op: ephemeral state, re-elect on restart
}

void ProxySQL_Raft_StateManager::save_state(
		const nuraft::srv_state& /*state*/) {
	// No-op: ephemeral state, re-elect on restart
}

nuraft::ptr<nuraft::srv_state> ProxySQL_Raft_StateManager::read_state() {
	return nuraft::cs_new<nuraft::srv_state>();
}

nuraft::ptr<nuraft::log_store> ProxySQL_Raft_StateManager::load_log_store() {
	return log_store_;
}

nuraft::int32 ProxySQL_Raft_StateManager::server_id() {
	return node_id_;
}

void ProxySQL_Raft_StateManager::system_exit(const int /*exit_code*/) {
	// No-op
}

// ===================================================================
// ProxySQL_Raft_Manager
// ===================================================================

ProxySQL_Raft_Manager::~ProxySQL_Raft_Manager() {
	stop();
}

void ProxySQL_Raft_Manager::start(
		int node_id,
		int raft_port,
		int heartbeat_ms,
		int election_timeout_ms,
		const std::vector<ProxySQL_Raft_Node>& cluster_nodes) {

	node_id_ = node_id;
	cluster_nodes_ = cluster_nodes;

	// Build this node's raft address for the state manager
	std::string my_raft_addr;
	for (const auto& node : cluster_nodes_) {
		if (node.id == node_id) {
			my_raft_addr = node.hostname + ":" + std::to_string(node.raft_port);
			break;
		}
	}

	auto sm = nuraft::cs_new<ProxySQL_Raft_StateMachine>();
	auto smgr = nuraft::cs_new<ProxySQL_Raft_StateManager>(
		node_id, my_raft_addr, cluster_nodes_);

	// Configure Raft parameters
	nuraft::raft_params params;
	params.heart_beat_interval_ = heartbeat_ms;
	params.election_timeout_lower_bound_ = election_timeout_ms;
	params.election_timeout_upper_bound_ = election_timeout_ms * 2;
	params.reserved_log_items_ = 5;
	params.snapshot_distance_ = 0;  // No Raft snapshots
	params.client_req_timeout_ = 3000;
	params.return_method_ = nuraft::raft_params::blocking;

	// ASIO options
	nuraft::asio_service::options asio_opts;
	asio_opts.thread_pool_size_ = 2;

	// Init options with leadership callbacks
	nuraft::raft_server::init_options init_opts;
	init_opts.raft_callback_ = [this](nuraft::cb_func::Type type,
	                                   nuraft::cb_func::Param* param)
		-> nuraft::cb_func::ReturnCode
	{
		if (type == nuraft::cb_func::BecomeLeader) {
			on_become_leader();
		} else if (type == nuraft::cb_func::BecomeFollower) {
			int lid = param ? param->leaderId : 0;
			on_become_follower(lid);
		}
		return nuraft::cb_func::Ok;
	};

	// Launch NuRaft
	launcher_ = std::make_unique<nuraft::raft_launcher>();
	raft_instance_ = launcher_->init(
		sm, smgr, nullptr, raft_port, asio_opts, params, init_opts);

	if (!raft_instance_) {
		proxy_error("Raft: failed to initialize NuRaft on port %d\n", raft_port);
		return;
	}

	proxy_info("Raft: node %d started on port %d "
	           "(heartbeat=%dms, election_timeout=%d-%dms, nodes=%zu)\n",
	           node_id, raft_port,
	           heartbeat_ms, election_timeout_ms, election_timeout_ms * 2,
	           cluster_nodes_.size());
}

void ProxySQL_Raft_Manager::stop() {
	if (launcher_) {
		proxy_info("Raft: shutting down node %d\n", node_id_);
		launcher_->shutdown(5);
		launcher_.reset();
		raft_instance_.reset();
	}
}

bool ProxySQL_Raft_Manager::is_leader() const {
	return is_leader_.load();
}

uint64_t ProxySQL_Raft_Manager::current_term() const {
	if (raft_instance_) {
		return raft_instance_->get_term();
	}
	return current_term_.load();
}

bool ProxySQL_Raft_Manager::get_leader_info(char** hostname, uint16_t* port) {
	int lid = leader_id_.load();
	if (lid == 0 && is_leader_.load()) {
		lid = node_id_;
	}
	if (lid == 0) {
		return false;
	}

	for (const auto& node : cluster_nodes_) {
		if (node.id == lid) {
			*hostname = strdup(node.hostname.c_str());
			*port = node.raft_port;
			return true;
		}
	}
	return false;
}

void ProxySQL_Raft_Manager::on_become_leader() {
	is_leader_.store(true);
	leader_id_.store(node_id_);

	proxy_info("Raft: node %d became LEADER (term %" PRIu64 ")\n",
	           node_id_,
	           raft_instance_ ? raft_instance_->get_term() : 0);

	// CRITICAL: Bump epoch on all config modules so that the existing
	// checksum-based cluster sync mechanism will push config from the
	// new leader to all followers.
	unsigned long long new_epoch = time(NULL);
	pthread_mutex_lock(&GloVars.checksum_mutex);
	__sync_lock_test_and_set(&GloVars.checksums_values.admin_variables.epoch, new_epoch);
	__sync_lock_test_and_set(&GloVars.checksums_values.mysql_query_rules.epoch, new_epoch);
	__sync_lock_test_and_set(&GloVars.checksums_values.mysql_servers.epoch, new_epoch);
	__sync_lock_test_and_set(&GloVars.checksums_values.mysql_servers_v2.epoch, new_epoch);
	__sync_lock_test_and_set(&GloVars.checksums_values.mysql_users.epoch, new_epoch);
	__sync_lock_test_and_set(&GloVars.checksums_values.mysql_variables.epoch, new_epoch);
	__sync_lock_test_and_set(&GloVars.checksums_values.proxysql_servers.epoch, new_epoch);
	__sync_lock_test_and_set(&GloVars.checksums_values.ldap_variables.epoch, new_epoch);
	pthread_mutex_unlock(&GloVars.checksum_mutex);

	proxy_info("Raft: bumped config epochs to %llu for cluster sync\n", new_epoch);
}

void ProxySQL_Raft_Manager::on_become_follower(int leader_id) {
	is_leader_.store(false);
	leader_id_.store(leader_id);

	proxy_info("Raft: node %d became FOLLOWER (leader=%d, term %" PRIu64 ")\n",
	           node_id_, leader_id,
	           raft_instance_ ? raft_instance_->get_term() : 0);
}
