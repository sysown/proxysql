/*
 * ProxySQL_Raft.h — Raft leader-election classes for ProxySQL clustering
 *
 * Uses NuRaft in "election-only" mode: no application data flows through Raft,
 * it is used solely for leader election and heartbeats. On leadership change,
 * the existing checksum-based config-sync mechanism is triggered by bumping
 * epoch values on all config modules.
 */

#ifndef CLASS_PROXYSQL_RAFT_H
#define CLASS_PROXYSQL_RAFT_H

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <libnuraft/nuraft.hxx>

/**
 * Descriptor for a single ProxySQL node in the Raft cluster.
 */
struct ProxySQL_Raft_Node {
	int id;               // unique node ID (1-based)
	std::string hostname;
	uint16_t raft_port;
};

/**
 * No-op state machine for election-only Raft.
 * commit() just tracks last_committed_idx; no application state is modified.
 */
class ProxySQL_Raft_StateMachine : public nuraft::state_machine {
public:
	ProxySQL_Raft_StateMachine() = default;

	nuraft::ptr<nuraft::buffer> commit(const nuraft::ulong log_idx,
	                                   nuraft::buffer& data) override;

	bool apply_snapshot(nuraft::snapshot& s) override;

	nuraft::ptr<nuraft::snapshot> last_snapshot() override;

	nuraft::ulong last_commit_index() override;

	void create_snapshot(nuraft::snapshot& s,
	                     nuraft::async_result<bool>::handler_type& when_done) override;

private:
	std::atomic<uint64_t> last_committed_idx_{0};
};

/**
 * In-memory, ephemeral log store. Lost on restart (re-election occurs).
 */
class ProxySQL_Raft_LogStore : public nuraft::log_store {
public:
	ProxySQL_Raft_LogStore();

	nuraft::ulong next_slot() const override;
	nuraft::ulong start_index() const override;
	nuraft::ptr<nuraft::log_entry> last_entry() const override;
	nuraft::ulong append(nuraft::ptr<nuraft::log_entry>& entry) override;
	void write_at(nuraft::ulong index, nuraft::ptr<nuraft::log_entry>& entry) override;
	nuraft::ptr<std::vector<nuraft::ptr<nuraft::log_entry>>>
		log_entries(nuraft::ulong start, nuraft::ulong end) override;
	nuraft::ptr<nuraft::log_entry> entry_at(nuraft::ulong index) override;
	nuraft::ulong term_at(nuraft::ulong index) override;
	nuraft::ptr<nuraft::buffer> pack(nuraft::ulong index, nuraft::int32 cnt) override;
	void apply_pack(nuraft::ulong index, nuraft::buffer& pack) override;
	bool compact(nuraft::ulong last_log_index) override;
	bool flush() override;

private:
	static nuraft::ptr<nuraft::log_entry> make_clone(
		const nuraft::ptr<nuraft::log_entry>& entry);

	mutable std::mutex logs_lock_;
	std::map<nuraft::ulong, nuraft::ptr<nuraft::log_entry>> logs_;
	nuraft::ulong start_idx_;
};

/**
 * State manager providing static cluster configuration to NuRaft.
 * All state is ephemeral — on restart the node re-joins and re-elects.
 */
class ProxySQL_Raft_StateManager : public nuraft::state_mgr {
public:
	ProxySQL_Raft_StateManager(int node_id,
	                           const std::string& my_raft_addr,
	                           const std::vector<ProxySQL_Raft_Node>& cluster_nodes);

	nuraft::ptr<nuraft::cluster_config> load_config() override;
	void save_config(const nuraft::cluster_config& config) override;
	void save_state(const nuraft::srv_state& state) override;
	nuraft::ptr<nuraft::srv_state> read_state() override;
	nuraft::ptr<nuraft::log_store> load_log_store() override;
	nuraft::int32 server_id() override;
	void system_exit(const int exit_code) override;

private:
	int node_id_;
	std::string my_raft_addr_;
	std::vector<ProxySQL_Raft_Node> cluster_nodes_;
	nuraft::ptr<ProxySQL_Raft_LogStore> log_store_;
};

/**
 * Orchestrator: initializes NuRaft, handles leadership callbacks,
 * and exposes leader state to the rest of ProxySQL.
 */
class ProxySQL_Raft_Manager {
public:
	ProxySQL_Raft_Manager() = default;
	~ProxySQL_Raft_Manager();

	/**
	 * Initialize and start the Raft subsystem.
	 *
	 * @param node_id           This node's unique ID (1-based).
	 * @param raft_port         Port for Raft RPC.
	 * @param heartbeat_ms      Heartbeat interval in milliseconds.
	 * @param election_timeout_ms  Election timeout lower bound (upper = 2x).
	 * @param cluster_nodes     All nodes in the cluster (including self).
	 */
	void start(int node_id,
	           int raft_port,
	           int heartbeat_ms,
	           int election_timeout_ms,
	           const std::vector<ProxySQL_Raft_Node>& cluster_nodes);

	/**
	 * Shut down the Raft subsystem gracefully.
	 */
	void stop();

	/**
	 * @return true if this node is currently the Raft leader.
	 */
	bool is_leader() const;

	/**
	 * @return Current Raft term number.
	 */
	uint64_t current_term() const;

	/**
	 * Get the leader's hostname and raft_port from the cluster node list.
	 *
	 * @param[out] hostname  Set to leader's hostname (caller must free).
	 * @param[out] port      Set to leader's raft_port.
	 * @return true if leader info is available, false otherwise.
	 */
	bool get_leader_info(char** hostname, uint16_t* port);

private:
	void on_become_leader();
	void on_become_follower(int leader_id);

	std::atomic<bool> is_leader_{false};
	std::atomic<int> leader_id_{0};
	std::atomic<uint64_t> current_term_{0};
	int node_id_{0};

	std::vector<ProxySQL_Raft_Node> cluster_nodes_;
	std::unique_ptr<nuraft::raft_launcher> launcher_;
	nuraft::ptr<nuraft::raft_server> raft_instance_;
};

#endif /* CLASS_PROXYSQL_RAFT_H */
