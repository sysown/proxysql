#ifndef PROXYSQL_MYSQL_ROUTER_RECONCILER_H
#define PROXYSQL_MYSQL_ROUTER_RECONCILER_H

#include "mysql_router_types.h"
#include "mysql_router_users.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

struct ReconcileTopologySnapshot {
	bool metadata_available {true};
	bool complete {false};
	bool registration_exists {false};
	bool identity_valid {false};
	bool has_metadata_endpoint {false};
	std::string fingerprint;
	std::string warning_kind;
	std::string warning_code;
	std::string warning_message;
	DesiredTopology desired;
	EffectiveTopology effective;
};

struct ReconcileSchedule {
	uint64_t topology_interval_ms {2000};
	uint64_t user_interval_ms {30000};
};

struct RefreshRequest {
	bool force_topology {false};
	bool force_users {false};
};

struct ReconcileResult {
	bool topology_published {false};
	bool users_published {false};
	bool metadata_available {false};
	bool registration_exists {true};
	bool gates_ready {false};
	uint64_t topology_generation {0};
	uint64_t user_generation {0};
	std::string topology_error;
	std::string user_error;
};

class IReconcileBackend {
public:
	virtual ~IReconcileBackend() = default;
	virtual uint64_t monotonic_ms() const = 0;
	virtual ReconcileTopologySnapshot read_topology() = 0;
	virtual AccountSnapshot read_users() = 0;
	virtual uint64_t publish_topology(
		const ReconcileTopologySnapshot& snapshot, uint64_t generation) = 0;
	virtual uint64_t publish_users(
		const AccountSnapshot& snapshot, uint64_t generation) = 0;
	virtual bool topology_drifted(const ReconcileTopologySnapshot&) { return false; }
	virtual void record_drift_correction() {}
	virtual void set_gates(bool ready, std::string_view reason) = 0;
	virtual void record_transition(std::string_view kind, std::string_view code,
		std::string_view message, bool log_transition) = 0;
	virtual void clear_transition() {}
	virtual void record_refresh(std::string_view, bool, uint64_t, uint64_t,
		std::string_view) {}
	virtual ReconcileSchedule schedule() const { return {}; }
	virtual uint64_t initial_topology_generation() const { return 0; }
	virtual uint64_t initial_user_generation() const { return 0; }
};

class MysqlRouterReconciler {
public:
	MysqlRouterReconciler(IReconcileBackend& backend, ReconcileSchedule schedule,
		uint64_t topology_generation, uint64_t user_generation);
	~MysqlRouterReconciler();
	MysqlRouterReconciler(const MysqlRouterReconciler&) = delete;
	MysqlRouterReconciler& operator=(const MysqlRouterReconciler&) = delete;

	ReconcileResult refresh(RefreshRequest request);
	bool start(bool initial_refresh = true);
	void stop();
	bool running() const { return running_.load(); }
	ReconcileResult status() const;

private:
	uint64_t next_generation() const;
	void issue(std::string_view kind, std::string_view code, std::string_view message);
	void clear_issue(std::string_view kind = {});
	void clear_topology_issue();
	void worker_main();

	IReconcileBackend& backend_;
	ReconcileSchedule schedule_;
	mutable std::mutex state_mutex_;
	ReconcileResult status_;
	std::string topology_fingerprint_;
	std::string last_issue_;
	uint64_t last_topology_attempt_ms_ {0};
	uint64_t last_user_attempt_ms_ {0};
	bool first_valid_topology_ {false};

	std::atomic<bool> running_ {false};
	std::mutex worker_mutex_;
	std::condition_variable worker_cv_;
	bool stop_requested_ {false};
	bool worker_initial_refresh_ {true};
	std::thread worker_;
};

struct ProxySQL_PluginServices;
std::unique_ptr<IReconcileBackend> create_mysql_router_reconcile_backend(
	ProxySQL_PluginServices& services);

#endif
