#include "tap.h"

#include "mysql_router_reconciler.h"

#include <chrono>
#include <deque>
#include <stdexcept>
#include <thread>

namespace {

ReconcileTopologySnapshot topology(const char* fingerprint,
	bool metadata = true, bool complete = true, bool registered = true) {
	ReconcileTopologySnapshot value;
	value.metadata_available = metadata;
	value.complete = complete;
	value.registration_exists = registered;
	value.identity_valid = true;
	value.has_metadata_endpoint = true;
	value.fingerprint = fingerprint;
	value.desired.topology_uuid = "cluster-1";
	value.effective.writer = "writer-1";
	return value;
}

class Backend final : public IReconcileBackend {
public:
	uint64_t now {1000};
	std::deque<ReconcileTopologySnapshot> candidates;
	bool fail_users {false};
	bool fail_topology {false};
	bool gate_ready {false};
	unsigned topology_publishes {0};
	unsigned user_publishes {0};
	unsigned transition_events {0};
	unsigned transition_logs {0};
	unsigned transition_clears {0};
	bool drifted {false};
	unsigned drift_corrections {0};

	uint64_t monotonic_ms() const override { return now; }
	ReconcileTopologySnapshot read_topology() override {
		if (candidates.empty()) throw std::runtime_error("metadata unavailable");
		auto result = candidates.front();
		candidates.pop_front();
		return result;
	}
	AccountSnapshot read_users() override {
		if (fail_users) throw std::runtime_error("account query failed");
		AccountSnapshot snapshot;
		snapshot.accounts.push_back({"app", "%", "caching_sha2_password",
			"$A$005$app", false, false, ""});
		return snapshot;
	}
	uint64_t publish_topology(const ReconcileTopologySnapshot&, uint64_t generation) override {
		if (fail_topology) throw std::runtime_error("topology publication failed");
		++topology_publishes;
		return generation;
	}
	uint64_t publish_users(const AccountSnapshot&, uint64_t generation) override {
		++user_publishes;
		return generation;
	}
	void set_gates(bool ready, std::string_view) override { gate_ready = ready; }
	void record_transition(std::string_view, std::string_view, std::string_view,
		bool log_transition) override {
		++transition_events;
		if (log_transition) ++transition_logs;
	}
	void clear_transition() override { ++transition_clears; }
	bool topology_drifted(const ReconcileTopologySnapshot&) override { return drifted; }
	void record_drift_correction() override {
		++drift_corrections;
		drifted = false;
	}
};

} // namespace

int main() {
	plan(28);

	Backend backend;
	MysqlRouterReconciler reconciler(backend, {2000, 30000}, 10, 9);
	backend.candidates.push_back(topology("startup"));
	auto first = reconciler.refresh({true, true});
	ok(first.topology_generation == 11 && first.user_generation == 12,
	   "startup publishes separate monotonic topology and user generations");
	ok(first.topology_published && first.users_published && backend.gate_ready,
	   "the first complete topology and user refresh opens Router gates");

	backend.now += 2000;
	backend.candidates.push_back(topology("primary-2"));
	auto primary = reconciler.refresh({false, false});
	ok(primary.topology_generation == 13 && primary.user_generation == 12 &&
	   primary.topology_published && !primary.users_published,
	   "a GR primary change advances topology without refreshing users early");

	backend.now += 30000;
	backend.fail_users = true;
	backend.candidates.push_back(topology("primary-3"));
	auto user_failure = reconciler.refresh({false, false});
	ok(user_failure.topology_generation == 14 && user_failure.user_generation == 12 &&
	   user_failure.topology_published && !user_failure.users_published,
	   "an account query failure does not delay a complete topology generation");
	ok(user_failure.user_error == "account query failed" && backend.gate_ready,
	   "an account failure retains the previous user generation and ready gates");
	backend.fail_users = false;

	backend.now += 2000;
	backend.candidates.push_back(topology("incomplete", true, false));
	auto incomplete = reconciler.refresh({false, false});
	ok(!incomplete.topology_published && incomplete.topology_generation == 14,
	   "an incomplete topology publishes no generation");

	backend.now += 2000;
	backend.candidates.push_back(topology("health-shun", false, true));
	auto outage = reconciler.refresh({false, false});
	ok(outage.topology_published && outage.topology_generation == 15,
	   "metadata loss can still publish current live-health changes over the last desired topology");
	ok(!outage.metadata_available && backend.gate_ready,
	   "temporary metadata loss retains ready gates after a valid health publication");

	backend.now += 2000;
	backend.candidates.push_back(topology("missing-registration", true, true, false));
	auto missing = reconciler.refresh({false, false});
	ok(!missing.registration_exists && !missing.topology_published && !backend.gate_ready,
	   "a deleted Router registration closes gates and blocks publication");

	backend.now += 2000;
	backend.candidates.push_back(topology("option-change"));
	auto options = reconciler.refresh({false, false});
	ok(options.topology_published && options.topology_generation == 16 && backend.gate_ready,
	   "a supported Router option change publishes on the next poll and reopens gates");

	backend.now += 2000;
	auto failed_once = reconciler.refresh({false, false});
	backend.now += 2000;
	auto failed_twice = reconciler.refresh({false, false});
	ok(!failed_once.topology_error.empty() && failed_once.topology_error == failed_twice.topology_error,
	   "repeated identical metadata failures retain one stable transition identity");
	ok(backend.transition_events >= 2 && backend.transition_logs == 5,
	   "repeated warnings increment occurrences but log only state transitions");

	backend.now += 30000;
	backend.candidates.push_back(topology("option-change"));
	auto due_users = reconciler.refresh({false, false});
	ok(!due_users.topology_published && due_users.users_published &&
	   due_users.topology_generation == 16 && due_users.user_generation == 17,
	   "the independent user interval can advance without republishing identical topology");
	backend.now += 2000;
	backend.drifted = true;
	backend.candidates.push_back(topology("option-change"));
	auto drift = reconciler.refresh({false, false});
	ok(drift.topology_published && drift.topology_generation == 18,
	   "owned-hostgroup drift republishes an otherwise unchanged topology");
	ok(backend.drift_corrections == 1,
	   "a successful drift repair increments its metric once");

	Backend worker_backend;
	worker_backend.candidates.push_back(topology("worker-start"));
	MysqlRouterReconciler worker(worker_backend, {5, 30000}, 0, 0);
	ok(worker.start(), "the periodic reconciliation worker starts once");
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	ok(worker.running(), "the periodic worker remains live between refreshes");
	worker.stop();
	ok(!worker.running(), "stop joins the reconciliation worker before plugin unload");
	ok(worker_backend.topology_publishes == 1 && worker_backend.user_publishes == 1,
	   "the worker performs one synchronous complete startup refresh");
	Backend resumed_backend;
	resumed_backend.candidates.push_back(topology("runtime-ready"));
	MysqlRouterReconciler resumed(resumed_backend, {50, 30000}, 0, 0);
	(void)resumed.refresh({true, true});
	ok(resumed.start(false),
	   "a worker can start after the caller's synchronous runtime-ready refresh");
	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	resumed.stop();
	ok(resumed_backend.topology_publishes == 1 && resumed_backend.user_publishes == 1,
	   "starting after runtime-ready does not immediately publish a duplicate user generation");
	ok(backend.topology_publishes == 6 && backend.user_publishes == 2,
	   "only complete changed topology and due user snapshots reach the publisher");
	ok(reconciler.status().topology_generation == 18 &&
	   reconciler.status().user_generation == 17,
	   "runtime status retains the independently active generations");

	Backend warning_backend;
	auto warning = topology("warning-start");
	warning.warning_kind = "metadata";
	warning.warning_code = "check_in_failed";
	warning.warning_message = "metadata check-in failed";
	warning_backend.candidates.push_back(warning);
	warning_backend.candidates.push_back(warning);
	warning_backend.candidates.push_back(topology("warning-start"));
	MysqlRouterReconciler warnings(warning_backend, {1, 30000}, 0, 0);
	auto warning_first = warnings.refresh({true, false});
	warning_backend.now += 1;
	auto warning_repeat = warnings.refresh({false, false});
	warning_backend.now += 1;
	auto warning_recovered = warnings.refresh({false, false});
	ok(warning_first.topology_published && warning_first.topology_error.empty(),
	   "a metadata check-in warning does not roll back a valid topology generation");
	ok(!warning_repeat.topology_published && warning_backend.transition_logs == 1,
	   "an identical auxiliary warning is counted but logged only once");
	ok(warning_recovered.topology_error.empty() && warning_backend.transition_clears == 1,
	   "a successful poll clears the recovered auxiliary warning");

	Backend failed_publish_backend;
	failed_publish_backend.candidates.push_back(topology("published"));
	MysqlRouterReconciler failed_publish(failed_publish_backend, {1, 1}, 0, 0);
	(void)failed_publish.refresh({true, true});
	failed_publish_backend.now += 1;
	failed_publish_backend.fail_topology = true;
	failed_publish_backend.candidates.push_back(topology("rejected"));
	auto rejected = failed_publish.refresh({false, false});
	ok(!rejected.topology_published && !rejected.topology_error.empty(),
	   "a failed topology publication retains the active topology generation");
	ok(!rejected.users_published && failed_publish_backend.user_publishes == 1,
	   "a due user refresh cannot publish the rejected topology in the same cycle");

	return exit_status();
}
