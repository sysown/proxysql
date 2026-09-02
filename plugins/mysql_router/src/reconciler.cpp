#include "mysql_router_reconciler.h"

#include <algorithm>
#include <chrono>
#include <limits>
#include <stdexcept>

namespace {

bool due(uint64_t now, uint64_t previous, uint64_t interval, bool attempted) {
	return !attempted || interval == 0 || now < previous || now - previous >= interval;
}

} // namespace

MysqlRouterReconciler::MysqlRouterReconciler(IReconcileBackend& backend,
	ReconcileSchedule schedule, uint64_t topology_generation, uint64_t user_generation)
	: backend_(backend), schedule_(schedule) {
	status_.topology_generation = topology_generation;
	status_.user_generation = user_generation;
}

MysqlRouterReconciler::~MysqlRouterReconciler() {
	stop();
}

uint64_t MysqlRouterReconciler::next_generation() const {
	const uint64_t active = std::max(
		status_.topology_generation, status_.user_generation);
	if (active == static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
		throw std::runtime_error("Router configuration generation is exhausted");
	}
	return active + 1;
}

void MysqlRouterReconciler::issue(std::string_view kind, std::string_view code,
	std::string_view message) {
	std::string identity;
	identity.reserve(kind.size() + code.size() + message.size() + 2);
	identity.append(kind);
	identity.push_back('\0');
	identity.append(code);
	identity.push_back('\0');
	identity.append(message);
	const bool changed = identity != last_issue_;
	backend_.record_transition(kind, code, message, changed);
	last_issue_ = std::move(identity);
}

void MysqlRouterReconciler::clear_issue(std::string_view kind) {
	if (!kind.empty()) {
		const size_t separator = last_issue_.find('\0');
		if (separator == std::string::npos ||
			std::string_view(last_issue_.data(), separator) != kind) return;
	}
	if (!last_issue_.empty()) backend_.clear_transition();
	last_issue_.clear();
}

void MysqlRouterReconciler::clear_topology_issue() {
	const size_t separator = last_issue_.find('\0');
	if (separator != std::string::npos &&
		std::string_view(last_issue_.data(), separator) == "users") return;
	clear_issue();
}

ReconcileResult MysqlRouterReconciler::refresh(RefreshRequest request) {
	std::lock_guard<std::mutex> guard(state_mutex_);
	status_.topology_published = false;
	status_.users_published = false;
	const uint64_t now = backend_.monotonic_ms();
	const bool topology_due = request.force_topology ||
		due(now, last_topology_attempt_ms_, schedule_.topology_interval_ms, topology_attempted_);
	const uint64_t topology_from = status_.topology_generation;
	bool topology_refresh_valid = !topology_due;
	if (topology_due) {
		last_topology_attempt_ms_ = now;
		topology_attempted_ = true;
		try {
			ReconcileTopologySnapshot candidate = backend_.read_topology();
			status_.metadata_available = candidate.metadata_available;
			status_.registration_exists = candidate.registration_exists;
			if (!candidate.registration_exists) {
				status_.topology_error = "Router registration is missing";
				status_.gates_ready = false;
				backend_.set_gates(false, status_.topology_error);
				issue("registration", "missing", status_.topology_error);
			} else if (!candidate.complete || !candidate.identity_valid ||
				!candidate.has_metadata_endpoint || candidate.fingerprint.empty()) {
				status_.topology_error = "topology snapshot is incomplete";
				issue("topology", "incomplete", status_.topology_error);
			} else {
				topology_refresh_valid = true;
				const bool changed = candidate.fingerprint != topology_fingerprint_;
				const bool drifted = !changed && backend_.topology_drifted(candidate);
				if (changed || drifted) {
					const uint64_t requested = next_generation();
					const uint64_t published = backend_.publish_topology(candidate, requested);
					if (published < requested) {
						throw std::runtime_error("topology publisher returned an unexpected generation");
					}
					status_.topology_generation = published;
					status_.topology_published = true;
					topology_fingerprint_ = std::move(candidate.fingerprint);
					if (drifted) backend_.record_drift_correction();
				}
				status_.topology_error.clear();
				status_.gates_ready = false;
				backend_.set_gates(true, {});
				status_.gates_ready = true;
				first_valid_topology_ = true;
				if (!candidate.warning_code.empty()) {
					issue(candidate.warning_kind.empty() ? "metadata" : candidate.warning_kind,
						candidate.warning_code, candidate.warning_message);
				} else if (candidate.metadata_available) clear_topology_issue();
				else issue("metadata", "unavailable", "using last validated metadata with current health");
			}
		} catch (const std::exception& error) {
			status_.metadata_available = false;
			status_.topology_error = error.what();
			issue("metadata", "refresh_failed", status_.topology_error);
		}
		backend_.record_refresh("topology", status_.topology_error.empty(), topology_from,
			status_.topology_generation, status_.topology_error);
	}

	const bool users_due = request.force_users ||
		(first_valid_topology_ && !user_attempted_) ||
		due(now, last_user_attempt_ms_, schedule_.user_interval_ms, user_attempted_);
	if (first_valid_topology_ && status_.registration_exists && status_.metadata_available &&
		topology_refresh_valid && users_due) {
		const uint64_t user_from = status_.user_generation;
		last_user_attempt_ms_ = now;
		user_attempted_ = true;
		try {
			AccountSnapshot snapshot = backend_.read_users();
			const uint64_t requested = next_generation();
			const uint64_t published = backend_.publish_users(snapshot, requested);
			if (published < requested) {
				throw std::runtime_error("user publisher returned an unexpected generation");
			}
			status_.user_generation = published;
			status_.users_published = true;
			status_.user_error.clear();
			if (status_.topology_error.empty()) clear_issue("users");
		} catch (const std::exception& error) {
			status_.user_error = error.what();
			issue("users", "refresh_failed", status_.user_error);
		}
		backend_.record_refresh("users", status_.user_error.empty(), user_from,
			status_.user_generation, status_.user_error);
	}
	return status_;
}

bool MysqlRouterReconciler::start(bool initial_refresh) {
	bool expected = false;
	if (!running_.compare_exchange_strong(expected, true)) return false;
	{
		std::lock_guard<std::mutex> guard(worker_mutex_);
		stop_requested_ = false;
		worker_initial_refresh_ = initial_refresh;
	}
	try {
		worker_ = std::thread(&MysqlRouterReconciler::worker_main, this);
	} catch (...) {
		running_.store(false);
		throw;
	}
	return true;
}

void MysqlRouterReconciler::stop() {
	if (!running_.load() && !worker_.joinable()) return;
	{
		std::lock_guard<std::mutex> guard(worker_mutex_);
		stop_requested_ = true;
	}
	worker_cv_.notify_all();
	if (worker_.joinable()) worker_.join();
	running_.store(false);
}

void MysqlRouterReconciler::worker_main() {
	if (worker_initial_refresh_) {
		try { (void)refresh({true, true}); }
		catch (...) {}
	}
	std::unique_lock<std::mutex> lock(worker_mutex_);
	while (!stop_requested_) {
		const uint64_t interval = std::min(schedule_.topology_interval_ms,
			schedule_.user_interval_ms);
		const auto delay = std::chrono::milliseconds(std::max<uint64_t>(1, interval));
		if (worker_cv_.wait_for(lock, delay, [&] { return stop_requested_; })) break;
		lock.unlock();
		try { (void)refresh({false, false}); }
		catch (...) {}
		lock.lock();
	}
	running_.store(false);
}

ReconcileResult MysqlRouterReconciler::status() const {
	std::lock_guard<std::mutex> guard(state_mutex_);
	return status_;
}
