/*
 * Independent control harness for the production tcp_proxy::Engine.
 *
 * This file deliberately contains NO relay, selection, health-check or
 * statistics implementation for the product.  It only:
 *   - parses newline-delimited JSON requests from stdin,
 *   - converts JSON into tcp_proxy::Config value objects,
 *   - converts the separate TEST fixture envelope into a test-only
 *     BackendProvider,
 *   - invokes the production Engine operations,
 *   - serialises Config/Snapshot back to stdout.
 *
 * The four-table product configuration has no server table.  The top-level
 * `backend_fixtures` array is NOT part of tcp_proxy::Config: it is the TEST
 * backend fixture list consumed only by TestBackendProvider.  Endpoint
 * identity, capacity, administrative status and retry ordering live entirely
 * in this test provider and never in product Config.  `config` must contain
 * only settings/hostgroups/listeners/rules; obsolete keys are rejected.
 * Consequently a PASS in these Engine fixtures proves relay/lifetime/frontend
 * behaviour, not actual core hostgroup-manager selection, health or counters.
 *
 * Protocol (one JSON object per line, request/response correlated by "id"):
 *
 *   {"id":1,"op":"ping"}
 *   {"id":2,"op":"validate","config":{...},"backend_fixtures":[...]}
 *   {"id":3,"op":"start","config":{...},"backend_fixtures":[...]}
 *   {"id":4,"op":"apply","config":{...},"backend_fixtures":[...]}
 *   {"id":5,"op":"snapshot"}
 *   {"id":6,"op":"provider_snapshot"}
 *   {"id":7,"op":"config"}
 *   {"id":8,"op":"stop"}
 *   {"id":9,"op":"apply_concurrent","configs":[configA,...],"backend_fixtures":[[...],...]}
 *   {"id":10,"op":"apply_stop_race","config":{...},"backend_fixtures":[...]}
 *   {"id":11,"op":"quit"}
 *
 * Every response contains "id" (echoed), "op" and "ok".  Failed requests add
 * "error".  start/apply/stop return a product "snapshot"; the same response
 * carries a sibling "backend_provider" document with TEST fixture counters.
 * config returns a full product "config".  apply_concurrent additionally
 * returns per-thread timing and an "overlapped" flag.
 */

#include "tcp_proxy.h"

#include "json.hpp"

#ifndef TCP_PROXY_HEADER_SHA256
#define TCP_PROXY_HEADER_SHA256 "unknown"
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <unistd.h>

using json = nlohmann::json;
using Clock = std::chrono::steady_clock;

namespace {

int64_t micros_since(const Clock::time_point& origin)
{
	return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - origin).count();
}

template <typename T>
T get_int(const json& obj, const char* key, T fallback, std::string& error,
	const std::string& context)
{
	if (!obj.contains(key) || obj[key].is_null()) {
		return fallback;
	}
	const json& value = obj[key];
	int64_t parsed = 0;
	if (value.is_number_unsigned()) {
		const uint64_t raw = value.get<uint64_t>();
		if (raw > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
			error = context + "." + key + " exceeds signed int32 range";
			return fallback;
		}
		parsed = static_cast<int64_t>(raw);
	} else if (value.is_number_integer()) {
		parsed = value.get<int64_t>();
	} else {
		error = context + "." + key + " must be a signed integer";
		return fallback;
	}
	if (parsed < static_cast<int64_t>(std::numeric_limits<int32_t>::min())
		|| parsed > static_cast<int64_t>(std::numeric_limits<int32_t>::max())) {
		error = context + "." + key + " exceeds signed int32 range";
		return fallback;
	}
	return static_cast<T>(parsed);
}

std::string get_string(const json& obj, const char* key, const std::string& fallback)
{
	if (obj.contains(key) && !obj[key].is_null()) {
		return obj[key].get<std::string>();
	}
	return fallback;
}

bool check_keys(const json& obj, std::initializer_list<const char*> allowed,
	const std::string& context, std::string& error)
{
	if (!obj.is_object()) {
		error = context + " must be an object";
		return false;
	}
	std::set<std::string> accepted;
	for (const char* key : allowed) {
		accepted.insert(key);
	}
	for (auto it = obj.begin(); it != obj.end(); ++it) {
		if (accepted.find(it.key()) == accepted.end()) {
			error = context + " contains obsolete/unsupported key: " + it.key();
			return false;
		}
	}
	return true;
}

void parse_settings(const json& j, tcp_proxy::Settings& s, std::string& error)
{
	if (!check_keys(j, { "id", "worker_threads", "max_connections", "buffer_size",
			"shutdown_timeout_ms", "half_close_timeout_ms" }, "settings", error)) {
		return;
	}
	s.id = get_int<int>(j, "id", s.id, error, "settings");
	s.worker_threads = get_int<int>(j, "worker_threads", s.worker_threads, error, "settings");
	s.max_connections = get_int<int>(j, "max_connections", s.max_connections, error, "settings");
	s.buffer_size = get_int<int>(j, "buffer_size", s.buffer_size, error, "settings");
	s.shutdown_timeout_ms = get_int<int>(j, "shutdown_timeout_ms", s.shutdown_timeout_ms,
		error, "settings");
	s.half_close_timeout_ms = get_int<int>(j, "half_close_timeout_ms",
		s.half_close_timeout_ms, error, "settings");
}

void parse_hostgroup(const json& j, tcp_proxy::Hostgroup& h, std::string& error,
	const std::string& context)
{
	if (!check_keys(j, { "hostgroup_id", "source_protocol", "source_hostgroup", "comment" },
			context, error)) {
		return;
	}
	h.hostgroup_id = get_int<int>(j, "hostgroup_id", h.hostgroup_id, error, context);
	h.source_protocol = get_string(j, "source_protocol", h.source_protocol);
	h.source_hostgroup = get_int<int>(j, "source_hostgroup", h.source_hostgroup, error, context);
	h.comment = get_string(j, "comment", h.comment);
}

void parse_listener(const json& j, tcp_proxy::Listener& l, std::string& error,
	const std::string& context)
{
	if (!check_keys(j, { "listener_id", "active", "bind_address", "bind_port",
			"default_hostgroup", "max_connections", "connect_timeout_ms",
			"idle_timeout_ms", "max_connect_attempts", "comment" }, context, error)) {
		return;
	}
	l.listener_id = get_int<int>(j, "listener_id", l.listener_id, error, context);
	l.active = get_int<int>(j, "active", l.active, error, context);
	l.bind_address = get_string(j, "bind_address", l.bind_address);
	l.bind_port = get_int<int>(j, "bind_port", l.bind_port, error, context);
	l.default_hostgroup = get_int<int>(j, "default_hostgroup", l.default_hostgroup, error, context);
	l.max_connections = get_int<int>(j, "max_connections", l.max_connections, error, context);
	l.connect_timeout_ms = get_int<int>(j, "connect_timeout_ms", l.connect_timeout_ms, error, context);
	l.idle_timeout_ms = get_int<int>(j, "idle_timeout_ms", l.idle_timeout_ms, error, context);
	l.max_connect_attempts = get_int<int>(j, "max_connect_attempts", l.max_connect_attempts,
		error, context);
	l.comment = get_string(j, "comment", l.comment);
}

void parse_rule(const json& j, tcp_proxy::Rule& r, std::string& error,
	const std::string& context)
{
	if (!check_keys(j, { "rule_id", "active", "listener_id", "source_cidr", "action",
			"destination_hostgroup", "comment" }, context, error)) {
		return;
	}
	r.rule_id = get_int<int>(j, "rule_id", r.rule_id, error, context);
	r.active = get_int<int>(j, "active", r.active, error, context);
	if (j.contains("listener_id") && !j["listener_id"].is_null()) {
		r.listener_id = get_int<int>(j, "listener_id", 0, error, context);
	} else {
		r.listener_id.reset();
	}
	if (j.contains("source_cidr") && !j["source_cidr"].is_null()) {
		r.source_cidr = j["source_cidr"].get<std::string>();
	} else {
		r.source_cidr.reset();
	}
	r.action = get_string(j, "action", r.action);
	if (j.contains("destination_hostgroup") && !j["destination_hostgroup"].is_null()) {
		r.destination_hostgroup = get_int<int>(j, "destination_hostgroup", 0, error, context);
	} else {
		r.destination_hostgroup.reset();
	}
	r.comment = get_string(j, "comment", r.comment);
}

/*
 * Parse only the four product configuration tables.  Obsolete keys are
 * rejected, never silently ignored: `servers`, `hostgroup_mappings` and old
 * hostgroup balance/health fields are not part of the approved Config.
 */
bool parse_config(const json& j, tcp_proxy::Config& c, std::string& error)
{
	if (!check_keys(j, { "settings", "hostgroups", "listeners", "rules" },
			"config", error)) {
		return false;
	}
	if (j.contains("settings") && !j["settings"].is_null()) {
		parse_settings(j["settings"], c.settings, error);
	}
	if (!error.empty()) {
		return false;
	}
	if (j.contains("hostgroups") && !j["hostgroups"].is_null()) {
		if (!j["hostgroups"].is_array()) {
			error = "config.hostgroups must be an array";
			return false;
		}
		for (size_t i = 0; i < j["hostgroups"].size(); ++i) {
			tcp_proxy::Hostgroup h;
			parse_hostgroup(j["hostgroups"][i], h, error,
				"hostgroups[" + std::to_string(i) + "]");
			if (!error.empty()) {
				return false;
			}
			c.hostgroups.push_back(h);
		}
	}
	if (j.contains("listeners") && !j["listeners"].is_null()) {
		if (!j["listeners"].is_array()) {
			error = "config.listeners must be an array";
			return false;
		}
		for (size_t i = 0; i < j["listeners"].size(); ++i) {
			tcp_proxy::Listener l;
			parse_listener(j["listeners"][i], l, error,
				"listeners[" + std::to_string(i) + "]");
			if (!error.empty()) {
				return false;
			}
			c.listeners.push_back(l);
		}
	}
	if (j.contains("rules") && !j["rules"].is_null()) {
		if (!j["rules"].is_array()) {
			error = "config.rules must be an array";
			return false;
		}
		for (size_t i = 0; i < j["rules"].size(); ++i) {
			tcp_proxy::Rule r;
			parse_rule(j["rules"][i], r, error, "rules[" + std::to_string(i) + "]");
			if (!error.empty()) {
				return false;
			}
			c.rules.push_back(r);
		}
	}
	return error.empty();
}

json settings_json(const tcp_proxy::Settings& s)
{
	return json{
		{"id", s.id},
		{"worker_threads", s.worker_threads},
		{"max_connections", s.max_connections},
		{"buffer_size", s.buffer_size},
		{"shutdown_timeout_ms", s.shutdown_timeout_ms},
		{"half_close_timeout_ms", s.half_close_timeout_ms},
	};
}

json config_json(const tcp_proxy::Config& c)
{
	json out;
	out["settings"] = settings_json(c.settings);
	out["hostgroups"] = json::array();
	for (const auto& h : c.hostgroups) {
		out["hostgroups"].push_back(json{
			{"hostgroup_id", h.hostgroup_id},
			{"source_protocol", h.source_protocol},
			{"source_hostgroup", h.source_hostgroup},
			{"comment", h.comment},
		});
	}
	out["listeners"] = json::array();
	for (const auto& l : c.listeners) {
		out["listeners"].push_back(json{
			{"listener_id", l.listener_id},
			{"active", l.active},
			{"bind_address", l.bind_address},
			{"bind_port", l.bind_port},
			{"default_hostgroup", l.default_hostgroup},
			{"max_connections", l.max_connections},
			{"connect_timeout_ms", l.connect_timeout_ms},
			{"idle_timeout_ms", l.idle_timeout_ms},
			{"max_connect_attempts", l.max_connect_attempts},
			{"comment", l.comment},
		});
	}
	out["rules"] = json::array();
	for (const auto& r : c.rules) {
		json row{
			{"rule_id", r.rule_id},
			{"active", r.active},
			{"listener_id", r.listener_id ? json(*r.listener_id) : json(nullptr)},
			{"source_cidr", r.source_cidr ? json(*r.source_cidr) : json(nullptr)},
			{"action", r.action},
			{"destination_hostgroup", r.destination_hostgroup ? json(*r.destination_hostgroup) : json(nullptr)},
			{"comment", r.comment},
		};
		out["rules"].push_back(std::move(row));
	}
	return out;
}

json snapshot_json(const tcp_proxy::Snapshot& s)
{
	json out{
		{"generation", s.generation},
		{"running", s.running},
		{"last_error", s.last_error},
		{"active_connections", s.active_connections},
		{"retired_connections", s.retired_connections},
		{"accepted_total", s.accepted_total},
		{"rejected_total", s.rejected_total},
		{"connect_errors", s.connect_errors},
		{"bytes_client_to_server", s.bytes_client_to_server},
		{"bytes_server_to_client", s.bytes_server_to_client},
	};
	out["listeners"] = json::array();
	for (const auto& l : s.listeners) {
		out["listeners"].push_back(json{
			{"listener_id", l.listener_id},
			{"retired", l.retired},
			{"active_connections", l.active_connections},
			{"accepted_total", l.accepted_total},
			{"rejected_total", l.rejected_total},
			{"connect_errors", l.connect_errors},
			{"bytes_client_to_server", l.bytes_client_to_server},
			{"bytes_server_to_client", l.bytes_server_to_client},
		});
	}
	out["rules"] = json::array();
	for (const auto& r : s.rules) {
		out["rules"].push_back(json{
			{"rule_id", r.rule_id},
			{"retired", r.retired},
			{"active_connections", r.active_connections},
			{"matched_total", r.matched_total},
			{"rejected_total", r.rejected_total},
			{"bytes_client_to_server", r.bytes_client_to_server},
			{"bytes_server_to_client", r.bytes_server_to_client},
		});
	}
	return out;
}

/*
 * TEST-ONLY fixture provider.  It is not product code and never validates a
 * core HGM.  Its only purpose is to let the real Engine relay to controlled
 * loopback endpoints while exercising removed-endpoint, capacity, status and
 * retry-ordering paths.
 */
struct FixtureSpec {
	int server_id { 0 };
	int hostgroup_id { 0 };          // TCP hostgroup owning this test endpoint
	std::string source_protocol {};  // MYSQL | PGSQL
	int source_hostgroup { 0 };
	std::string hostname {};
	int port { 0 };
	std::string status { "ONLINE" };
	int weight { 1 };
	int max_connections { 1000 };
	int backup { 0 };
	std::string comment {};
};

struct FixtureCounters {
	uint64_t active { 0 };
	uint64_t selected_total { 0 };
	uint64_t connect_errors { 0 };
	uint64_t bytes_client_to_server { 0 };
	uint64_t bytes_server_to_client { 0 };
};

std::string source_key(const std::string& protocol, int hostgroup)
{
	return protocol + ":" + std::to_string(hostgroup);
}

class TestBackendProvider;

class TestBackendConnection final : public tcp_proxy::BackendConnection {
public:
	TestBackendConnection(std::shared_ptr<TestBackendProvider> provider,
		const FixtureSpec& fixture, uint64_t hard_epoch);
	~TestBackendConnection() override;

	const std::string& hostname() const noexcept override { return hostname_; }
	int port() const noexcept override { return port_; }
	void connect_result(int socket_errno) noexcept override;
	void account_io(uint64_t sent, uint64_t received) noexcept override;
	bool offline_hard() const noexcept override;
	bool destroy() noexcept override;

private:
	std::shared_ptr<TestBackendProvider> provider_;
	int server_id_ { 0 };
	std::string hostname_ {};
	int port_ { 0 };
	uint64_t hard_epoch_ { 0 };
	bool destroyed_ { false };
	mutable bool offline_hard_cached_ { false };
};

class TestBackendProvider final : public tcp_proxy::BackendProvider,
	public std::enable_shared_from_this<TestBackendProvider> {
public:
	bool available() const noexcept override { return true; }

	void configure(const std::vector<FixtureSpec>& fixtures)
	{
		std::lock_guard<std::mutex> lock(mutex_);
		std::map<int, FixtureSpec> previous;
		for (const auto& row : fixtures_) {
			previous[row.server_id] = row;
		}
		for (const auto& row : fixtures) {
			auto old = previous.find(row.server_id);
			if (row.status == "OFFLINE_HARD"
				&& (old == previous.end() || old->second.status != "OFFLINE_HARD")) {
				hard_epoch_[row.server_id] = ++hard_epoch_sequence_;
			}
		}
		fixtures_ = fixtures;
		rr_cursor_.clear();
	}

	std::unique_ptr<tcp_proxy::BackendConnection> acquire(
		const std::string& protocol, int source_hostgroup) override;

	uint64_t hard_epoch(int server_id) const noexcept
	{
		std::lock_guard<std::mutex> lock(mutex_);
		auto it = hard_epoch_.find(server_id);
		return it == hard_epoch_.end() ? 0 : it->second;
	}

	void on_destroy(int server_id) noexcept
	{
		std::lock_guard<std::mutex> lock(mutex_);
		auto& counters = counters_[server_id];
		if (counters.active > 0) {
			--counters.active;
		}
	}

	void on_connect_result(int server_id, int socket_errno) noexcept
	{
		if (socket_errno == 0) {
			return;
		}
		std::lock_guard<std::mutex> lock(mutex_);
		++counters_[server_id].connect_errors;
	}

	void on_account_io(int server_id, uint64_t sent, uint64_t received) noexcept
	{
		std::lock_guard<std::mutex> lock(mutex_);
		auto& counters = counters_[server_id];
		counters.bytes_client_to_server += sent;
		counters.bytes_server_to_client += received;
	}

	bool offline_hard(int server_id, uint64_t acquired_epoch) const noexcept
	{
		std::lock_guard<std::mutex> lock(mutex_);
		auto it = hard_epoch_.find(server_id);
		return it != hard_epoch_.end() && it->second > acquired_epoch;
	}

	json snapshot_json() const
	{
		std::lock_guard<std::mutex> lock(mutex_);
		json out;
		out["kind"] = "test-backend-provider";
		out["disclaimer"] = "TEST fixture endpoints only; not a core HGM assertion";
		out["servers"] = json::array();
		for (const auto& fixture : fixtures_) {
			FixtureCounters counters;
			auto counter = counters_.find(fixture.server_id);
			if (counter != counters_.end()) {
				counters = counter->second;
			}
			out["servers"].push_back(json{
				{"server_id", fixture.server_id},
				{"hostgroup_id", fixture.hostgroup_id},
				{"source_protocol", fixture.source_protocol},
				{"source_hostgroup", fixture.source_hostgroup},
				{"hostname", fixture.hostname},
				{"port", fixture.port},
				{"status", fixture.status},
				{"health_status", fixture.status == "ONLINE" ? "UP" : "DISABLED"},
				{"weight", fixture.weight},
				{"max_connections", fixture.max_connections},
				{"backup", fixture.backup},
				{"retired", false},
				{"active_connections", counters.active},
				{"selected_total", counters.selected_total},
				{"connect_errors", counters.connect_errors},
				{"bytes_client_to_server", counters.bytes_client_to_server},
				{"bytes_server_to_client", counters.bytes_server_to_client},
			});
		}
		return out;
	}

private:
	friend class TestBackendConnection;

	std::vector<FixtureSpec> fixtures_;
	std::map<int, FixtureCounters> counters_;
	std::map<int, uint64_t> hard_epoch_;
	std::map<std::string, uint64_t> rr_cursor_;
	uint64_t hard_epoch_sequence_ { 0 };
	mutable std::mutex mutex_;
};

TestBackendConnection::TestBackendConnection(
	std::shared_ptr<TestBackendProvider> provider, const FixtureSpec& fixture,
	uint64_t hard_epoch)
	: provider_(std::move(provider)), server_id_(fixture.server_id),
	  hostname_(fixture.hostname), port_(fixture.port), hard_epoch_(hard_epoch)
{
}

TestBackendConnection::~TestBackendConnection()
{
	destroy();
}

void TestBackendConnection::connect_result(int socket_errno) noexcept
{
	if (provider_) {
		provider_->on_connect_result(server_id_, socket_errno);
	}
}

void TestBackendConnection::account_io(uint64_t sent, uint64_t received) noexcept
{
	if (provider_) {
		provider_->on_account_io(server_id_, sent, received);
	}
}

bool TestBackendConnection::offline_hard() const noexcept
{
	if (offline_hard_cached_) {
		return true;
	}
	if (provider_ && provider_->offline_hard(server_id_, hard_epoch_)) {
		offline_hard_cached_ = true;
	}
	return offline_hard_cached_;
}

bool TestBackendConnection::destroy() noexcept
{
	if (destroyed_) {
		return offline_hard_cached_;
	}
	destroyed_ = true;
	const bool hard = offline_hard();
	if (provider_) {
		provider_->on_destroy(server_id_);
	}
	return hard;
}

std::unique_ptr<tcp_proxy::BackendConnection> TestBackendProvider::acquire(
	const std::string& protocol, int source_hostgroup)
{
	std::lock_guard<std::mutex> lock(mutex_);
	const std::string key = source_key(protocol, source_hostgroup);

	auto eligible = [&](bool include_backup) {
		std::vector<const FixtureSpec*> rows;
		for (const auto& row : fixtures_) {
			if (row.source_protocol != protocol || row.source_hostgroup != source_hostgroup) {
				continue;
			}
			if (row.status != "ONLINE") {
				continue;
			}
			if (row.backup != 0 && !include_backup) {
				continue;
			}
			auto counter = counters_.find(row.server_id);
			const uint64_t active = counter == counters_.end() ? 0 : counter->second.active;
			if (active >= static_cast<uint64_t>(row.max_connections)) {
				continue;
			}
			if (row.weight <= 0) {
				continue;
			}
			rows.push_back(&row);
		}
		return rows;
	};

	std::vector<const FixtureSpec*> rows = eligible(false);
	if (rows.empty()) {
		rows = eligible(true);
	}
	if (rows.empty()) {
		return nullptr;
	}
	int total_weight = 0;
	for (const auto* row : rows) {
		total_weight += row->weight;
	}
	if (total_weight <= 0) {
		return nullptr;
	}
	uint64_t& cursor = rr_cursor_[key];
	const int ticket = static_cast<int>(cursor++ % static_cast<uint64_t>(total_weight));
	int running = 0;
	const FixtureSpec* chosen = rows.back();
	for (const auto* row : rows) {
		running += row->weight;
		if (ticket < running) {
			chosen = row;
			break;
		}
	}
	auto& counters = counters_[chosen->server_id];
	++counters.active;
	++counters.selected_total;
	const uint64_t epoch = [&]() {
		auto it = hard_epoch_.find(chosen->server_id);
		return it == hard_epoch_.end() ? 0 : it->second;
	}();
	return std::make_unique<TestBackendConnection>(shared_from_this(), *chosen, epoch);
}

/*
 * Test fixture envelope validation.  This is deliberately not product
 * validation: it keeps the old adversarial fixture-only edge cases while the
 * production Config validates only mappings/listeners/rules.
 */
bool validate_fixture_rows(const json& rows, const tcp_proxy::Config& config,
	std::vector<FixtureSpec>& out, std::string& error)
{
	std::set<int> seen;
	out.clear();
	for (const auto& row : rows) {
		if (!row.is_object()) {
			error = "test fixture row must be an object";
			return false;
		}
		const std::string context = "backend_fixtures[" + std::to_string(out.size()) + "]";
		if (!check_keys(row, { "server_id", "hostgroup_id", "hostname", "port",
				"status", "weight", "max_connections", "backup", "comment" },
				context, error)) {
			return false;
		}
		FixtureSpec f;
		f.server_id = get_int<int>(row, "server_id", 0, error, context);
		f.hostgroup_id = get_int<int>(row, "hostgroup_id", 0, error, context);
		f.hostname = get_string(row, "hostname", "");
		f.port = get_int<int>(row, "port", 0, error, context);
		f.status = get_string(row, "status", "ONLINE");
		f.weight = get_int<int>(row, "weight", 1, error, context);
		f.max_connections = get_int<int>(row, "max_connections", 1000, error, context);
		f.backup = get_int<int>(row, "backup", 0, error, context);
		f.comment = get_string(row, "comment", "");
		if (!error.empty()) {
			return false;
		}

		const tcp_proxy::Hostgroup* mapping = nullptr;
		for (const auto& h : config.hostgroups) {
			if (h.hostgroup_id == f.hostgroup_id) {
				mapping = &h;
				break;
			}
		}
		if (mapping == nullptr) {
			error = "test fixture server " + std::to_string(f.server_id)
				+ " references unknown TCP hostgroup " + std::to_string(f.hostgroup_id);
			return false;
		}
		f.source_protocol = mapping->source_protocol;
		f.source_hostgroup = mapping->source_hostgroup;

		if (f.server_id < 0) {
			error = "test fixture server_id must be nonnegative";
			return false;
		}
		if (!seen.insert(f.server_id).second) {
			error = "duplicate test fixture server_id " + std::to_string(f.server_id);
			return false;
		}
		if (f.port < 1 || f.port > 65535) {
			error = "test fixture port out of range for server " + std::to_string(f.server_id);
			return false;
		}
		if (f.hostname.empty() || f.hostname.find('\0') != std::string::npos) {
			error = "test fixture hostname invalid for server " + std::to_string(f.server_id);
			return false;
		}
		{
			unsigned char address[sizeof(struct in6_addr)] {};
			const int family = f.hostname.find(':') != std::string::npos ? AF_INET6 : AF_INET;
			if (::inet_pton(family, f.hostname.c_str(), address) != 1) {
				error = "test fixture hostname must be a numeric IPv4/IPv6 address for server "
					+ std::to_string(f.server_id);
				return false;
			}
		}
		if (f.status != "ONLINE" && f.status != "OFFLINE_SOFT"
			&& f.status != "OFFLINE_HARD" && f.status != "SHUNNED") {
			error = "test fixture status invalid for server " + std::to_string(f.server_id);
			return false;
		}
		if (f.weight < 1 || f.weight > 1000) {
			error = "test fixture weight out of range for server " + std::to_string(f.server_id);
			return false;
		}
		if (f.max_connections < 1 || f.max_connections > 1000000) {
			error = "test fixture max_connections out of range for server "
				+ std::to_string(f.server_id);
			return false;
		}
		if (f.backup != 0 && f.backup != 1) {
			error = "test fixture backup out of range for server " + std::to_string(f.server_id);
			return false;
		}
		out.push_back(std::move(f));
	}
	return true;
}

bool extract_fixtures(const json& request, const tcp_proxy::Config& config,
	std::vector<FixtureSpec>& out, bool& present, std::string& error)
{
	present = false;
	out.clear();
	if (!request.contains("backend_fixtures") || request["backend_fixtures"].is_null()) {
		return true;
	}
	if (!request["backend_fixtures"].is_array()) {
		error = "backend_fixtures must be an array outside product config";
		return false;
	}
	present = true;
	return validate_fixture_rows(request["backend_fixtures"], config, out, error);
}

json base_response(const json& request, const char* op, bool ok)
{
	json out;
	out["id"] = request.contains("id") ? request["id"] : json(nullptr);
	out["op"] = op;
	out["ok"] = ok;
	return out;
}

std::string lower_ascii(std::string value)
{
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
		return static_cast<char>(std::tolower(c));
	});
	return value;
}

bool looks_busy(const std::string& error)
{
	const std::string lower = lower_ascii(error);
	// The frozen header only promises a busy rejection, not a specific word.
	// Accept the current descriptive phrasing as well as explicit "busy".
	return lower.find("busy") != std::string::npos ||
		lower.find("already in progress") != std::string::npos ||
		lower.find("in progress") != std::string::npos ||
		lower.find("concurrent") != std::string::npos;
}

struct ApplyResult {
	bool ok { false };
	std::string error;
	int64_t start_us { 0 };
	int64_t end_us { 0 };
};

/*
 * Wait on a condition-variable barrier so every helper thread has reached the
 * starting line before any production Engine call is made.  This is the only
 * place, together with apply_stop_race(), where Engine calls are concurrent.
 */
std::vector<ApplyResult> run_concurrent_applies(tcp_proxy::Engine& engine,
	const std::shared_ptr<TestBackendProvider>& provider,
	const std::vector<tcp_proxy::Config>& configs,
	const std::vector<std::vector<FixtureSpec>>& fixtures,
	const std::vector<bool>& fixture_present, int64_t& origin_us)
{
	const size_t n = configs.size();
	std::vector<ApplyResult> results(n);
	std::mutex mutex;
	std::condition_variable cv;
	size_t ready = 0;
	bool go = false;

	const Clock::time_point origin = Clock::now();
	origin_us = 0;

	std::vector<std::thread> threads;
	threads.reserve(n);
	for (size_t i = 0; i < n; ++i) {
		threads.emplace_back([&, i]() {
			{
				std::unique_lock<std::mutex> lock(mutex);
				++ready;
				cv.notify_all();
				cv.wait(lock, [&go]() { return go; });
			}
			results[i].start_us = micros_since(origin);
			std::string error;
			bool ok = false;
			try {
				ok = engine.apply(configs[i], error);
			} catch (const std::exception& e) {
				error = std::string("exception: ") + e.what();
			} catch (...) {
				error = "unknown exception";
			}
			results[i].end_us = micros_since(origin);
			results[i].ok = ok;
			results[i].error = std::move(error);
		});
	}

	{
		std::unique_lock<std::mutex> lock(mutex);
		cv.wait(lock, [&]() { return ready == n; });
		go = true;
	}
	cv.notify_all();
	for (auto& thread : threads) {
		thread.join();
	}
	// Completion time and contender index do not identify Engine's winner:
	// a thread can be descheduled after its apply commits. Match the actual
	// published Config after joining, keeping Engine calls concurrent.
	const json final_config = config_json(engine.config());
	auto fixture_json = [](const std::vector<FixtureSpec>& rows) {
		json out = json::array();
		for (const auto& f : rows) {
			out.push_back(json::array({f.server_id, f.hostgroup_id,
				f.source_protocol, f.source_hostgroup, f.hostname, f.port,
				f.status, f.weight, f.max_connections, f.backup, f.comment}));
		}
		return out;
	};
	size_t winner = n;
	for (size_t i = 0; i < n; ++i) {
		if (!results[i].ok || config_json(configs[i]) != final_config) continue;
		if (winner != n && (fixture_present[i] != fixture_present[winner]
			|| fixture_json(fixtures[i]) != fixture_json(fixtures[winner]))) {
			// Identical product configurations with different fixture sets have
			// no observable winner. Fail closed rather than silently guessing.
			provider->configure({});
			throw std::runtime_error("ambiguous fixtures for final concurrent Config");
		}
		winner = i;
	}
	if (winner != n && fixture_present[winner]) {
		provider->configure(fixtures[winner]);
	}

	return results;
}

json apply_result_json(const ApplyResult& result)
{
	return json{
		{"ok", result.ok},
		{"busy", !result.ok && looks_busy(result.error)},
		{"error", result.error},
		{"start_us", result.start_us},
		{"end_us", result.end_us},
	};
}

bool intervals_overlap(const ApplyResult& a, const ApplyResult& b)
{
	return a.start_us < b.end_us && b.start_us < a.end_us;
}

void write_response(const json& response)
{
	std::cout << response.dump() << '\n';
	std::cout.flush();
}

json unknown_op_response(const json& request, const std::string& op)
{
	json response = base_response(request, op.c_str(), false);
	response["error"] = "unknown op: " + op;
	return response;
}

} // namespace

int main()
{
	std::ios::sync_with_stdio(false);
	std::cerr << "engine_harness ready pid=" << static_cast<long long>(::getpid()) << '\n';

	auto provider = std::make_shared<TestBackendProvider>();
	tcp_proxy::Engine engine(provider);
	bool quit = false;
	std::string line;

	while (!quit && std::getline(std::cin, line)) {
		if (!line.empty() && line.back() == '\r') {
			line.pop_back();
		}
		if (line.find_first_not_of(" \t") == std::string::npos) {
			continue;
		}

		json request;
		try {
			request = json::parse(line);
		} catch (const std::exception& e) {
			json response;
			response["id"] = nullptr;
			response["op"] = "parse";
			response["ok"] = false;
			response["error"] = std::string("invalid JSON: ") + e.what();
			write_response(response);
			continue;
		}
		if (!request.is_object()) {
			json response;
			response["id"] = nullptr;
			response["op"] = "parse";
			response["ok"] = false;
			response["error"] = "request must be a JSON object";
			write_response(response);
			continue;
		}

		const std::string op = request.value("op", std::string());
		try {
			if (op == "ping") {
				json response = base_response(request, "ping", true);
				response["pid"] = static_cast<long long>(::getpid());
				response["header_sha256"] = TCP_PROXY_HEADER_SHA256;
				write_response(response);
			} else if (op == "validate") {
				tcp_proxy::Config config;
				std::string error;
				bool config_ok = true;
				if (request.contains("config") && !request["config"].is_null()) {
					if (!request["config"].is_object()) {
						error = "config must be an object";
						config_ok = false;
					} else {
						config_ok = parse_config(request["config"], config, error);
					}
				}
				bool valid = config_ok && tcp_proxy::validate_config(config, error);
				std::vector<FixtureSpec> fixtures;
				bool fixture_present = false;
				if (valid && !extract_fixtures(request, config, fixtures, fixture_present, error)) {
					valid = false;
				}
				json response = base_response(request, "validate", true);
				response["valid"] = valid;
				response["error"] = error;
				write_response(response);
			} else if (op == "start") {
				tcp_proxy::Config config;
				std::string error;
				bool config_ok = true;
				if (request.contains("config") && !request["config"].is_null()) {
					if (!request["config"].is_object()) {
						error = "config must be an object";
						config_ok = false;
					} else {
						config_ok = parse_config(request["config"], config, error);
					}
				}
				std::vector<FixtureSpec> fixtures;
				bool fixture_present = false;
				bool fixture_ok = config_ok &&
					extract_fixtures(request, config, fixtures, fixture_present, error);
				// No harness prevalidation: Engine::start must record its own
				// validation verdict and last_error.
				bool ok = config_ok && fixture_ok && engine.start(config, error);
				if (ok && fixture_present) {
					provider->configure(fixtures);
				}
				json response = base_response(request, "start", ok);
				response["error"] = error;
				if (ok) {
					response["generation"] = engine.snapshot().generation;
				}
				response["snapshot"] = snapshot_json(engine.snapshot());
				response["backend_provider"] = provider->snapshot_json();
				write_response(response);
			} else if (op == "apply") {
				tcp_proxy::Config config;
				std::string error;
				bool config_ok = true;
				if (request.contains("config") && !request["config"].is_null()) {
					if (!request["config"].is_object()) {
						error = "config must be an object";
						config_ok = false;
					} else {
						config_ok = parse_config(request["config"], config, error);
					}
				}
				std::vector<FixtureSpec> fixtures;
				bool fixture_present = false;
				bool fixture_ok = config_ok &&
					extract_fixtures(request, config, fixtures, fixture_present, error);
				// No harness prevalidation: Engine::apply must record its own
				// validation verdict and last_error.
				bool ok = config_ok && fixture_ok && engine.apply(config, error);
				if (ok && fixture_present) {
					provider->configure(fixtures);
				}
				json response = base_response(request, "apply", ok);
				response["error"] = error;
				response["snapshot"] = snapshot_json(engine.snapshot());
				response["backend_provider"] = provider->snapshot_json();
				write_response(response);
			} else if (op == "snapshot") {
				json response = base_response(request, "snapshot", true);
				response["snapshot"] = snapshot_json(engine.snapshot());
				response["backend_provider"] = provider->snapshot_json();
				write_response(response);
			} else if (op == "provider_snapshot") {
				json response = base_response(request, "provider_snapshot", true);
				response["backend_provider"] = provider->snapshot_json();
				write_response(response);
			} else if (op == "config") {
				json response = base_response(request, "config", true);
				response["config"] = config_json(engine.config());
				response["running"] = engine.running();
				write_response(response);
			} else if (op == "stop") {
				engine.stop();
				json response = base_response(request, "stop", true);
				response["snapshot"] = snapshot_json(engine.snapshot());
				response["backend_provider"] = provider->snapshot_json();
				write_response(response);
			} else if (op == "apply_concurrent") {
				std::vector<tcp_proxy::Config> configs;
				std::vector<std::vector<FixtureSpec>> fixtures;
				std::vector<bool> fixture_present;
				std::string fixture_error;
				const bool fixture_sets_present = request.contains("backend_fixtures")
					&& !request["backend_fixtures"].is_null();
				if (fixture_sets_present && !request["backend_fixtures"].is_array()) {
					fixture_error = "apply_concurrent backend_fixtures must be an array of arrays";
				}
				if (request.contains("configs") && request["configs"].is_array()) {
					for (size_t i = 0; i < request["configs"].size(); ++i) {
						const auto& row = request["configs"][i];
						tcp_proxy::Config config;
						std::string parse_error;
						if (!row.is_object()) {
							fixture_error = "configs[" + std::to_string(i) + "] must be an object";
							break;
						}
						if (!parse_config(row, config, parse_error)) {
							fixture_error = "configs[" + std::to_string(i) + "]: " + parse_error;
							break;
						}
						std::vector<FixtureSpec> rows;
						bool present = false;
						if (fixture_sets_present) {
							const auto& sets = request["backend_fixtures"];
							if (!sets.is_array() || i >= sets.size() || !sets[i].is_array()) {
								fixture_error = "apply_concurrent requires one backend_fixtures "
									"array per config";
								break;
							}
							present = true;
							if (!validate_fixture_rows(sets[i], config, rows, fixture_error)) {
								break;
							}
						}
						configs.push_back(std::move(config));
						fixtures.push_back(std::move(rows));
						fixture_present.push_back(present);
					}
				}
				if (!fixture_error.empty()) {
					json response = base_response(request, "apply_concurrent", false);
					response["error"] = fixture_error;
					write_response(response);
					continue;
				}
				if (configs.size() < 2) {
					json response = base_response(request, "apply_concurrent", false);
					response["error"] = "apply_concurrent requires at least two configs";
					write_response(response);
					continue;
				}
				if (fixture_sets_present
					&& request["backend_fixtures"].size() != configs.size()) {
					json response = base_response(request, "apply_concurrent", false);
					response["error"] = "apply_concurrent backend_fixtures count must match configs";
					write_response(response);
					continue;
				}
				int64_t origin_us = 0;
				const std::vector<ApplyResult> results = run_concurrent_applies(
					engine, provider, configs, fixtures, fixture_present, origin_us);
				json response = base_response(request, "apply_concurrent", true);
				response["origin_us"] = origin_us;
				response["results"] = json::array();
				size_t successes = 0;
				size_t busy = 0;
				bool overlapped = false;
				for (size_t i = 0; i < results.size(); ++i) {
					json row = apply_result_json(results[i]);
					row["index"] = i;
					response["results"].push_back(std::move(row));
					if (results[i].ok) {
						++successes;
					} else if (looks_busy(results[i].error)) {
						++busy;
					}
				}
				for (size_t i = 0; i < results.size(); ++i) {
					for (size_t j = i + 1; j < results.size(); ++j) {
						if (intervals_overlap(results[i], results[j])) {
							overlapped = true;
						}
					}
				}
				response["successes"] = successes;
				response["busy_rejections"] = busy;
				response["overlapped"] = overlapped;
				response["snapshot"] = snapshot_json(engine.snapshot());
				response["backend_provider"] = provider->snapshot_json();
				write_response(response);
			} else if (op == "apply_stop_race") {
				tcp_proxy::Config config;
				std::string fixture_error;
				bool config_ok = true;
				if (request.contains("config") && !request["config"].is_null()) {
					if (!request["config"].is_object()) {
						fixture_error = "config must be an object";
						config_ok = false;
					} else {
						config_ok = parse_config(request["config"], config, fixture_error);
					}
				}
				std::vector<FixtureSpec> fixtures;
				bool fixture_present = false;
				const bool fixture_ok = config_ok && extract_fixtures(
					request, config, fixtures, fixture_present, fixture_error);
				std::mutex mutex;
				std::condition_variable cv;
				int ready = 0;
				bool go = false;
				ApplyResult apply_result;
				int64_t stop_start_us = 0;
				int64_t stop_end_us = 0;
				const Clock::time_point origin = Clock::now();

				std::thread apply_thread([&]() {
					{
						std::unique_lock<std::mutex> lock(mutex);
						++ready;
						cv.notify_all();
						cv.wait(lock, [&go]() { return go; });
					}
					apply_result.start_us = micros_since(origin);
					std::string error;
					try {
						if (!fixture_ok) {
							error = fixture_error;
						} else {
							apply_result.ok = engine.apply(config, error);
							if (apply_result.ok && fixture_present) {
								provider->configure(fixtures);
							}
						}
					} catch (const std::exception& e) {
						error = std::string("exception: ") + e.what();
					} catch (...) {
						error = "unknown exception";
					}
					apply_result.end_us = micros_since(origin);
					apply_result.error = std::move(error);
				});
				std::thread stop_thread([&]() {
					{
						std::unique_lock<std::mutex> lock(mutex);
						++ready;
						cv.notify_all();
						cv.wait(lock, [&go]() { return go; });
					}
					stop_start_us = micros_since(origin);
					try {
						engine.stop();
					} catch (...) {
					}
					stop_end_us = micros_since(origin);
				});
				{
					std::unique_lock<std::mutex> lock(mutex);
					cv.wait(lock, [&]() { return ready == 2; });
					go = true;
				}
				cv.notify_all();
				apply_thread.join();
				stop_thread.join();

				json response = base_response(request, "apply_stop_race", true);
				response["apply"] = apply_result_json(apply_result);
				response["stop"] = json{
					{"start_us", stop_start_us},
					{"end_us", stop_end_us},
				};
				response["snapshot"] = snapshot_json(engine.snapshot());
				response["backend_provider"] = provider->snapshot_json();
				write_response(response);
			} else if (op == "quit") {
				engine.stop();
				json response = base_response(request, "quit", true);
				write_response(response);
				quit = true;
			} else {
				write_response(unknown_op_response(request, op));
			}
		} catch (const std::exception& e) {
			json response = base_response(request, op.c_str(), false);
			response["error"] = std::string("harness exception: ") + e.what();
			write_response(response);
		} catch (...) {
			json response = base_response(request, op.c_str(), false);
			response["error"] = "harness unknown exception";
			write_response(response);
		}
	}

	engine.stop();
	return 0;
}
