#include "PgSQL_LSN_Manager.h"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cstdio>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>

using namespace pgsql_lsn;

namespace pgsql_lsn {
struct Batch {
	uint64_t id = 0, attempt = 0;
	bool in_flight = false;
	std::optional<Lsn> lsn;
};
struct GroupState {
	mutable std::mutex mutex;
	GroupConfig config;
	Generation generation = 0;
	uint64_t revision = 1, activation_epoch = 0, next_batch = 1;
	uint64_t completions = 0, batches = 0;
	std::optional<ServerToken> writer;
	std::optional<Lsn> last_insert;
	std::map<Endpoint, Progress> servers;
	std::map<Endpoint, uint64_t> retired_connections;
	std::shared_ptr<Batch> open, sealed;
	std::vector<std::weak_ptr<Batch>> resolved;
};

std::optional<Lsn> parse_lsn(std::string_view text) {
	const auto slash = text.find('/');
	if (slash == std::string_view::npos || slash == 0 || slash > 8
		|| text.size() <= slash + 1 || text.size() - slash - 1 > 8) return {};
	uint32_t high = 0, low = 0;
	auto a = std::from_chars(text.data(), text.data() + slash, high, 16);
	auto b = std::from_chars(text.data() + slash + 1, text.data() + text.size(), low, 16);
	if (a.ec != std::errc() || a.ptr != text.data() + slash
		|| b.ec != std::errc() || b.ptr != text.data() + text.size()) return {};
	return (static_cast<Lsn>(high) << 32) | low;
}
std::string format_lsn(Lsn value) {
	char text[18];
	std::snprintf(text, sizeof(text), "%X/%X", static_cast<unsigned>(value >> 32),
		static_cast<unsigned>(value & 0xffffffff));
	return text;
}
const char* reason_code(Reason reason) {
	switch (reason) {
	case Reason::None: return "";
	case Reason::HistoryChanged: return "LSN_HISTORY_CHANGED";
	case Reason::TrackingNotInitialized: return "LSN_TRACKING_NOT_INITIALIZED";
	case Reason::NoSafeBackend: return "LSN_NO_SAFE_BACKEND";
	}
	return "LSN_NO_SAFE_BACKEND";
}
bool replica_satisfies(const DependencyView& dependency, const Progress& progress,
	const ServerToken& backend) {
	if (dependency.state != DependencyState::Ready || !dependency.source
		|| !dependency.required_lsn || !progress.valid || !progress.replay_lsn
		|| backend.role != Role::Replica || !(backend == progress.server)) return false;
	const auto& source = *dependency.source;
	return source.group == backend.group && source.generation == backend.generation
		&& source.incarnation.history == backend.incarnation.history
		&& *progress.replay_lsn >= *dependency.required_lsn;
}
bool validate_lsn_groups(const std::vector<GroupConfig>& groups, std::string& error) {
	std::set<uint32_t> used;
	for (const auto& g : groups) {
		if (!g.enabled) continue;
		if (!used.insert(g.writer_hostgroup).second || !used.insert(g.reader_hostgroup).second) {
			error = "LSN causal hostgroups must have disjoint writer and reader membership";
			return false;
		}
	}
	error.clear();
	return true;
}
} // namespace pgsql_lsn

struct PgSQL_LSN_Manager::Impl {
	// Lock order: registry -> group. No callback or external lock under either.
	mutable std::mutex mutex;
	std::map<GroupId, std::shared_ptr<GroupState>> groups;
	std::atomic<Generation> next_generation{1};
	uint64_t config_epoch = 0;
	std::shared_ptr<GroupState> find(GroupId id) const {
		std::lock_guard<std::mutex> lock(mutex);
		auto it = groups.find(id);
		return it == groups.end() ? nullptr : it->second;
	}
	void invalidate(GroupState& g) {
		g.generation = next_generation.fetch_add(1);
		++g.revision;
		g.writer.reset();
		g.last_insert.reset();
		g.open.reset();
		g.sealed.reset();
		g.resolved.clear();
		g.servers.clear();
		g.retired_connections.clear();
	}
};

namespace {
bool contains(const std::vector<Endpoint>& endpoints, const Endpoint& endpoint) {
	return std::find(endpoints.begin(), endpoints.end(), endpoint) != endpoints.end();
}
void maximum(std::optional<Lsn>& value, std::optional<Lsn> candidate) {
	if (candidate && (!value || *candidate > *value)) value = candidate;
}
bool acceptable_progress(const GroupState& g, const Progress& p) {
	if (!g.config.enabled || g.generation != p.server.generation
		|| p.server.group != g.config.writer_hostgroup || !p.valid
		|| !p.server.incarnation.history.system_id || !p.server.incarnation.history.timeline
		|| !p.server.incarnation.postmaster_start_us) return false;
	if (p.server.role == Role::Writer) {
		if (g.config.writers.size() != 1 || !(g.config.writers[0] == p.server.endpoint) || !p.insert_lsn)
			return false;
	} else if (!contains(g.config.readers, p.server.endpoint) || !p.replay_lsn) return false;
	auto retired = g.retired_connections.find(p.server.endpoint);
	if (retired != g.retired_connections.end() && p.connection_generation <= retired->second) return false;
	auto it = g.servers.find(p.server.endpoint);
	if (it != g.servers.end()) {
		const auto& prev = it->second;
		if (p.connection_generation < prev.connection_generation) return false;
		if (p.connection_generation == prev.connection_generation && p.sampled_at_us < prev.sampled_at_us)
			return false;
	}
	return true;
}
GroupSnapshot copy_snapshot(GroupState& g) {
	GroupSnapshot result;
	result.config = g.config;
	result.generation = g.generation;
	result.revision = g.revision;
	result.activation_epoch = g.activation_epoch;
	result.writer = g.writer;
	result.completions = g.completions;
	result.batches = g.batches;
	for (const auto& entry : g.servers) result.servers.push_back(entry.second);
	for (const auto* batch : {&g.open, &g.sealed}) {
		if (!*batch) continue;
		++result.unresolved_batches;
		if (batch->use_count() > 1) {
			++result.live_batches;
			result.has_pending = true;
		}
	}
	g.resolved.erase(std::remove_if(g.resolved.begin(), g.resolved.end(), [&](const std::weak_ptr<Batch>& weak) {
		auto batch = weak.lock();
		if (!batch) return true;
		++result.live_batches;
		maximum(result.required_lsn, batch->lsn);
		return false;
	}), g.resolved.end());
	return result;
}
} // namespace

PgSQL_LSN_Manager::PgSQL_LSN_Manager() : impl_(new Impl) {}
PgSQL_LSN_Manager::~PgSQL_LSN_Manager() = default;

void PgSQL_LSN_Manager::reconcile_groups(const std::vector<GroupConfig>& configs) {
	std::string error;
	if (!validate_lsn_groups(configs, error)) throw std::invalid_argument(error);
	std::lock_guard<std::mutex> registry(impl_->mutex);
	std::set<GroupId> keep;
	for (auto config : configs) {
		if (!config.enabled) continue;
		std::sort(config.writers.begin(), config.writers.end());
		std::sort(config.readers.begin(), config.readers.end());
		keep.insert(config.writer_hostgroup);
		auto& group = impl_->groups[config.writer_hostgroup];
		if (!group) {
			group = std::make_shared<GroupState>();
			group->generation = impl_->next_generation.fetch_add(1);
			group->activation_epoch = ++impl_->config_epoch;
		}
		std::lock_guard<std::mutex> lock(group->mutex);
		const auto& old = group->config;
		if (old.enabled && (old.reader_hostgroup != config.reader_hostgroup || old.writers != config.writers)) {
			impl_->invalidate(*group);
			++impl_->config_epoch;
		} else if (old.readers != config.readers) {
			for (auto it = group->servers.begin(); it != group->servers.end();) {
				if (it->second.server.role == Role::Replica && !contains(config.readers, it->first))
					it = group->servers.erase(it);
				else ++it;
			}
			++group->revision;
		}
		group->config = std::move(config);
	}
	for (auto it = impl_->groups.begin(); it != impl_->groups.end();) {
		if (keep.count(it->first)) { ++it; continue; }
		auto retired = it->second; // Own the mutex until its guard is destroyed.
		std::lock_guard<std::mutex> lock(retired->mutex);
		impl_->invalidate(*retired);
		retired->config.enabled = false;
		++impl_->config_epoch;
		it = impl_->groups.erase(it);
	}
}

Dependency PgSQL_LSN_Manager::observe_completion(const ServerToken& source, const Dependency& previous) {
	Dependency dependency;
	dependency.source_ = source;
	const auto prior = resolve(previous);
	if (prior.state == DependencyState::Invalid) {
		dependency.error_ = prior.reason;
		return dependency;
	}
	auto group = impl_->find(source.group);
	if (!group) { dependency.error_ = Reason::HistoryChanged; return dependency; }
	std::lock_guard<std::mutex> lock(group->mutex);
	if (!group->writer || !(*group->writer == source) || group->config.writers.size() != 1) {
		dependency.error_ = Reason::HistoryChanged;
		return dependency;
	}
	if (prior.source && !(*prior.source == source)) {
		dependency.error_ = Reason::HistoryChanged;
		return dependency;
	}
	if (!group->open) {
		group->open = std::make_shared<Batch>();
		group->open->id = group->next_batch++;
	}
	dependency.group_ = group;
	dependency.batch_ = group->open;
	dependency.floor_ = prior.required_lsn;
	++group->completions;
	++group->revision;
	return dependency;
}

DependencyView PgSQL_LSN_Manager::resolve(const Dependency& dependency) const {
	DependencyView result;
	result.source = dependency.source_;
	if (dependency.error_ != Reason::None) {
		result.state = DependencyState::Invalid; result.reason = dependency.error_; return result;
	}
	if (!dependency.group_) return result;
	std::lock_guard<std::mutex> lock(dependency.group_->mutex);
	const auto& group = *dependency.group_;
	result.revision = group.revision;
	if (!group.config.enabled || !result.source || result.source->generation != group.generation) {
		result.state = DependencyState::Invalid; result.reason = Reason::HistoryChanged; return result;
	}
	result.batch_id = dependency.batch_->id;
	result.required_lsn = dependency.floor_;
	maximum(result.required_lsn, dependency.batch_->lsn);
	result.state = dependency.batch_->lsn ? DependencyState::Ready : DependencyState::Pending;
	return result;
}

std::optional<SampleTicket> PgSQL_LSN_Manager::seal_writer_batch(GroupId id) {
	auto group = impl_->find(id);
	if (!group) return {};
	std::lock_guard<std::mutex> lock(group->mutex);
	if (!group->writer || group->config.writers.size() != 1) return {};
	if (group->sealed && group->sealed->in_flight) return {};
	if (group->sealed && group->sealed.use_count() == 1) group->sealed.reset();
	if (!group->sealed) {
		if (!group->open || group->open.use_count() == 1) { group->open.reset(); return {}; }
		group->sealed = std::move(group->open);
		++group->batches;
	}
	group->sealed->in_flight = true;
	SampleTicket ticket;
	ticket.source_ = *group->writer;
	ticket.batch_ = group->sealed->id;
	ticket.attempt_ = ++group->sealed->attempt;
	++group->revision;
	return ticket;
}

bool PgSQL_LSN_Manager::complete_writer_sample(const SampleTicket& ticket, const Progress& progress) {
	auto group = impl_->find(ticket.source_.group);
	if (!group) return false;
	std::lock_guard<std::mutex> lock(group->mutex);
	auto& batch = group->sealed;
	if (!batch || !batch->in_flight || batch->id != ticket.batch_ || batch->attempt != ticket.attempt_
		|| !(progress.server == ticket.source_) || !acceptable_progress(*group, progress)
		|| (group->last_insert && *progress.insert_lsn < *group->last_insert)) return false;
	batch->lsn = progress.insert_lsn;
	batch->in_flight = false;
	group->last_insert = progress.insert_lsn;
	group->servers[progress.server.endpoint] = progress;
	group->resolved.erase(std::remove_if(group->resolved.begin(), group->resolved.end(),
		[](const std::weak_ptr<Batch>& b) { return b.expired(); }), group->resolved.end());
	group->resolved.emplace_back(batch);
	batch.reset();
	++group->revision;
	return true;
}

void PgSQL_LSN_Manager::fail_writer_sample(const SampleTicket& ticket, const std::string& error) {
	auto group = impl_->find(ticket.source_.group);
	if (!group) return;
	std::lock_guard<std::mutex> lock(group->mutex);
	auto& batch = group->sealed;
	if (group->generation != ticket.source_.generation || !batch || batch->id != ticket.batch_
		|| batch->attempt != ticket.attempt_ || !batch->in_flight) return;
	batch->in_flight = false;
	auto it = group->servers.find(ticket.source_.endpoint);
	if (it != group->servers.end()) { it->second.valid = false; it->second.error = error; }
	++group->revision;
}

void PgSQL_LSN_Manager::publish_progress(const Progress& progress) {
	auto group = impl_->find(progress.server.group);
	if (!group) return;
	std::lock_guard<std::mutex> lock(group->mutex);
	if (!acceptable_progress(*group, progress)) return;
	if (progress.server.role == Role::Writer) {
		if (group->writer && !(*group->writer == progress.server)) {
			impl_->invalidate(*group);
			return; // Revalidate in the new generation; never transplant dependencies.
		}
		if (group->last_insert && *progress.insert_lsn < *group->last_insert) return;
		group->writer = progress.server;
		group->last_insert = progress.insert_lsn;
	}
	group->servers[progress.server.endpoint] = progress;
	++group->revision;
}

void PgSQL_LSN_Manager::invalidate_endpoint(const Endpoint& endpoint, Reason reason,
	uint64_t retired_connection_generation) {
	std::vector<std::shared_ptr<GroupState>> groups;
	{
		std::lock_guard<std::mutex> registry(impl_->mutex);
		for (const auto& entry : impl_->groups) groups.push_back(entry.second);
	}
	for (auto& group : groups) {
		std::lock_guard<std::mutex> lock(group->mutex);
		if (retired_connection_generation && (contains(group->config.writers, endpoint) || contains(group->config.readers, endpoint)))
			group->retired_connections[endpoint] = std::max(group->retired_connections[endpoint], retired_connection_generation);
		if (reason == Reason::HistoryChanged && group->writer && group->writer->endpoint == endpoint) {
			impl_->invalidate(*group);
			continue;
		}
		auto it = group->servers.find(endpoint);
		if (it == group->servers.end()) continue;
		it->second.valid = false;
		it->second.error = reason_code(reason);
		++group->revision;
	}
}

GroupSnapshot PgSQL_LSN_Manager::snapshot(GroupId id) const {
	auto group = impl_->find(id);
	if (!group) return {};
	std::lock_guard<std::mutex> lock(group->mutex);
	return copy_snapshot(*group);
}
std::vector<GroupSnapshot> PgSQL_LSN_Manager::snapshots() const {
	std::vector<std::shared_ptr<GroupState>> groups;
	{
		std::lock_guard<std::mutex> registry(impl_->mutex);
		for (const auto& entry : impl_->groups) groups.push_back(entry.second);
	}
	std::vector<GroupSnapshot> result;
	for (auto& group : groups) {
		std::lock_guard<std::mutex> lock(group->mutex);
		result.push_back(copy_snapshot(*group));
	}
	return result;
}
std::optional<GroupId> PgSQL_LSN_Manager::group_for_hostgroup(uint32_t hostgroup) const {
	std::lock_guard<std::mutex> registry(impl_->mutex);
	for (const auto& entry : impl_->groups) {
		std::lock_guard<std::mutex> lock(entry.second->mutex);
		if (entry.second->config.writer_hostgroup == hostgroup || entry.second->config.reader_hostgroup == hostgroup)
			return entry.first;
	}
	return {};
}
uint64_t PgSQL_LSN_Manager::configuration_epoch() const {
	std::lock_guard<std::mutex> registry(impl_->mutex);
	return impl_->config_epoch;
}
