#include "PgSQL_LSN_Manager.h"
#include <algorithm>
#include <atomic>
#include <charconv>
#include <cstdio>
#include <map>
#include <mutex>
#include <set>
using namespace pgsql_lsn;

namespace pgsql_lsn {
struct Batch {
	uint64_t id = 0, attempt = 0;
	bool in_flight = false;
	std::optional<Lsn> lsn;
};
struct ServerState {
	mutable std::mutex mutex;
	Endpoint endpoint;
	bool tracked = true;
	Generation generation = 0;
	uint64_t next_batch = 1, completions = 0, batches = 0;
	uint64_t retired_connection = 0;
	std::optional<ServerToken> writer;
	std::optional<Lsn> last_insert;
	std::optional<Progress> progress;
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
	return source.incarnation.history == backend.incarnation.history
		&& *progress.replay_lsn >= *dependency.required_lsn;
}
} // namespace pgsql_lsn

struct PgSQL_LSN_Manager::Impl {
	// Lock order: endpoint registry -> individual server. No external callbacks.
	mutable std::mutex mutex;
	std::map<Endpoint, std::shared_ptr<ServerState>> servers;
	std::atomic<Generation> next_generation{1};
	std::atomic<uint64_t> revision{1};
	std::shared_ptr<ServerState> find(const Endpoint& endpoint) const {
		std::lock_guard<std::mutex> lock(mutex);
		auto it = servers.find(endpoint);
		return it == servers.end() ? nullptr : it->second;
	}
	void invalidate(ServerState& s) {
		s.generation = next_generation.fetch_add(1);
		s.writer.reset(); s.last_insert.reset(); s.progress.reset();
		s.open.reset(); s.sealed.reset(); s.resolved.clear();
		++revision;
	}
};
namespace {
void maximum(std::optional<Lsn>& value, std::optional<Lsn> candidate) {
	if (candidate && (!value || *candidate > *value)) value = candidate;
}
bool acceptable_progress(const ServerState& s, const Progress& p) {
	if (!s.tracked || s.generation != p.server.generation || !(s.endpoint == p.server.endpoint)
		|| !p.valid || !p.server.incarnation.history.system_id || !p.server.incarnation.history.timeline
		|| !p.server.incarnation.postmaster_start_us) return false;
	if (p.server.role == Role::Writer ? !p.insert_lsn : !p.replay_lsn) return false;
	if (s.retired_connection && p.connection_generation <= s.retired_connection) return false;
	if (s.progress) {
		if (p.connection_generation < s.progress->connection_generation) return false;
		if (p.connection_generation == s.progress->connection_generation &&
			p.sampled_at_us < s.progress->sampled_at_us) return false;
	}
	return true;
}
ServerSnapshot copy_snapshot(ServerState& s) {
	ServerSnapshot result;
	result.endpoint = s.endpoint; result.generation = s.generation; result.progress = s.progress;
	result.completions = s.completions; result.batches = s.batches;
	for (const auto* batch : {&s.open, &s.sealed}) {
		if (!*batch) continue;
		++result.unresolved_batches;
		if (batch->use_count() > 1) { ++result.live_batches; result.has_pending = true; }
	}
	s.resolved.erase(std::remove_if(s.resolved.begin(), s.resolved.end(), [&](const std::weak_ptr<Batch>& weak) {
		auto batch = weak.lock();
		if (!batch) return true;
		++result.live_batches; maximum(result.required_lsn, batch->lsn);
		return false;
	}), s.resolved.end());
	return result;
}
} // namespace

PgSQL_LSN_Manager::PgSQL_LSN_Manager() : impl_(new Impl) {}
PgSQL_LSN_Manager::~PgSQL_LSN_Manager() = default;
void PgSQL_LSN_Manager::reconcile_endpoints(const std::vector<Endpoint>& endpoints) {
	const std::set<Endpoint> keep(endpoints.begin(), endpoints.end());
	std::lock_guard<std::mutex> registry(impl_->mutex);
	for (const auto& endpoint : keep) {
		auto& server = impl_->servers[endpoint];
		if (server) continue;
		server = std::make_shared<ServerState>();
		server->endpoint = endpoint;
		server->generation = impl_->next_generation.fetch_add(1);
		++impl_->revision;
	}
	for (auto it = impl_->servers.begin(); it != impl_->servers.end();) {
		if (keep.count(it->first)) { ++it; continue; }
		auto retired = it->second; // Keep the mutex alive through guard destruction.
		std::lock_guard<std::mutex> lock(retired->mutex);
		impl_->invalidate(*retired); retired->tracked = false;
		it = impl_->servers.erase(it);
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
	auto server = impl_->find(source.endpoint);
	if (!server) { dependency.error_ = Reason::HistoryChanged; return dependency; }
	std::lock_guard<std::mutex> lock(server->mutex);
	if (!server->writer || !(*server->writer == source) || !server->tracked) {
		dependency.error_ = Reason::HistoryChanged;
		return dependency;
	}
	if (prior.source && !(*prior.source == source)) {
		dependency.error_ = Reason::HistoryChanged;
		return dependency;
	}
	if (!server->open) {
		server->open = std::make_shared<Batch>();
		server->open->id = server->next_batch++;
	}
	dependency.server_ = server;
	dependency.batch_ = server->open;
	dependency.floor_ = prior.required_lsn;
	++server->completions;
	++impl_->revision;
	return dependency;
}

DependencyView PgSQL_LSN_Manager::resolve(const Dependency& dependency) const {
	DependencyView result;
	result.source = dependency.source_;
	if (dependency.error_ != Reason::None) {
		result.state = DependencyState::Invalid; result.reason = dependency.error_; return result;
	}
	if (!dependency.server_) return result;
	std::lock_guard<std::mutex> lock(dependency.server_->mutex);
	const auto& server = *dependency.server_;
	result.revision = impl_->revision.load();
	if (!server.tracked || !result.source || result.source->generation != server.generation) {
		result.state = DependencyState::Invalid; result.reason = Reason::HistoryChanged; return result;
	}
	result.batch_id = dependency.batch_->id;
	result.required_lsn = dependency.floor_;
	maximum(result.required_lsn, dependency.batch_->lsn);
	result.state = dependency.batch_->lsn ? DependencyState::Ready : DependencyState::Pending;
	return result;
}

std::optional<SampleTicket> PgSQL_LSN_Manager::seal_writer_batch(const Endpoint& endpoint) {
	auto server = impl_->find(endpoint);
	if (!server) return {};
	std::lock_guard<std::mutex> lock(server->mutex);
	if (!server->writer || !server->tracked) return {};
	if (server->sealed && server->sealed->in_flight) return {};
	if (server->sealed && server->sealed.use_count() == 1) server->sealed.reset();
	if (!server->sealed) {
		if (!server->open || server->open.use_count() == 1) { server->open.reset(); return {}; }
		server->sealed = std::move(server->open);
		++server->batches;
	}
	server->sealed->in_flight = true;
	SampleTicket ticket;
	ticket.source_ = *server->writer;
	ticket.batch_ = server->sealed->id;
	ticket.attempt_ = ++server->sealed->attempt;
	++impl_->revision;
	return ticket;
}

bool PgSQL_LSN_Manager::complete_writer_sample(const SampleTicket& ticket, const Progress& progress) {
	auto server = impl_->find(ticket.source_.endpoint);
	if (!server) return false;
	std::lock_guard<std::mutex> lock(server->mutex);
	auto& batch = server->sealed;
	if (!batch || !batch->in_flight || batch->id != ticket.batch_ || batch->attempt != ticket.attempt_
		|| !(progress.server == ticket.source_) || !acceptable_progress(*server, progress)
		|| (server->last_insert && *progress.insert_lsn < *server->last_insert)) return false;
	batch->lsn = progress.insert_lsn;
	batch->in_flight = false;
	server->last_insert = progress.insert_lsn;
	server->progress = progress;
	server->resolved.erase(std::remove_if(server->resolved.begin(), server->resolved.end(),
		[](const std::weak_ptr<Batch>& b) { return b.expired(); }), server->resolved.end());
	server->resolved.emplace_back(batch);
	batch.reset();
	++impl_->revision;
	return true;
}

void PgSQL_LSN_Manager::fail_writer_sample(const SampleTicket& ticket, const std::string& error) {
	auto server = impl_->find(ticket.source_.endpoint);
	if (!server) return;
	std::lock_guard<std::mutex> lock(server->mutex);
	auto& batch = server->sealed;
	if (server->generation != ticket.source_.generation || !batch || batch->id != ticket.batch_
		|| batch->attempt != ticket.attempt_ || !batch->in_flight) return;
	batch->in_flight = false;
	if (server->progress) { server->progress->valid = false; server->progress->error = error; }
	++impl_->revision;
}

void PgSQL_LSN_Manager::publish_progress(const Progress& progress) {
	auto server = impl_->find(progress.server.endpoint);
	if (!server) return;
	std::lock_guard<std::mutex> lock(server->mutex);
	if (!acceptable_progress(*server, progress)) return;
	if (server->progress && !(server->progress->server == progress.server)) {
		impl_->invalidate(*server);
		return; // Revalidate in a new generation; never transplant dependencies.
	}
	if (progress.server.role == Role::Writer) {
		if (server->last_insert && *progress.insert_lsn < *server->last_insert) return;
		server->writer = progress.server; server->last_insert = progress.insert_lsn;
	}
	server->progress = progress;
	++impl_->revision;
}
void PgSQL_LSN_Manager::invalidate_endpoint(const Endpoint& endpoint, Reason reason,
	uint64_t retired_connection_generation) {
	auto server = impl_->find(endpoint);
	if (!server) return;
	std::lock_guard<std::mutex> lock(server->mutex);
	server->retired_connection = std::max(server->retired_connection, retired_connection_generation);
	if (reason == Reason::HistoryChanged) { impl_->invalidate(*server); return; }
	if (server->progress) { server->progress->valid = false; server->progress->error = reason_code(reason); }
	++impl_->revision;
}
ServerSnapshot PgSQL_LSN_Manager::snapshot(const Endpoint& endpoint) const {
	auto server = impl_->find(endpoint);
	if (!server) return {};
	std::lock_guard<std::mutex> lock(server->mutex);
	return copy_snapshot(*server);
}
std::vector<ServerSnapshot> PgSQL_LSN_Manager::snapshots() const {
	std::vector<std::shared_ptr<ServerState>> servers;
	{
		std::lock_guard<std::mutex> registry(impl_->mutex);
		for (const auto& entry : impl_->servers) servers.push_back(entry.second);
	}
	std::vector<ServerSnapshot> result;
	for (auto& server : servers) {
		std::lock_guard<std::mutex> lock(server->mutex);
		result.push_back(copy_snapshot(*server));
	}
	return result;
}
uint64_t PgSQL_LSN_Manager::revision() const { return impl_->revision.load(); }
