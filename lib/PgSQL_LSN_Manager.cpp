#include "PgSQL_LSN_Manager.h"
#ifdef PROXYSQL31
#include <algorithm>
#include <charconv>
#include <cstdio>
#include <deque>
#include <map>
#include <mutex>
#include <set>
using namespace pgsql_lsn;
namespace pgsql_lsn {
std::optional<Lsn> parse_lsn(std::string_view text) {
	const auto slash = text.find('/');
	if (slash == std::string_view::npos || slash == 0 || slash > 8 || text.size() <= slash + 1 ||
		text.size() - slash - 1 > 8)
		return {};
	uint32_t high = 0, low = 0;
	auto a = std::from_chars(text.data(), text.data() + slash, high, 16);
	auto b = std::from_chars(text.data() + slash + 1, text.data() + text.size(), low, 16);
	if (a.ec != std::errc() || a.ptr != text.data() + slash || b.ec != std::errc() ||
		b.ptr != text.data() + text.size())
		return {};
	return (Lsn{high} << 32) | low;
}
std::string format_lsn(Lsn value) {
	char text[18];
	std::snprintf(text, sizeof(text), "%X/%X", unsigned(value >> 32), unsigned(value & 0xffffffff));
	return text;
}
} // namespace pgsql_lsn
namespace {
struct State {
	mutable std::mutex mutex;
	Endpoint endpoint;
	bool tracked = true;
	std::optional<Observation> current;
	std::deque<Sample> samples; // pop_front releases expired chunks, unlike vector capacity.
	std::optional<Micros> boundary;
};
void discard_prefix(State &state, size_t count) {
	while (count--)
		state.samples.pop_front();
}
} // namespace
struct PgSQL_LSN_Manager::Impl {
	mutable std::mutex mutex;
	std::map<Endpoint, std::shared_ptr<State>> endpoints;
	std::shared_ptr<State> find(const Endpoint &e) const {
		std::lock_guard<std::mutex> lock(mutex);
		auto it = endpoints.find(e);
		return it == endpoints.end() ? nullptr : it->second;
	}
	std::vector<std::shared_ptr<State>> all() const {
		std::lock_guard<std::mutex> lock(mutex);
		std::vector<std::shared_ptr<State>> result;
		for (const auto &e : endpoints)
			result.push_back(e.second);
		return result;
	}
};
PgSQL_LSN_Manager::PgSQL_LSN_Manager() : impl_(new Impl) {}
PgSQL_LSN_Manager::~PgSQL_LSN_Manager() = default;
void PgSQL_LSN_Manager::reconcile_endpoints(const std::vector<Endpoint> &endpoints) {
	const std::set<Endpoint> keep(endpoints.begin(), endpoints.end());
	std::lock_guard<std::mutex> registry(impl_->mutex);
	for (const auto &e : keep) {
		auto &s = impl_->endpoints[e];
		if (!s) {
			s = std::make_shared<State>();
			s->endpoint = e;
		} else {
			std::lock_guard<std::mutex> lock(s->mutex);
			if (!s->tracked) {
				s->tracked = true;
			}
		}
	}
	// Retain known identity tombstones, so removal/re-add cannot disguise a reset as first
	// discovery.
	for (auto &e : impl_->endpoints)
		if (!keep.count(e.first)) {
			std::lock_guard<std::mutex> lock(e.second->mutex);
			if (e.second->tracked) {
				e.second->tracked = false;
				e.second->samples.clear();
				if (e.second->current)
					e.second->current->valid = false;
			}
		}
}
void PgSQL_LSN_Manager::publish(const Observation &observation) {
	if (!observation.valid || !observation.history.system_id || !observation.history.timeline ||
		observation.postmaster_start_us <= 0)
		return;
	auto s = impl_->find(observation.endpoint);
	if (!s)
		return;
	std::lock_guard<std::mutex> lock(s->mutex);
	if (!s->tracked)
		return;
	if (s->current) {
		if (observation.sample.started_at <= s->current->sample.started_at)
			return;
		if (!(observation.history == s->current->history) ||
			observation.postmaster_start_us != s->current->postmaster_start_us ||
			observation.sample.lsn < s->current->sample.lsn) {
			s->boundary = observation.sample.started_at;
			s->samples.clear();
		}
	}
	if (!s->samples.empty() && s->samples.back().lsn == observation.sample.lsn)
		s->samples.back() = observation.sample;
	else
		s->samples.push_back(observation.sample);
	s->current = observation;
}
void PgSQL_LSN_Manager::withdraw(const Endpoint &endpoint) {
	auto s = impl_->find(endpoint);
	if (!s)
		return;
	std::lock_guard<std::mutex> lock(s->mutex);
	if (s->current && s->current->valid) {
		s->current->valid = false;
	}
}
LookupResult PgSQL_LSN_Manager::lookup_after(const Endpoint &endpoint, Micros completed_at) const {
	auto s = impl_->find(endpoint);
	if (!s)
		return {};
	std::lock_guard<std::mutex> lock(s->mutex);
	if (s->boundary && completed_at < *s->boundary)
		return {LookupState::HistoryChanged, {}};
	if (!s->tracked)
		return {};
	const auto sample =
		std::upper_bound(s->samples.begin(), s->samples.end(), completed_at,
						 [](Micros t, const Sample &p) { return t < p.started_at; });
	if (sample == s->samples.end())
		return {LookupState::Pending, {}};
	return {LookupState::Ready, RequiredLsn{s->current->history, sample->lsn}};
}
std::optional<Observation> PgSQL_LSN_Manager::latest(const Endpoint &endpoint) const {
	auto s = impl_->find(endpoint);
	if (!s)
		return {};
	std::lock_guard<std::mutex> lock(s->mutex);
	return s->tracked ? s->current : std::nullopt;
}
void PgSQL_LSN_Manager::retain_predecessor(const Endpoint &endpoint, Lsn floor) {
	auto s = impl_->find(endpoint);
	if (!s)
		return;
	std::lock_guard<std::mutex> lock(s->mutex);
	auto first = std::lower_bound(s->samples.begin(), s->samples.end(), floor,
								  [](const Sample &p, Lsn l) { return p.lsn < l; });
	const size_t below = first - s->samples.begin();
	if (below > 1) {
		discard_prefix(*s, below - 1);
	}
}
void PgSQL_LSN_Manager::prune_before(Micros cutoff) {
	for (auto &s : impl_->all()) {
		std::lock_guard<std::mutex> lock(s->mutex);
		auto first = std::lower_bound(s->samples.begin(), s->samples.end(), cutoff,
									  [](const Sample &p, Micros t) { return p.started_at < t; });
		const size_t before = first - s->samples.begin();
		if (before > 1) {
			discard_prefix(*s, before - 1);
		}
	}
}
std::vector<Observation> PgSQL_LSN_Manager::latest_all() const {
	std::vector<Observation> result;
	for (auto &s : impl_->all()) {
		std::lock_guard<std::mutex> lock(s->mutex);
		if (!s->tracked) continue;
		if (s->current) {
			result.push_back(*s->current);
		} else {
			Observation unavailable;
			unavailable.endpoint = s->endpoint;
			result.push_back(std::move(unavailable));
		}
	}
	return result;
}
#endif
