#include "PgSQL_LSN_Monitor.h"
#ifdef PROXYSQL31
#include "PgSQL_LSN_Probe.h"
#include <algorithm>
#include <chrono>
#include <libpq-fe.h>
#include <limits>
#include <map>
#include <mutex>
#include <poll.h>
#include <set>
#include <thread>
using namespace pgsql_lsn;
namespace {
Micros clock_us() {
	return std::chrono::duration_cast<std::chrono::microseconds>(
			   std::chrono::steady_clock::now().time_since_epoch())
		.count();
}
Micros deadline_after(Micros now, Micros timeout) {
	return timeout > std::numeric_limits<Micros>::max() - now ? std::numeric_limits<Micros>::max()
															  : now + timeout;
}
// libpq can resolve an uncached hostname synchronously in PQconnectStart. Only
// that start runs off-scheduler. A process-wide registry bounds blocked starts
// across timeout, reset and monitor disable/re-enable to one per endpoint.
// Helpers own strings and libpq only, never a monitor/manager/session pointer.
struct ConnectionStart {
	std::mutex mutex;
	PGconn *conn = nullptr;
	bool ready = false, cancelled = false;
	~ConnectionStart() {
		if (conn)
			PQfinish(conn);
	}
};
struct StartRegistry {
	std::mutex mutex;
	std::map<Endpoint, std::shared_ptr<ConnectionStart>> entries;
};
StartRegistry &start_registry() {
	// A resolver may finish while static objects are being destroyed at process
	// exit. Keep only this tiny registry process-lived; completed entries erase
	// themselves and their PGconn storage is still released normally.
	static auto *registry = new StartRegistry;
	return *registry;
}
std::shared_ptr<ConnectionStart> begin_connection(const Endpoint &endpoint, std::string conninfo) {
	auto &registry = start_registry();
	std::lock_guard<std::mutex> guard(registry.mutex);
	auto old = registry.entries.find(endpoint);
	if (old != registry.entries.end())
		return old->second;
	auto start = std::make_shared<ConnectionStart>();
	registry.entries.emplace(endpoint, start);
	std::thread([endpoint, conninfo = std::move(conninfo), start] {
		PGconn *conn = PQconnectStart(conninfo.c_str());
		{
			std::lock_guard<std::mutex> lock(start->mutex);
			start->conn = conn;
			start->ready = true;
		}
		auto &registry = start_registry();
		std::lock_guard<std::mutex> guard(registry.mutex);
		auto it = registry.entries.find(endpoint);
		if (it != registry.entries.end() && it->second == start)
			registry.entries.erase(it);
	}).detach();
	return start;
}
struct Entry {
	PGconn *conn = nullptr;
	std::shared_ptr<ConnectionStart> starter;
	bool connecting = false, flushing = false;
	short events = POLLIN;
	Micros deadline = 0;
	ProbeCadence cadence;
	std::optional<History> identity;
	std::optional<WalLayout> layout;
	std::unique_ptr<PgSQL_LSN_Probe> probe;
	ProbeRows rows;
	unsigned results = 0;
	~Entry() {
		if (conn)
			PQfinish(conn);
	}
};
} // namespace
struct PgSQL_LSN_Monitor::Impl {
	PgSQL_LSN_Manager &manager;
	Conninfo conninfo;
	Clock clock;
	Housekeeping housekeeping;
	std::map<Endpoint, Entry> entries;
	Micros interval = 10000;
	bool changed = false;
	Impl(PgSQL_LSN_Manager &m, Conninfo c, Clock k, Housekeeping h)
		: manager(m), conninfo(std::move(c)), clock(k ? std::move(k) : Clock{clock_us}),
		  housekeeping(std::move(h)) {
	}
	void retire(const Endpoint &endpoint, Entry &e) {
		manager.withdraw(endpoint);
		if (e.starter) {
			std::lock_guard<std::mutex> lock(e.starter->mutex);
			e.starter->cancelled = true;
		}
		e.starter.reset();
		if (e.conn)
			PQfinish(e.conn);
		e.conn = nullptr;
		e.connecting = e.flushing = false;
		e.probe.reset();
		e.identity.reset();
		e.layout.reset();
		e.rows.clear();
		e.results = 0;
		e.cadence.finished();
		changed = true;
	}
	bool send(Entry &e) {
		// This clock is monotonic_time() in production, identical to frontend
		// completion.
		const Micros sent_at = clock();
		auto command = e.probe->next_command(sent_at);
		if (!command || !PQsendQuery(e.conn, command->c_str()))
			return false;
		if (command->compare(0, 6, "SELECT") == 0)
			e.cadence.started(sent_at);
		e.rows.clear();
		e.results = 0;
		const int flush = PQflush(e.conn);
		if (flush < 0)
			return false;
		e.flushing = flush != 0;
		e.events = POLLIN | (e.flushing ? POLLOUT : 0);
		return true;
	}
	bool start_probe(const Endpoint &endpoint, Entry &e, Micros now, Micros timeout) {
		e.deadline = deadline_after(now, timeout);
		e.probe.reset(new PgSQL_LSN_Probe(endpoint, e.identity, e.layout));
		return send(e);
	}
	void advance(const Endpoint &endpoint, Entry &e, Micros now, Micros timeout) {
		if ((e.connecting || e.probe) && now >= e.deadline) {
			retire(endpoint, e);
			return;
		}
		if (e.starter) {
			bool ready = false, failed = false;
			{
				std::lock_guard<std::mutex> lock(e.starter->mutex);
				ready = e.starter->ready;
				if (ready) {
					failed = e.starter->cancelled;
					if (!failed) {
						e.conn = e.starter->conn;
						e.starter->conn = nullptr;
					}
				}
			}
			if (!ready)
				return;
			e.starter.reset();
			if (failed || !e.conn || PQstatus(e.conn) == CONNECTION_BAD ||
				PQsetnonblocking(e.conn, 1)) {
				retire(endpoint, e);
				return;
			}
		}
		pollfd fd{PQsocket(e.conn), e.events, 0};
		if (fd.fd < 0 || poll(&fd, 1, 0) < 0 || (fd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
			retire(endpoint, e);
			return;
		}
		if (e.connecting) {
			if (!fd.revents)
				return;
			const auto status = PQconnectPoll(e.conn);
			if (status == PGRES_POLLING_READING) {
				e.events = POLLIN;
				return;
			}
			if (status == PGRES_POLLING_WRITING) {
				e.events = POLLOUT;
				return;
			}
			if (status != PGRES_POLLING_OK) {
				retire(endpoint, e);
				return;
			}
			e.connecting = false;
			if (!start_probe(endpoint, e, now, timeout))
				retire(endpoint, e);
			return;
		}
		if ((fd.revents & POLLIN) && !PQconsumeInput(e.conn)) {
			retire(endpoint, e);
			return;
		}
		if (e.flushing && fd.revents) {
			const int flushed = PQflush(e.conn);
			if (flushed < 0) {
				retire(endpoint, e);
				return;
			}
			e.flushing = flushed != 0;
			e.events = POLLIN | (e.flushing ? POLLOUT : 0);
		}
		if (!e.probe || e.flushing)
			return;
		// Check before every PQgetResult, including final NULL after delayed Z.
		while (!PQisBusy(e.conn)) {
			PGresult *result = PQgetResult(e.conn);
			if (result) {
				const bool valid = ++e.results == 1 && PQresultStatus(result) == PGRES_TUPLES_OK &&
								   PQntuples(result) == 1 && PQnfields(result) <= 4;
				if (valid) {
					std::vector<std::optional<std::string>> row;
					for (int col = 0; col < PQnfields(result); ++col)
						row.emplace_back(
							PQgetisnull(result, 0, col)
								? std::nullopt
								: std::optional<std::string>{std::string(
									  PQgetvalue(result, 0, col), PQgetlength(result, 0, col))});
					e.rows.emplace_back(std::move(row));
				}
				PQclear(result);
				if (!valid) {
					retire(endpoint, e);
					return;
				}
				continue;
			}
			std::string error;
			if (e.results != 1 || !e.probe->consume_result(e.rows, error)) {
				retire(endpoint, e);
				return;
			}
			auto observation = e.probe->finish();
			if (!observation) {
				if (!send(e))
					retire(endpoint, e);
				return;
			}
			e.identity = observation->history;
			e.layout = e.probe->layout();
			manager.publish(*observation);
			e.probe.reset();
			e.cadence.finished();
			changed = true;
			return;
		}
	}
};
PgSQL_LSN_Monitor::PgSQL_LSN_Monitor(PgSQL_LSN_Manager &m, Conninfo c, Clock k, Housekeeping h)
	: impl_(new Impl(m, std::move(c), std::move(k), std::move(h))) {
}
PgSQL_LSN_Monitor::~PgSQL_LSN_Monitor() {
	reset();
}
bool PgSQL_LSN_Monitor::tick(Micros now, const std::vector<Endpoint> &endpoints, Micros interval,
							 Micros connect_timeout, Micros query_timeout) {
	auto &impl = *impl_;
	impl.changed = false;
	impl.interval = interval;
	// Retention runs regardless of missing connections, failed probes or idle
	// LSNs.
	if (impl.housekeeping)
		impl.housekeeping(now);
	// Retention may consume time; preserve a caller's synthetic future clock.
	now = std::max(now, impl.clock());
	const std::set<Endpoint> desired(endpoints.begin(), endpoints.end());
	for (auto it = impl.entries.begin(); it != impl.entries.end();) {
		if (!desired.count(it->first)) {
			impl.retire(it->first, it->second);
			it = impl.entries.erase(it);
		} else
			++it;
	}
	for (const auto &endpoint : desired) {
		now = std::max(now, impl.clock());
		auto &e = impl.entries[endpoint];
		if (!e.connecting && !e.probe && e.cadence.due(now, interval)) {
			e.cadence.started(now);
			if (!e.conn) {
				auto conninfo = impl.conninfo(endpoint);
				if (!conninfo) {
					impl.retire(endpoint, e);
					continue;
				}
				e.starter = begin_connection(endpoint, std::move(*conninfo));
				e.connecting = true;
				e.events = POLLOUT;
				e.deadline = deadline_after(now, connect_timeout);
			} else if (!impl.start_probe(endpoint, e, now, query_timeout)) {
				impl.retire(endpoint, e);
				continue;
			}
		}
		if (e.conn || e.starter)
			impl.advance(endpoint, e, now, query_timeout);
	}
	return impl.changed;
}
void PgSQL_LSN_Monitor::wait(Micros max_wait) {
	auto &impl = *impl_;
	std::vector<pollfd> fds;
	const Micros now = impl.clock();
	if (!impl.entries.empty())
		max_wait = std::min(max_wait, impl.interval);
	for (const auto &item : impl.entries) {
		const auto &e = item.second;
		if (e.conn)
			fds.push_back({PQsocket(e.conn), e.events, 0});
		// Detached start completion has no socket yet; revisit promptly.
		if (e.starter)
			max_wait = std::min<Micros>(max_wait, 1000);
		if (e.connecting || e.probe)
			max_wait = std::min(max_wait, e.deadline > now ? e.deadline - now : 0);
	}
	const int timeout_ms =
		std::min<Micros>((max_wait + 999) / 1000, std::numeric_limits<int>::max());
	poll(fds.data(), fds.size(), timeout_ms);
}
void PgSQL_LSN_Monitor::reset() {
	for (auto &item : impl_->entries)
		impl_->retire(item.first, item.second);
	impl_->entries.clear();
}
#endif
