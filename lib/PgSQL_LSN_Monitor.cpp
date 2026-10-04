#include "PgSQL_LSN_Monitor.h"
#include "PgSQL_LSN_Probe.h"
#include <libpq-fe.h>
#include <poll.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <limits>
#include <map>

using namespace pgsql_lsn;
namespace {
std::atomic<uint64_t> connection_sequence{0};
Micros clock_us() {
	return std::chrono::duration_cast<std::chrono::microseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
}
struct Entry {
	PGconn* conn = nullptr;
	uint64_t connection_generation = 0;
	bool connecting = false, flushing = false;
	short events = POLLIN;
	Micros deadline = 0, started = 0;
	ProbeCadence cadence;
	std::optional<ServerToken> identity;
	Generation generation = 0;
	std::unique_ptr<PgSQL_LSN_Probe> probe;
	std::optional<SampleTicket> ticket;
	ProbeRows rows;
	unsigned results = 0;
	~Entry() { if (conn) PQfinish(conn); }
};
}

struct PgSQL_LSN_Monitor::Impl {
	PgSQL_LSN_Manager& manager;
	Conninfo conninfo;
	std::map<Endpoint, Entry> entries;
	Micros interval = 10000;
	bool changed = false;
	Impl(PgSQL_LSN_Manager& m, Conninfo c) : manager(m), conninfo(std::move(c)) {}

	void retire(const Endpoint& endpoint, Entry& e, const std::string& error, Reason reason) {
		if (e.ticket) manager.fail_writer_sample(*e.ticket, error);
		manager.invalidate_endpoint(endpoint, reason, e.connection_generation);
		if (e.conn) PQfinish(e.conn);
		e.conn = nullptr;
		e.connecting = e.flushing = false;
		e.probe.reset(); e.identity.reset(); e.ticket.reset(); e.rows.clear(); e.results = 0;
		e.cadence.finished();
		changed = true;
	}
	bool send(Entry& e) {
		auto command = e.probe->next_command();
		if (!command || !PQsendQuery(e.conn, command->c_str())) return false;
		e.rows.clear(); e.results = 0;
		const int flush = PQflush(e.conn);
		if (flush < 0) return false;
		e.flushing = flush != 0;
		e.events = POLLIN | (e.flushing ? POLLOUT : 0);
		return true;
	}
	bool start_probe(const Endpoint& endpoint, Entry& e, Micros now, Micros query_timeout) {
		e.started = now; e.deadline = now + query_timeout;
		// Seal before sending any command, including discovery IDENTIFY_SYSTEM.
		e.ticket = manager.seal_writer_batch(endpoint);
		e.probe.reset(new PgSQL_LSN_Probe(e.generation, endpoint,
			e.identity, e.connection_generation, now,
			e.identity ? std::optional<History>{e.identity->incarnation.history} : std::nullopt));
		return send(e);
	}
	void advance(const Endpoint& endpoint, Entry& e, Micros now, Micros query_timeout) {
		if (e.connecting || e.probe) {
			if (now >= e.deadline) {
				retire(endpoint, e, "LSN probe deadline exceeded", Reason::NoSafeBackend); return;
			}
		}
		pollfd fd{PQsocket(e.conn), e.events, 0};
		if (fd.fd < 0 || poll(&fd, 1, 0) < 0 || (fd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
			retire(endpoint, e, "LSN monitor connection lost", Reason::NoSafeBackend); return;
		}
		if (e.connecting) {
			if (!fd.revents) return;
			const auto status = PQconnectPoll(e.conn);
			if (status == PGRES_POLLING_READING) { e.events = POLLIN; return; }
			if (status == PGRES_POLLING_WRITING) { e.events = POLLOUT; return; }
			if (status != PGRES_POLLING_OK) {
				retire(endpoint, e, "LSN monitor connection failed", Reason::NoSafeBackend); return;
			}
			e.connecting = false;
			if (!start_probe(endpoint, e, now, query_timeout))
				retire(endpoint, e, "Cannot send LSN probe", Reason::NoSafeBackend);
			return;
		}
		if ((fd.revents & POLLIN) && !PQconsumeInput(e.conn)) {
			retire(endpoint, e, "Cannot read LSN probe", Reason::NoSafeBackend); return;
		}
		if (e.flushing && fd.revents) {
			const int flushed = PQflush(e.conn);
			if (flushed < 0) { retire(endpoint, e, "Cannot flush LSN probe", Reason::NoSafeBackend); return; }
			e.flushing = flushed != 0;
			e.events = POLLIN | (e.flushing ? POLLOUT : 0);
		}
		if (!e.probe || e.flushing) return;
		// PQgetResult may block after CommandComplete while waiting for Z.
		// Check PQisBusy before EVERY call, including the final NULL result.
		while (!PQisBusy(e.conn)) {
			PGresult* result = PQgetResult(e.conn);
			if (result) {
				const bool valid = ++e.results == 1 && PQresultStatus(result) == PGRES_TUPLES_OK
					&& PQntuples(result) == 1 && PQnfields(result) <= 4;
				if (valid) {
					std::vector<std::optional<std::string>> row;
					for (int col = 0; col < PQnfields(result); ++col)
						row.emplace_back(PQgetisnull(result, 0, col) ? std::nullopt :
							std::optional<std::string>{std::string(PQgetvalue(result, 0, col), PQgetlength(result, 0, col))});
					e.rows.emplace_back(std::move(row));
				}
				PQclear(result);
				if (!valid) { retire(endpoint, e, "Invalid LSN probe response", Reason::NoSafeBackend); return; }
				continue;
			}
			std::string error;
			if (e.results != 1 || !e.probe->consume_result(e.rows, error)) {
				retire(endpoint, e, error, e.probe->failure_reason()); return;
			}
			auto progress = e.probe->finish();
			if (!progress) {
				if (!send(e)) retire(endpoint, e, "Cannot send LSN probe", Reason::NoSafeBackend);
				return;
			}
			progress->duration_us = now - e.started;
			e.identity = progress->server;
			manager.publish_progress(*progress);
			if (e.ticket && !manager.complete_writer_sample(*e.ticket, *progress))
				manager.fail_writer_sample(*e.ticket, "LSN publication rejected");
			e.probe.reset(); e.ticket.reset(); e.cadence.finished(); changed = true;
			return;
		}
	}
};

PgSQL_LSN_Monitor::PgSQL_LSN_Monitor(PgSQL_LSN_Manager& m, Conninfo c) : impl_(new Impl(m, std::move(c))) {}
PgSQL_LSN_Monitor::~PgSQL_LSN_Monitor() { reset(); }

bool PgSQL_LSN_Monitor::tick(Micros now, Micros interval, Micros connect_timeout, Micros query_timeout) {
	auto& impl = *impl_; impl.changed = false; impl.interval = interval;
	const auto snapshots = impl.manager.snapshots();
	std::map<Endpoint, ServerSnapshot> desired;
	for (const auto& server : snapshots) desired.emplace(server.endpoint, server);
	for (auto it = impl.entries.begin(); it != impl.entries.end();) {
		if (!desired.count(it->first)) {
			impl.retire(it->first, it->second, "LSN endpoint removed", Reason::NoSafeBackend);
			it = impl.entries.erase(it);
		} else ++it;
	}
	for (auto& item : desired) {
		auto& e = impl.entries[item.first];
		const auto& server = item.second;
		bool demand = !server.progress || !server.progress->valid || server.has_pending;
		if (server.progress && server.progress->server.role == Role::Replica) {
			for (const auto& origin : snapshots) {
				if (!origin.progress || !(origin.progress->server.incarnation.history ==
					server.progress->server.incarnation.history)) continue;
				demand |= origin.has_pending || (origin.required_lsn &&
					(!server.progress->replay_lsn || *server.progress->replay_lsn < *origin.required_lsn));
			}
		}

		if (!e.connecting && !e.probe && e.cadence.due(now, interval, demand)) {
			e.cadence.started(now); e.generation = server.generation;
			if (!e.conn) {
				e.connection_generation = ++connection_sequence;
				auto conninfo = impl.conninfo(item.first);
				if (conninfo) e.conn = PQconnectStart(conninfo->c_str());
				if (!e.conn || PQstatus(e.conn) == CONNECTION_BAD || PQsetnonblocking(e.conn, 1)) {
					impl.retire(item.first, e, "Cannot start LSN monitor connection", Reason::NoSafeBackend); continue;
				}
				e.connecting = true; e.events = POLLOUT; e.deadline = now + connect_timeout;
			} else if (!impl.start_probe(item.first, e, now, query_timeout)) {
				impl.retire(item.first, e, "Cannot send LSN probe", Reason::NoSafeBackend); continue;
			}
		}
		if (e.conn) impl.advance(item.first, e, now, query_timeout);
	}
	return impl.changed;
}

void PgSQL_LSN_Monitor::wait(Micros max_wait) {
	auto& impl = *impl_;
	std::vector<pollfd> fds;
	const Micros now = clock_us();
	if (!impl.entries.empty()) max_wait = std::min(max_wait, impl.interval);
	for (const auto& item : impl.entries) {
		const auto& e = item.second;
		if (e.conn) fds.push_back({PQsocket(e.conn), e.events, 0});
		if (e.connecting || e.probe) max_wait = std::min(max_wait, e.deadline > now ? e.deadline - now : 0);
	}
	const int timeout_ms = std::min<Micros>((max_wait + 999) / 1000, std::numeric_limits<int>::max());
	poll(fds.data(), fds.size(), timeout_ms);
}

void PgSQL_LSN_Monitor::reset() {
	for (auto& item : impl_->entries)
		impl_->retire(item.first, item.second, "LSN monitor reset", Reason::NoSafeBackend);
	impl_->entries.clear();
}
