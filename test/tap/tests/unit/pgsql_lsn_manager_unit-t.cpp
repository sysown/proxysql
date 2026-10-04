#include "tap.h"
#include "PgSQL_LSN_Manager.h"

#include <algorithm>
#include <atomic>
#include <thread>
#include <vector>

using namespace pgsql_lsn;

static const Endpoint writer_endpoint{"writer", 5432};
static std::vector<Endpoint> endpoints() {
	return {writer_endpoint, {"reader1",5432}, {"reader2",5432}};
}

static ServerToken token(Generation generation, Role role = Role::Writer) {
	return {generation, {role == Role::Writer ? "writer" : "reader1", 5432},
		{{12345, 1}, role == Role::Writer ? 1000 : 2000}, role};
}

static Progress progress(ServerToken server, Lsn lsn, uint64_t connection = 1) {
	Progress p;
	p.server = server;
	p.connection_generation = connection;
	p.valid = true;
	p.sampled_at_us = 10;
	if (server.role == Role::Writer) p.insert_lsn = lsn;
	else p.replay_lsn = lsn;
	return p;
}

static ServerToken initialize(PgSQL_LSN_Manager& manager) {
	manager.reconcile_endpoints(endpoints());
	auto writer = token(manager.snapshot(writer_endpoint).generation);
	manager.publish_progress(progress(writer, 0));
	return writer;
}

int main() {
	plan(NO_PLAN);
	for (const char* bad : {"", "0", "/1", "1/", "0/100000000", "100000000/0",
		"0/1junk", " 0/1", "0/1 ", "-1/0", "0/+1", "0/1/2", "0x1/2"}) {
		ok(!parse_lsn(bad), "reject malformed LSN '%s'", bad);
	}
	ok(parse_lsn("0/0") == 0, "zero is a valid LSN, distinct from unknown");
	ok(parse_lsn("FFFFFFFF/FFFFFFFF") == UINT64_MAX, "accept full uint64 LSN");
	ok(parse_lsn("1/abcdef") == 0x100abcdefULL, "parse lowercase hex");
	ok(format_lsn(0x100abcdefULL) == "1/ABCDEF", "format PostgreSQL LSN");

	PgSQL_LSN_Manager manager;
	auto writer = initialize(manager);
	ok(manager.resolve({}).state == DependencyState::Clean, "new frontend is clean");
	ok(!manager.seal_writer_batch(writer_endpoint), "idle writer needs no position sample");
	auto before = manager.observe_completion(writer, {});
	auto peer = manager.observe_completion(writer, {});
	auto first = manager.seal_writer_batch(writer_endpoint);
	ok(first.has_value(), "completions create a sealable batch");
	if (!first) return exit_status();
	ok(!manager.seal_writer_batch(writer_endpoint), "only one writer probe can be in flight");
	auto after = manager.observe_completion(writer, {});
	ok(manager.complete_writer_sample(*first, progress(writer, 0x100)), "publish sealed sample");
	ok(manager.resolve(before).required_lsn == 0x100, "pre-seal completion resolved");
	ok(manager.resolve(peer).required_lsn == 0x100, "many sessions share one sample");
	ok(manager.resolve(after).state == DependencyState::Pending, "post-seal completion still pending");
	ok(!manager.complete_writer_sample(*first, progress(writer, 0x200)), "sample cannot resolve twice");
	ok(manager.resolve(before).required_lsn == 0x100, "resolved target is immutable");
	auto second = manager.seal_writer_batch(writer_endpoint);
	ok(second.has_value(), "next sample covers the later completion");
	if (!second) return exit_status();
	manager.fail_writer_sample(*second, "timeout");
	auto newer = manager.observe_completion(writer, before);
	ok(manager.snapshot(writer_endpoint).unresolved_batches == 2, "retry and new completions use two unresolved batches");
	auto retry = manager.seal_writer_batch(writer_endpoint);
	ok(retry.has_value(), "failed sealed batch is retried");
	if (!retry) return exit_status();
	ok(!manager.complete_writer_sample(*second, progress(writer, 0x300)), "late reply from failed attempt rejected");
	ok(manager.complete_writer_sample(*retry, progress(writer, 0x200)), "retry resolves same sealed batch");
	ok(manager.resolve(after).required_lsn == 0x200, "retry covers its original member");
	ok(manager.resolve(newer).state == DependencyState::Pending, "retry never covers later operations");
	auto third = manager.seal_writer_batch(writer_endpoint);
	if (!third) return exit_status();
	ok(!manager.complete_writer_sample(*third, progress(writer, 0x100)), "regressing writer sample rejected");
	manager.fail_writer_sample(*third, "regression");
	third = manager.seal_writer_batch(writer_endpoint);
	if (!third) return exit_status();
	ok(manager.complete_writer_sample(*third, progress(writer, 0x400)), "new dependency resolved");
	ok(manager.resolve(before).required_lsn == 0x100, "unrelated sampling cannot move old target");

	auto required = manager.resolve(newer);
	auto reader = token(manager.snapshot({"reader1",5432}).generation, Role::Replica);
	auto replay = progress(reader, 0x400);
	ok(replica_satisfies(required, replay, reader), "replica caught up with different postmaster time");
	replay.replay_lsn = 0x3ff;
	ok(!replica_satisfies(required, replay, reader), "lagging replay cannot qualify");
	replay.replay_lsn.reset(); replay.insert_lsn = 0xffff;
	ok(!replica_satisfies(required, replay, reader), "receive/insert LSN cannot replace replay");
	replay = progress(reader, 0xffff);
	replay.server.incarnation.history.system_id++;
	ok(!replica_satisfies(required, replay, reader), "higher LSN from other system rejected");
	replay = progress(reader, 0xffff);
	replay.server.incarnation.history.timeline++;
	ok(!replica_satisfies(required, replay, reader), "higher LSN from other timeline rejected");
	replay = progress(reader, 0x400);
	auto stale_backend = reader; stale_backend.incarnation.postmaster_start_us--;
	ok(!replica_satisfies(required, replay, stale_backend), "backend incarnation must match certificate");
	replay.valid = false;
	ok(!replica_satisfies(required, replay, reader), "withdrawn certification cannot qualify");

	manager.publish_progress(progress(reader, 0x400, 2));
	manager.publish_progress(progress(reader, 0x900, 1));
	auto reader_progress = manager.snapshot(reader.endpoint).progress;
	ok(reader_progress && reader_progress->connection_generation == 2, "old connection publication rejected");
	manager.invalidate_endpoint(reader.endpoint, Reason::NoSafeBackend);
	ok(manager.resolve(newer).state == DependencyState::Ready, "replica outage preserves frontend dependency");
	reader.incarnation.postmaster_start_us++;
	manager.publish_progress(progress(reader, 0x400, 3));
	reader.generation = manager.snapshot(reader.endpoint).generation;
	manager.publish_progress(progress(reader, 0x400, 3));
	ok(manager.resolve(newer).state == DependencyState::Ready, "replica restart does not invalidate writer history");
	manager.invalidate_endpoint(reader.endpoint, Reason::NoSafeBackend, 3);
	manager.publish_progress(progress(reader, 0xffff, 3));
	reader_progress = manager.snapshot(reader.endpoint).progress;
	ok(reader_progress && !reader_progress->valid, "retired connection cannot recertify endpoint");
	manager.publish_progress(progress(reader, 0x400, 4));
	manager.reconcile_endpoints(endpoints());
	ok(manager.resolve(newer).state == DependencyState::Ready, "unchanged endpoint set preserves dependency");
	manager.invalidate_endpoint(writer.endpoint, Reason::NoSafeBackend);
	ok(manager.resolve(newer).state == DependencyState::Ready, "temporary writer outage preserves history");
	auto pending = manager.observe_completion(writer, newer);
	auto stale_ticket = manager.seal_writer_batch(writer_endpoint);
	auto replacement = writer; replacement.incarnation.postmaster_start_us++;
	manager.publish_progress(progress(replacement, 0xffff, 4));
	ok(manager.resolve(newer).state == DependencyState::Invalid, "writer restart invalidates resolved dependency");
	ok(manager.resolve(pending).state == DependencyState::Invalid, "writer restart invalidates open dependency");
	if (stale_ticket) ok(!manager.complete_writer_sample(*stale_ticket, progress(writer, 0xffff)), "old generation reply rejected");
	ok(manager.snapshot(writer_endpoint).generation != writer.generation, "writer restart advances server generation");
	ok(manager.resolve(manager.observe_completion(writer, {})).state == DependencyState::Invalid,
		"old backend cannot establish a new dependency");

	PgSQL_LSN_Manager shared_server;
	auto sw = initialize(shared_server);
	auto shared_dep = shared_server.observe_completion(sw, {});
	shared_server.reconcile_endpoints({writer_endpoint, writer_endpoint, {"reader1",5432}, {"reader2",5432}});
	ok(shared_server.snapshots().size() == 3, "duplicate endpoint registrations share one tracker");
	ok(shared_server.snapshot(writer_endpoint).generation == sw.generation,
		"hostgroup multiplicity cannot change server generation");
	auto shared_peer = shared_server.observe_completion(sw, {});
	ok(shared_server.resolve(shared_dep).batch_id == shared_server.resolve(shared_peer).batch_id,
		"duplicate endpoint registrations share the same completion batch");
	shared_server.reconcile_endpoints({writer_endpoint});
	ok(shared_server.resolve(shared_dep).state == DependencyState::Pending,
		"removing other registrations preserves surviving endpoint dependencies");
	ok(shared_server.snapshot(writer_endpoint).completions == 2,
		"completion counters belong to the physical endpoint");
	PgSQL_LSN_Manager removed;
	auto removed_writer = initialize(removed);
	auto removed_dep = removed.observe_completion(removed_writer, {});
	removed.reconcile_endpoints({});
	ok(removed.resolve(removed_dep).state == DependencyState::Invalid, "removal invalidates live handles");
	removed.reconcile_endpoints(endpoints());
	ok(removed.snapshot(writer_endpoint).generation != removed_writer.generation, "readdition never reuses generation");

	PgSQL_LSN_Manager bounded;
	auto bw = initialize(bounded);
	Dependency only;
	for (unsigned i = 1; i <= 1000; ++i) {
		only = bounded.observe_completion(bw, only);
		auto ticket = bounded.seal_writer_batch(writer_endpoint);
		if (ticket) bounded.complete_writer_sample(*ticket, progress(bw, i));
	}
	ok(bounded.resolve(only).required_lsn == 1000, "repeated frontend writes advance dependency");
	ok(bounded.snapshot(writer_endpoint).live_batches == 1, "no chain of historical batch references");
	only = {};
	ok(bounded.snapshot(writer_endpoint).live_batches == 0, "disconnect releases resolved demand");
	ok(!bounded.snapshot(writer_endpoint).required_lsn, "idle server has no replay demand");

	PgSQL_LSN_Manager concurrent;
	auto cw = initialize(concurrent);
	std::vector<Dependency> deps(64);
	std::atomic<bool> go{false};
	std::vector<std::thread> workers;
	for (size_t t = 0; t < 4; ++t) workers.emplace_back([&, t] {
		while (!go.load()) std::this_thread::yield();
		for (size_t i = t; i < deps.size(); i += 4) deps[i] = concurrent.observe_completion(cw, {});
	});
	go.store(true);
	for (auto& worker : workers) worker.join();
	auto shared = concurrent.seal_writer_batch(writer_endpoint);
	if (!shared) return exit_status();
	concurrent.complete_writer_sample(*shared, progress(cw, 42));
	bool all = true;
	for (const auto& d : deps) all &= concurrent.resolve(d).required_lsn == 42;
	ok(all, "concurrent frontend completions share the sealed batch");
	ok(concurrent.snapshot(writer_endpoint).completions == 64 && concurrent.snapshot(writer_endpoint).batches == 1,
		"sample count grows with batches rather than completions");
	deps.clear();
	ok(concurrent.snapshot(writer_endpoint).live_batches == 0, "concurrent handles release all demand");

	std::atomic<uint64_t> commit_sequence{42};
	std::atomic<bool> finished{false};
	std::atomic<unsigned> violations{0};
	std::thread sampler([&] {
		while (!finished.load()) {
			auto ticket = concurrent.seal_writer_batch(writer_endpoint);
			if (ticket) {
				const auto sampled_lsn = commit_sequence.load();
				std::this_thread::yield(); // More completions may arrive before the reply.
				if (!concurrent.complete_writer_sample(*ticket, progress(cw, sampled_lsn))) ++violations;
			}
			if (concurrent.snapshot(writer_endpoint).unresolved_batches > 2) ++violations;
			std::this_thread::yield();
		}
	});
	workers.clear();
	for (unsigned t = 0; t < 4; ++t) workers.emplace_back([&] {
		Dependency session;
		for (unsigned i = 0; i < 1000; ++i) {
			const auto committed = ++commit_sequence;
			session = concurrent.observe_completion(cw, session);
			std::this_thread::yield();
			const auto view = concurrent.resolve(session);
			if (view.state == DependencyState::Ready && *view.required_lsn < committed) ++violations;
			if (view.state == DependencyState::Invalid) ++violations;
		}
	});
	for (auto& worker : workers) worker.join();
	finished.store(true);
	sampler.join();
	ok(violations.load() == 0, "concurrent sealing/publication never certifies a later commit with earlier LSN");
	ok(concurrent.snapshot(writer_endpoint).live_batches == 0, "concurrent publication and teardown release demand");
	return exit_status();
}
