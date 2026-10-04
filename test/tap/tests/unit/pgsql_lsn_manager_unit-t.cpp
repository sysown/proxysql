#include "PgSQL_LSN_Manager.h"
#include "tap.h"
#include <chrono>
#if defined(__GLIBC__)
#include <malloc.h>
#endif
using namespace pgsql_lsn;
static const Endpoint endpoint{"source", 5432};
static Observation observation(Micros t, Lsn lsn, History history = {12, 1}, int64_t start = 1000) {
	return {endpoint, history, start, {t, lsn}, true};
}
static void seed(PgSQL_LSN_Manager &m) {
	m.reconcile_endpoints({endpoint, endpoint});
	m.publish(observation(100, 12330));
	m.publish(observation(200, 12339));
	m.publish(observation(300, 12345));
}
static bool ready(PgSQL_LSN_Manager &m, Micros t, Lsn lsn) {
	auto r = m.lookup_after(endpoint, t);
	return r.state == LookupState::Ready && r.required && r.required->lsn == lsn;
}
int main() {
	plan(NO_PLAN);
	PgSQL_LSN_Manager m;
	ok(m.lookup_after(endpoint, 10).state == LookupState::Unavailable,
	   "missing endpoint remains unavailable");
	m.reconcile_endpoints({endpoint});
	const auto undiscovered = m.latest_all();
	ok(undiscovered.size() == 1 && undiscovered[0].endpoint == endpoint && !undiscovered[0].valid,
	   "stats enumeration includes never-sampled physical endpoint as unavailable");
	ok(m.lookup_after(endpoint, 10).state == LookupState::Pending,
	   "empty tracked history is pending");
	m.publish(observation(100, 12330));
	ok(ready(m, 50, 12330), "first discovery after completion resolves without activation guard");
	ok(m.lookup_after(endpoint, 100).state == LookupState::Pending,
	   "equal timestamp does not resolve completion");
	ok(m.lookup_after(endpoint, 150).state == LookupState::Pending,
	   "delayed pre-completion sample cannot resolve");
	m.publish(observation(200, 12339));
	m.publish(observation(300, 12345));
	ok(ready(m, 150, 12339) && ready(m, 250, 12345),
	   "binary search chooses first strictly later actual sample");
	auto fixed = m.lookup_after(endpoint, 150).required;
	m.retain_predecessor(endpoint, 12340);
	ok(ready(m, 50, 12339) && ready(m, 150, 12339) && ready(m, 250, 12345),
	   "progress pruning retains newest real predecessor");
	ok(m.lookup_after(endpoint, 350).state == LookupState::Pending,
	   "progress anchor cannot fabricate later sample");
	ok(fixed && fixed->lsn == 12339, "resolved targets stay copied and fixed");
	m.publish(observation(250, 99999));
	ok(m.latest(endpoint)->sample.lsn == 12345, "out-of-order publication is ignored");
	m.withdraw(endpoint);
	ok(!m.latest(endpoint)->valid && ready(m, 150, 12339),
	   "withdrawal removes candidate eligibility but preserves validated source samples");
	ok(m.lookup_after(endpoint, 350).state == LookupState::Pending,
	   "withdrawn source with no strictly later successful sample remains pending");
	m.publish(observation(300, 12345));
	ok(!m.latest(endpoint)->valid, "stale equal-start response cannot undo withdrawal");
	m.publish(observation(400, 12350));
	ok(ready(m, 350, 12350), "new validated probe restores same history");
	m.publish(observation(500, 10, {12, 2}));
	ok(m.lookup_after(endpoint, 450).state == LookupState::HistoryChanged,
	   "observed timeline reset invalidates older timestamps");
	ok(m.lookup_after(endpoint, 500).state == LookupState::Pending,
	   "completion at reset sample still requires later sample");
	m.publish(observation(499, 99999, {99, 9}));
	ok(m.latest(endpoint)->history == History{12, 2},
	   "delayed old-generation publication cannot replace newer identity");
	m.publish(observation(600, 20, {12, 2}));
	ok(ready(m, 550, 20), "post-reset completion uses new history");
	m.prune_before(1000);
	ok(m.lookup_after(endpoint, 450).state == LookupState::HistoryChanged,
	   "age anchor cannot erase reset boundary");
	m.publish(observation(700, 5, {12, 2}, 2000));
	ok(m.lookup_after(endpoint, 650).state == LookupState::HistoryChanged,
	   "incarnation change invalidates old timestamps");
	m.publish(observation(800, 4, {12, 2}, 2000));
	ok(m.lookup_after(endpoint, 750).state == LookupState::HistoryChanged,
	   "LSN regression establishes reset boundary");
	m.reconcile_endpoints({});
	ok(m.lookup_after(endpoint, 900).state == LookupState::Unavailable,
	   "removed endpoint never becomes unconstrained");
	for (bool progress_first : {false, true}) {
		PgSQL_LSN_Manager p;
		seed(p);
		if (progress_first)
			p.retain_predecessor(endpoint, 12340);
		p.prune_before(250);
		if (!progress_first)
			p.retain_predecessor(endpoint, 12340);
		ok(ready(p, 150, 12339) && ready(p, 250, 12345),
		   "both prune orders preserve strict lookup and real anchors");
		p.prune_before(400);
		ok(ready(p, 150, 12345) && p.lookup_after(endpoint, 350).state == LookupState::Pending,
		   "all-old cutoff retains only original newest sample");
		p.prune_before(0);
		ok(ready(p, 150, 12345), "enlarging history window cannot reconstruct removed samples");
	}
	{
		PgSQL_LSN_Manager p;
		seed(p);
		p.prune_before(200);
		ok(ready(p, 50, 12330) && ready(p, 100, 12339),
		   "cutoff equality retains equal-time sample and older predecessor");
		p.retain_predecessor(endpoint, 12330);
		ok(ready(p, 50, 12330), "floor without a predecessor cannot remove a prefix");
	}
	{
		PgSQL_LSN_Manager p;
		p.reconcile_endpoints({endpoint});
		p.prune_before(500);
		ok(p.lookup_after(endpoint, 0).state == LookupState::Pending,
		   "empty age cleanup fabricates no sample");
		p.publish(observation(100, 10));
		p.publish(observation(200, 10));
		p.publish(observation(300, 20));
		ok(ready(p, 150, 10) && ready(p, 200, 20),
		   "unchanged LSN coalesces to later conservative timestamp");
		p.retain_predecessor(endpoint, 20);
		ok(ready(p, 50, 10), "equal-LSN floor retains strictly lower predecessor");
	}
#if defined(__GLIBC__) && __GLIBC_PREREQ(2, 33)
	{
		PgSQL_LSN_Manager bounded;
		bounded.reconcile_endpoints({endpoint});
		const auto before = mallinfo2().uordblks;
		const auto began = std::chrono::steady_clock::now();
		for (Micros t = 1; t <= 200000; ++t) {
			bounded.publish(observation(t, t));
			if (t % 1000 == 0)
				bounded.prune_before(t > 6000 ? t - 6000 : 0);
		}
		const auto after = mallinfo2().uordblks;
		const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
			std::chrono::steady_clock::now() - began).count();
		diag("200000 publications/cleanup: %lld us, retained allocator growth: %zu bytes",
			static_cast<long long>(elapsed), static_cast<size_t>(after > before ? after - before : 0));
		ok(after <= before + 256 * 1024,
		   "200000 advancing polls release expired storage, retaining about 6000 samples");
		ok(ready(bounded, 1, 193999), "large bounded history retains original age anchor");
	}
#endif
	ok(parse_lsn("AB/10") == ((Lsn{0xAB} << 32) | 16) && format_lsn(0x123) == "0/123",
	   "numeric LSN helpers retained");
	ok(!parse_lsn("0/G") && !parse_lsn("1/123456789"), "invalid LSN values rejected");
	return exit_status();
}
