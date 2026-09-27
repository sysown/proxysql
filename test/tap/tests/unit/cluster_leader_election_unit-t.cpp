/**
 * @file cluster_leader_election_unit-t.cpp
 * @brief Unit tests for the pure cluster leader election logic
 *  (cluster_elect_leader + Cluster_Leader_State grace-window machine).
 */

#include <string>
#include <vector>

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "ProxySQL_Cluster_Leader.h"

static Cluster_Leader_Candidate mk(const char* uuid, uint64_t weight, bool alive) {
	Cluster_Leader_Candidate c;
	c.uuid = uuid;
	c.hostname = "host";
	c.port = 6032;
	c.weight = weight;
	c.alive = alive;
	return c;
}

// 7 oks
static void test_elect_leader() {
	std::vector<Cluster_Leader_Candidate> v;
	ok(cluster_elect_leader(v) == -1, "empty candidate set elects nobody");

	v = { mk("aaa", 0, false), mk("bbb", 0, false) };
	ok(cluster_elect_leader(v) == -1, "no alive candidate elects nobody");

	v = { mk("aaa", 0, true) };
	ok(cluster_elect_leader(v) == 0, "single alive candidate is leader");

	v = { mk("aaa", 100, true), mk("bbb", 300, true), mk("ccc", 200, true) };
	ok(cluster_elect_leader(v) == 1, "highest weight wins");

	v = { mk("ccc", 100, true), mk("aaa", 100, true), mk("bbb", 100, true) };
	ok(cluster_elect_leader(v) == 1, "equal weight: lexicographically smallest uuid wins");

	v = { mk("aaa", 300, false), mk("bbb", 100, true) };
	ok(cluster_elect_leader(v) == 1, "dead high-weight candidate is skipped");

	v = { mk("", 300, true), mk("bbb", 100, true) };
	ok(cluster_elect_leader(v) == 1, "candidate with unknown uuid is not electable");
}

// 10 oks
static void test_grace_state() {
	Cluster_Leader_State s;
	ok(s.current_leader_uuid.empty(), "initial state has no leader");

	// First observation enters pending, no change yet (grace 1000ms)
	ok(s.update("aaa", 1000, 1000) == false, "new leader is pending, not applied");
	ok(s.current_leader_uuid.empty(), "leader unchanged during grace");

	// Still pending, grace not elapsed
	ok(s.update("aaa", 1500, 1000) == false, "grace not elapsed yet");

	// Grace elapsed -> applied
	ok(s.update("aaa", 2100, 1000) == true, "leader applied after grace");
	ok(s.current_leader_uuid == "aaa", "current leader is aaa");

	// Stable: no change
	ok(s.update("aaa", 3000, 1000) == false, "stable leader: no change");

	// Flap within grace: bbb appears then aaa returns before grace elapses
	s.update("bbb", 4000, 1000);
	ok(s.update("aaa", 4500, 1000) == false && s.current_leader_uuid == "aaa",
		"flap within grace window is ignored");

	// Loss of leader ("" computed) also honors grace
	s.update("", 5000, 1000);
	ok(s.update("", 6100, 1000) == true && s.current_leader_uuid.empty(),
		"leader loss applied after grace");

	// grace_ms == 0 applies on the same update
	Cluster_Leader_State z;
	ok(z.update("ccc", 100, 0) == true && z.current_leader_uuid == "ccc",
		"zero grace applies immediately");
}

// 2 oks
static void test_reset() {
	Cluster_Leader_State s;
	s.update("aaa", 100, 0);
	s.update("bbb", 200, 5000);
	s.reset();
	ok(s.current_leader_uuid.empty() && s.pending_leader_uuid.empty() && s.pending_since_ms == 0,
		"reset clears all state");
	ok(s.update("aaa", 300, 0) == true, "state machine works again after reset");
}

int main() {
	plan(19);
	test_elect_leader();   // 7
	test_grace_state();    // 10
	test_reset();          // 2
	return exit_status();
}
