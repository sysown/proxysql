#ifndef __CLASS_PROXYSQL_CLUSTER_LEADER_H
#define __CLASS_PROXYSQL_CLUSTER_LEADER_H

#include <cstdint>
#include <string>
#include <vector>

struct Cluster_Leader_Candidate {
	std::string uuid;      // empty = unknown (not electable)
	std::string hostname;
	uint16_t port = 0;
	uint64_t weight = 0;
	bool alive = false;
};

// Deterministic, ballot-free election over a locally-observed candidate set.
// Electable = alive && uuid non-empty. Highest weight wins; ties broken by
// lexicographically smallest uuid. Returns index into candidates, or -1.
int cluster_elect_leader(const std::vector<Cluster_Leader_Candidate>& candidates);

// Grace-window state machine: a computed leader (or leader loss, "") must be
// observed continuously for grace_ms before it becomes effective.
class Cluster_Leader_State {
	public:
	std::string current_leader_uuid;   // empty = no leader
	std::string pending_leader_uuid;
	unsigned long long pending_since_ms = 0;
	// Returns true when the effective leader changed.
	bool update(const std::string& computed_uuid, unsigned long long now_ms, unsigned long long grace_ms);
	void reset();
};

#endif // __CLASS_PROXYSQL_CLUSTER_LEADER_H
