#include "ProxySQL_Cluster_Leader.h"

int cluster_elect_leader(const std::vector<Cluster_Leader_Candidate>& candidates) {
	int best = -1;
	for (size_t i = 0; i < candidates.size(); i++) {
		const Cluster_Leader_Candidate& c = candidates[i];
		if (c.alive == false || c.uuid.empty()) {
			continue;
		}
		if (best == -1) {
			best = (int)i;
			continue;
		}
		const Cluster_Leader_Candidate& b = candidates[best];
		if (c.weight > b.weight || (c.weight == b.weight && c.uuid < b.uuid)) {
			best = (int)i;
		}
	}
	return best;
}

bool Cluster_Leader_State::update(const std::string& computed_uuid, unsigned long long now_ms, unsigned long long grace_ms) {
	if (computed_uuid == current_leader_uuid) {
		pending_leader_uuid.clear();
		pending_since_ms = 0;
		return false;
	}
	if (pending_since_ms == 0 || pending_leader_uuid != computed_uuid) {
		pending_leader_uuid = computed_uuid;
		pending_since_ms = now_ms;
	}
	if (now_ms - pending_since_ms >= grace_ms) {
		current_leader_uuid = pending_leader_uuid;
		pending_leader_uuid.clear();
		pending_since_ms = 0;
		return true;
	}
	return false;
}

void Cluster_Leader_State::reset() {
	current_leader_uuid.clear();
	pending_leader_uuid.clear();
	pending_since_ms = 0;
}
