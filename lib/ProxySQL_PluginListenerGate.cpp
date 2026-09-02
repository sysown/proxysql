#ifdef PROXYSQL40

#include "ProxySQL_PluginListenerGate.h"

#include <arpa/inet.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <mutex>
#include <unistd.h>

namespace {

constexpr uint64_t WARNING_INTERVAL_US = 30ULL * 1000ULL * 1000ULL;
constexpr const char* DEGRADED_REASON = "runtime readiness degraded";

bool is_ipv6_address(const std::string& address) {
	return address.find(':') != std::string::npos;
}

bool is_wildcard_address(const std::string& address) {
	return address == "0.0.0.0" || address == "::";
}

bool addresses_overlap(const std::string& lhs, const std::string& rhs) {
	if (lhs == rhs) return true;
	return is_ipv6_address(lhs) == is_ipv6_address(rhs) &&
		(is_wildcard_address(lhs) || is_wildcard_address(rhs));
}

} // namespace

std::optional<std::string> ProxySQL_PluginListenerGateRegistry::normalize_address(const char* address) {
	if (address == nullptr || address[0] == '\0') return std::nullopt;
	if (address[0] == '/' || address[0] == '@') return std::string(address);
	char normalized[INET6_ADDRSTRLEN] {};
	struct in_addr ipv4 {};
	if (inet_pton(AF_INET, address, &ipv4) == 1) {
		if (inet_ntop(AF_INET, &ipv4, normalized, sizeof(normalized)) == nullptr) return std::nullopt;
		return std::string(normalized);
	}
	struct in6_addr ipv6 {};
	if (inet_pton(AF_INET6, address, &ipv6) == 1) {
		if (inet_ntop(AF_INET6, &ipv6, normalized, sizeof(normalized)) == nullptr) return std::nullopt;
		return std::string(normalized);
	}
	std::string hostname(address);
	std::transform(hostname.begin(), hostname.end(), hostname.begin(), [](unsigned char ch) {
		return static_cast<char>(std::tolower(ch));
	});
	return hostname;
}

std::optional<ProxySQL_PluginListenerGateRegistry::key_t>
ProxySQL_PluginListenerGateRegistry::normalize_key(const char* address, uint16_t port) {
	auto normalized_address = normalize_address(address);
	if (!normalized_address) return std::nullopt;
	return key_t { std::move(*normalized_address), port };
}

bool ProxySQL_PluginListenerGateRegistry::set(const ProxySQL_PluginListenerGate& gate) {
	if (gate.owner == nullptr || gate.owner[0] == '\0' || gate.port == 6032 || gate.port == 6033) {
		return false;
	}
	auto key = normalize_key(gate.address, gate.port);
	if (!key) return false;
	const std::string owner(gate.owner);
	std::unique_lock<std::shared_mutex> lock(mutex_);
	for (const auto& existing : gates_) {
		if (existing.first.port == key->port &&
			existing.second.snapshot.owner != owner &&
			addresses_overlap(existing.first.address, key->address)) {
			return false;
		}
	}
	entry_t& entry = gates_[*key];
	const uint64_t rejected_accepts = entry.snapshot.rejected_accepts;
	entry.snapshot.owner = owner;
	entry.snapshot.address = key->address;
	entry.snapshot.port = key->port;
	entry.snapshot.state = gate.state;
	entry.snapshot.reason = gate.reason != nullptr ? gate.reason : "";
	entry.snapshot.rejected_accepts = rejected_accepts;
	return true;
}

std::optional<ProxySQL_PluginListenerGateSnapshot>
ProxySQL_PluginListenerGateRegistry::lookup(const char* address, uint16_t port) const {
	auto key = normalize_key(address, port);
	if (!key) return std::nullopt;
	std::shared_lock<std::shared_mutex> lock(mutex_);
	auto found = gates_.find(*key);
	if (found != gates_.end()) return found->second.snapshot;

	const bool is_ipv6 = key->address.find(':') != std::string::npos;
	const key_t wildcard { is_ipv6 ? "::" : "0.0.0.0", port };
	found = gates_.find(wildcard);
	if (found != gates_.end()) return found->second.snapshot;
	return std::nullopt;
}

ProxySQL_PluginListenerGateAcceptDecision
ProxySQL_PluginListenerGateRegistry::inspect_accept(
	const char* address, uint16_t port, uint64_t now_monotonic_us) {
	ProxySQL_PluginListenerGateAcceptDecision decision {};
	auto key = normalize_key(address, port);
	if (!key) return decision;
	std::unique_lock<std::shared_mutex> lock(mutex_);
	auto found = gates_.find(*key);
	if (found == gates_.end()) {
		const bool is_ipv6 = key->address.find(':') != std::string::npos;
		found = gates_.find(key_t { is_ipv6 ? "::" : "0.0.0.0", port });
	}
	if (found == gates_.end() ||
		found->second.snapshot.state != ProxySQL_PluginListenerState::closed) return decision;

	entry_t& entry = found->second;
	decision.reject = true;
	decision.should_warn = entry.last_warning_monotonic_us == 0 ||
		now_monotonic_us - entry.last_warning_monotonic_us >= WARNING_INTERVAL_US;
	if (decision.should_warn) entry.last_warning_monotonic_us = now_monotonic_us;
	++entry.snapshot.rejected_accepts;
	decision.gate = entry.snapshot;
	return decision;
}

void ProxySQL_PluginListenerGateRegistry::force_close_owner(const char* owner) {
	if (owner == nullptr || owner[0] == '\0') return;
	std::unique_lock<std::shared_mutex> lock(mutex_);
	for (auto& gate : gates_) {
		entry_t& entry = gate.second;
		if (entry.snapshot.owner == owner) {
			entry.snapshot.state = ProxySQL_PluginListenerState::closed;
			entry.snapshot.reason = DEGRADED_REASON;
		}
	}
}

void ProxySQL_PluginListenerGateRegistry::remove_owner(const char* owner) {
	if (owner == nullptr || owner[0] == '\0') return;
	std::unique_lock<std::shared_mutex> lock(mutex_);
	for (auto it = gates_.begin(); it != gates_.end();) {
		if (it->second.snapshot.owner == owner) {
			it = gates_.erase(it);
		} else {
			++it;
		}
	}
}

ProxySQL_PluginListenerGateRegistry& proxysql_plugin_listener_gate_registry() {
	static ProxySQL_PluginListenerGateRegistry registry {};
	return registry;
}

bool proxysql_plugin_set_listener_gate(const ProxySQL_PluginListenerGate& gate) {
	return proxysql_plugin_listener_gate_registry().set(gate);
}

std::optional<ProxySQL_PluginListenerGateSnapshot> proxysql_plugin_listener_gate_lookup(
	const char* address, uint16_t port) {
	return proxysql_plugin_listener_gate_registry().lookup(address, port);
}

std::optional<ProxySQL_PluginListenerGateAcceptDecision>
proxysql_plugin_listener_gate_close_if_closed(
	const char* address, uint16_t port, int fd, uint64_t now_monotonic_us) {
	auto decision = proxysql_plugin_listener_gate_registry().inspect_accept(
		address, port, now_monotonic_us);
	if (!decision.reject) return std::nullopt;
	close(fd);
	return decision;
}

#endif /* PROXYSQL40 */
