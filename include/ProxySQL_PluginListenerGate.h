#ifndef PROXYSQL_PLUGIN_LISTENER_GATE_H
#define PROXYSQL_PLUGIN_LISTENER_GATE_H

#ifdef PROXYSQL40

#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>

enum class ProxySQL_PluginListenerState : uint8_t { closed = 0, ready = 1 };

struct ProxySQL_PluginListenerGate {
	const char* owner;
	const char* address;
	uint16_t port;
	ProxySQL_PluginListenerState state;
	const char* reason;
};

struct ProxySQL_PluginListenerGateSnapshot {
	std::string owner;
	std::string address;
	uint16_t port { 0 };
	ProxySQL_PluginListenerState state { ProxySQL_PluginListenerState::closed };
	std::string reason;
	uint64_t rejected_accepts { 0 };
};

struct ProxySQL_PluginListenerGateAcceptDecision {
	bool reject { false };
	bool should_warn { false };
	ProxySQL_PluginListenerGateSnapshot gate {};
};

class ProxySQL_PluginListenerGateRegistry {
public:
	bool set(const ProxySQL_PluginListenerGate& gate);
	std::optional<ProxySQL_PluginListenerGateSnapshot> lookup(
		const char* address, uint16_t port) const;
	ProxySQL_PluginListenerGateAcceptDecision inspect_accept(
		const char* address, uint16_t port, uint64_t now_monotonic_us);
	// Runtime readiness degradation must never leave this owner's previous
	// ready gates accepting traffic. The registry supplies a fixed safe reason.
	void force_close_owner(const char* owner);
	void remove_owner(const char* owner);

private:
	struct key_t {
		std::string address;
		uint16_t port { 0 };
		bool operator==(const key_t& other) const {
			return port == other.port && address == other.address;
		}
	};
	struct key_hash_t {
		size_t operator()(const key_t& key) const {
			return std::hash<std::string>{}(key.address) ^
				(static_cast<size_t>(key.port) << 1U);
		}
	};
	struct entry_t {
		ProxySQL_PluginListenerGateSnapshot snapshot {};
		uint64_t last_warning_monotonic_us { 0 };
	};

	static std::optional<std::string> normalize_address(const char* address);
	static std::optional<key_t> normalize_key(const char* address, uint16_t port);
	std::unordered_map<key_t, entry_t, key_hash_t> gates_ {};
	mutable std::shared_mutex mutex_ {};
};

ProxySQL_PluginListenerGateRegistry& proxysql_plugin_listener_gate_registry();
bool proxysql_plugin_set_listener_gate(const ProxySQL_PluginListenerGate& gate);
std::optional<ProxySQL_PluginListenerGateSnapshot> proxysql_plugin_listener_gate_lookup(
	const char* address, uint16_t port);
// The accept path calls this before constructing a session. It closes `fd`
// only when a matching gate is closed and returns the copied decision for
// rate-limited logging; ready and unrelated listeners return std::nullopt.
std::optional<ProxySQL_PluginListenerGateAcceptDecision>
proxysql_plugin_listener_gate_close_if_closed(
	const char* address, uint16_t port, int fd, uint64_t now_monotonic_us);

#endif /* PROXYSQL40 */
#endif /* PROXYSQL_PLUGIN_LISTENER_GATE_H */
