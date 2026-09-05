#include "ProxySQL_PluginListenerGate.h"
#include "tap.h"

#include <atomic>
#include <cstring>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

ProxySQL_PluginListenerGate gate(const char* owner, const char* address,
	uint16_t port, ProxySQL_PluginListenerState state, const char* reason) {
	return {owner, address, port, state, reason};
}

} // namespace

int main() {
	plan(32);

	ProxySQL_PluginListenerGateRegistry registry;
	char reason[] = "first publication is incomplete";
	ok(registry.set(gate("router-a", "127.0.0.1", 6446,
		ProxySQL_PluginListenerState::closed, reason)),
		"owner can install a closed gate");
	reason[0] = 'X';
	auto exact = registry.lookup("127.0.0.1", 6446);
	ok(exact.has_value() && exact->reason == "first publication is incomplete",
		"registry copies the gate reason instead of borrowing it");
	ok(!registry.set(gate("router-b", "127.0.0.1", 6446,
		ProxySQL_PluginListenerState::ready, "other owner")),
		"another owner cannot replace an installed gate");
	ok(registry.set(gate("router-a", "127.0.0.1", 6446,
		ProxySQL_PluginListenerState::ready, "complete")),
		"the owning plugin can update its own gate");
	exact = registry.lookup("127.0.0.1", 6446);
	ok(exact.has_value() && exact->state == ProxySQL_PluginListenerState::ready,
		"owner update changes the exact gate state");

	ok(registry.set(gate("router-a", "0.0.0.0", 6447,
		ProxySQL_PluginListenerState::closed, "IPv4 wildcard")),
		"IPv4 wildcard gate installs");
	ok(registry.lookup("192.0.2.10", 6447).has_value(),
		"IPv4 wildcard matches a concrete listener address");
	ok(registry.set(gate("router-a", "::", 6448,
		ProxySQL_PluginListenerState::closed, "IPv6 wildcard")),
		"IPv6 wildcard gate installs");
	ok(registry.lookup("2001:db8::10", 6448).has_value(),
		"IPv6 wildcard matches a concrete listener address");
	ok(!registry.set(gate("router-b", "127.0.0.1", 6447,
		ProxySQL_PluginListenerState::ready, "overlaps IPv4 wildcard")),
		"another owner cannot replace an IPv4 wildcard gate with an exact gate");
	ok(registry.set(gate("router-a", "127.0.0.1", 6447,
		ProxySQL_PluginListenerState::ready, "owner exact exception")),
		"the owning plugin can install an exact gate alongside its IPv4 wildcard");
	const auto owner_exact = registry.lookup("127.0.0.1", 6447);
	const auto owner_wildcard = registry.lookup("192.0.2.11", 6447);
	ok(owner_exact && owner_exact->state == ProxySQL_PluginListenerState::ready &&
		owner_wildcard && owner_wildcard->state == ProxySQL_PluginListenerState::closed,
		"the owning plugin can keep distinct exact and IPv4 wildcard gates");
	ok(registry.set(gate("router-a", "127.0.0.1", 6451,
		ProxySQL_PluginListenerState::closed, "IPv4 exact")) &&
		!registry.set(gate("router-b", "0.0.0.0", 6451,
			ProxySQL_PluginListenerState::ready, "overlaps IPv4 exact")),
		"another owner cannot replace an IPv4 exact gate with a wildcard gate");
	ok(!registry.set(gate("router-b", "2001:db8::1", 6448,
		ProxySQL_PluginListenerState::ready, "overlaps IPv6 wildcard")),
		"another owner cannot replace an IPv6 wildcard gate with an exact gate");
	ok(registry.set(gate("router-a", "2001:db8::1", 6452,
		ProxySQL_PluginListenerState::closed, "IPv6 exact")) &&
		!registry.set(gate("router-b", "::", 6452,
			ProxySQL_PluginListenerState::ready, "overlaps IPv6 exact")),
		"another owner cannot replace an IPv6 exact gate with a wildcard gate");
	ok(!registry.lookup("192.0.2.10", 6446).has_value(),
		"lookup keeps address and port as an exact composite key");
	ok(registry.set(gate("socket-upper", "/tmp/Router.sock", 0, // NOSONAR: value-only test path; no file access.
		ProxySQL_PluginListenerState::closed, "uppercase socket")) &&
		registry.set(gate("socket-lower", "/tmp/router.sock", 0, // NOSONAR: value-only test path; no file access.
			ProxySQL_PluginListenerState::ready, "lowercase socket")),
		"case-sensitive Unix socket paths can be owned independently");
	const auto upper_socket = registry.lookup("/tmp/Router.sock", 0); // NOSONAR: value-only lookup.
	const auto lower_socket = registry.lookup("/tmp/router.sock", 0); // NOSONAR: value-only lookup.
	ok(upper_socket && upper_socket->owner == "socket-upper" &&
		lower_socket && lower_socket->owner == "socket-lower",
		"Unix socket lookup preserves path case");

	ok(!registry.set(gate("", "127.0.0.1", 6449,
		ProxySQL_PluginListenerState::closed, "missing owner")),
		"empty gate owner is rejected");
	ok(!registry.set(gate("router-a", "127.0.0.1", 6032,
		ProxySQL_PluginListenerState::closed, "admin")),
		"Admin port 6032 cannot be gated");
	ok(!registry.set(gate("router-a", "127.0.0.1", 6033,
		ProxySQL_PluginListenerState::closed, "default")),
		"default MySQL port 6033 cannot be gated");

	std::atomic<bool> readers_ok { true };
	std::vector<std::thread> readers;
	for (int i = 0; i != 8; ++i) {
		readers.emplace_back([&] {
			for (int j = 0; j != 1000; ++j) {
				auto snapshot = registry.lookup("127.0.0.1", 6446);
				if (!snapshot || snapshot->owner != "router-a") readers_ok = false;
			}
		});
	}
	for (auto& reader : readers) reader.join();
	ok(readers_ok.load(), "concurrent readers observe complete owned snapshots");

	std::atomic<bool> accepts_ok { true };
	std::vector<std::thread> acceptors;
	for (int i = 0; i != 8; ++i) {
		acceptors.emplace_back([&] {
			for (int j = 0; j != 1000; ++j) {
				const auto decision = registry.inspect_accept("127.0.0.1", 6446, 300);
				if (decision.reject) accepts_ok = false;
			}
		});
	}
	for (auto& acceptor : acceptors) acceptor.join();
	ok(accepts_ok.load(), "concurrent ready-gate accepts stay on the handshake path");

	ok(registry.set(gate("router-a", "127.0.0.1", 6450,
		ProxySQL_PluginListenerState::closed, "not reconciled")),
		"closed socket-test gate installs");
	const auto first_reject = registry.inspect_accept("127.0.0.1", 6450, 100);
	const auto second_reject = registry.inspect_accept("127.0.0.1", 6450, 200);
	const auto resumed_warning = registry.inspect_accept("127.0.0.1", 6450, 30000100);
	ok(first_reject.reject && first_reject.should_warn &&
		second_reject.reject && !second_reject.should_warn &&
		resumed_warning.reject && resumed_warning.should_warn,
		"closed gate rejects each accept but rate-limits its warning for 30 seconds");
	auto rejected_snapshot = registry.lookup("127.0.0.1", 6450);
	ok(rejected_snapshot && rejected_snapshot->rejected_accepts == 3,
		"closed-gate accepts increment the registry snapshot counter");

	int closed_pair[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, closed_pair);
	ok(proxysql_plugin_set_listener_gate(gate("socket-test", "127.0.0.1", 6450,
		ProxySQL_PluginListenerState::closed, "not reconciled")),
		"global accept-path gate installs");
	const auto closed_socket = proxysql_plugin_listener_gate_close_if_closed(
		"127.0.0.1", 6450, closed_pair[0], 600);
	char byte = '\0';
	ok(closed_socket && closed_socket->reject && recv(closed_pair[1], &byte, 1, 0) == 0,
		"closed gate closes an accepted socket without a protocol handshake");
	close(closed_pair[1]);

	const auto ready_accept = registry.inspect_accept("127.0.0.1", 6446, 300);
	const auto unrelated_accept = registry.inspect_accept("127.0.0.1", 6500, 300);
	ok(!ready_accept.reject, "ready gate reaches the normal handshake path");
	ok(!unrelated_accept.reject, "unrelated listener reaches the normal handshake path");
	registry.force_close_owner("router-a");
	const auto degraded = registry.lookup("127.0.0.1", 6446);
	ok(degraded && degraded->state == ProxySQL_PluginListenerState::closed &&
		degraded->reason == "runtime readiness degraded",
		"owner-scoped degradation closes a previously ready gate with a safe reason");

	registry.remove_owner("router-a");
	ok(!registry.lookup("127.0.0.1", 6446).has_value() &&
		!registry.lookup("192.0.2.10", 6447).has_value(),
		"owner cleanup removes every one of its gates");
	return exit_status();
}
