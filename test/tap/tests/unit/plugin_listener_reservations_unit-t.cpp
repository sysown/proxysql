/**
 * @file plugin_listener_reservations_unit-t.cpp
 * @brief Standalone TAP coverage for the generic core listener reservation
 *        service introduced by plugin ABI 17.
 *
 * The service owns the enabled core listener strings that startup already
 * collected, validates plugin candidates as numeric TCP endpoints only, and
 * never borrows caller memory after a call returns.  It deliberately does not
 * reuse validate_module_listener_conflicts(), because that helper skips
 * same-module pairs; a plugin must not bypass a reservation by naming itself
 * after the owning core module.
 */

#include "ProxySQL_PluginListenerReservations.h"
#include "ProxySQL_Plugin.h"
#include "plugin_services_abi_layout.h"
#include "tap.h"

#include <cstddef>
#include <string>
#include <type_traits>
#include <vector>

using ProxySQL_PluginListenerReservations::ModuleReservation;
using ProxySQL_PluginListenerReservations::clear_reservations;
using ProxySQL_PluginListenerReservations::replace_reservations;
using ProxySQL_PluginListenerReservations::validate_candidate;

namespace {

bool accepts(const char* owner, const char* candidate) {
	std::string error = "stale error must be cleared before validation";
	const bool accepted = validate_candidate(owner, candidate, error);
	return accepted && error.empty();
}

bool rejects(const char* owner, const char* candidate, const std::string& expected = {}) {
	std::string error = "stale error must be cleared before validation";
	const bool accepted = validate_candidate(owner, candidate, error);
	if (accepted) return false;
	if (error.empty()) return false;
	return expected.empty() || error.find(expected) != std::string::npos;
}

} // namespace

int main() {
	plan(NO_PLAN);

	// ------------------------------------------------------------------
	// ABI-18 tail placement: the raw-backend getter follows the frozen
	// ABI-17 validator, and every ABI-16 service slot keeps its exact offset.
	// ------------------------------------------------------------------
	ok(PROXYSQL_PLUGIN_ABI_LAYOUT_VERSION == 18u,
		"ABI18: current layout version is 18");
	ok(PROXYSQL_PLUGIN_ABI_LAYOUT_VERSION_MAX == 18u,
		"ABI18: maximum accepted layout version is 18");
	ok((PROXYSQL_PLUGIN_ABI_VERSION & ~PROXYSQL_PLUGIN_ABI_DEBUG_BIT) == 18u,
		"ABI18: DEBUG tag remains independent of the layout number");
#ifdef DEBUG
	ok(PROXYSQL_PLUGIN_ABI_VERSION ==
		(PROXYSQL_PLUGIN_ABI_LAYOUT_VERSION | PROXYSQL_PLUGIN_ABI_DEBUG_BIT),
		"ABI17: a DEBUG build sets the DEBUG bit");
#else
	ok(PROXYSQL_PLUGIN_ABI_VERSION == PROXYSQL_PLUGIN_ABI_LAYOUT_VERSION,
		"ABI17: a release build leaves the DEBUG bit clear");
#endif
	ok(std::is_same<decltype(ProxySQL_PluginServices::validate_listener_interfaces),
		bool (*)(const char*, const char*, std::string&)>::value,
		"ABI17: listener validation service has the documented callback shape");
	ok(offsetof(ProxySQL_PluginServices, validate_listener_interfaces) ==
		sizeof(plugin_services_abi_layout_test::ManagedConfigurationAbi16),
		"ABI17: validate_listener_interfaces starts exactly where the frozen complete ABI16 prefix ends");
	ok(offsetof(ProxySQL_PluginServices, get_raw_backend_service) ==
		sizeof(plugin_services_abi_layout_test::ListenerValidationAbi17),
		"ABI18: raw-backend getter starts exactly where the complete frozen ABI17 prefix ends");
	ok(offsetof(ProxySQL_PluginServices, get_raw_backend_service) ==
		offsetof(ProxySQL_PluginServices, validate_listener_interfaces) +
		sizeof(ProxySQL_PluginServices::validate_listener_interfaces),
		"ABI18: raw-backend getter is the single pointer directly after listener validation");

	// ------------------------------------------------------------------
	// Exact and wildcard collisions, both address families.
	// ------------------------------------------------------------------
	replace_reservations({{"MySQL", "0.0.0.0:6033"}});
	ok(rejects("tcp_proxy", "0.0.0.0:6033", "MySQL"),
		"exact IPv4 collision is rejected with the reserved module in the error");

	replace_reservations({{"MySQL", "[::1]:6033"}});
	ok(rejects("tcp_proxy", "[::1]:6033", "MySQL"),
		"exact IPv6 collision is rejected");

	replace_reservations({{"MySQL", "0.0.0.0:6033"}});
	ok(rejects("tcp_proxy", "127.0.0.1:6033", "MySQL"),
		"IPv4 wildcard reservation covers a concrete IPv4 candidate");

	replace_reservations({{"MySQL", "127.0.0.1:6033"}});
	ok(rejects("tcp_proxy", "0.0.0.0:6033", "MySQL"),
		"IPv4 wildcard candidate covers a concrete IPv4 reservation");

	replace_reservations({{"MySQL", "[::]:6033"}});
	ok(rejects("tcp_proxy", "[2001:db8::1]:6033", "MySQL"),
		"IPv6 wildcard reservation covers a concrete IPv6 candidate");

	replace_reservations({{"MySQL", "[2001:db8::1]:6033"}});
	ok(rejects("tcp_proxy", "[::]:6033", "MySQL"),
		"IPv6 wildcard candidate covers a concrete IPv6 reservation");

	replace_reservations({{"MySQL", "[::1]:6033"}});
	ok(accepts("tcp_proxy", "127.0.0.1:6033"),
		"distinct address families on the same port do not conflict");

	// A plugin cannot bypass the reservation by masquerading as the core
	// module that owns it.
	replace_reservations({{"MySQL", "0.0.0.0:6033"}});
	ok(rejects("MySQL", "0.0.0.0:6033"),
		"owner-name equality does not skip reservation validation");
	ok(rejects(nullptr, "0.0.0.0:6033"),
		"a null owner still validates the candidate");

	// ------------------------------------------------------------------
	// Disabled, empty, and distinct-port reservations.
	// ------------------------------------------------------------------
	replace_reservations({});
	ok(accepts("tcp_proxy", "0.0.0.0:6033"),
		"empty reservation snapshot accepts any valid candidate and clears the error");
	replace_reservations({{"PostgreSQL", ""}});
	ok(accepts("tcp_proxy", "0.0.0.0:6033"),
		"an empty interfaces reservation behaves like a disabled module");

	replace_reservations({{"MySQL", "0.0.0.0:6033"}});
	ok(accepts("tcp_proxy", "0.0.0.0:6034"),
		"distinct ports do not conflict");

	// ------------------------------------------------------------------
	// Snapshot replacement and reload semantics.
	// ------------------------------------------------------------------
	replace_reservations({{"MySQL", "0.0.0.0:6033"}});
	replace_reservations({{"PostgreSQL", "0.0.0.0:6034"}});
	ok(accepts("tcp_proxy", "0.0.0.0:6033"),
		"replacing the snapshot clears the old reservation");
	ok(rejects("tcp_proxy", "0.0.0.0:6034", "PostgreSQL"),
		"replacing the snapshot installs the new reservation");
	clear_reservations();
	ok(accepts("tcp_proxy", "0.0.0.0:6034"),
		"clearing the snapshot removes every reservation");

	// The service must own its inputs: mutating or clearing the caller's
	// strings after replace_reservations() cannot change later validation.
	{
		std::string module_name = "MySQL";
		std::string interfaces = "0.0.0.0:6033";
		replace_reservations({{module_name, interfaces}});
		module_name.assign("mutated");
		interfaces.assign(512, 'x');
	}
	ok(rejects("tcp_proxy", "0.0.0.0:6033", "MySQL"),
		"reservation snapshot owns module and interface strings");
	clear_reservations();

	// Candidate inputs are borrowed only for the duration of a call.
	{
		std::string candidate = "0.0.0.0:6033";
		replace_reservations({{"MySQL", "0.0.0.0:6033"}});
		ok(!accepts("tcp_proxy", candidate.c_str()),
			"candidate validation sees the borrowed candidate");
		candidate.assign(128, 'z');
	}
	clear_reservations();

	// ------------------------------------------------------------------
	// Candidate-side parsing is strict and numeric-only.
	// ------------------------------------------------------------------
	replace_reservations({});
	ok(accepts("tcp_proxy", ""),
		"empty candidate means zero listeners");
	ok(accepts("tcp_proxy", "   "),
		"whitespace-only candidate means zero listeners");
	ok(accepts("tcp_proxy", nullptr),
		"a null candidate means zero listeners");

	// A nonempty candidate list with an empty element is malformed, not an
	// empty listener list: silently dropping it would hide a typo/config bug.
	ok(rejects("tcp_proxy", ";", "empty"),
		"a lone semicolon is an empty interface element");
	ok(rejects("tcp_proxy", ";127.0.0.1:1234", "empty"),
		"a leading semicolon is an empty interface element");
	ok(rejects("tcp_proxy", "127.0.0.1:1234;", "empty"),
		"a trailing semicolon is an empty interface element");
	ok(rejects("tcp_proxy", "127.0.0.1:1234;;127.0.0.2:1235", "empty"),
		"a doubled semicolon is an empty interface element");
	ok(rejects("tcp_proxy", "127.0.0.1:1234;   ;127.0.0.2:1235", "empty"),
		"a whitespace-only interface element is rejected");
	ok(rejects("tcp_proxy", "   ;  ", "empty"),
		"a whitespace/semicolon-only list contains empty interface elements");

	ok(rejects("tcp_proxy", "127.0.0.1", "port"),
		"candidate without a port is rejected");
	ok(rejects("tcp_proxy", "127.0.0.1:0", "port"),
		"candidate port zero is rejected");
	ok(rejects("tcp_proxy", "127.0.0.1:65536", "port"),
		"candidate port above 65535 is rejected");
	ok(rejects("tcp_proxy", "127.0.0.1:abc", "port"),
		"non-numeric candidate port is rejected");
	ok(rejects("tcp_proxy", "127.0.0.1:6033:1", "port"),
		"candidate with extra port text is rejected");
	ok(rejects("tcp_proxy", "localhost:6033", "numeric"),
		"hostname candidate is rejected instead of resolved");
	ok(rejects("tcp_proxy", "*:6033", "numeric"),
		"wildcard spelling other than 0.0.0.0/:: is rejected");
	ok(rejects("tcp_proxy", "::1:6033", "bracket"),
		"unbracketed IPv6 candidate is rejected");
	ok(rejects("tcp_proxy", "[::1]6033", "port"),
		"bracketed IPv6 candidate without a colon is rejected");
	ok(rejects("tcp_proxy", "[::1]:", "port"),
		"bracketed IPv6 candidate without a port value is rejected");
	ok(rejects("tcp_proxy", "[::1]:6033x", "port"),
		"bracketed IPv6 candidate with trailing port text is rejected");
	ok(rejects("tcp_proxy", "[::ffff:127.0.0.1]:6033", "IPv4-mapped"),
		"IPv4-mapped IPv6 candidate is rejected");
	ok(rejects("tcp_proxy", "[::ffff:7f00:1]:6033", "IPv4-mapped"),
		"hex-spelled IPv4-mapped IPv6 candidate is rejected");
	ok(rejects("tcp_proxy", "[127.0.0.1]:6033", "IPv6"),
		"bracket notation is only for IPv6; bracketed IPv4 is rejected");

	// ------------------------------------------------------------------
	// Candidate-internal duplicates and overlaps.
	// ------------------------------------------------------------------
	ok(rejects("tcp_proxy", "0.0.0.0:6033;0.0.0.0:6033", "duplicate"),
		"duplicate candidate endpoints are rejected");
	ok(rejects("tcp_proxy", "0.0.0.0:6033;127.0.0.1:6033", "overlap"),
		"overlapping candidate wildcard and concrete endpoint are rejected");
	ok(rejects("tcp_proxy", "[::]:6033;[2001:db8::1]:6033", "overlap"),
		"overlapping IPv6 candidate wildcard and concrete endpoint are rejected");
	ok(accepts("tcp_proxy", "0.0.0.0:6033;[::1]:6033"),
		"IPv4 and IPv6 candidates on the same port are allowed (V6ONLY)");
	ok(accepts("tcp_proxy", "0.0.0.0:6033;0.0.0.0:6034"),
		"distinct candidate ports are allowed");
	ok(accepts("tcp_proxy", "127.0.0.1:6033;[2001:db8::1]:6034"),
		"multiple distinct candidate endpoints are allowed");

	clear_reservations();
	return exit_status();
}
