// Generic core listener reservation service for plugin ABI 17.
//
// This translation unit intentionally depends only on the header-only core
// listener validator and the C library.  It must remain safe to call from
// plugin init/start and Admin LOAD paths: no SQL, logging, sockets, or DNS is
// performed while validating a candidate against the owned snapshot.
#ifdef PROXYSQL40

#include "ProxySQL_PluginListenerReservations.h"

#include "proxysql_listen_validator.h"

#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <utility>

namespace {

namespace listener_validator = proxysql_listen_validator;

std::shared_mutex g_reservations_mutex;
std::vector<listener_validator::parsed_listener> g_reservations;

bool parse_port(const std::string& text, int& port, std::string& reason) {
	if (text.empty()) {
		reason = "listener port is missing";
		return false;
	}
	for (const unsigned char ch : text) {
		if (std::isdigit(ch) == 0) {
			reason = "listener port '" + text + "' is not numeric";
			return false;
		}
	}
	errno = 0;
	char* end = nullptr;
	const long value = std::strtol(text.c_str(), &end, 10);
	if (errno != 0 || end == text.c_str() || *end != '\0' || value <= 0 || value > 65535) {
		reason = "listener port '" + text + "' is outside 1..65535";
		return false;
	}
	port = static_cast<int>(value);
	return true;
}

bool is_blank(const std::string& text) {
	for (const unsigned char ch : text) {
		if (std::isspace(ch) == 0) {
			return false;
		}
	}
	return true;
}

std::vector<std::string> split_candidate_list(const std::string& source) {
	// listen_validator::split_listener_list() deliberately discards empty
	// tokens, which is correct for core's permissive existing reservation
	// parsing.  Plugin candidates are a new, strict surface: keep every
	// element so a typo such as "a:1;;b:2" is rejected instead of silently
	// shrinking the listener set.
	std::vector<std::string> result {};
	std::string current {};
	for (const char ch : source) {
		if (ch == ';') {
			result.push_back(listener_validator::trim_copy(current));
			current.clear();
		} else {
			current.push_back(ch);
		}
	}
	result.push_back(listener_validator::trim_copy(current));
	return result;
}

bool parse_numeric_address(const std::string& host,
	listener_validator::parsed_listener& parsed, std::string& reason) {
	in_addr address4 {};
	if (inet_pton(AF_INET, host.c_str(), &address4) == 1) {
		char text[INET_ADDRSTRLEN] {};
		if (inet_ntop(AF_INET, &address4, text, sizeof(text)) == nullptr) {
			reason = "listener address '" + host + "' cannot be normalized";
			return false;
		}
		if (std::strcmp(text, "0.0.0.0") == 0) {
			parsed.wildcard_v4 = true;
		} else {
			parsed.ipv4_addrs.insert(text);
		}
		return true;
	}

	in6_addr address6 {};
	if (inet_pton(AF_INET6, host.c_str(), &address6) == 1) {
		if (IN6_IS_ADDR_V4MAPPED(&address6)) {
			reason = "IPv4-mapped IPv6 listener addresses are not supported";
			return false;
		}
		char text[INET6_ADDRSTRLEN] {};
		if (inet_ntop(AF_INET6, &address6, text, sizeof(text)) == nullptr) {
			reason = "listener address '" + host + "' cannot be normalized";
			return false;
		}
		if (std::strcmp(text, "::") == 0) {
			parsed.wildcard_v6 = true;
		} else {
			parsed.ipv6_addrs.insert(text);
		}
		return true;
	}

	reason = "listener address '" + host +
		"' is not a numeric IPv4 or IPv6 address (hostname and DNS lookups are not allowed)";
	return false;
}

// Strict candidate parser: unlike proxysql_listen_validator::parse_listener it
// rejects malformed input instead of returning an invalid entry the core
// validator would silently skip, and it never calls getaddrinfo().
bool parse_numeric_candidate(const std::string& listener,
	listener_validator::parsed_listener& parsed, std::string& reason) {
	if (listener.empty()) {
		reason = "listener is empty";
		return false;
	}

	std::string host {};
	std::string port_text {};

	if (listener[0] == '[') {
		const std::string::size_type closing = listener.find(']');
		if (closing == std::string::npos) {
			reason = "unterminated bracketed IPv6 listener";
			return false;
		}
		host = listener.substr(1, closing - 1);
		if (host.empty()) {
			reason = "bracketed listener is missing an address";
			return false;
		}
		if (host.find(':') == std::string::npos) {
			reason = "bracket notation is reserved for IPv6 listener addresses";
			return false;
		}
		if (closing + 1 >= listener.size() || listener[closing + 1] != ':') {
			reason = "bracketed IPv6 listener must be followed by ':port'";
			return false;
		}
		port_text = listener.substr(closing + 2);
	} else {
		const std::string::size_type colon = listener.find(':');
		if (colon == std::string::npos) {
			reason = "listener is missing a port separator";
			return false;
		}
		host = listener.substr(0, colon);
		port_text = listener.substr(colon + 1);
		if (host.empty()) {
			reason = "listener address is missing; IPv6 listener addresses must use bracket notation";
			return false;
		}
	}

	if (host.find(':') != std::string::npos && listener[0] != '[') {
		reason = "IPv6 listener addresses must use bracket notation";
		return false;
	}

	int port = 0;
	if (!parse_port(port_text, port, reason)) {
		return false;
	}
	if (!parse_numeric_address(host, parsed, reason)) {
		return false;
	}

	parsed.kind = listener_validator::listener_kind::tcp;
	parsed.port = port;
	parsed.valid = true;
	return true;
}

std::string owner_name(const char* owner) {
	return owner != nullptr && owner[0] != '\0' ? std::string(owner) : std::string("plugin");
}

} // namespace

namespace ProxySQL_PluginListenerReservations {

void replace_reservations(std::vector<ModuleReservation> reservations) {
	std::vector<listener_validator::parsed_listener> parsed_reservations {};
	for (const ModuleReservation& reservation : reservations) {
		// parse_listener preserves the existing core parser's permissive
		// behavior, including its startup-time hostname resolution.  Malformed
		// reservations are skipped exactly as validate_module_listener_conflicts
		// already skips them.
		const std::vector<std::string> listeners =
			listener_validator::split_listener_list(reservation.interfaces.c_str());
		for (const std::string& listener : listeners) {
			listener_validator::parsed_listener parsed =
				listener_validator::parse_listener(reservation.module_name, listener);
			if (parsed.valid) {
				parsed_reservations.push_back(std::move(parsed));
			}
		}
	}

	std::unique_lock<std::shared_mutex> lock(g_reservations_mutex);
	g_reservations.swap(parsed_reservations);
}

void clear_reservations() {
	std::unique_lock<std::shared_mutex> lock(g_reservations_mutex);
	g_reservations.clear();
}

bool validate_candidate(const char* owner, const char* interfaces, std::string& error) {
	error.clear();

	const std::string candidate_owner = owner_name(owner);
	std::vector<listener_validator::parsed_listener> candidates {};

	// Empty, null, and whitespace-only input means "zero listeners".  Once
	// there is any non-whitespace content, every semicolon-separated element
	// must be a real listener; an empty element is malformed.
	if (interfaces == nullptr) {
		return true;
	}
	const std::string candidate_interfaces { interfaces };
	if (is_blank(candidate_interfaces)) {
		return true;
	}

	const std::vector<std::string> listeners =
		split_candidate_list(candidate_interfaces);
	for (const std::string& listener : listeners) {
		if (listener.empty()) {
			error = "listener candidate list contains an empty interface element";
			return false;
		}
		listener_validator::parsed_listener parsed {};
		std::string reason {};
		if (!parse_numeric_candidate(listener, parsed, reason)) {
			error = "listener candidate '" + listener + "' is invalid: " + reason;
			return false;
		}
		parsed.module_name = candidate_owner;
		parsed.listener = listener;
		candidates.push_back(std::move(parsed));
	}

	for (std::size_t i = 0; i < candidates.size(); ++i) {
		for (std::size_t j = i + 1; j < candidates.size(); ++j) {
			if (listener_validator::listeners_conflict(candidates[i], candidates[j])) {
				if (candidates[i].listener == candidates[j].listener) {
					error = "listener candidate duplicate: '" + candidates[i].listener +
						"' appears more than once";
				} else {
					error = "listener candidate overlap: '" + candidates[i].listener +
						"' overlaps with candidate '" + candidates[j].listener + "'";
				}
				return false;
			}
		}
	}

	std::shared_lock<std::shared_mutex> lock(g_reservations_mutex);
	for (const listener_validator::parsed_listener& candidate : candidates) {
		for (const listener_validator::parsed_listener& reserved : g_reservations) {
			// Deliberately no same-module skip: owner strings are plugin-supplied
			// diagnostics, never proof that the core module does not own the port.
			if (listener_validator::listeners_conflict(candidate, reserved)) {
				error = "listener conflict detected: " + candidate_owner + " listener '" +
					candidate.listener + "' overlaps with " + reserved.module_name +
					" listener '" + reserved.listener + "'";
				return false;
			}
		}
	}

	return true;
}

} // namespace ProxySQL_PluginListenerReservations

#endif /* PROXYSQL40 */
