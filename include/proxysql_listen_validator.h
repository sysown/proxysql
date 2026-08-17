#ifndef PROXYSQL_LISTEN_VALIDATOR_H
#define PROXYSQL_LISTEN_VALIDATOR_H

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <set>
#include <string>
#include <vector>

/**
 * @namespace proxysql_listen_validator
 * @brief Utility for validating listener configurations across different modules.
 */
namespace proxysql_listen_validator {

/**
 * @struct module_listener_config
 * @brief Represents the listener configuration for a specific module.
 */
struct module_listener_config {
	const char* module_name; ///< The name of the module (e.g., "MySQL", "PostgreSQL").
	const char* listeners;   ///< Semicolon-separated list of listener interfaces.
};

/**
 * @enum listener_kind
 * @brief Type of listener.
 */
enum class listener_kind {
	tcp,        ///< TCP network interface.
	unix_socket ///< UNIX domain socket.
};

/**
 * @struct parsed_listener
 * @brief Contains detailed information about a parsed listener.
 */
struct parsed_listener {
	std::string module_name; ///< The module associated with this listener.
	std::string listener;    ///< Original listener string.
	listener_kind kind { listener_kind::tcp }; ///< Kind of listener.
	bool valid { true };     ///< Whether the listener string was valid.
	int port { 0 };          ///< Port number (for TCP).
	bool wildcard_v4 { false }; ///< True if listening on IPv4 wildcard (0.0.0.0).
	bool wildcard_v6 { false }; ///< True if listening on IPv6 wildcard (::).
	std::set<std::string> ipv4_addrs {}; ///< Resolved IPv4 addresses.
	std::set<std::string> ipv6_addrs {}; ///< Resolved IPv6 addresses.
	std::set<std::string> unresolved_hosts {}; ///< Hosts that failed to resolve.
};

/**
 * @brief Trims whitespace from both ends of a string.
 * @param value The string to trim.
 * @return A new trimmed string.
 */
static inline std::string trim_copy(const std::string& value) {
	std::string::size_type start = 0;
	while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
		start++;
	}

	std::string::size_type end = value.size();
	while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
		end--;
	}

	return value.substr(start, end - start);
}

/**
 * @brief Splits a semicolon-separated list of listeners into individual strings.
 * @param listeners The raw listener string from configuration.
 * @return A vector of trimmed listener strings.
 */
static inline std::vector<std::string> split_listener_list(const char* listeners) {
	std::vector<std::string> result {};

	if (listeners == nullptr) {
		return result;
	}

	std::string current {};
	const std::string source { listeners };
	for (char ch : source) {
		if (ch == ';') {
			std::string token = trim_copy(current);
			if (token.empty() == false) {
				result.push_back(token);
			}
			current.clear();
		} else {
			current.push_back(ch);
		}
	}

	std::string token = trim_copy(current);
	if (token.empty() == false) {
		result.push_back(token);
	}

	return result;
}

/**
 * @brief Checks if a host string represents an IPv4 wildcard.
 * @param host The hostname or IP string.
 * @return True if it's a wildcard.
 */
static inline bool is_ipv4_wildcard(const std::string& host) {
	return host.empty() || host == "0.0.0.0" || host == "*";
}

/**
 * @brief Checks if a host string represents an IPv6 wildcard.
 * @param host The hostname or IP string.
 * @return True if it's a wildcard.
 */
static inline bool is_ipv6_wildcard(const std::string& host) {
	return host == "::";
}

/**
 * @brief Adds a resolved address from a sockaddr structure to the appropriate set.
 * @param addr Pointer to the sockaddr structure.
 * @param ipv4_addrs Set to store IPv4 addresses.
 * @param ipv6_addrs Set to store IPv6 addresses.
 */
static inline void add_resolved_address(
	const sockaddr* addr, std::set<std::string>& ipv4_addrs, std::set<std::string>& ipv6_addrs
) {
	char buffer[INET6_ADDRSTRLEN] {};

	if (addr->sa_family == AF_INET) {
		const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(addr);
		if (inet_ntop(AF_INET, &addr4->sin_addr, buffer, sizeof(buffer))) {
			ipv4_addrs.insert(buffer);
		}
	} else if (addr->sa_family == AF_INET6) {
		const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(addr);
		if (inet_ntop(AF_INET6, &addr6->sin6_addr, buffer, sizeof(buffer))) {
			ipv6_addrs.insert(buffer);
		}
	}
}

/**
 * @brief Resolves a hostname or IP string into its constituent addresses.
 * 
 * Handles special cases like wildcards and 'localhost', and uses getaddrinfo
 * for general DNS resolution.
 * 
 * @param host The host string to resolve.
 * @param wildcard_v4 Output flag for IPv4 wildcard detection.
 * @param wildcard_v6 Output flag for IPv6 wildcard detection.
 * @param ipv4_addrs Set to store resolved IPv4 addresses.
 * @param ipv6_addrs Set to store resolved IPv6 addresses.
 * @param unresolved_hosts Set to store hosts that could not be resolved.
 */
static inline void resolve_host(
	const std::string& host,
	bool& wildcard_v4,
	bool& wildcard_v6,
	std::set<std::string>& ipv4_addrs,
	std::set<std::string>& ipv6_addrs,
	std::set<std::string>& unresolved_hosts
) {
	if (is_ipv4_wildcard(host)) {
		wildcard_v4 = true;
		return;
	}

	if (is_ipv6_wildcard(host)) {
		wildcard_v6 = true;
		return;
	}

	std::string host_lc { host };
	std::transform(host_lc.begin(), host_lc.end(), host_lc.begin(), [](unsigned char c) { return std::tolower(c); });

	if (host_lc == "localhost") {
		ipv4_addrs.insert("127.0.0.1");
		ipv6_addrs.insert("::1");
		return;
	}

	addrinfo hints {};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	addrinfo* results = nullptr;
	int rc = getaddrinfo(host.c_str(), nullptr, &hints, &results);
	if (rc != 0) {
		unresolved_hosts.insert(host_lc);
		return;
	}

	for (addrinfo* current = results; current != nullptr; current = current->ai_next) {
		add_resolved_address(current->ai_addr, ipv4_addrs, ipv6_addrs);
	}

	freeaddrinfo(results);
}

/**
 * @brief Parses a listener string and populates a parsed_listener structure.
 * 
 * Supports both TCP (host:port) and UNIX sockets (path). Handles IPv6 
 * bracketed syntax [::1]:6033.
 * 
 * @param module_name Name of the module configuring this listener.
 * @param listener The listener string to parse.
 * @return A populated parsed_listener structure.
 */
static inline parsed_listener parse_listener(const std::string& module_name, const std::string& listener) {
	parsed_listener parsed {};
	parsed.module_name = module_name;
	parsed.listener = listener;

	std::string host {};
	std::string port_text {};

	if (listener.empty() == false && listener[0] == '[') {
		std::string::size_type closing = listener.find(']');
		if (closing != std::string::npos) {
			host = listener.substr(1, closing - 1);
			if (closing + 1 < listener.size() && listener[closing + 1] == ':') {
				port_text = listener.substr(closing + 2);
			}
		} else {
			parsed.valid = false;
			return parsed;
		}
	} else {
		std::string::size_type colon = listener.find(':');
		if (colon == std::string::npos) {
			parsed.kind = listener_kind::unix_socket;
			return parsed;
		}

		host = listener.substr(0, colon);
		port_text = listener.substr(colon + 1);
	}

	if (port_text.empty()) {
		parsed.valid = false;
		return parsed;
	}

	char* endptr = nullptr;
	long parsed_port = strtol(port_text.c_str(), &endptr, 10);
	if (endptr == port_text.c_str() || *endptr != '\0' || parsed_port <= 0 || parsed_port > 65535) {
		parsed.valid = false;
		return parsed;
	}

	parsed.kind = listener_kind::tcp;
	parsed.port = static_cast<int>(parsed_port);
	resolve_host(host, parsed.wildcard_v4, parsed.wildcard_v6, parsed.ipv4_addrs, parsed.ipv6_addrs, parsed.unresolved_hosts);

	return parsed;
}

/**
 * @brief Checks if two sets of strings have any common elements.
 * @param lhs First set.
 * @param rhs Second set.
 * @return True if sets intersect.
 */
static inline bool sets_intersect(const std::set<std::string>& lhs, const std::set<std::string>& rhs) {
	for (const std::string& value : lhs) {
		if (rhs.find(value) != rhs.end()) {
			return true;
		}
	}

	return false;
}

/**
 * @brief Determines if two listeners conflict with each other.
 * 
 * Conflicts occur if:
 * - Both are identical UNIX socket paths.
 * - Both are TCP listeners on the same port and share an IP/wildcard overlap.
 * 
 * @param lhs First listener.
 * @param rhs Second listener.
 * @return True if a conflict is detected.
 */
static inline bool listeners_conflict(const parsed_listener& lhs, const parsed_listener& rhs) {
	if (lhs.kind == listener_kind::unix_socket || rhs.kind == listener_kind::unix_socket) {
		return lhs.kind == listener_kind::unix_socket &&
			rhs.kind == listener_kind::unix_socket &&
			lhs.listener == rhs.listener;
	}

	if (lhs.port != rhs.port) {
		return false;
	}

	if ((lhs.wildcard_v4 && (rhs.wildcard_v4 || rhs.ipv4_addrs.empty() == false)) ||
		(rhs.wildcard_v4 && lhs.ipv4_addrs.empty() == false)) {
		return true;
	}

	if ((lhs.wildcard_v6 && (rhs.wildcard_v6 || rhs.ipv6_addrs.empty() == false)) ||
		(rhs.wildcard_v6 && lhs.ipv6_addrs.empty() == false)) {
		return true;
	}

	if (sets_intersect(lhs.ipv4_addrs, rhs.ipv4_addrs) || sets_intersect(lhs.ipv6_addrs, rhs.ipv6_addrs)) {
		return true;
	}

	return sets_intersect(lhs.unresolved_hosts, rhs.unresolved_hosts);
}

/**
 * @brief Validates all listeners across provided modules for cross-module conflicts.
 * 
 * This is the main entry point for the validator. It parses all listeners and 
 * performs pairwise conflict detection across different modules.
 * 
 * @param modules Vector of module listener configurations.
 * @param error String to store a descriptive error message on conflict.
 * @return True if no cross-module conflicts are found, false otherwise.
 */
static inline bool validate_module_listener_conflicts(
	const std::vector<module_listener_config>& modules, std::string& error
) {
	std::vector<parsed_listener> parsed_listeners {};

	for (const module_listener_config& listener_module : modules) {
		if (listener_module.listeners == nullptr || *listener_module.listeners == '\0' || strcmp(listener_module.listeners, "(null)") == 0) {
			continue;
		}
		std::vector<std::string> listeners = split_listener_list(listener_module.listeners);
		for (const std::string& listener : listeners) {
			parsed_listener parsed = parse_listener(listener_module.module_name, listener);
			if (parsed.valid) {
				parsed_listeners.push_back(parsed);
			}
		}
	}

	for (std::size_t i = 0; i < parsed_listeners.size(); i++) {
		for (std::size_t j = i + 1; j < parsed_listeners.size(); j++) {
			const parsed_listener& lhs = parsed_listeners[i];
			const parsed_listener& rhs = parsed_listeners[j];

			if (lhs.module_name == rhs.module_name) {
				continue;
			}

			if (listeners_conflict(lhs, rhs)) {
				error =
					"Configuration conflict detected: " + lhs.module_name + " listener '" + lhs.listener +
					"' overlaps with " + rhs.module_name + " listener '" + rhs.listener + "'";
				return false;
			}
		}
	}

	return true;
}

} // namespace proxysql_listen_validator

#endif // PROXYSQL_LISTEN_VALIDATOR_H
