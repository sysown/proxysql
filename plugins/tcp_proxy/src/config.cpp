// Pure configuration validation, numeric address/CIDR parsing and route
// formatting.  This file has no sockets, SQL, DNS or ProxySQL dependencies.

#include "engine_internal.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <set>
#include <sstream>

namespace tcp_proxy {
namespace detail {
namespace {

bool has_nul(const std::string& value) {
	return value.find('\0') != std::string::npos;
}

bool is_zero_address(const std::array<unsigned char, 16>& address, int family) {
	const int bytes = family == AF_INET ? 4 : 16;
	for (int i = 0; i < bytes; ++i) {
		if (address[static_cast<size_t>(i)] != 0) {
			return false;
		}
	}
	return true;
}

bool is_mapped_v6(const std::array<unsigned char, 16>& address) {
	for (int i = 0; i < 10; ++i) {
		if (address[static_cast<size_t>(i)] != 0) {
			return false;
		}
	}
	return address[10] == 0xff && address[11] == 0xff;
}

std::string format_host_port(const Endpoint& endpoint) {
	if (!endpoint.valid()) {
		return {};
	}
	if (endpoint.family == AF_INET6) {
		return "[" + endpoint.text + "]:" + std::to_string(endpoint.port);
	}
	return endpoint.text + ":" + std::to_string(endpoint.port);
}

std::string quoted(const std::string& value) {
	return "'" + value + "'";
}

bool fail(std::string& error, const std::string& message) {
	error = message;
	return false;
}

} // namespace

bool Endpoint::is_wildcard() const {
	if (!valid()) {
		return false;
	}
	return is_zero_address(address, family);
}

std::string Endpoint::host_port() const {
	return format_host_port(*this);
}

std::string Endpoint::key() const {
	if (!valid()) {
		return {};
	}
	return (family == AF_INET ? "4|" : "6|") + text + "|" + std::to_string(port);
}

bool parse_ip_address(const std::string& text, Endpoint& out, std::string& error) {
	out = Endpoint {};
	if (text.empty()) {
		return fail(error, "address is empty");
	}
	if (has_nul(text)) {
		return fail(error, "address contains an embedded NUL byte");
	}

	Endpoint parsed;
	parsed.text = text;
	in_addr a4 {};
	if (inet_pton(AF_INET, text.c_str(), &a4) == 1) {
		parsed.family = AF_INET;
		std::memcpy(parsed.address.data(), &a4, sizeof(a4));
		char buf[INET_ADDRSTRLEN] {};
		if (inet_ntop(AF_INET, &a4, buf, sizeof(buf)) == nullptr) {
			return fail(error, "invalid IPv4 address");
		}
		parsed.text = buf;
		out = parsed;
		return true;
	}

	in6_addr a6 {};
	if (inet_pton(AF_INET6, text.c_str(), &a6) == 1) {
		parsed.family = AF_INET6;
		std::memcpy(parsed.address.data(), &a6, sizeof(a6));
		if (is_mapped_v6(parsed.address)) {
			return fail(error, "IPv4-mapped IPv6 address " + quoted(text) +
					" is not supported; use the numeric IPv4 spelling");
		}
		char buf[INET6_ADDRSTRLEN] {};
		if (inet_ntop(AF_INET6, &a6, buf, sizeof(buf)) == nullptr) {
			return fail(error, "invalid IPv6 address");
		}
		parsed.text = buf;
		out = parsed;
		return true;
	}

	return fail(error, "numeric IPv4 or IPv6 address required (DNS names are not supported): " +
			quoted(text));
}

bool parse_cidr(const std::string& text, Cidr& out, std::string& error) {
	out = Cidr {};
	if (text.empty()) {
		return fail(error, "CIDR is empty");
	}
	if (has_nul(text)) {
		return fail(error, "CIDR contains an embedded NUL byte");
	}
	const std::string::size_type slash = text.find('/');
	if (slash == std::string::npos || text.find('/', slash + 1) != std::string::npos) {
		return fail(error, "invalid CIDR (missing or repeated '/'): " + quoted(text));
	}
	const std::string address_text = text.substr(0, slash);
	const std::string prefix_text = text.substr(slash + 1);
	if (prefix_text.empty()) {
		return fail(error, "invalid CIDR prefix: " + quoted(text));
	}
	for (char ch : prefix_text) {
		if (ch < '0' || ch > '9') {
			return fail(error, "invalid CIDR prefix: " + quoted(text));
		}
	}
	errno = 0;
	char* end = nullptr;
	const long prefix = std::strtol(prefix_text.c_str(), &end, 10);
	if (errno != 0 || end == nullptr || *end != '\0') {
		return fail(error, "invalid CIDR prefix: " + quoted(text));
	}
	Endpoint address;
	std::string address_error;
	if (!parse_ip_address(address_text, address, address_error)) {
		return fail(error, "invalid CIDR address: " + address_error);
	}
	const int bits = address.family == AF_INET ? 32 : 128;
	if (prefix < 0 || prefix > bits) {
		return fail(error, "CIDR prefix out of range: " + quoted(text));
	}

	Cidr cidr;
	cidr.family = address.family;
	cidr.network = address.address;
	cidr.prefix = static_cast<int>(prefix);
	const int full_bytes = cidr.prefix / 8;
	const int partial_bits = cidr.prefix % 8;
	const int total_bytes = bits / 8;
	for (int i = 0; i < total_bytes; ++i) {
		unsigned char mask = 0;
		if (i < full_bytes) {
			mask = 0xff;
		} else if (i == full_bytes && partial_bits != 0) {
			mask = static_cast<unsigned char>(0xff << (8 - partial_bits));
		}
		const unsigned char masked =
			static_cast<unsigned char>(cidr.network[static_cast<size_t>(i)] & mask);
		if (masked != cidr.network[static_cast<size_t>(i)]) {
			return fail(error, "CIDR is not canonical (host bits set): " + quoted(text));
		}
		cidr.network[static_cast<size_t>(i)] = masked;
	}
	out = cidr;
	return true;
}

bool Cidr::matches(const Endpoint& endpoint) const {
	if (!valid() || !endpoint.valid() || endpoint.family != family) {
		return false;
	}
	const int full_bytes = prefix / 8;
	const int partial_bits = prefix % 8;
	if (full_bytes > 0 &&
		std::memcmp(network.data(), endpoint.address.data(), static_cast<size_t>(full_bytes)) != 0) {
		return false;
	}
	if (partial_bits != 0) {
		const unsigned char mask = static_cast<unsigned char>(0xff << (8 - partial_bits));
		if ((network[static_cast<size_t>(full_bytes)] & mask) !=
			(endpoint.address[static_cast<size_t>(full_bytes)] & mask)) {
			return false;
		}
	}
	return true;
}

bool endpoint_overlaps(const Endpoint& lhs, const Endpoint& rhs) {
	if (!lhs.valid() || !rhs.valid() || lhs.family != rhs.family || lhs.port != rhs.port) {
		return false;
	}
	if (lhs.is_wildcard() || rhs.is_wildcard()) {
		return true;
	}
	return lhs.address == rhs.address;
}

bool validate_config(const Config& config, std::string& error) {
	error.clear();
	const Settings& settings = config.settings;
	if (settings.id != 1) {
		return fail(error, "tcp_settings.id must be 1");
	}
	if (settings.worker_threads < 1 || settings.worker_threads > 64) {
		return fail(error, "tcp_settings.worker_threads must be between 1 and 64");
	}
	if (settings.max_connections < 1 || settings.max_connections > 1000000) {
		return fail(error, "tcp_settings.max_connections must be between 1 and 1000000");
	}
	if (settings.buffer_size < 1024 || settings.buffer_size > 1048576) {
		return fail(error, "tcp_settings.buffer_size must be between 1024 and 1048576");
	}
	if (settings.shutdown_timeout_ms < 0 || settings.shutdown_timeout_ms > 60000) {
		return fail(error, "tcp_settings.shutdown_timeout_ms must be between 0 and 60000");
	}
	if (settings.half_close_timeout_ms < 1 || settings.half_close_timeout_ms > 3600000) {
		return fail(error, "tcp_settings.half_close_timeout_ms must be between 1 and 3600000");
	}

	std::set<int> hostgroup_ids;
	for (const Hostgroup& hostgroup : config.hostgroups) {
		if (hostgroup.hostgroup_id < 0) {
			return fail(error, "tcp_hostgroups.hostgroup_id must be nonnegative");
		}
		if (!hostgroup_ids.insert(hostgroup.hostgroup_id).second) {
			return fail(error, "duplicate tcp_hostgroups.hostgroup_id " +
					std::to_string(hostgroup.hostgroup_id));
		}
		if (has_nul(hostgroup.source_protocol)) {
			return fail(error, "tcp_hostgroups.source_protocol contains an embedded NUL "
					"byte");
		}
		if (has_nul(hostgroup.comment)) {
			return fail(error, "tcp_hostgroups.comment contains an embedded NUL byte");
		}
		if (hostgroup.source_protocol != "MYSQL" &&
			hostgroup.source_protocol != "PGSQL") {
			return fail(error, "tcp_hostgroups.source_protocol must be MYSQL or PGSQL for "
					"hostgroup " + std::to_string(hostgroup.hostgroup_id));
		}
		if (hostgroup.source_hostgroup < 0) {
			return fail(error, "tcp_hostgroups.source_hostgroup must be nonnegative for "
					"hostgroup " + std::to_string(hostgroup.hostgroup_id));
		}
	}

	std::set<int> listener_ids;
	std::vector<Endpoint> active_endpoints;
	for (const Listener& listener : config.listeners) {
		if (listener.listener_id < 0) {
			return fail(error, "tcp_listeners.listener_id must be nonnegative");
		}
		if (!listener_ids.insert(listener.listener_id).second) {
			return fail(error, "duplicate tcp_listeners.listener_id " +
					std::to_string(listener.listener_id));
		}
		if (listener.active != 0 && listener.active != 1) {
			return fail(error, "tcp_listeners.active must be 0 or 1 for listener " +
					std::to_string(listener.listener_id));
		}
		Endpoint endpoint;
		std::string address_error;
		if (!parse_ip_address(listener.bind_address, endpoint, address_error)) {
			return fail(error, "tcp_listeners.bind_address for listener " +
					std::to_string(listener.listener_id) + ": " + address_error);
		}
		if (has_nul(listener.comment)) {
			return fail(error, "tcp_listeners.comment contains an embedded NUL byte");
		}
		if (listener.bind_port < 1 || listener.bind_port > 65535) {
			return fail(error, "tcp_listeners.bind_port must be between 1 and 65535 for "
					"listener " + std::to_string(listener.listener_id));
		}
		endpoint.port = static_cast<uint16_t>(listener.bind_port);
		if (hostgroup_ids.count(listener.default_hostgroup) == 0) {
			return fail(error, "tcp_listeners.default_hostgroup " +
					std::to_string(listener.default_hostgroup) + " does not reference a "
					"configured hostgroup (listener " +
					std::to_string(listener.listener_id) + ")");
		}
		if (listener.max_connections < 1 || listener.max_connections > 1000000) {
			return fail(error, "tcp_listeners.max_connections must be between 1 and 1000000 "
					"for listener " + std::to_string(listener.listener_id));
		}
		if (listener.connect_timeout_ms < 1 || listener.connect_timeout_ms > 60000) {
			return fail(error, "tcp_listeners.connect_timeout_ms must be between 1 and 60000 "
					"for listener " + std::to_string(listener.listener_id));
		}
		if (listener.idle_timeout_ms != 0 &&
			(listener.idle_timeout_ms < 1 || listener.idle_timeout_ms > 86400000)) {
			return fail(error, "tcp_listeners.idle_timeout_ms must be 0 or between 1 and "
					"86400000 for listener " + std::to_string(listener.listener_id));
		}
		if (listener.max_connect_attempts < 1 || listener.max_connect_attempts > 16) {
			return fail(error, "tcp_listeners.max_connect_attempts must be between 1 and 16 "
					"for listener " + std::to_string(listener.listener_id));
		}
		if (listener.active == 1) {
			for (const Endpoint& existing : active_endpoints) {
				if (endpoint_overlaps(existing, endpoint)) {
					return fail(error, "active listeners overlap at " + endpoint.host_port() +
							" (listener " + std::to_string(listener.listener_id) +
							" conflicts with another active listener)");
				}
			}
			active_endpoints.push_back(endpoint);
		}
	}

	std::set<int> rule_ids;
	for (const Rule& rule : config.rules) {
		if (rule.rule_id < 0) {
			return fail(error, "tcp_routing_rules.rule_id must be nonnegative");
		}
		if (!rule_ids.insert(rule.rule_id).second) {
			return fail(error, "duplicate tcp_routing_rules.rule_id " +
					std::to_string(rule.rule_id));
		}
		if (rule.active != 0 && rule.active != 1) {
			return fail(error, "tcp_routing_rules.active must be 0 or 1 for rule " +
					std::to_string(rule.rule_id));
		}
		if (rule.listener_id.has_value()) {
			if (*rule.listener_id < 0 || listener_ids.count(*rule.listener_id) == 0) {
				return fail(error, "tcp_routing_rules.listener_id " +
						std::to_string(*rule.listener_id) + " does not reference a configured "
						"listener (rule " + std::to_string(rule.rule_id) + ")");
			}
		}
		if (rule.source_cidr.has_value()) {
			Cidr cidr;
			std::string cidr_error;
			if (!parse_cidr(*rule.source_cidr, cidr, cidr_error)) {
				return fail(error, "tcp_routing_rules.source_cidr for rule " +
						std::to_string(rule.rule_id) + ": " + cidr_error);
			}
		}
		if (has_nul(rule.action)) {
			return fail(error, "tcp_routing_rules.action contains an embedded NUL byte");
		}
		if (has_nul(rule.comment)) {
			return fail(error, "tcp_routing_rules.comment contains an embedded NUL byte");
		}
		if (rule.action != "ROUTE" && rule.action != "REJECT") {
			return fail(error, "tcp_routing_rules.action must be ROUTE or REJECT for rule " +
					std::to_string(rule.rule_id));
		}
		if (rule.action == "ROUTE") {
			if (!rule.destination_hostgroup.has_value()) {
				return fail(error, "tcp_routing_rules.destination_hostgroup is required for "
						"ROUTE rule " + std::to_string(rule.rule_id));
			}
			if (*rule.destination_hostgroup < 0 ||
				hostgroup_ids.count(*rule.destination_hostgroup) == 0) {
				return fail(error, "tcp_routing_rules.destination_hostgroup " +
						std::to_string(*rule.destination_hostgroup) + " does not reference a "
						"configured hostgroup (rule " + std::to_string(rule.rule_id) + ")");
			}
		} else {
			if (rule.destination_hostgroup.has_value()) {
				return fail(error, "tcp_routing_rules.destination_hostgroup must be NULL for "
						"REJECT rule " + std::to_string(rule.rule_id));
			}
		}
	}

	return true;
}

std::string listener_interfaces(const Config& config) {
	std::set<std::string> interfaces;
	for (const Listener& listener : config.listeners) {
		if (listener.active != 1) {
			continue;
		}
		Endpoint endpoint;
		std::string error;
		if (!parse_ip_address(listener.bind_address, endpoint, error)) {
			continue;
		}
		if (listener.bind_port < 1 || listener.bind_port > 65535) {
			continue;
		}
		endpoint.port = static_cast<uint16_t>(listener.bind_port);
		interfaces.insert(endpoint.host_port());
	}
	std::string out;
	for (const std::string& value : interfaces) {
		if (!out.empty()) {
			out += ';';
		}
		out += value;
	}
	return out;
}

} // namespace detail

bool validate_config(const Config& config, std::string& error) {
	return detail::validate_config(config, error);
}

std::string listener_interfaces(const Config& config) {
	return detail::listener_interfaces(config);
}

} // namespace tcp_proxy
