#ifndef PROXY_PROTOCOL_INFO_H
#define PROXY_PROTOCOL_INFO_H

#include <string.h>
#include <netinet/in.h>
#include <string>
#include <arpa/inet.h>


class ProxyProtocolInfo {
public:
	char source_address[INET6_ADDRSTRLEN+1];
	char destination_address[INET6_ADDRSTRLEN+1];
	char proxy_address[INET6_ADDRSTRLEN+1];
	uint16_t source_port;
	uint16_t destination_port;
	uint16_t proxy_port;
	// GHSA-gw94-85m2-x8v2: set by parseProxyProtocolHeader() when the
	// PP1 frame uses the UNKNOWN protocol token. Per the HAProxy PP1
	// spec the receiver MUST ignore any address fields after UNKNOWN,
	// so the parser returns false and callers must NOT override the
	// real TCP peer's address from this frame.
	bool header_was_unknown;

	// Constructor (initializes to zeros)
	ProxyProtocolInfo() {
		memset(this, 0, sizeof(ProxyProtocolInfo));
	}

	// Copy constructor
	ProxyProtocolInfo(const ProxyProtocolInfo& other) {
		memcpy(this, &other, sizeof(ProxyProtocolInfo));
	}

	// Parse a PROXY-Protocol v1 header into this object.
	//
	// Return-value contract (relied upon by callers in lib/mysql_data_stream.cpp):
	//   - true  : the frame was a well-formed TCP4 or TCP6 line and the
	//             source/destination address+port fields are populated.
	//             The caller MAY override its session's client_addr from
	//             source_address/source_port.
	//   - false AND header_was_unknown == true :
	//             the frame was a well-formed PROXY UNKNOWN line.  Per
	//             the HAProxy PP1 spec, address fields MUST be ignored
	//             and the real TCP peer remains authoritative.  The
	//             caller MUST NOT override client_addr from this frame.
	//   - false AND header_was_unknown == false :
	//             the frame was malformed.  The caller treats it as a
	//             skip with a warning and does not override client_addr.
	//
	// Changing this contract requires updating the matching branch in
	// MySQL_Data_Stream::buffer2array() — the new UNKNOWN handling there
	// depends on the return-false + header_was_unknown=true signal to
	// avoid strdup-ing an empty source_address into client_addr
	// (GHSA-gw94-85m2-x8v2).
	bool parseProxyProtocolHeader(const char* packet, size_t packet_length);

	bool is_in_network(const struct sockaddr* client_addr, const std::string& subnet_mask);
	bool is_client_in_any_subnet(const struct sockaddr* client_addr, const char* subnet_list);

	// Copy method
	ProxyProtocolInfo& copy(const ProxyProtocolInfo& other) {
		if (this != &other) {
			memcpy(this, &other, sizeof(ProxyProtocolInfo));
		}
		return *this;
	}
#ifdef DEBUG
	sockaddr_in create_ipv4_addr(const std::string& ip);
	sockaddr_in6 create_ipv6_addr(const std::string& ip);
	void run_tests();
#endif // DEBUG
	bool is_valid_subnet_list(const char* subnet_list);
	bool is_valid_subnet(const char* subnet);
};

#endif // PROXY_PROTOCOL_INFO_H
