#ifndef PROXY_PROTOCOL_INFO_H
#define PROXY_PROTOCOL_INFO_H

#include <string.h>
#include <netinet/in.h>
#include <string>
#include <arpa/inet.h>

#define PPV2_HEADER_LENGTH 16
#define PPV2_SIGNATURE_LENGTH 12
#define PPV2_SIGNATURE "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"

enum ProxyProtocolVersion {
	NONE,
	PPv1,
	PPv2,
};

class ProxyProtocolInfo {
public:
	char source_address[INET6_ADDRSTRLEN+1];
	char destination_address[INET6_ADDRSTRLEN+1];
	char proxy_address[INET6_ADDRSTRLEN+1];
	uint16_t source_port;
	uint16_t destination_port;
	uint16_t proxy_port;
	ProxyProtocolVersion version;

	// Constructor (initializes to zeros)
	ProxyProtocolInfo() {
		memset(this, 0, sizeof(ProxyProtocolInfo));
	}

	// Copy constructor
	ProxyProtocolInfo(const ProxyProtocolInfo& other) {
		memcpy(this, &other, sizeof(ProxyProtocolInfo));
	}

	// Function to parse the PROXY protocol header (declared)
	bool parseProxyProtocolHeader(const char* packet, size_t packet_length);

	// Function to parse the PROXY V2 protocol header, returns the total length of the header and -1 on error
	int parseProxyProtocolV2Header(const char* packet, size_t packet_length);

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
