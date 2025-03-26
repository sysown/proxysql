#include "proxy_protocol_info.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <iostream>

static bool DEBUG_ProxyProtocolInfo = false;

// Function to parse the PROXY protocol header
bool ProxyProtocolInfo::parseProxyProtocolHeader(const char* packet, size_t packet_length) {
	// Check for minimum header length (including CRLF)
	if (packet_length < 15) {
		return false; // Not a valid PROXY protocol header
	}

	// Create a temporary buffer on the stack
	char temp_buffer[packet_length + 1]; 

	// Copy the packet data
	memcpy(temp_buffer, packet, packet_length);
	temp_buffer[packet_length] = '\0'; // Null-terminate the buffer


	// Verify the PROXY protocol signature
	if (memcmp(temp_buffer, "PROXY", 5) != 0) {
		return false; // Not a valid PROXY protocol header
	}

	// Check for the space after "PROXY"
	if (temp_buffer[5] != ' ') {
		return false; // Invalid header format
	}

	// Check for the protocol type
	if (memcmp(temp_buffer + 6, "TCP4", 4) == 0 ||
		memcmp(temp_buffer + 6, "TCP6", 4) == 0 ||
		memcmp(temp_buffer + 6, "UNKNOWN", 7) == 0) {

		// Parse the header using sscanf
		int result = sscanf(temp_buffer, "PROXY %*s %s %s %hu %hu\r\n", 
						   source_address, destination_address, 
						   &source_port, &destination_port);

		// Check if sscanf successfully parsed all fields
		if (result == 4) {
			return true; // Successful parsing
		} else {
			// Handle partial parsing or invalid format
			return false; // Indicate an error
		}
	}

	return false; // Invalid header format
}

#define PPV2_VERSION_COMMAND_PROXY 0x21
#define PPV2_FAMILY_IPV4_TCP 0x11
#define PPV2_FAMILY_IPV4_UDP 0x12
#define PPV2_FAMILY_IPV6_TCP 0x21
#define PPV2_FAMILY_IPV6_UDP 0x22

////////////////////////////////////////////////////////////////
//                  Proxy Protocol Version 2
////////////////////////////////////////////////////////////////
/*
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   PPv2 Signature (12 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version command|Protocol family|    Remaining Length           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          IPv4 (12 bytes) or IPv6 Address (36 bytes)           |
|                           ...                                 |
|                           ...                                 |
|                           ...                                 |
|                           ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// Taken from https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
typedef struct {
	uint8_t sig[12];  /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
	uint8_t ver_cmd;  /* protocol version and command */
	uint8_t fam;      /* protocol family and address */
	uint16_t len;     /* number of following bytes part of the header */
} ppv2_header_t;

typedef union {
	struct {        /* for TCP/UDP over IPv4, len = 12 */
		uint32_t src_addr;
		uint32_t dst_addr;
		uint16_t src_port;
		uint16_t dst_port;
	} ipv4_addr;
	struct {        /* for TCP/UDP over IPv6, len = 36 */
		uint8_t  src_addr[16];
		uint8_t  dst_addr[16];
		uint16_t src_port;
		uint16_t dst_port;
	} ipv6_addr;
} proxy_addr_t;

int ProxyProtocolInfo::parseProxyProtocolV2Header(const char* packet, size_t packet_length) {
	// Verify that the packet length is sufficient for a PPv2 header
	if (packet_length < PPV2_HEADER_LENGTH) {
		return -1;
	}

	ppv2_header_t *ppv2_header = (ppv2_header_t *) packet;

	// Verify that the header's signature matches the PPv2 protocol signature
	if (memcmp(ppv2_header->sig, PPV2_SIGNATURE, sizeof(ppv2_header->sig)) != 0) {
		return -1;
	}

	// Verify that this is a version 2 PROXY command.
	// This does not handle the LOCAL command case.
	if (ppv2_header->ver_cmd != PPV2_VERSION_COMMAND_PROXY) {
		return -1;
	}

	uint8_t family = ppv2_header->fam;
	uint16_t remaining_length = ntohs(ppv2_header->len);

	// Verify length of packet is longer than header and remaining length
	uint16_t total_length = PPV2_HEADER_LENGTH + remaining_length;
	if (packet_length < total_length) {
		return -1;
	}

	// Point the address immediately after the fixed PPv2 header
	packet += PPV2_HEADER_LENGTH;
	proxy_addr_t *proxy_addr = (proxy_addr_t *) packet;
	// Only IPv4 and IPv6 are handled here.
	// AF_UNSPEC and AF_UNIX are not handled.
	if (family == PPV2_FAMILY_IPV4_TCP || family == PPV2_FAMILY_IPV4_UDP) {
		// Verify address length is sufficient for IPv4
		if (remaining_length < sizeof(proxy_addr->ipv4_addr)) {
			return -1;
		}

		// Parse IPv4 address
		if (!inet_ntop(AF_INET, &proxy_addr->ipv4_addr.src_addr, source_address, sizeof(source_address))) {
			return -1;
		}
		if (!inet_ntop(AF_INET, &proxy_addr->ipv4_addr.dst_addr, destination_address, sizeof(destination_address))) {
			return -1;
		}
		source_port = ntohs(proxy_addr->ipv4_addr.src_port);
		destination_port = ntohs(proxy_addr->ipv4_addr.dst_port);
	} else if (family == PPV2_FAMILY_IPV6_TCP || family == PPV2_FAMILY_IPV6_UDP) {
		// Verify address length is sufficient for IPv6
		if (remaining_length < sizeof(proxy_addr->ipv6_addr)) {
			return -1;
		}

		// Parse IPv6 address
		if (!inet_ntop(AF_INET6, &proxy_addr->ipv6_addr.src_addr, source_address, sizeof(source_address))) {
			return -1;
		}
		if (!inet_ntop(AF_INET6, &proxy_addr->ipv6_addr.dst_addr, destination_address, sizeof(destination_address))) {
			return -1;
		}
		source_port = ntohs(proxy_addr->ipv6_addr.src_port);
		destination_port = ntohs(proxy_addr->ipv6_addr.dst_port);
	} else {
		return -1;
	}

	// TLVs are not handled

	return total_length;
}

/**
 * Checks if a client address is within a specified subnet.
 *
 * @param client_addr Pointer to the client's sockaddr structure (either sockaddr_in or sockaddr_in6).
 * @param subnet_mask The subnet in CIDR notation (e.g., "192.168.1.0/24" for IPv4 or "2001:db8::/32" for IPv6).
 * @return True if the client address is within the specified subnet, otherwise false.
 */
bool ProxyProtocolInfo::is_in_network(const struct sockaddr* client_addr, const std::string& subnet_mask) {
	// Determine address family (IPv4 or IPv6)
	int family = client_addr->sa_family;

	// Parse the subnet and mask
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} subnet_addr;

	uint8_t mask = 0;
	char addr_str[INET6_ADDRSTRLEN];

	if (family == AF_INET) {
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Parsing IPv4 subnet mask" << std::endl;
		// Parse the IPv4 subnet mask using sscanf
		if (sscanf(subnet_mask.c_str(), "%[^/]/%hhu", addr_str, &mask) != 2) {
			if (DEBUG_ProxyProtocolInfo==true)
				std::cout << "Invalid subnet/mask format" << std::endl;
			return false; // Invalid subnet/mask format
		}
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Subnet: " << addr_str << ", Mask: " << (int)mask << std::endl;
		// Convert the parsed subnet address to binary format
		if (inet_pton(AF_INET, addr_str, &subnet_addr.v4) != 1) {
			if (DEBUG_ProxyProtocolInfo==true)
				std::cout << "Invalid IPv4 address" << std::endl;
			return false; // Invalid IPv4 address
		}
	} else if (family == AF_INET6) {
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Parsing IPv6 subnet mask" << std::endl;
		// Parse the IPv6 subnet mask using sscanf
		if (sscanf(subnet_mask.c_str(), "%[^/]/%hhu", addr_str, &mask) != 2) {
			if (DEBUG_ProxyProtocolInfo==true)
				std::cout << "Invalid subnet/mask format" << std::endl;
			return false; // Invalid subnet/mask format
		}
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Subnet: " << addr_str << ", Mask: " << (int)mask << std::endl;
		// Convert the parsed subnet address to binary format
		if (inet_pton(AF_INET6, addr_str, &subnet_addr.v6) != 1) {
			if (DEBUG_ProxyProtocolInfo==true)
				std::cout << "Invalid IPv6 address" << std::endl;
			return false; // Invalid IPv6 address
		}
	} else {
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Unsupported address family" << std::endl;
		return false; // Unsupported address family
	}

	uint8_t network_addr[16] = {0};
	if (family == AF_INET) {
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Calculating network address for IPv4" << std::endl;
		// Calculate the network address for IPv4
		uint32_t subnet = ntohl(subnet_addr.v4.s_addr) & (0xFFFFFFFF << (32 - mask));
		subnet = htonl(subnet);
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Subnet address (masked): " << inet_ntoa(*(struct in_addr*)&subnet) << std::endl;
		// Copy the masked subnet address into the network_addr array
		memcpy(network_addr, &subnet, sizeof(subnet));
	} else if (family == AF_INET6) {
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Calculating network address for IPv6" << std::endl;
		// Calculate the network address for IPv6
		uint8_t* addr = subnet_addr.v6.s6_addr;
		int bits_left = mask;
		for (int i = 0; i < 16; ++i) {
			if (bits_left >= 8) {
				network_addr[i] = addr[i];
				bits_left -= 8;
			} else if (bits_left > 0) {
				network_addr[i] = addr[i] & (0xFF << (8 - bits_left));
				bits_left = 0;
			} else {
				network_addr[i] = 0;
			}
		}
		if (DEBUG_ProxyProtocolInfo==true) {
			char network_addr_str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, network_addr, network_addr_str, INET6_ADDRSTRLEN);
			std::cout << "Subnet address (masked): " << network_addr_str << std::endl;
		}
	}

	uint8_t client_addr_int[16] = {0};
	if (family == AF_INET) {
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Extracting client address for IPv4" << std::endl;
		// Extract the client address for IPv4
		uint32_t client = ntohl(((struct sockaddr_in*)client_addr)->sin_addr.s_addr);
		client = htonl(client);
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Client address: " << inet_ntoa(*(struct in_addr*)&client) << std::endl;
		// Copy the client address into the client_addr_int array
		memcpy(client_addr_int, &client, sizeof(client));
	} else if (family == AF_INET6) {
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Extracting client address for IPv6" << std::endl;
		// Copy the client address into the client_addr_int array
		memcpy(client_addr_int, ((struct sockaddr_in6*)client_addr)->sin6_addr.s6_addr, 16);
		if (DEBUG_ProxyProtocolInfo==true) {
			char client_addr_str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, client_addr_int, client_addr_str, INET6_ADDRSTRLEN);
			std::cout << "Client address: " << client_addr_str << std::endl;
		}
	}

	// Calculate the number of bytes to compare based on the mask
	int bytes_to_compare = mask / 8;
	int remaining_bits = mask % 8;

	if (DEBUG_ProxyProtocolInfo==true)
		std::cout << "Comparing full bytes covered by the mask" << std::endl;
	// Compare the full bytes covered by the mask
	if (memcmp(network_addr, client_addr_int, bytes_to_compare) != 0) {
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Address does not match in full byte comparison" << std::endl;
		return false;
	}

	if (remaining_bits > 0) {
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Comparing remaining bits" << std::endl;
		// Compare the remaining bits covered by the mask
		uint8_t mask_byte = 0xFF << (8 - remaining_bits);
		if ((network_addr[bytes_to_compare] & mask_byte) != (client_addr_int[bytes_to_compare] & mask_byte)) {
			if (DEBUG_ProxyProtocolInfo==true)
				std::cout << "Address does not match in remaining bits comparison" << std::endl;
			return false; // Addresses don't match in remaining bits comparison
		}
	}

	if (DEBUG_ProxyProtocolInfo==true)
		std::cout << "Client address is within the subnet" << std::endl;
	return true; // Client address is within the subnet
}

bool ProxyProtocolInfo::is_client_in_any_subnet(const struct sockaddr* client_addr, const char* subnet_list) {
	// Create a copy of the subnet list to avoid modifying the original string
	char* subnet_list_copy = new char[strlen(subnet_list) + 1];
	strcpy(subnet_list_copy, subnet_list);

	char* token = strtok(subnet_list_copy, ","); // Get the first subnet
	while (token != NULL) {
		if (DEBUG_ProxyProtocolInfo==true)
			std::cout << "Checking subnet: " << token << std::endl;
		if (is_in_network(client_addr, token)) {
			if (DEBUG_ProxyProtocolInfo==true)
				std::cout << "Client is in subnet: " << token << std::endl;
			delete[] subnet_list_copy; // Deallocate the copy
			return true; // Client is in at least one subnet
		}
		token = strtok(NULL, ","); // Get the next subnet
	}
	delete[] subnet_list_copy; // Deallocate the copy
	return false; // Client is not in any of the subnets
}

#ifdef DEBUG

// Helper function to create an IPv4 sockaddr structure
sockaddr_in ProxyProtocolInfo::create_ipv4_addr(const std::string& ip) {
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
	return addr;
}

// Helper function to create an IPv6 sockaddr structure
sockaddr_in6 ProxyProtocolInfo::create_ipv6_addr(const std::string& ip) {
	sockaddr_in6 addr;
	addr.sin6_family = AF_INET6;
	inet_pton(AF_INET6, ip.c_str(), &addr.sin6_addr);
	return addr;
}

// Test cases for the is_in_network function
void ProxyProtocolInfo::run_tests() {
	// IPv4 Tests
	{
		sockaddr_in client_addr = create_ipv4_addr("192.168.1.10");
		assert(is_in_network((sockaddr*)&client_addr, "192.168.1.0/24") == true);
		assert(is_in_network((sockaddr*)&client_addr, "192.168.1.0/25") == true);
		assert(is_in_network((sockaddr*)&client_addr, "192.168.1.0/26") == true);
		assert(is_in_network((sockaddr*)&client_addr, "192.168.2.0/24") == false);
		assert(is_in_network((sockaddr*)&client_addr, "192.168.0.0/16") == true);
		assert(is_in_network((sockaddr*)&client_addr, "192.168.1.10/32") == true);
		assert(is_in_network((sockaddr*)&client_addr, "192.168.1.11/32") == false);
	}

	// IPv6 Tests
	{
		sockaddr_in6 client_addr = create_ipv6_addr("2001:db8::1");
		assert(is_in_network((sockaddr*)&client_addr, "2001:db8::/32") == true);
		assert(is_in_network((sockaddr*)&client_addr, "2001:db8::/48") == true);
		assert(is_in_network((sockaddr*)&client_addr, "2001:db8::/64") == true);
		assert(is_in_network((sockaddr*)&client_addr, "2001:db8:0:1::/64") == false);
		assert(is_in_network((sockaddr*)&client_addr, "2001:db8::1/128") == true);
		assert(is_in_network((sockaddr*)&client_addr, "2001:db8::2/128") == false);
	}
	{
		sockaddr_in6 client_addr = create_ipv6_addr("2001:db8:0:1::1");
		assert(is_in_network((sockaddr*)&client_addr, "2001:db8:0:1::/64") == true);
		assert(is_in_network((sockaddr*)&client_addr, "2001:db8::/32") == true);
		assert(is_in_network((sockaddr*)&client_addr, "2001:db8:0:2::/64") == false);
		assert(is_in_network((sockaddr*)&client_addr, "2001:db8::1/128") == false);
		assert(is_in_network((sockaddr*)&client_addr, "2001:db8:0:1::1/128") == true);
	}
	{
		struct sockaddr_in client_addr = create_ipv4_addr("172.16.14.1");
		assert(is_client_in_any_subnet((sockaddr*)&client_addr, "172.16.0.0/16,192.168.1.0/24") == true);
		assert(is_client_in_any_subnet((sockaddr*)&client_addr, "172.17.0.0/16,192.168.1.0/24") == false);
		assert(is_client_in_any_subnet((sockaddr*)&client_addr, "2001:db8:0:1::/64,172.16.0.0/16,192.168.1.0/24") == true);
		assert(is_client_in_any_subnet((sockaddr*)&client_addr, "2001:db8:0:1::/64,172.17.0.0/16,192.168.1.0/24") == false);
	}
	{
		sockaddr_in6 client_addr = create_ipv6_addr("2001:db8:0:1::1");
		assert(is_client_in_any_subnet((sockaddr*)&client_addr, "2001:db8:0:1::/64,2001:db8:0:2::/64") == true);
		assert(is_client_in_any_subnet((sockaddr*)&client_addr, "2001:db8:0:2::/64,2001:db8:0:1::/64") == true);
		assert(is_client_in_any_subnet((sockaddr*)&client_addr, "2001:db8:0:1::/64,172.16.0.0/16") == true);
		assert(is_client_in_any_subnet((sockaddr*)&client_addr, "172.16.0.0/16,2001:db8:0:1::/64") == true);
		assert(is_client_in_any_subnet((sockaddr*)&client_addr, "2001:db8:0:2::/64,172.16.0.0/16") == false);
		assert(is_client_in_any_subnet((sockaddr*)&client_addr, "172.16.0.0/16,2001:db8:0:2::/64") == false);
	}
	{
		const char* subnet_list1 = "192.168.1.0/24,10.0.0.0/8,2001:0:200::/32";
		const char* subnet_list2 = "192.168.1.0/24,10.0.0.0/not_a_mask,2001:0:200::/32";
		const char* subnet_list3 = "192.168.1.0/24,invalid_ipv4,2001:0:200::/32";
		const char* subnet_list4 = "";

		assert(is_valid_subnet_list(subnet_list1) == true);
		assert(is_valid_subnet_list(subnet_list2) == false);
		assert(is_valid_subnet_list(subnet_list3) == false);
		assert(is_valid_subnet_list(subnet_list4) == false);
	}
}

#endif // DEBUG

bool ProxyProtocolInfo::is_valid_subnet_list(const char* subnet_list) {
	// Check if the string is empty
	if (subnet_list == nullptr || *subnet_list == '\0') {
		return false; // Empty string is not a valid subnet list
	}

	// Create a copy of the string to avoid modifying the original
	char* subnet_list_copy = new char[strlen(subnet_list) + 1];
	strcpy(subnet_list_copy, subnet_list);

	// Tokenize the string using ',' as the delimiter
	char* token = strtok(subnet_list_copy, ",");
	while (token != NULL) {
		// Check if the token is a valid subnet
		if (!is_valid_subnet(token)) {
			delete[] subnet_list_copy; // Deallocate the copy
			return false; // Invalid subnet found
		}
		token = strtok(NULL, ","); // Get the next token
	}

	delete[] subnet_list_copy; // Deallocate the copy
	return true; // All subnets are valid
}


// Helper function to verify a single subnet
bool ProxyProtocolInfo::is_valid_subnet(const char* subnet) {
	// Check if the subnet is empty
	if (subnet == NULL || *subnet == '\0') {
		return false; // Empty subnet is not valid
	}

	// Check if the subnet contains a '/' character (CIDR notation)
	if (strchr(subnet, '/') == NULL) {
		return false; // Missing '/' character in subnet
	}

	// Check if the subnet is a valid IPv4 or IPv6 address
	int family = AF_INET; // Default to IPv4
	if (strchr(subnet, ':') != NULL) {
		family = AF_INET6; // IPv6 if a colon is found
	}

	char addr_str[INET6_ADDRSTRLEN];
	uint8_t mask = 0;

	if (family == AF_INET) {
		// Parse IPv4 subnet using sscanf
		if (sscanf(subnet, "%[^/]/%hhu", addr_str, &mask) != 2) {
			return false; // Invalid IPv4 subnet format
		} 
	} else if (family == AF_INET6) {
		// Parse IPv6 subnet using sscanf
		if (sscanf(subnet, "%[^/]/%hhu", addr_str, &mask) != 2) {
			return false; // Invalid IPv6 subnet format
		}
	} else {
		return false; // Unsupported address family
	}

	// Validate the mask value
	if (mask < 0 || mask > 128) {
		return false; // Invalid mask value
	}

	// Check if the address is valid using inet_pton
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} addr; // Create a union to hold both IPv4 and IPv6 addresses
	if (inet_pton(family, addr_str, &addr) != 1) { 
		return false; // Invalid IP address
	}

	return true; // Valid subnet
}
