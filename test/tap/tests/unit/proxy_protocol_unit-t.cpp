/**
 * @file proxy_protocol_unit-t.cpp
 * @brief Unit tests for ProxyProtocolInfo: header parsing, subnet validation,
 *        and network matching.
 *
 * Tests the public methods of ProxyProtocolInfo:
 *   - parseProxyProtocolHeader()
 *   - is_valid_subnet() / is_valid_subnet_list()
 *   - is_in_network()
 *   - is_client_in_any_subnet()
 *
 * These functions have no global state dependencies and are linked
 * from libproxysql.a via the unit test harness.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "proxy_protocol_info.h"

#include <cstring>
#include <arpa/inet.h>

// Helper: create a sockaddr_in for IPv4 testing
static struct sockaddr_in make_ipv4(const char *ip) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &addr.sin_addr);
    return addr;
}

// Helper: create a sockaddr_in6 for IPv6 testing
static struct sockaddr_in6 make_ipv6(const char *ip) {
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip, &addr.sin6_addr);
    return addr;
}

// ============================================================
// parseProxyProtocolHeader() tests
// ============================================================

static void test_parse_valid_tcp4() {
    const char *header = "PROXY TCP4 192.168.1.1 10.0.0.1 12345 3306\r\n";
    ProxyProtocolInfo ppi;
    bool result = ppi.parseProxyProtocolHeader(header, strlen(header));
    ok(result == true, "parseProxyProtocol: valid TCP4 header parsed");
}

static void test_parse_valid_tcp6() {
    const char *header = "PROXY TCP6 ::1 ::1 12345 3306\r\n";
    ProxyProtocolInfo ppi;
    bool result = ppi.parseProxyProtocolHeader(header, strlen(header));
    ok(result == true, "parseProxyProtocol: valid TCP6 header parsed");
}

static void test_parse_unknown() {
    // GHSA-gw94-85m2-x8v2: PP1 UNKNOWN frames signal that the upstream
    // proxy does not know the client identity. The receiver MUST ignore
    // any trailing fields. The parser returns false (so the caller does
    // not override addr.addr) and sets header_was_unknown=true so the
    // caller can distinguish "spec-compliant skip" from "malformed".
    const char *header = "PROXY UNKNOWN\r\n";
    ProxyProtocolInfo ppi;
    bool result = ppi.parseProxyProtocolHeader(header, strlen(header));
    ok(result == false, "parseProxyProtocol: UNKNOWN returns false");
    ok(ppi.header_was_unknown == true, "parseProxyProtocol: UNKNOWN sets header_was_unknown");
    ok(ppi.source_address[0] == '\0', "parseProxyProtocol: UNKNOWN leaves source_address empty");
}

static void test_parse_unknown_spoof_payload() {
    // GHSA-gw94-85m2-x8v2 PoC payload: peer claims source IP 10.0.0.5
    // after the UNKNOWN token. The parser MUST ignore the trailing
    // address fields and NOT write "10.0.0.5" anywhere.
    const char *header = "PROXY UNKNOWN 10.0.0.5 1.2.3.4 12345 3306\r\n";
    ProxyProtocolInfo ppi;
    bool result = ppi.parseProxyProtocolHeader(header, strlen(header));
    ok(result == false, "parseProxyProtocol: UNKNOWN+spoofed addresses returns false");
    ok(ppi.header_was_unknown == true, "parseProxyProtocol: UNKNOWN+spoofed sets header_was_unknown");
    ok(strcmp(ppi.source_address, "10.0.0.5") != 0,
       "parseProxyProtocol: UNKNOWN+spoofed source_address is NOT '10.0.0.5' (security: forged IP not parsed)");
    ok(ppi.source_address[0] == '\0',
       "parseProxyProtocol: UNKNOWN+spoofed source_address is empty");
}

static void test_parse_unknown_bogus_token() {
    // The byte after "UNKNOWN" must be ' ' or '\r'. A token like
    // "UNKNOWNFOO" must be rejected outright (not treated as UNKNOWN).
    const char *header = "PROXY UNKNOWNFOO 10.0.0.5 1.2.3.4 12345 3306\r\n";
    ProxyProtocolInfo ppi;
    bool result = ppi.parseProxyProtocolHeader(header, strlen(header));
    ok(result == false, "parseProxyProtocol: UNKNOWNFOO returns false");
    ok(ppi.header_was_unknown == false,
       "parseProxyProtocol: UNKNOWNFOO does NOT set header_was_unknown");
}

static void test_parse_tcp4_prefix_match_rejected() {
    // GHSA-gw94-85m2-x8v2 (secondary): the previous 4-byte memcmp let
    // "TCP4xyz" through. The protocol token must be followed by ' '.
    const char *header = "PROXY TCP4xyz 10.0.0.5 1.2.3.4 12345 3306\r\n";
    ProxyProtocolInfo ppi;
    bool result = ppi.parseProxyProtocolHeader(header, strlen(header));
    ok(result == false, "parseProxyProtocol: 'TCP4xyz' bogus protocol token rejected");
    ok(strcmp(ppi.source_address, "10.0.0.5") != 0,
       "parseProxyProtocol: 'TCP4xyz' did not write 10.0.0.5 into source_address");
}

static void test_parse_tcp4_valid_source() {
    // Sanity check: legitimate TCP4 still parses source_address correctly.
    const char *header = "PROXY TCP4 192.168.1.1 10.0.0.1 12345 3306\r\n";
    ProxyProtocolInfo ppi;
    bool result = ppi.parseProxyProtocolHeader(header, strlen(header));
    ok(result == true, "parseProxyProtocol: TCP4 returns true");
    ok(strcmp(ppi.source_address, "192.168.1.1") == 0,
       "parseProxyProtocol: TCP4 source_address parsed as 192.168.1.1");
    ok(ppi.header_was_unknown == false,
       "parseProxyProtocol: TCP4 does NOT set header_was_unknown");
}

static void test_parse_invalid_prefix() {
    const char *header = "NOTPROXY TCP4 1.2.3.4 5.6.7.8 100 200\r\n";
    ProxyProtocolInfo ppi;
    bool result = ppi.parseProxyProtocolHeader(header, strlen(header));
    ok(result == false, "parseProxyProtocol: invalid prefix rejected");
}

static void test_parse_empty() {
    ProxyProtocolInfo ppi;
    bool result = ppi.parseProxyProtocolHeader("", 0);
    ok(result == false, "parseProxyProtocol: empty packet rejected");
}

// ============================================================
// is_valid_subnet() / is_valid_subnet_list() tests
// ============================================================

static void test_valid_subnet_ipv4() {
    ProxyProtocolInfo ppi;
    ok(ppi.is_valid_subnet("192.168.1.0/24") == true, "is_valid_subnet: 192.168.1.0/24 valid");
    ok(ppi.is_valid_subnet("10.0.0.0/8") == true, "is_valid_subnet: 10.0.0.0/8 valid");
    ok(ppi.is_valid_subnet("0.0.0.0/0") == true, "is_valid_subnet: 0.0.0.0/0 valid (any)");
}

static void test_valid_subnet_ipv6() {
    ProxyProtocolInfo ppi;
    ok(ppi.is_valid_subnet("::1/128") == true, "is_valid_subnet: ::1/128 valid");
    ok(ppi.is_valid_subnet("fe80::/10") == true, "is_valid_subnet: fe80::/10 valid");
}

static void test_invalid_subnet() {
    ProxyProtocolInfo ppi;
    ok(ppi.is_valid_subnet("not_an_ip/24") == false, "is_valid_subnet: garbage rejected");
    ok(ppi.is_valid_subnet("192.168.1.0") == false, "is_valid_subnet: missing /prefix rejected");
}

static void test_valid_subnet_list() {
    ProxyProtocolInfo ppi;
    ok(ppi.is_valid_subnet_list("10.0.0.0/8,192.168.1.0/24") == true,
       "is_valid_subnet_list: two subnets valid");
    ok(ppi.is_valid_subnet_list("10.0.0.0/8") == true,
       "is_valid_subnet_list: single subnet valid");
}

// ============================================================
// is_in_network() tests
// ============================================================

static void test_ipv4_in_subnet() {
    ProxyProtocolInfo ppi;
    auto addr = make_ipv4("192.168.1.100");
    ok(ppi.is_in_network((struct sockaddr *)&addr, "192.168.1.0/24") == true,
       "is_in_network: 192.168.1.100 is in 192.168.1.0/24");
}

static void test_ipv4_not_in_subnet() {
    ProxyProtocolInfo ppi;
    auto addr = make_ipv4("10.0.0.1");
    ok(ppi.is_in_network((struct sockaddr *)&addr, "192.168.1.0/24") == false,
       "is_in_network: 10.0.0.1 is NOT in 192.168.1.0/24");
}

static void test_ipv4_any_subnet() {
    ProxyProtocolInfo ppi;
    auto addr = make_ipv4("1.2.3.4");
    ok(ppi.is_in_network((struct sockaddr *)&addr, "0.0.0.0/0") == true,
       "is_in_network: any address matches 0.0.0.0/0");
}

static void test_ipv6_in_subnet() {
    ProxyProtocolInfo ppi;
    auto addr = make_ipv6("fe80::1");
    ok(ppi.is_in_network((struct sockaddr *)&addr, "fe80::/10") == true,
       "is_in_network: fe80::1 is in fe80::/10");
}

static void test_ipv4_host_mask() {
    ProxyProtocolInfo ppi;
    auto addr = make_ipv4("10.0.0.1");
    ok(ppi.is_in_network((struct sockaddr *)&addr, "10.0.0.1/32") == true,
       "is_in_network: exact match with /32");
    ok(ppi.is_in_network((struct sockaddr *)&addr, "10.0.0.2/32") == false,
       "is_in_network: /32 rejects different host");
}

// ============================================================
// is_client_in_any_subnet() — multi-subnet matching
// ============================================================

static void test_client_in_any_subnet() {
    ProxyProtocolInfo ppi;
    auto addr = make_ipv4("192.168.1.50");
    ok(ppi.is_client_in_any_subnet((struct sockaddr *)&addr, "10.0.0.0/8,192.168.1.0/24") == true,
       "is_client_in_any_subnet: matches second subnet");
}

static void test_client_in_no_subnet() {
    ProxyProtocolInfo ppi;
    auto addr = make_ipv4("172.16.0.1");
    ok(ppi.is_client_in_any_subnet((struct sockaddr *)&addr, "10.0.0.0/8,192.168.1.0/24") == false,
       "is_client_in_any_subnet: matches no subnet");
}

int main() {
    plan(35);
    test_init_minimal();

    test_parse_valid_tcp4();                  // 1
    test_parse_valid_tcp6();                  // 1
    test_parse_unknown();                     // 3 (GHSA-gw94-85m2-x8v2)
    test_parse_unknown_spoof_payload();       // 4 (GHSA-gw94-85m2-x8v2)
    test_parse_unknown_bogus_token();         // 2 (GHSA-gw94-85m2-x8v2)
    test_parse_tcp4_prefix_match_rejected();  // 2 (GHSA-gw94-85m2-x8v2)
    test_parse_tcp4_valid_source();           // 3
    test_parse_invalid_prefix();              // 1
    test_parse_empty();                       // 1
    test_valid_subnet_ipv4();                 // 3
    test_valid_subnet_ipv6();                 // 2
    test_invalid_subnet();                    // 2
    test_valid_subnet_list();                 // 2
    test_ipv4_in_subnet();                    // 1
    test_ipv4_not_in_subnet();                // 1
    test_ipv4_any_subnet();                   // 1
    test_ipv6_in_subnet();                    // 1
    test_ipv4_host_mask();                    // 2
    test_client_in_any_subnet();              // 1
    test_client_in_no_subnet();               // 1

    test_cleanup_minimal();
    return exit_status();
}
