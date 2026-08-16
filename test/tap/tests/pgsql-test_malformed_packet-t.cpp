/**
 * @file pgsql-test_malformed_packet-t.cpp
 * @brief Validates ProxySQL's PostgreSQL protocol handling stability and ensures it does not crash
 *        when subjected to multiple malformed packets on its admin and backend connections.
 *
 * This test has two phases:
 *
 * Phase 1: Malformed packets BEFORE authentication
 * - Sends various malformed PostgreSQL protocol packets prior to completing authentication
 * - Verifies that ProxySQL properly rejects malformed packets without crashing
 *
 * Phase 2: Malformed packets AFTER authentication
 * - Establishes authenticated connections to BACKEND and ADMIN interfaces
 * - Sends malformed packets (Query, Parse, Bind, Execute, etc.) after successful authentication
 * - Verifies that ProxySQL handles malformed data gracefully and remains operational
 *
 * Verification criteria for both phases:
 * 1. ProxySQL does not crash when receiving malformed packets
 * 2. ProxySQL properly closes the connection or sends error responses
 * 3. ProxySQL remains operational for legitimate connections after test completion
 *
 * Test cases cover:
 * - Truncated startup packets
 * - Invalid length fields (zero, too large, mismatched, integer overflow)
 * - Malformed SSL requests and cancel requests
 * - Invalid packet types before startup
 * - Malformed SASL authentication data
 * - Query packets with missing null terminators (Phase 2)
 * - Extended query protocol malformed packets (Parse, Bind, Execute, Close, Describe) (Phase 2)
 * - Copy protocol malformed packets (Phase 2)
 */

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <cstring>
#include <vector>
#include <string>
#include <sstream>

#include "libpq-fe.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

constexpr size_t BUFFER_SIZE = 4096;
constexpr int TIMEOUT_SEC = 5;

// PostgreSQL protocol constants
constexpr uint32_t PG_PROTOCOL_VERSION = 196608;  // 3.0 (0x00030000)
constexpr uint32_t PG_SSL_REQUEST_CODE = 80877103;  // (1234 << 16) | 5679
constexpr uint32_t PG_CANCEL_REQUEST_CODE = 80877102;  // (1234 << 16) | 5678
constexpr uint32_t PG_GSS_ENCRYPT_CODE = 80877104;  // (1234 << 16) | 5680

// Forward declarations for helper functions
bool send_exact(int sock, const void* buf, size_t len);
bool recv_exact(int sock, void* buf, size_t len);

#define REPORT_ERROR_AND_EXIT(fmt, ...) \
    do { \
        fprintf(stderr, "File %s, line %d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        close(sock); \
        return; \
    } while (0)

typedef enum {
    BACKEND = 0,
    ADMIN
} Connection_type_t;

/**
 * @brief Create a raw TCP socket connection to the specified host and port
 *
 * Supports both IP addresses (IPv4 and IPv6) and domain names.
 * Uses getaddrinfo() for name resolution.
 */
int create_raw_connection(const std::string& host, int port) {
    struct addrinfo hints{};
    struct addrinfo* result = nullptr;
    struct addrinfo* rp = nullptr;
    int sock = -1;

    // Prepare hints for getaddrinfo
    hints.ai_family = AF_UNSPEC;      // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;  // TCP socket

    // Convert port to string for getaddrinfo
    std::string port_str = std::to_string(port);

    // Resolve the hostname
    int gai_err = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (gai_err != 0) {
        fprintf(stderr, "Failed to resolve host '%s': %s\n",
                host.c_str(), gai_strerror(gai_err));
        return -1;
    }

    // Try each address returned by getaddrinfo until we successfully connect
    for (rp = result; rp != nullptr; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) {
            continue;  // Try next address
        }

        // Set socket timeout
        struct timeval timeout;
        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_usec = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            fprintf(stderr, "Failed to set socket timeout: %s\n", strerror(errno));
            close(sock);
            sock = -1;
            continue;
        }

        // Set TCP_NODELAY for immediate packet sending
        int flag = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

        // Attempt to connect
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            // Success!
            break;
        }

        // Connection failed, try next address
        close(sock);
        sock = -1;
    }

    freeaddrinfo(result);

    if (sock < 0) {
        fprintf(stderr, "Connection failed to %s:%d\n", host.c_str(), port);
        return -1;
    }

    return sock;
}

/**
 * @brief Send a malformed packet and verify ProxySQL handles it gracefully
 *
 * Valid outcomes:
 * - Connection closed (bytes_received <= 0): ProxySQL rejected the packet immediately
 * - Error response received (bytes_received > 0): ProxySQL sent an error packet (also valid)
 * - Both are acceptable - what matters is ProxySQL doesn't crash
 */
void test_malformed_packet(const std::string& test_name,
                          const std::string& host,
                          int port,
                          const std::vector<uint8_t>& data) {

    int sock = create_raw_connection(host, port);
    if (sock < 0) {
        ok(0, "%s: Failed to create connection", test_name.c_str());
        return;
    }

    // Send the malformed data
    if (!send_exact(sock, data.data(), data.size())) {
        close(sock);
        ok(0, "%s: Failed to send data", test_name.c_str());
        return;
    }

    // Try to receive response
    std::vector<char> buffer(BUFFER_SIZE);
    ssize_t bytes_received = recv(sock, buffer.data(), buffer.size(), 0);

    // Valid outcomes:
    // - Connection closed (bytes_received == 0): ProxySQL rejected/closed connection
    // - Timeout (bytes_received < 0 with EAGAIN/EWOULDBLOCK): No response within timeout
    // - Error response (bytes_received > 0 && buffer[0] == 'E'): ProxySQL sent error
    bool connection_closed = (bytes_received == 0);
    bool timeout = (bytes_received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    bool got_error_response = (bytes_received > 0 && buffer[0] == 'E');
    bool handled_gracefully = connection_closed || timeout || got_error_response;

    ok(handled_gracefully, "%s: Malformed packet handled (closed=%d, timeout=%d, error=%d)",
       test_name.c_str(), (int)connection_closed, (int)timeout, (int)got_error_response);

    close(sock);
}

/**
 * @brief Verify ProxySQL is still operational after malformed packet test
 */
bool verify_proxysql_alive(const CommandLine& cl, Connection_type_t conn_type) {
    std::stringstream ss;
    if (conn_type == BACKEND) {
        ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port;
        ss << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password;
    } else {
        // Admin interface - use MySQL admin credentials on PostgreSQL admin port
        ss << "host=" << cl.admin_host << " port=" << cl.pgsql_admin_port;
        ss << " user=" << cl.admin_username << " password=" << cl.admin_password;
    }
    ss << " sslmode=disable";

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        PQfinish(conn);
        return false;
    }

    // Try a simple query
    PGresult* res = PQexec(conn, "SELECT 1");
    bool success = (PQresultStatus(res) == PGRES_TUPLES_OK);
    PQclear(res);
    PQfinish(conn);

    return success;
}

/**
 * @brief Build a valid startup packet
 */
std::vector<uint8_t> build_startup_packet(const std::vector<std::pair<std::string, std::string>>& params) {
    std::vector<uint8_t> packet;

    // Reserve space for length (4 bytes)
    packet.resize(4);

    // Protocol version (4 bytes, big-endian)
    packet.push_back((PG_PROTOCOL_VERSION >> 24) & 0xFF);
    packet.push_back((PG_PROTOCOL_VERSION >> 16) & 0xFF);
    packet.push_back((PG_PROTOCOL_VERSION >> 8) & 0xFF);
    packet.push_back(PG_PROTOCOL_VERSION & 0xFF);

    // Parameters (name\0value\0)
    for (const auto& [name, value] : params) {
        for (char c : name) packet.push_back(c);
        packet.push_back(0);
        for (char c : value) packet.push_back(c);
        packet.push_back(0);
    }

    // Null terminator
    packet.push_back(0);

    // Update length
    uint32_t len = packet.size();
    packet[0] = (len >> 24) & 0xFF;
    packet[1] = (len >> 16) & 0xFF;
    packet[2] = (len >> 8) & 0xFF;
    packet[3] = len & 0xFF;

    return packet;
}

/**
 * @brief Build SSL request packet
 */
std::vector<uint8_t> build_ssl_request_packet() {
    std::vector<uint8_t> packet(8);

    // Length
    packet[0] = 0;
    packet[1] = 0;
    packet[2] = 0;
    packet[3] = 8;

    // SSL request code
    packet[4] = (PG_SSL_REQUEST_CODE >> 24) & 0xFF;
    packet[5] = (PG_SSL_REQUEST_CODE >> 16) & 0xFF;
    packet[6] = (PG_SSL_REQUEST_CODE >> 8) & 0xFF;
    packet[7] = PG_SSL_REQUEST_CODE & 0xFF;

    return packet;
}

/**
 * @brief Build cancel request packet
 */
std::vector<uint8_t> build_cancel_request_packet(uint32_t pid, uint32_t key) {
    std::vector<uint8_t> packet(16);

    // Length
    packet[0] = 0;
    packet[1] = 0;
    packet[2] = 0;
    packet[3] = 16;

    // Cancel request code
    packet[4] = (PG_CANCEL_REQUEST_CODE >> 24) & 0xFF;
    packet[5] = (PG_CANCEL_REQUEST_CODE >> 16) & 0xFF;
    packet[6] = (PG_CANCEL_REQUEST_CODE >> 8) & 0xFF;
    packet[7] = PG_CANCEL_REQUEST_CODE & 0xFF;

    // Process ID
    packet[8] = (pid >> 24) & 0xFF;
    packet[9] = (pid >> 16) & 0xFF;
    packet[10] = (pid >> 8) & 0xFF;
    packet[11] = pid & 0xFF;

    // Secret key
    packet[12] = (key >> 24) & 0xFF;
    packet[13] = (key >> 16) & 0xFF;
    packet[14] = (key >> 8) & 0xFF;
    packet[15] = key & 0xFF;

    return packet;
}

/**
 * @brief Build password message packet (type 'p')
 */
std::vector<uint8_t> build_password_packet(const std::string& password) {
    std::vector<uint8_t> packet;

    // Type byte
    packet.push_back('p');

    // Reserve space for length
    packet.resize(5);

    // Password (null-terminated)
    for (char c : password) packet.push_back(c);
    packet.push_back(0);

    // Update length (includes length field itself)
    uint32_t len = packet.size() - 1;  // Exclude type byte from length
    packet[1] = (len >> 24) & 0xFF;
    packet[2] = (len >> 16) & 0xFF;
    packet[3] = (len >> 8) & 0xFF;
    packet[4] = len & 0xFF;

    return packet;
}

void run_malformed_packet_tests(const std::string& host, int port, const char* target_name) {
    diag(">>> Testing malformed packets on %s (%s:%d) <<<", target_name, host.c_str(), port);

    // ==================== STARTUP PACKET TESTS ====================

    // Test 1: Empty packet
    test_malformed_packet("Empty packet", host, port, {});

    // Test 2: Truncated startup - only length, no version
    test_malformed_packet("Truncated startup (length only)", host, port,
        {0x00, 0x00, 0x00, 0x08});

    // Test 3: Startup with length = 0
    test_malformed_packet("Startup with zero length", host, port,
        {0x00, 0x00, 0x00, 0x00});

    // Test 4: Startup with length = 4 (too small, only version, no params)
    test_malformed_packet("Startup with minimal length", host, port,
        {0x00, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00});

    // Test 5: Startup with invalid protocol version (0)
    test_malformed_packet("Startup with version 0", host, port,
        {0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00});

    // Test 6: Startup with invalid protocol version (1)
    test_malformed_packet("Startup with version 1", host, port,
        {0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01});

    // Test 7: Startup with huge length (potential DoS)
    test_malformed_packet("Startup with huge length", host, port,
        {0x7F, 0xFF, 0xFF, 0xFF, 0x00, 0x03, 0x00, 0x00});

    // Test 8: Startup with length > packet size (mismatch)
    test_malformed_packet("Startup length > data", host, port,
        {0x00, 0x00, 0x00, 0x20, 0x00, 0x03, 0x00, 0x00});

    // Test 9: Startup packet without null terminator
    test_malformed_packet("Startup without terminator", host, port,
        {0x00, 0x00, 0x00, 0x0C, 0x00, 0x03, 0x00, 0x00,
         'u', 's', 'e', 'r'});

    // Test 10: Startup with user param but no value
    test_malformed_packet("Startup with user, no value", host, port,
        {0x00, 0x00, 0x00, 0x0D, 0x00, 0x03, 0x00, 0x00,
         'u', 's', 'e', 'r', 0x00});

    // Test 11: Startup with only version and null terminator
    test_malformed_packet("Startup with only version", host, port,
        {0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x00, 0x00});

    // ==================== SSL REQUEST TESTS ====================

    // Test 12: SSL request with wrong length (too short)
    test_malformed_packet("SSL request with short length", host, port,
        {0x00, 0x00, 0x00, 0x04,
         (PG_SSL_REQUEST_CODE >> 24) & 0xFF,
         (PG_SSL_REQUEST_CODE >> 16) & 0xFF,
         (PG_SSL_REQUEST_CODE >> 8) & 0xFF,
         PG_SSL_REQUEST_CODE & 0xFF});

    // Test 13: SSL request with wrong length (too long)
    test_malformed_packet("SSL request with long length", host, port,
        {0x00, 0x00, 0x00, 0x10,
         (PG_SSL_REQUEST_CODE >> 24) & 0xFF,
         (PG_SSL_REQUEST_CODE >> 16) & 0xFF,
         (PG_SSL_REQUEST_CODE >> 8) & 0xFF,
         PG_SSL_REQUEST_CODE & 0xFF});

    // Test 14: SSL request with invalid code
    test_malformed_packet("SSL request with invalid code", host, port,
        {0x00, 0x00, 0x00, 0x08,
         0xDE, 0xAD, 0xBE, 0xEF});

    // Test 15: GSS encrypt request (not supported)
    test_malformed_packet("GSS encrypt request", host, port,
        {0x00, 0x00, 0x00, 0x08,
         (PG_GSS_ENCRYPT_CODE >> 24) & 0xFF,
         (PG_GSS_ENCRYPT_CODE >> 16) & 0xFF,
         (PG_GSS_ENCRYPT_CODE >> 8) & 0xFF,
         PG_GSS_ENCRYPT_CODE & 0xFF});

    // ==================== CANCEL REQUEST TESTS ====================

    // Test 16: Cancel request with length too short (< 16)
    test_malformed_packet("Cancel request too short", host, port,
        {0x00, 0x00, 0x00, 0x0C,
         (PG_CANCEL_REQUEST_CODE >> 24) & 0xFF,
         (PG_CANCEL_REQUEST_CODE >> 16) & 0xFF,
         (PG_CANCEL_REQUEST_CODE >> 8) & 0xFF,
         PG_CANCEL_REQUEST_CODE & 0xFF,
         0x00, 0x00, 0x00, 0x01});

    // Test 17: Cancel request with length too long (> 268)
    test_malformed_packet("Cancel request too long", host, port,
        {0x00, 0x00, 0x01, 0x0D,  // 269 bytes
         (PG_CANCEL_REQUEST_CODE >> 24) & 0xFF,
         (PG_CANCEL_REQUEST_CODE >> 16) & 0xFF,
         (PG_CANCEL_REQUEST_CODE >> 8) & 0xFF,
         PG_CANCEL_REQUEST_CODE & 0xFF});

    // Test 18: Cancel request with invalid code
    test_malformed_packet("Cancel request invalid code", host, port,
        {0x00, 0x00, 0x00, 0x10,
         0xDE, 0xAD, 0xBE, 0xEF,
         0x00, 0x00, 0x00, 0x01,
         0x00, 0x00, 0x00, 0x02});

    // ==================== PACKET TYPE CONFUSION TESTS ====================

    // Test 19: Regular packet type before startup
    test_malformed_packet("Password packet before startup", host, port,
        build_password_packet("test"));

    // Test 20: Query packet before startup
    test_malformed_packet("Query packet before startup", host, port,
        {'Q', 0x00, 0x00, 0x00, 0x0D, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0x00});

    // Test 21: Unknown packet type
    test_malformed_packet("Unknown packet type (0xFF)", host, port,
        {0xFF, 0x00, 0x00, 0x00, 0x04});

    // Test 22: Packet with length overflow (negative when cast to signed)
    test_malformed_packet("Packet with length 0x80000000", host, port,
        {'Q', 0x80, 0x00, 0x00, 0x00});

    // Test 23: Special packet with non-zero second byte
    test_malformed_packet("Special packet with non-zero second byte", host, port,
        {0x00, 0x01, 0x00, 0x00, 0x00, 0x08});

    // ==================== MALFORMED DATA TESTS ====================

    // Test 24: Random binary data
    test_malformed_packet("Random binary data", host, port,
        {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
         0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0});

    // Test 25: All zeros
    test_malformed_packet("All zeros packet", host, port,
        std::vector<uint8_t>(100, 0x00));

    // Test 26: All 0xFF
    test_malformed_packet("All 0xFF packet", host, port,
        std::vector<uint8_t>(100, 0xFF));

    // Test 27: Maximum length field with minimal data
    test_malformed_packet("Max length, min data", host, port,
        {'Q', 0xFF, 0xFF, 0xFF, 0xFF});

    // Test 28: Startup v2 protocol (deprecated)
    test_malformed_packet("Startup v2 protocol", host, port,
        {0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00});
}

/**
 * @brief Build a PostgreSQL message packet with type byte
 */
std::vector<uint8_t> build_message_packet(char type, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> packet;
    packet.reserve(1 + 4 + data.size());

    // Message type
    packet.push_back(type);

    // Message length (includes self)
    uint32_t len = data.size() + 4;
    packet.push_back((len >> 24) & 0xFF);
    packet.push_back((len >> 16) & 0xFF);
    packet.push_back((len >> 8) & 0xFF);
    packet.push_back(len & 0xFF);

    // Message data
    packet.insert(packet.end(), data.begin(), data.end());

    return packet;
}

/**
 * @brief Read an exact number of bytes from socket
 * @return true if all bytes received, false on error/short read
 */
bool recv_exact(int sock, void* buf, size_t len) {
    char* ptr = (char*)buf;
    size_t received = 0;
    while (received < len) {
        ssize_t n = recv(sock, ptr + received, len - received, 0);
        if (n <= 0) return false;
        received += n;
    }
    return true;
}

/**
 * @brief Send an exact number of bytes to socket
 * @return true if all bytes sent, false on error/short write
 */
bool send_exact(int sock, const void* buf, size_t len) {
    const char* ptr = (const char*)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, ptr + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

/**
 * @brief Read a PostgreSQL message from socket
 */
bool read_message(int sock, char& type, std::vector<uint8_t>& buffer) {
    // Read message type (1 byte)
    char type_buf[1];
    if (!recv_exact(sock, type_buf, 1)) return false;
    type = type_buf[0];

    // Read length (4 bytes, big-endian, includes self)
    char len_buf[4];
    if (!recv_exact(sock, len_buf, 4)) return false;

    int32_t len = ((unsigned char)len_buf[0] << 24) |
                  ((unsigned char)len_buf[1] << 16) |
                  ((unsigned char)len_buf[2] << 8) |
                  (unsigned char)len_buf[3];

    if (len < 4) return false;

    // Read message body
    int32_t body_len = len - 4;
    buffer.resize(body_len);
    if (!recv_exact(sock, buffer.data(), body_len)) return false;

    return true;
}

/**
 * @brief Send a malformed packet on an authenticated connection (Phase 2)
 *
 * Phase 2 tests send malformed packets AFTER successful authentication.
 * This tests post-authentication crash vulnerabilities.
 */
void test_malformed_packet_phase2(const std::string& test_name,
                                   const std::string& host,
                                   int port,
                                   const std::string& username,
                                   const std::string& password,
                                   const std::vector<uint8_t>& malformed_data,
                                   bool accept_ready_for_query = false) {

    // Use libpq to establish authenticated connection, then extract socket
    std::stringstream conninfo;
    conninfo << "host=" << host << " port=" << port
             << " user=" << username << " password=" << password
             << " sslmode=disable";

    PGconn* conn = PQconnectdb(conninfo.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        diag("libpq connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        ok(0, "%s: Failed to create libpq connection", test_name.c_str());
        return;
    }

    // Get the underlying socket from libpq connection
    int sock = PQsocket(conn);
    if (sock < 0) {
        diag("PQsocket failed");
        PQfinish(conn);
        ok(0, "%s: Failed to get socket from libpq connection", test_name.c_str());
        return;
    }

    // Set socket to blocking mode (libpq may have set it non-blocking)
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
    }

    // Note: libpq has already completed authentication and reached ReadyForQuery
    // We can now send malformed packets on this authenticated connection

    // Step 6: Send the malformed packet on the authenticated connection
    if (!send_exact(sock, malformed_data.data(), malformed_data.size())) {
        close(sock);
        ok(0, "%s: Failed to send malformed data", test_name.c_str());
        return;
    }

    // Step 7: Wait for a response to the packet.
    // Most cases expect an error response, connection close, or timeout. The
    // rapid-Sync stress case also accepts ReadyForQuery, which is a normal
    // response to a complete Sync frame.
    bool got_error_response = false;
    bool got_ready_for_query = false;
    bool connection_closed = false;
    bool timeout = false;
    char first_byte = 0;

    for (int i = 0; i < 16; ++i) {
        char msg_type = 0;
        std::vector<uint8_t> msg_data;

        // Try to read a message with timeout
        ssize_t bytes_received = recv(sock, &msg_type, 1, MSG_PEEK | MSG_DONTWAIT);
        if (bytes_received == 0) {
            connection_closed = true;
            break;
        }
        if (bytes_received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                timeout = true;
            }
            break;
        }

        // Message available, read it fully
        if (!read_message(sock, msg_type, msg_data)) {
            connection_closed = true;
            break;
        }

        first_byte = msg_type;

        // Check if this is an error response to our malformed packet
        if (msg_type == 'E') {
            got_error_response = true;
            break;
        }
        if (accept_ready_for_query && msg_type == 'Z') {
            got_ready_for_query = true;
            break;
        }
        // Continue reading if it's other protocol traffic
    }

    bool handled_gracefully = connection_closed || timeout || got_error_response || got_ready_for_query;

    ok(handled_gracefully, "%s: Phase 2 packet handled (closed=%d, timeout=%d, error=%d, ready=%d, first=0x%02X)",
       test_name.c_str(), (int)connection_closed, (int)timeout, (int)got_error_response,
       (int)got_ready_for_query, first_byte);

    // Clean up libpq connection (closes socket internally)
    PQfinish(conn);
}

/**
 * @brief Run Phase 2 tests - malformed packets AFTER authentication
 *
 * Phase 2 tests establish a valid connection first, then send malformed
 * packets on the authenticated connection to test post-auth crash vectors.
 */
void run_phase2_malformed_packet_tests(const std::string& host, int port,
                                        const std::string& username,
                                        const std::string& password,
                                        const char* target_name) {
    diag(">>> Phase 2: Testing malformed packets AFTER AUTH on %s (%s:%d) <<<",
         target_name, host.c_str(), port);

    // ==================== QUERY PACKET TESTS ('Q') ====================

    // Test 1: Query packet with length < 5 (integer underflow)
    // This targets PgSQL_Session.cpp:2079-2082 where query_len = pkt.size - 5
    test_malformed_packet_phase2("Query packet length=4 (underflow)",
        host, port, username, password,
        {'Q', 0x00, 0x00, 0x00, 0x04});

    // Test 2: Query packet with length=0
    test_malformed_packet_phase2("Query packet length=0",
        host, port, username, password,
        {'Q', 0x00, 0x00, 0x00, 0x00});

    // Test 3: Query packet with length=1 (just type byte)
    test_malformed_packet_phase2("Query packet length=1",
        host, port, username, password,
        {'Q', 0x00, 0x00, 0x00, 0x01});

    // Test 4: Query with null terminator but truncated
    test_malformed_packet_phase2("Query truncated without null",
        host, port, username, password,
        {'Q', 0x00, 0x00, 0x00, 0x08, 'S', 'E', 'L', 'E'});

    // Test 5: Query with huge length
    test_malformed_packet_phase2("Query with huge length",
        host, port, username, password,
        {'Q', 0x7F, 0xFF, 0xFF, 0xFF});

    // Test 6: Query with negative length (0x80000000)
    test_malformed_packet_phase2("Query with negative length",
        host, port, username, password,
        {'Q', 0x80, 0x00, 0x00, 0x00});

    // ==================== EXTENDED QUERY PROTOCOL TESTS ====================

    // Test 7: Parse 'P' packet with length < 5
    test_malformed_packet_phase2("Parse packet length=4",
        host, port, username, password,
        {'P', 0x00, 0x00, 0x00, 0x04});

    // Test 8: Parse packet with statement name no null terminator
    test_malformed_packet_phase2("Parse stmt name no null",
        host, port, username, password,
        {'P', 0x00, 0x00, 0x00, 0x0A, 's', 't', 'm', 't', '1', 0x00});

    // Test 9: Parse packet with query no null terminator
    test_malformed_packet_phase2("Parse query no null",
        host, port, username, password,
        {'P', 0x00, 0x00, 0x00, 0x10,
         's', 0x00,
         'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0x00});

    // Test 10: Bind 'B' packet with length < 5
    test_malformed_packet_phase2("Bind packet length=4",
        host, port, username, password,
        {'B', 0x00, 0x00, 0x00, 0x04});

    // Test 11: Bind with malformed parameter format codes
    test_malformed_packet_phase2("Bind malformed param formats",
        host, port, username, password,
        {'B', 0x00, 0x00, 0x00, 0x0C,
         'p', 0x00,
         's', 0x00,
         0x00, 0x01,
         0x00, 0x01});

    // Test 12: Execute 'E' packet with length < 5
    test_malformed_packet_phase2("Execute packet length=4",
        host, port, username, password,
        {'E', 0x00, 0x00, 0x00, 0x04});

    // Test 13: Execute with portal name no null
    test_malformed_packet_phase2("Execute portal no null",
        host, port, username, password,
        {'E', 0x00, 0x00, 0x00, 0x08,
         'p', 'o', 'r', 't', 'a', 'l', '1'});

    // Test 14: Close 'C' packet with length < 5
    test_malformed_packet_phase2("Close packet length=4",
        host, port, username, password,
        {'C', 0x00, 0x00, 0x00, 0x04});

    // Test 15: Describe 'D' packet with length < 5
    test_malformed_packet_phase2("Describe packet length=4",
        host, port, username, password,
        {'D', 0x00, 0x00, 0x00, 0x04});

    // Test 16: Sync 'S' packet with invalid length
    test_malformed_packet_phase2("Sync packet invalid length",
        host, port, username, password,
        {'S', 0x00, 0x00, 0x00, 0x08});

    // Test 17: Flush 'H' packet with invalid length
    test_malformed_packet_phase2("Flush packet invalid length",
        host, port, username, password,
        {'H', 0x00, 0x00, 0x00, 0x08});

    // ==================== COPY PROTOCOL TESTS ====================

    // Test 18: CopyData 'd' packet with zero length
    test_malformed_packet_phase2("CopyData length=4",
        host, port, username, password,
        {'d', 0x00, 0x00, 0x00, 0x04});

    // Test 19: CopyData with huge length
    test_malformed_packet_phase2("CopyData huge length",
        host, port, username, password,
        {'d', 0x7F, 0xFF, 0xFF, 0xFF});

    // Test 20: CopyDone 'c' packet with invalid length
    test_malformed_packet_phase2("CopyDone invalid length",
        host, port, username, password,
        {'c', 0x00, 0x00, 0x00, 0x08});

    // Test 21: CopyFail 'f' packet with no error message
    test_malformed_packet_phase2("CopyFail no message",
        host, port, username, password,
        {'f', 0x00, 0x00, 0x00, 0x04});

    // ==================== TERMINATE MESSAGE TESTS ====================

    // Test 22: Terminate 'X' packet with invalid length
    test_malformed_packet_phase2("Terminate invalid length",
        host, port, username, password,
        {'X', 0xFF, 0xFF, 0xFF, 0xFF});

    // Test 23: Terminate with length=0
    test_malformed_packet_phase2("Terminate length=0",
        host, port, username, password,
        {'X', 0x00, 0x00, 0x00, 0x00});

    // ==================== MULTI-PACKET / ARITHMETIC TESTS ====================

    // Test 24: Multiple small packets in sequence
    std::vector<uint8_t> multi_pkt;
    for (int i = 0; i < 10; i++) {
        multi_pkt.push_back('Q');
        multi_pkt.push_back(0x00);
        multi_pkt.push_back(0x00);
        multi_pkt.push_back(0x00);
        multi_pkt.push_back(0x05);
        multi_pkt.push_back('x');
    }
    test_malformed_packet_phase2("Multiple small queries",
        host, port, username, password, multi_pkt);

    // Test 25: Rapid-fire complete Sync packets. Sync is not malformed; a
    // ReadyForQuery response is the expected graceful outcome.
    std::vector<uint8_t> rapid;
    for (int i = 0; i < 100; i++) {
        rapid.insert(rapid.end(), {'S', 0x00, 0x00, 0x00, 0x04});
    }
    test_malformed_packet_phase2("Rapid fire Sync packets",
        host, port, username, password, rapid, true);

    // ==================== DATA TYPE OVERFLOW TESTS ====================

    // Test 26: Integer overflow in length field
    test_malformed_packet_phase2("Integer overflow length",
        host, port, username, password,
        {'Q', 0xFF, 0xFF, 0xFF, 0xFF});

    // Test 27: Parameter count overflow in Bind
    test_malformed_packet_phase2("Bind param count overflow",
        host, port, username, password,
        {'B', 0x00, 0x00, 0x00, 0x20,
         'p', 0x00,
         's', 0x00,
         0xFF, 0xFF,
         0x00, 0x00});

    // Test 28: Column count overflow in Parse
    test_malformed_packet_phase2("Parse column count overflow",
        host, port, username, password,
        {'P', 0x00, 0x00, 0x00, 0x10,
         's', 0x00,
         'Q', 0x00,
         0xFF, 0xFF,
         0x00, 0x00});

    // ==================== PASSWORD MESSAGE TESTS ====================
    // Tests for extract_password() vulnerability

    // Test 29: Password message with length=4 (too small)
    test_malformed_packet_phase2("Password message length=4",
        host, port, username, password,
        {'p', 0x00, 0x00, 0x00, 0x04});

    // Test 30: Password message with huge length field
    test_malformed_packet_phase2("Password message huge length",
        host, port, username, password,
        {'p', 0x7F, 0xFF, 0xFF, 0xFF});

    // Test 31: Password message with length=0
    test_malformed_packet_phase2("Password message length=0",
        host, port, username, password,
        {'p', 0x00, 0x00, 0x00, 0x00});

    // ==================== SASL AUTHENTICATION TESTS ====================
    // Tests for scram_handle_client_first/client_final vulnerabilities

    // Test 32: SASL client-first with invalid length
    test_malformed_packet_phase2("SASL client-first invalid length",
        host, port, username, password,
        {'p', 0x00, 0x00, 0x00, 0x08,
         'S', 'C', 'R', 'A', 'M', '-', 'S', 'H'});

    // Test 33: SASL client-first with truncated data
    test_malformed_packet_phase2("SASL client-first truncated",
        host, port, username, password,
        {'p', 0x00, 0x00, 0x01, 0x00,
         'S', 'C', 'R', 'A', 'M', '-', 'S', 'H', 'A', '-', '2', '5', '6', 0x00});

    // Test 34: SASL response with invalid length
    test_malformed_packet_phase2("SASL response invalid length",
        host, port, username, password,
        {'p', 0xFF, 0xFF, 0xFF, 0xFF});

    // ==================== MULTI-PACKET TESTS ====================
    // Tests for multi_pkt underflow vulnerability

    // Test 35: Multi-packet scenario with small size
    test_malformed_packet_phase2("Multi-packet small size",
        host, port, username, password,
        {'Q', 0x00, 0x00, 0x00, 0x05, 'x'});

    // ==================== EXTENDED QUERY LENGTH TESTS ====================
    // Additional tests for extended query protocol

    // Test 36: Parse with zero-length statement name and query
    test_malformed_packet_phase2("Parse zero length fields",
        host, port, username, password,
        {'P', 0x00, 0x00, 0x00, 0x06, 0x00, 0x00});

    // Test 37: Bind with zero-length portal and statement
    test_malformed_packet_phase2("Bind zero length fields",
        host, port, username, password,
        {'B', 0x00, 0x00, 0x00, 0x06, 0x00, 0x00});

    // Test 38: Execute with zero-length portal
    test_malformed_packet_phase2("Execute zero length portal",
        host, port, username, password,
        {'E', 0x00, 0x00, 0x00, 0x05, 0x00});

    // Test 39: Close with zero-length name
    test_malformed_packet_phase2("Close zero length name",
        host, port, username, password,
        {'C', 0x00, 0x00, 0x00, 0x05, 0x00});

    // Test 40: Describe with zero-length name
    test_malformed_packet_phase2("Describe zero length name",
        host, port, username, password,
        {'D', 0x00, 0x00, 0x00, 0x05, 0x00});

    // ==================== PACKET TYPE CONFUSION AFTER AUTH ====================

    // Test 41: Startup packet sent after authentication
    test_malformed_packet_phase2("Startup after auth",
        host, port, username, password,
        {0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00});

    // Test 42: SSL request after authentication
    test_malformed_packet_phase2("SSL request after auth",
        host, port, username, password,
        {0x00, 0x00, 0x00, 0x08,
         0x04, 0xD2, 0x16, 0x2F});

    // Test 43: Cancel request after authentication
    test_malformed_packet_phase2("Cancel request after auth",
        host, port, username, password,
        {0x00, 0x00, 0x00, 0x10,
         0x04, 0xD2, 0x16, 0x2E,
         0x00, 0x00, 0x00, 0x01,
         0x00, 0x00, 0x00, 0x02});
}

/**
 * @brief Final comprehensive check to verify ProxySQL did not crash
 * This runs after ALL tests and reports whether ProxySQL is still alive
 */
bool final_crash_check(const CommandLine& cl) {
    diag(">>> Final crash verification - checking if ProxySQL survived all malformed packets <<<");

    // Try to connect to BACKEND
    std::stringstream ss_backend;
    ss_backend << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port;
    ss_backend << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password;
    ss_backend << " sslmode=disable";

    PGconn* conn = PQconnectdb(ss_backend.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        diag("CRASH DETECTED: Cannot connect to BACKEND: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return false;
    }

    PGresult* res = PQexec(conn, "SELECT 1");
    bool backend_ok = (PQresultStatus(res) == PGRES_TUPLES_OK);
    PQclear(res);
    PQfinish(conn);

    if (!backend_ok) {
        diag("CRASH DETECTED: BACKEND query failed");
        return false;
    }

    // Try to connect to ADMIN
    std::stringstream ss_admin;
    ss_admin << "host=" << cl.admin_host << " port=" << cl.pgsql_admin_port;
    ss_admin << " user=" << cl.admin_username << " password=" << cl.admin_password;
    ss_admin << " sslmode=disable";

    conn = PQconnectdb(ss_admin.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        diag("CRASH DETECTED: Cannot connect to ADMIN: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return false;
    }

    res = PQexec(conn, "SELECT 1");
    bool admin_ok = (PQresultStatus(res) == PGRES_TUPLES_OK);
    PQclear(res);
    PQfinish(conn);

    if (!admin_ok) {
        diag("CRASH DETECTED: ADMIN query failed");
        return false;
    }

    return true;
}

int main(int argc, char** argv) {
    CommandLine cl;

    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return EXIT_FAILURE;
    }

    // Count the number of tests
    // Phase 1: 28 tests per target (BACKEND and ADMIN) = 56 tests
    // Phase 2: 43 tests per target (BACKEND and ADMIN) = 86 tests
    // Plus 4 operational checks (after each target/phase) + 1 final crash check
    const int phase1_tests = 56;  // 28 per target
    const int phase2_tests = 86;  // 43 per target
    const int total_malformed_tests = phase1_tests + phase2_tests;
    const int operational_checks = 4;  // After each target in Phase 1 and Phase 2
    const int final_check = 1;   // Final comprehensive crash check

    plan(total_malformed_tests + operational_checks + final_check);

    // =====================================================
    // PHASE 1: PRE-AUTHENTICATION MALFORMED PACKETS
    // =====================================================

    // Test BACKEND connection
    run_malformed_packet_tests(cl.pgsql_host, cl.pgsql_port, "BACKEND");

    // Verify ProxySQL is still alive after BACKEND Phase 1 tests
    bool backend_alive = verify_proxysql_alive(cl, BACKEND);
    ok(backend_alive, "ProxySQL BACKEND operational after Phase 1");

    // Test ADMIN connection
    run_malformed_packet_tests(cl.admin_host, cl.pgsql_admin_port, "ADMIN");

    // Verify ProxySQL is still alive after ADMIN Phase 1 tests
    bool admin_alive = verify_proxysql_alive(cl, ADMIN);
    ok(admin_alive, "ProxySQL ADMIN operational after Phase 1");

    // =====================================================
    // PHASE 2: POST-AUTHENTICATION MALFORMED PACKETS
    // =====================================================

    // Phase 2: Test malformed packets AFTER authentication on BACKEND
    run_phase2_malformed_packet_tests(cl.pgsql_host, cl.pgsql_port,
                                       cl.pgsql_username, cl.pgsql_password,
                                       "BACKEND");

    // Verify ProxySQL is still alive after BACKEND Phase 2 tests
    backend_alive = verify_proxysql_alive(cl, BACKEND);
    ok(backend_alive, "ProxySQL BACKEND operational after Phase 2");

    // Phase 2: Test malformed packets AFTER authentication on ADMIN
    run_phase2_malformed_packet_tests(cl.admin_host, cl.pgsql_admin_port,
                                       cl.admin_username, cl.admin_password,
                                       "ADMIN");

    // Verify ProxySQL is still alive after ADMIN Phase 2 tests
    admin_alive = verify_proxysql_alive(cl, ADMIN);
    ok(admin_alive, "ProxySQL ADMIN operational after Phase 2");

    // FINAL COMPREHENSIVE CRASH CHECK
    // This is the most important test - it proves ProxySQL didn't crash
    bool no_crash = final_crash_check(cl);
    ok(no_crash, "FINAL: ProxySQL did NOT crash - ALL MALFORMED PACKET TESTS PASSED");

    return exit_status();
}
