/**
 * @file mysql-test_malformed_packet-t.cpp
 * @brief Validates ProxySQL's stability and ensures it does not crash when subjected to 
 *       multiple malformed packets on its admin and backend connections.
 */
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>
#include <string>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "noise_utils.h"
#include "utils.h"

constexpr size_t BUFFER_SIZE = 1024;

#define REPORT_ERROR_AND_EXIT(fmt, ...) \
    do { \
        diag("File %s, line %d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
        if (sock >= 0) close(sock); \
        return; \
    } while (0)

typedef enum {
    BACKEND = 0,
    ADMIN
} Connection_type_t;

void execute_test(MYSQL* conn, const std::string& host, int port, const std::vector<uint8_t>& data) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        REPORT_ERROR_AND_EXIT("Socket creation failed");
    }

    struct timeval timeout;
    timeout.tv_sec = 10;  
    timeout.tv_usec = 0; 
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        REPORT_ERROR_AND_EXIT("Failed to set socket timeout");
    }

    // Resolve hostname
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port);
    int status = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (status != 0) {
        REPORT_ERROR_AND_EXIT("Failed to resolve host %s: %s", host.c_str(), gai_strerror(status));
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res);
        REPORT_ERROR_AND_EXIT("Connection to %s:%d failed", host.c_str(), port);
    }
    freeaddrinfo(res);

    diag("Connected to %s:%d. Waiting for server greeting...", host.c_str(), port);

    std::vector<char> buffer(BUFFER_SIZE);
    ssize_t bytes_received = recv(sock, buffer.data(), buffer.size(), 0);
    if (bytes_received < 0) {
        REPORT_ERROR_AND_EXIT("Failed to receive server greeting");
    }

    diag("Server greeting received (%ld bytes). Sending malformed packet...", bytes_received);
    ssize_t bytes_sent = send(sock, data.data(), data.size(), 0);
    if (bytes_sent < 0) {
        REPORT_ERROR_AND_EXIT("Failed to send data");
    }

    bytes_received = recv(sock, buffer.data(), buffer.size(), 0);
    if (bytes_received < 0) {
        int err = errno;
        diag("recv() returned -1, errno=%d (%s)", err, strerror(err));
    } else {
        diag("recv() returned %ld bytes", bytes_received);
    }
    
    // For Admin interface, we are more interested in stability (ProxySQL alive) 
    // than immediate connection closure, as the handlers differ.
    ok(bytes_received == 0 || bytes_received < 0, "Connection closed or timed out (Stability maintained)");
	close(sock);
	[[maybe_unused]] int sock_unused = sock;

    usleep(500000); // 0.5 second delay

    bool query_success = false;
    if (mysql_query(conn, "SELECT 1")) {
        diag("Verification query failed: %s", mysql_error(conn));
    } else {
        MYSQL_RES* result = mysql_store_result(conn);
        if (result) {
            MYSQL_ROW row = mysql_fetch_row(result);
            if (row && strcmp(row[0], "1") == 0) query_success = true;
            mysql_free_result(result);
        }
    }
    ok(query_success, "ProxySQL is still alive after malformed packet");
}

MYSQL* setup_mysql_connection(const CommandLine& cl, Connection_type_t conn_type) {
    MYSQL* conn = mysql_init(nullptr);
    if (conn == nullptr) return nullptr;

    const char* host = (conn_type == ADMIN) ? cl.admin_host : cl.host;
    int port = (conn_type == ADMIN) ? cl.admin_port : cl.port;
    const char* user = (conn_type == ADMIN) ? cl.admin_username : cl.username;
    const char* pass = (conn_type == ADMIN) ? cl.admin_password : cl.password;

    diag("Establishing monitor connection to %s:%d as %s", host, port, user);
    if (!mysql_real_connect(conn, host, user, pass, nullptr, port, nullptr, 0)) {
        diag("Monitor connection failed: %s", mysql_error(conn));
        mysql_close(conn);
        return nullptr;
    }
    return conn;
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) return EXIT_FAILURE;

    plan(36 + (cl.use_noise ? 3 : 0));
    diag("=== MySQL Malformed Packet Stability Test ===");
    diag("This test verifies that ProxySQL remains stable and operational when");
    diag("receiving invalid or malformed MySQL protocol packets.");
    diag("Scenarios tested:");
    diag("  1. Malformed packets on the standard MySQL frontend (port 6033).");
    diag("  2. Malformed packets on the ProxySQL Admin interface (port 6032).");
    diag("For each packet, the test confirms:");
    diag("  - ProxySQL closes the malicious connection.");
    diag("  - ProxySQL continues to process valid queries on existing connections.");
    diag("==============================================");

    spawn_internal_noise(cl, internal_noise_random_stats_poller);
    spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}});
    spawn_internal_noise(cl, internal_noise_pgsql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}});

    std::vector<std::vector<uint8_t>> malformed_pkts = {
        {0x01, 0x00},
        {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFE, 0x00, 0x00},
        {0x03, 0x00, 0x00, 0xFF, 0x00},
        {0x10, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x11, 0x22, 0x33, 0x44, 0x55},
        {0x03, 0x00, 0x00, 0x00, 0xFF, 0x00},
        {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00},
        {0x05, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00},
        {0x04, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00},
        {0x03, 0x00, 0x00, 0x2F, 0x2A, 0xE0, 0x00},
    };

    {
        diag(">>> PHASE 1: Malformed packets to FRONTEND (port %d) <<<", cl.port);
        MYSQL* conn = setup_mysql_connection(cl, BACKEND);
        if (conn) {
            for (const auto& pkt : malformed_pkts) execute_test(conn, cl.host, cl.port, pkt);
            mysql_close(conn);
        }
    }

    {
        diag(">>> PHASE 2: Malformed packets to ADMIN (port %d) <<<", cl.admin_port);
        MYSQL* conn = setup_mysql_connection(cl, ADMIN);
        if (conn) {
            for (const auto& pkt : malformed_pkts) execute_test(conn, cl.admin_host, cl.admin_port, pkt);
            mysql_close(conn);
        }
    }

    return exit_status();
}
