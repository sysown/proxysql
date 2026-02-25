/**
 * @file mysql-test_malformed_packet-t.cpp
 * @brief Validates ProxySQL's stability and ensures it does not crash when subjected to 
 *       multiple malformed packets on its admin and backend connections.
 */
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "noise_utils.h"
#include "utils.h"

constexpr size_t BUFFER_SIZE = 1024;

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

void execute_test(MYSQL* conn, const std::string& host, int port, const std::vector<uint8_t>& data) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        REPORT_ERROR_AND_EXIT("Socket creation failed");
    }

    struct timeval timeout;
    // Set the timeout for receive operations
    timeout.tv_sec = 60;  
    timeout.tv_usec = 0; 
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        REPORT_ERROR_AND_EXIT("Failed to set socket timeout");
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
        REPORT_ERROR_AND_EXIT("Invalid address or address not supported");
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        REPORT_ERROR_AND_EXIT("Connection to the server failed");
    }

    diag("Connected to the server. Waiting for server greeting...");

    std::vector<char> buffer(BUFFER_SIZE);
    ssize_t bytes_received = recv(sock, buffer.data(), buffer.size(), 0);
    if (bytes_received < 0) {
        REPORT_ERROR_AND_EXIT("Failed to receive server greeting");
    }

    diag("Server greeting received (length: %ld bytes).", bytes_received);

    diag("Sending malformed packet to the server...");
    ssize_t bytes_sent = send(sock, data.data(), data.size(), 0);
    if (bytes_sent < 0) {
        REPORT_ERROR_AND_EXIT("Failed to send data");
    }
    diag("Done");

    bytes_received = recv(sock, buffer.data(), buffer.size(), 0);
    ok(bytes_received == 0, "Connection closed by server");
    close(sock);

    usleep(1000000); // 1 second delay

	bool query_success = false;

    if (mysql_query(conn, "SELECT 1")) {
        fprintf(stderr, "mysql_query() failed: %s\n", mysql_error(conn));
    } else {

        MYSQL_RES* result = mysql_store_result(conn);
        if (result == nullptr) {
            fprintf(stderr, "mysql_store_result() failed: %s\n", mysql_error(conn));
		}
		else {
			MYSQL_ROW row = mysql_fetch_row(result);
			if (row && strcmp(row[0], "1") == 0) query_success = true;
			mysql_free_result(result);
		}
    }

    ok(query_success, "ProxySQL should be alive. %s", mysql_error(conn));
}

MYSQL* setup_mysql_connection(const CommandLine& cl, Connection_type_t conn_type) {
    MYSQL* conn = mysql_init(nullptr);
    if (conn == nullptr) {
        fprintf(stderr, "File %s, line %d, Error: mysql_init() failed\n", __FILE__, __LINE__);
        return nullptr;
    }

    if (conn_type == ADMIN) {
        if (!mysql_real_connect(conn, cl.admin_host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
            fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(conn));
            mysql_close(conn);
            return nullptr;
        }
    } else {
        if (!mysql_real_connect(conn, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
            fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(conn));
            mysql_close(conn);
            return nullptr;
        }
    }

    return conn;
}

int main(int argc, char** argv) {
    CommandLine cl;

    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return EXIT_FAILURE;
    }

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

    if (cl.use_noise) {
        plan(malformed_pkts.size() * 4 + 3);
    } else {
        plan(malformed_pkts.size() * 4);
    }

    {
        diag(">>> Sending malformed packets to BACKEND connection <<<");
        MYSQL* conn = setup_mysql_connection(cl, BACKEND);
        if (conn == nullptr) {
            return EXIT_FAILURE;
        }

        for (const auto& pkt : malformed_pkts) {
            execute_test(conn, cl.host, cl.port, pkt);
        }

        mysql_close(conn);
        diag("Done");
    }

    {
        diag(">>> Sending malformed packets to ADMIN connection <<<");
        MYSQL* conn = setup_mysql_connection(cl, ADMIN);
        if (conn == nullptr) {
            return EXIT_FAILURE;
        }

        for (const auto& pkt : malformed_pkts) {
            execute_test(conn, cl.host, cl.port, pkt);
        }

        mysql_close(conn);
        diag("Done");
    }

    return exit_status();
}
