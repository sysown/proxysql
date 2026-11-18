/**
 * @file pgsql_raw_client.h
 * @brief Raw PostgreSQL wire-protocol helpers shared by the PgSQL startup/TLS TAP tests.
 *
 * Header-only and independent of any test's globals: the user name is always passed in.
 */
#ifndef PGSQL_RAW_CLIENT_H
#define PGSQL_RAW_CLIENT_H

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <openssl/ssl.h>

/** Opens a TCP connection with a receive timeout and TCP_NODELAY; -1 on failure. */
static inline int create_raw_connection(const std::string& host, int port, int timeout_sec = 5) {
	struct addrinfo hints {};
	struct addrinfo* result = nullptr;
	int sock = -1;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) != 0) {
		return -1;
	}

	for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock < 0) continue;

		struct timeval timeout { timeout_sec, 0 };
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		int flag = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

		if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
		close(sock);
		sock = -1;
	}

	freeaddrinfo(result);
	return sock;
}

static inline void put_uint32(std::vector<uint8_t>& pkt, uint32_t val) {
	pkt.push_back((val >> 24) & 0xFF);
	pkt.push_back((val >> 16) & 0xFF);
	pkt.push_back((val >> 8) & 0xFF);
	pkt.push_back(val & 0xFF);
}

static inline uint32_t get_uint32(const std::vector<uint8_t>& buf, size_t off) {
	return ((uint32_t)buf[off] << 24) | ((uint32_t)buf[off + 1] << 16) |
		   ((uint32_t)buf[off + 2] << 8) | (uint32_t)buf[off + 3];
}

static inline bool send_exact(int sock, const void* buf, size_t len, SSL* tls = nullptr) {
	const char* p = (const char*)buf;
	while (len) {
		ssize_t n = tls ? SSL_write(tls, p, len) : send(sock, p, len, MSG_NOSIGNAL);
		if (n <= 0) return false;
		p += n;
		len -= n;
	}
	return true;
}

static inline bool recv_exact(int sock, void* buf, size_t len, SSL* tls = nullptr) {
	char* p = (char*)buf;
	while (len) {
		ssize_t n = tls ? SSL_read(tls, p, len) : recv(sock, p, len, 0);
		if (n <= 0) return false;
		p += n;
		len -= n;
	}
	return true;
}

/** Reads one message. Returns false when the peer closed instead of answering. */
static inline bool read_message(int sock, char& type, std::vector<uint8_t>& body, SSL* tls = nullptr) {
	// '?' means nothing came back, so a failed read cannot leave the previous message's type
	// behind and report a reply that never arrived.
	type = '?';
	if (!recv_exact(sock, &type, 1, tls)) return false;

	uint8_t len_buf[4];
	if (!recv_exact(sock, len_buf, 4, tls)) return false;
	int32_t len = ((int32_t)len_buf[0] << 24) | ((int32_t)len_buf[1] << 16) |
				  ((int32_t)len_buf[2] << 8) | (int32_t)len_buf[3];
	if (len < 4) return false;

	body.resize(len - 4);
	return body.empty() || recv_exact(sock, body.data(), body.size(), tls);
}

/** The startup packet bytes for a given version and user. */
static inline std::vector<uint8_t> startup_packet(uint32_t version, const std::string& user,
												  const std::string& database = "postgres") {
	std::vector<uint8_t> pkt(4);
	put_uint32(pkt, version);
	for (const std::string& p : {std::string("user"), user, std::string("database"), database}) {
		pkt.insert(pkt.end(), p.begin(), p.end());
		pkt.push_back(0);
	}
	pkt.push_back(0);
	const uint32_t len = pkt.size();
	pkt[0] = (len >> 24) & 0xFF;
	pkt[1] = (len >> 16) & 0xFF;
	pkt[2] = (len >> 8) & 0xFF;
	pkt[3] = len & 0xFF;
	return pkt;
}

/** The value of one ErrorResponse field, or "" when absent. */
static inline std::string error_field(const std::vector<uint8_t>& body, char field) {
	for (size_t i = 0; i + 1 < body.size() && body[i] != 0;) {
		const char f = body[i];
		// Bounded on purpose: a truncated reply must not walk off the end of the buffer.
		const void* nul = memchr(&body[i + 1], 0, body.size() - (i + 1));
		if (nul == nullptr) break;
		const std::string value((const char*)&body[i + 1]);
		if (f == field) return value;
		i += 1 + value.size() + 1;
	}
	return "";
}

#endif // PGSQL_RAW_CLIENT_H
