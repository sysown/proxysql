/**
 * @file aws_iam_mysql_server.cpp
 * @brief One-shot TLS MySQL server for AWS IAM backend protocol tests.
 *
 * This is intentionally not a SQL server. It implements only the initial
 * protocol-10 exchange, SSLRequest, TLS upgrade, mysql_clear_password auth
 * switch, and a terminal OK or ERR 1045 packet.
 */

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr uint32_t CLIENT_LONG_PASSWORD = 0x00000001U;
constexpr uint32_t CLIENT_PROTOCOL_41 = 0x00000200U;
constexpr uint32_t CLIENT_SSL = 0x00000800U;
constexpr uint32_t CLIENT_SECURE_CONNECTION = 0x00008000U;
constexpr uint32_t CLIENT_PLUGIN_AUTH = 0x00080000U;

struct Options {
	std::string mode;
	std::string certificate;
	std::string private_key;
	unsigned int delay_ms { 1500 };
	int stage_fd { -1 };
};

struct Observation {
	bool tls { false };
	bool pre_tls_payload { false };
	int minimum_tls_version { 0 };
	std::string username;
	std::string sni;
	std::string peer;
	size_t token_length { 0 };
	std::string token_sha256;
	std::string error { "none" };
};

uint32_t read_le32(const unsigned char *p) {
	return static_cast<uint32_t>(p[0]) |
		(static_cast<uint32_t>(p[1]) << 8U) |
		(static_cast<uint32_t>(p[2]) << 16U) |
		(static_cast<uint32_t>(p[3]) << 24U);
}

void append_le16(std::vector<unsigned char>& out, uint16_t value) {
	out.push_back(static_cast<unsigned char>(value & 0xffU));
	out.push_back(static_cast<unsigned char>((value >> 8U) & 0xffU));
}

void append_le32(std::vector<unsigned char>& out, uint32_t value) {
	for (unsigned int i = 0; i != 4; ++i) {
		out.push_back(static_cast<unsigned char>((value >> (8U * i)) & 0xffU));
	}
}

bool wait_fd(int fd, short events, int timeout_ms = 5000) {
	pollfd descriptor { fd, events, 0 };
	for (;;) {
		const int result = poll(&descriptor, 1, timeout_ms);
		if (result > 0) return (descriptor.revents & events) != 0;
		if (result == 0) return false;
		if (errno != EINTR) return false;
	}
}

bool read_exact_fd(int fd, unsigned char *data, size_t size) {
	while (size != 0) {
		if (!wait_fd(fd, POLLIN)) return false;
		const ssize_t count = recv(fd, data, size, 0);
		if (count <= 0) return false;
		data += count;
		size -= static_cast<size_t>(count);
	}
	return true;
}

bool write_exact_fd(int fd, const unsigned char *data, size_t size) {
	while (size != 0) {
		if (!wait_fd(fd, POLLOUT)) return false;
		const ssize_t count = send(fd, data, size, 0);
		if (count <= 0) return false;
		data += count;
		size -= static_cast<size_t>(count);
	}
	return true;
}

bool read_exact_ssl(SSL *ssl, unsigned char *data, size_t size) {
	while (size != 0) {
		const int count = SSL_read(ssl, data, static_cast<int>(size));
		if (count <= 0) return false;
		data += count;
		size -= static_cast<size_t>(count);
	}
	return true;
}

bool write_exact_ssl(SSL *ssl, const unsigned char *data, size_t size) {
	while (size != 0) {
		const int count = SSL_write(ssl, data, static_cast<int>(size));
		if (count <= 0) return false;
		data += count;
		size -= static_cast<size_t>(count);
	}
	return true;
}

template <typename Reader>
bool read_packet(Reader&& reader, std::vector<unsigned char>& payload, unsigned char& sequence) {
	unsigned char header[4] {};
	if (!reader(header, sizeof(header))) return false;
	const size_t length = static_cast<size_t>(header[0]) |
		(static_cast<size_t>(header[1]) << 8U) |
		(static_cast<size_t>(header[2]) << 16U);
	if (length > 16U * 1024U * 1024U) return false;
	sequence = header[3];
	payload.assign(length, 0);
	return length == 0 || reader(payload.data(), payload.size());
}

template <typename Writer>
bool write_packet(Writer&& writer, const std::vector<unsigned char>& payload,
	unsigned char sequence) {
	if (payload.size() > 0xffffffU) return false;
	unsigned char header[4] {
		static_cast<unsigned char>(payload.size() & 0xffU),
		static_cast<unsigned char>((payload.size() >> 8U) & 0xffU),
		static_cast<unsigned char>((payload.size() >> 16U) & 0xffU),
		sequence
	};
	return writer(header, sizeof(header)) &&
		(payload.empty() || writer(payload.data(), payload.size()));
}

std::vector<unsigned char> greeting() {
	const uint32_t capabilities = CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 |
		CLIENT_SSL | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
	const char server_version[] = "8.0.36-aws-iam-test";
	const unsigned char seed1[] = "12345678";
	const unsigned char seed2[] = "abcdefghijkl";
	const char plugin[] = "mysql_native_password";

	std::vector<unsigned char> packet;
	packet.push_back(10);
	packet.insert(packet.end(), server_version, server_version + sizeof(server_version));
	append_le32(packet, 4242);
	packet.insert(packet.end(), seed1, seed1 + 8);
	packet.push_back(0);
	append_le16(packet, static_cast<uint16_t>(capabilities & 0xffffU));
	packet.push_back(45);
	append_le16(packet, 2);
	append_le16(packet, static_cast<uint16_t>((capabilities >> 16U) & 0xffffU));
	packet.push_back(21);
	packet.insert(packet.end(), 10, 0);
	packet.insert(packet.end(), seed2, seed2 + 12);
	packet.push_back(0);
	packet.insert(packet.end(), plugin, plugin + sizeof(plugin));
	return packet;
}

std::vector<unsigned char> auth_switch() {
	const char plugin[] = "mysql_clear_password";
	std::vector<unsigned char> packet { 0xfe };
	packet.insert(packet.end(), plugin, plugin + sizeof(plugin));
	packet.push_back(0);
	return packet;
}

std::vector<unsigned char> ok_packet() {
	return { 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
}

std::vector<unsigned char> access_denied_packet() {
	std::vector<unsigned char> packet { 0xff, 0x15, 0x04, '#' };
	const char state[] = "28000";
	const char message[] = "Access denied";
	packet.insert(packet.end(), state, state + 5);
	packet.insert(packet.end(), message, message + sizeof(message) - 1);
	return packet;
}

std::string hex(const std::string& value) {
	static const char digits[] = "0123456789abcdef";
	std::string out;
	out.reserve(value.size() * 2);
	for (unsigned char byte : value) {
		out.push_back(digits[byte >> 4U]);
		out.push_back(digits[byte & 0x0fU]);
	}
	return out;
}

std::string sha256(const unsigned char *data, size_t size) {
	unsigned char digest[SHA256_DIGEST_LENGTH] {};
	SHA256(data, size, digest);
	return hex(std::string(reinterpret_cast<const char *>(digest), sizeof(digest)));
}

std::string parse_username(const std::vector<unsigned char>& response) {
	constexpr size_t username_offset = 4 + 4 + 1 + 23;
	if (response.size() <= username_offset) return {};
	const auto begin = response.begin() + static_cast<std::ptrdiff_t>(username_offset);
	const auto end = std::find(begin, response.end(), 0);
	if (end == response.end()) return {};
	return std::string(begin, end);
}

void report(const Observation& observation) {
	std::printf(
		"RESULT tls=%d pre_tls=%d min_tls=%d username_hex=%s token_len=%zu token_sha256=%s "
		"sni_hex=%s peer=%s error=%s\n",
		observation.tls ? 1 : 0,
		observation.pre_tls_payload ? 1 : 0,
		observation.minimum_tls_version,
		hex(observation.username).c_str(), observation.token_length,
		observation.token_sha256.empty() ? "-" : observation.token_sha256.c_str(),
		hex(observation.sni).c_str(),
		observation.peer.empty() ? "-" : observation.peer.c_str(),
		observation.error.c_str());
	std::fflush(stdout);
}

bool parse_options(int argc, char **argv, Options& options) {
	for (int i = 1; i < argc; ++i) {
		const std::string argument { argv[i] };
		if ((argument == "--mode" || argument == "--cert" ||
			argument == "--key" || argument == "--delay-ms" ||
			argument == "--stage-fd") && i + 1 < argc) {
			const std::string value { argv[++i] };
			if (argument == "--mode") options.mode = value;
			else if (argument == "--cert") options.certificate = value;
			else if (argument == "--key") options.private_key = value;
			else if (argument == "--delay-ms") {
				options.delay_ms = static_cast<unsigned int>(std::strtoul(value.c_str(), nullptr, 10));
			} else {
				options.stage_fd = static_cast<int>(std::strtol(value.c_str(), nullptr, 10));
			}
		} else {
			return false;
		}
	}
	return !options.mode.empty() && !options.certificate.empty() &&
		!options.private_key.empty();
}

int create_listener(uint16_t& port) {
	const int listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0) return -1;
	int enabled = 1;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
	sockaddr_in address {};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = 0;
	if (bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
		listen(listener, 1) != 0) {
		close(listener);
		return -1;
	}
	socklen_t length = sizeof(address);
	if (getsockname(listener, reinterpret_cast<sockaddr *>(&address), &length) != 0) {
		close(listener);
		return -1;
	}
	port = ntohs(address.sin_port);
	return listener;
}

} // namespace

int main(int argc, char **argv) {
	std::signal(SIGPIPE, SIG_IGN);
	Options options;
	if (!parse_options(argc, argv, options)) {
		std::fprintf(stderr,
			"usage: %s --mode MODE --cert FILE --key FILE [--delay-ms N] [--stage-fd FD]\n",
			argv[0]);
		return 2;
	}

	SSL_CTX *context = SSL_CTX_new(TLS_server_method());
	if (context == nullptr ||
		SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) != 1 ||
		SSL_CTX_use_certificate_chain_file(context, options.certificate.c_str()) != 1 ||
		SSL_CTX_use_PrivateKey_file(context, options.private_key.c_str(), SSL_FILETYPE_PEM) != 1 ||
		SSL_CTX_check_private_key(context) != 1) {
		ERR_print_errors_fp(stderr);
		if (context != nullptr) SSL_CTX_free(context);
		return 2;
	}

	uint16_t port = 0;
	const int listener = create_listener(port);
	if (listener < 0) {
		SSL_CTX_free(context);
		return 2;
	}
	std::printf("READY port=%u\n", port);
	std::fflush(stdout);

	Observation observation;
	observation.minimum_tls_version = SSL_CTX_get_min_proto_version(context);
	if (!wait_fd(listener, POLLIN, 10000)) {
		observation.error = "accept_timeout";
		report(observation);
		close(listener);
		SSL_CTX_free(context);
		return 1;
	}
	sockaddr_in peer {};
	socklen_t peer_length = sizeof(peer);
	const int client = accept(listener, reinterpret_cast<sockaddr *>(&peer), &peer_length);
	close(listener);
	if (client < 0) {
		observation.error = "accept_failed";
		report(observation);
		SSL_CTX_free(context);
		return 1;
	}
	const timeval io_timeout { 6, 0 };
	(void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &io_timeout, sizeof(io_timeout));
	(void)setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &io_timeout, sizeof(io_timeout));
	char peer_text[INET_ADDRSTRLEN] {};
	if (inet_ntop(AF_INET, &peer.sin_addr, peer_text, sizeof(peer_text)) != nullptr) {
		observation.peer = peer_text;
	}

	auto fd_reader = [client](unsigned char *data, size_t size) {
		return read_exact_fd(client, data, size);
	};
	auto fd_writer = [client](const unsigned char *data, size_t size) {
		return write_exact_fd(client, data, size);
	};
	if (options.mode == "delay_handshake") {
		if (options.stage_fd >= 0) {
			const char stage = 'S';
			(void)write(options.stage_fd, &stage, 1);
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(options.delay_ms));
	}
	if (!write_packet(fd_writer, greeting(), 0)) {
		observation.error = "greeting_write_failed";
		report(observation);
		close(client);
		SSL_CTX_free(context);
		return 1;
	}
	std::vector<unsigned char> request;
	unsigned char sequence = 0;
	if (!read_packet(fd_reader, request, sequence)) {
		observation.error = "initial_read_failed";
		report(observation);
		close(client);
		SSL_CTX_free(context);
		return 1;
	}
	const uint32_t client_capabilities = request.size() >= 4 ? read_le32(request.data()) : 0;
	if (request.size() != 32 || (client_capabilities & CLIENT_SSL) == 0) {
		observation.pre_tls_payload = true;
		observation.error = "non_tls_handshake_refused";
		report(observation);
		close(client);
		SSL_CTX_free(context);
		return 1;
	}
	if (options.mode == "close_transport") {
		observation.error = "transport_closed";
		report(observation);
		close(client);
		SSL_CTX_free(context);
		return 0;
	}
	SSL *ssl = SSL_new(context);
	SSL_set_fd(ssl, client);
	if (SSL_accept(ssl) != 1) {
		observation.error = "tls_accept_failed";
		report(observation);
		SSL_free(ssl);
		close(client);
		SSL_CTX_free(context);
		return options.mode == "wrong_hostname" || options.mode == "untrusted_ca" ||
			options.mode == "delay_handshake" ? 0 : 1;
	}
	observation.tls = true;
	const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (sni != nullptr) observation.sni = sni;

	auto ssl_reader = [ssl](unsigned char *data, size_t size) {
		return read_exact_ssl(ssl, data, size);
	};
	auto ssl_writer = [ssl](const unsigned char *data, size_t size) {
		return write_exact_ssl(ssl, data, size);
	};
	if (!read_packet(ssl_reader, request, sequence)) {
		observation.error = "tls_handshake_response_failed";
		report(observation);
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(client);
		SSL_CTX_free(context);
		return 1;
	}
	observation.username = parse_username(request);
	if (!write_packet(ssl_writer, auth_switch(), static_cast<unsigned char>(sequence + 1))) {
		observation.error = "auth_switch_write_failed";
	} else if (!read_packet(ssl_reader, request, sequence)) {
		observation.error = "auth_response_read_failed";
	} else if (request.empty() || request.back() != 0) {
		observation.error = "auth_response_not_nul_terminated";
	} else {
		observation.token_length = request.size() - 1;
		observation.token_sha256 = sha256(request.data(), observation.token_length);
		const std::vector<unsigned char> terminal = options.mode == "access_denied"
			? access_denied_packet() : ok_packet();
		if (!write_packet(ssl_writer, terminal, static_cast<unsigned char>(sequence + 1))) {
			observation.error = "terminal_write_failed";
		}
	}

	report(observation);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(client);
	SSL_CTX_free(context);
	return observation.error == "none" ? 0 : 1;
}
