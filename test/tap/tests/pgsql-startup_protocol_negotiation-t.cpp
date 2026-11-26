/**
 * @file pgsql-startup_protocol_negotiation-t.cpp
 * @brief Checks that ProxySQL answers a startup packet it cannot fully honour instead of
 *        closing the socket without a word.
 *
 * The protocol version a client asks for in its startup packet is negotiable in its minor part.
 * PostgreSQL answers a minor version it does not implement with NegotiateProtocolVersion, names
 * the version it does speak, and carries on; only the major version is fatal, and that is reported
 * as an error message. ProxySQL used to accept 3.0 and 3.1 only and drop every other startup
 * packet, so a client asking for 3.2 (PostgreSQL 18) saw a closed socket and could only report a
 * generic connection failure.
 *
 * Each case below is checked against ProxySQL only; the same probes run against a real PostgreSQL
 * produce the same replies, which is what they were written from.
 */

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <cstring>
#include <string>
#include <vector>

#include <openssl/ssl.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "pgsql_raw_client.h"

constexpr uint32_t PG_PROTOCOL_30 = 0x00030000;  // what ProxySQL speaks
constexpr uint32_t PG_PROTOCOL_32 = 0x00030002;  // PostgreSQL 18, negotiated down to 3.0
constexpr uint32_t PG_PROTOCOL_40 = 0x00040000;  // no such major version, must be refused
constexpr uint32_t PG_GSS_ENCRYPT_CODE = 80877104;
constexpr uint32_t PG_SSL_REQUEST_CODE = 80877103;

// The frontend user the probes log in as. None of them completes authentication, but ProxySQL
// answers with a challenge either way, so the value only has to be the one the harness configured.
static std::string frontend_user;

/**
 * @brief Asks for TLS and completes the handshake, returning the encrypted channel.
 *
 * A TLS client sends its startup packet on the encrypted stream, which means the startup handler
 * runs twice and the connection is in a different internal state the second time. Errors raised
 * on that second pass used to abort the whole proxy, so the cases below are worth running over
 * TLS as well as in the clear.
 */
static SSL* tls_connect(int sock, SSL_CTX** out_ctx) {
	std::vector<uint8_t> request;
	put_uint32(request, 8);
	put_uint32(request, PG_SSL_REQUEST_CODE);
	if (!send_exact(sock, request.data(), request.size())) return nullptr;

	char answer = 0;
	if (!recv_exact(sock, &answer, 1) || answer != 'S') return nullptr;

	SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == nullptr) return nullptr;
	SSL* tls = SSL_new(ctx);
	SSL_set_fd(tls, sock);
	if (SSL_connect(tls) != 1) {
		SSL_free(tls);
		SSL_CTX_free(ctx);
		return nullptr;
	}
	*out_ctx = ctx;
	return tls;
}

/** Opens a connection and sends a startup packet asking for `version`. */
static int send_startup(const std::string& host, int port, uint32_t version,
						const std::vector<std::pair<std::string, std::string>>& extra_params) {
	int sock = create_raw_connection(host, port);
	if (sock < 0) return -1;

	std::vector<uint8_t> pkt(4);  // length, filled in below
	put_uint32(pkt, version);

	std::vector<std::pair<std::string, std::string>> params = {{"user", frontend_user}, {"database", "postgres"}};
	params.insert(params.end(), extra_params.begin(), extra_params.end());
	for (const auto& [name, value] : params) {
		pkt.insert(pkt.end(), name.begin(), name.end());
		pkt.push_back(0);
		pkt.insert(pkt.end(), value.begin(), value.end());
		pkt.push_back(0);
	}
	pkt.push_back(0);

	const uint32_t len = pkt.size();
	pkt[0] = (len >> 24) & 0xFF;
	pkt[1] = (len >> 16) & 0xFF;
	pkt[2] = (len >> 8) & 0xFF;
	pkt[3] = len & 0xFF;

	if (!send_exact(sock, pkt.data(), pkt.size())) {
		close(sock);
		return -1;
	}
	return sock;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(15);

	frontend_user = cl.pgsql_username;
	const std::string host = cl.pgsql_host;
	const int port = cl.pgsql_port;

	char type = 0;
	std::vector<uint8_t> body;

	// A version we implement is not negotiated: the authentication request comes first.
	{
		int sock = send_startup(host, port, PG_PROTOCOL_30, {});
		// Read first, then assert: passing `type` straight to ok() would print it before
		// read_message() has filled it in.
		const bool answered = sock >= 0 && read_message(sock, type, body);
		ok(answered && type == 'R',
		   "protocol 3.0: answered with an authentication request, no negotiation (got '%c')", type);
		if (sock >= 0) close(sock);
	}

	// A higher minor version is negotiated down rather than dropped.
	{
		int sock = send_startup(host, port, PG_PROTOCOL_32, {});
		bool got = sock >= 0 && read_message(sock, type, body);
		ok(got && type == 'v', "protocol 3.2: answered with NegotiateProtocolVersion (got '%c')", type);

		const uint32_t version = (got && body.size() >= 8) ? get_uint32(body, 0) : 0;
		const uint32_t options = (got && body.size() >= 8) ? get_uint32(body, 4) : 1;
		// PostgreSQL puts the whole version number here, not the minor alone, and libpq compares
		// it as a whole number. 3.0 is 196608.
		ok(version == PG_PROTOCOL_30 && options == 0,
		   "protocol 3.2: negotiated down to %u.%u with no unsupported options (version=%u, options=%u)",
		   version >> 16, version & 0xFFFF, version, options);

		const bool authenticating = got && read_message(sock, type, body);
		ok(authenticating && type == 'R',
		   "protocol 3.2: connection continues to the authentication request (got '%c')", type);
		if (sock >= 0) close(sock);
	}

	// Protocol extensions we do not implement are reported back, whatever the version.
	{
		int sock = send_startup(host, port, PG_PROTOCOL_30, {{"_pq_.made_up_extension", "1"}});
		bool got = sock >= 0 && read_message(sock, type, body);
		const uint32_t options = (got && type == 'v' && body.size() >= 8) ? get_uint32(body, 4) : 0;
		const std::string name = (options == 1) ? std::string((const char*)&body[8]) : "";
		ok(type == 'v' && options == 1 && name == "_pq_.made_up_extension",
		   "unknown _pq_ option is reported as unsupported (got '%c', %u option(s), '%s')",
		   type, options, name.c_str());

		const bool authenticating = got && read_message(sock, type, body);
		ok(authenticating && type == 'R',
		   "unknown _pq_ option: connection continues to the authentication request (got '%c')", type);
		if (sock >= 0) close(sock);
	}

	// An unsupported major version is fatal, but it is said out loud.
	{
		int sock = send_startup(host, port, PG_PROTOCOL_40, {});
		bool got = sock >= 0 && read_message(sock, type, body);
		ok(got && type == 'E', "protocol 4.0: refused with an error packet, not a silent close (got '%c')", type);
		const std::string sqlstate = got ? error_field(body, 'C') : "";
		ok(sqlstate == "0A000", "protocol 4.0: refused as feature-not-supported (SQLSTATE '%s')", sqlstate.c_str());
		if (sock >= 0) close(sock);
	}

	// A GSSAPI encryption request is refused with 'N', which leaves the connection usable.
	{
		int sock = create_raw_connection(host, port);
		std::vector<uint8_t> pkt;
		put_uint32(pkt, 8);
		put_uint32(pkt, PG_GSS_ENCRYPT_CODE);

		char reply = 0;
		bool answered = sock >= 0 && send_exact(sock, pkt.data(), pkt.size()) &&
						recv_exact(sock, &reply, 1);
		ok(answered && reply == 'N', "GSSAPI encryption request: refused with 'N' (got '%c')", reply);

		// Same socket, as a client falling back to an unencrypted connection would use it.
		bool continued = false;
		if (answered && reply == 'N') {
			std::vector<uint8_t> startup(4);
			put_uint32(startup, PG_PROTOCOL_30);
			for (const std::string& p : {std::string("user"), frontend_user, std::string("database"), std::string("postgres")}) {
				startup.insert(startup.end(), p.begin(), p.end());
				startup.push_back(0);
			}
			startup.push_back(0);
			const uint32_t len = startup.size();
			startup[0] = (len >> 24) & 0xFF;
			startup[1] = (len >> 16) & 0xFF;
			startup[2] = (len >> 8) & 0xFF;
			startup[3] = len & 0xFF;
			continued = send_exact(sock, startup.data(), startup.size()) &&
						read_message(sock, type, body) && type == 'R';
		}
		ok(continued, "GSSAPI encryption request: startup on the same connection still works (got '%c')", type);
		if (sock >= 0) close(sock);
	}

	// The same negotiation, and the same refusal, on an encrypted connection.
	{
		SSL_CTX* ctx = nullptr;
		int sock = create_raw_connection(host, port);
		SSL* tls = (sock >= 0) ? tls_connect(sock, &ctx) : nullptr;

		const std::vector<uint8_t> pkt = startup_packet(PG_PROTOCOL_32, frontend_user);
		bool got = tls != nullptr && send_exact(sock, pkt.data(), pkt.size(), tls) &&
				   read_message(sock, type, body, tls);
		const uint32_t version = (got && type == 'v' && body.size() >= 8) ? get_uint32(body, 0) : 0;
		ok(got && type == 'v' && version == PG_PROTOCOL_30,
		   "TLS + protocol 3.2: negotiated down over the encrypted connection (got '%c', version=%u)", type, version);

		const bool authenticating = got && read_message(sock, type, body, tls);
		ok(authenticating && type == 'R',
		   "TLS + protocol 3.2: continues to the authentication request (got '%c')", type);

		if (tls) { SSL_free(tls); SSL_CTX_free(ctx); }
		if (sock >= 0) close(sock);
	}

	// An error raised while reading a startup packet on an encrypted connection. This used to
	// abort the proxy outright, so the check that follows it matters as much as this one.
	{
		SSL_CTX* ctx = nullptr;
		int sock = create_raw_connection(host, port);
		SSL* tls = (sock >= 0) ? tls_connect(sock, &ctx) : nullptr;

		const std::vector<uint8_t> pkt = startup_packet(PG_PROTOCOL_40, frontend_user);
		const bool got = tls != nullptr && send_exact(sock, pkt.data(), pkt.size(), tls) &&
						 read_message(sock, type, body, tls);
		const std::string sqlstate = got ? error_field(body, 'C') : "";
		ok(got && type == 'E' && sqlstate == "0A000",
		   "TLS + protocol 4.0: refused with an error packet over TLS (got '%c', SQLSTATE '%s')",
		   type, sqlstate.c_str());

		if (tls) { SSL_free(tls); SSL_CTX_free(ctx); }
		if (sock >= 0) close(sock);
	}

	// The same crash reached through code the negotiation work never touched: a startup packet
	// that simply carries no user name. Going through an older path keeps this check tied to the
	// crash itself rather than to how an unsupported version happens to be handled.
	{
		SSL_CTX* ctx = nullptr;
		int sock = create_raw_connection(host, port);
		SSL* tls = (sock >= 0) ? tls_connect(sock, &ctx) : nullptr;

		std::vector<uint8_t> pkt(4);
		put_uint32(pkt, PG_PROTOCOL_30);
		for (const std::string& p : {std::string("database"), std::string("postgres")}) {
			pkt.insert(pkt.end(), p.begin(), p.end());
			pkt.push_back(0);
		}
		pkt.push_back(0);
		const uint32_t len = pkt.size();
		pkt[0] = (len >> 24) & 0xFF;
		pkt[1] = (len >> 16) & 0xFF;
		pkt[2] = (len >> 8) & 0xFF;
		pkt[3] = len & 0xFF;

		const bool got = tls != nullptr && send_exact(sock, pkt.data(), pkt.size(), tls) &&
						 read_message(sock, type, body, tls);
		const std::string sqlstate = got ? error_field(body, 'C') : "";
		ok(got && type == 'E' && sqlstate == "28000",
		   "TLS + startup with no user name: refused with an error packet (got '%c', SQLSTATE '%s')",
		   type, sqlstate.c_str());

		if (tls) { SSL_free(tls); SSL_CTX_free(ctx); }
		if (sock >= 0) close(sock);
	}

	// ProxySQL is still serving after the errors above.
	{
		int sock = send_startup(host, port, PG_PROTOCOL_30, {});
		const bool answered = sock >= 0 && read_message(sock, type, body);
		ok(answered && type == 'R',
		   "ProxySQL still accepts connections after a TLS startup error (got '%c')", type);
		if (sock >= 0) close(sock);
	}

	return exit_status();
}
