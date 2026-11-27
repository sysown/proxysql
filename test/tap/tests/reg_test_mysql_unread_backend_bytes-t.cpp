#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <netdb.h>
#include <poll.h>
#include <netinet/tcp.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>
#include <zlib.h>

namespace {
constexpr unsigned int hostgroup = 946542;
constexpr uint16_t status_autocommit = 0x0002;
constexpr uint16_t status_more_results = 0x0008;
constexpr uint32_t client_compress = 0x00000020;
constexpr uint32_t client_capabilities =
	0x00000001 | 0x00000004 | 0x00000008 | client_compress | 0x00000200 |
	0x00002000 | 0x00008000 | 0x00010000 | 0x00020000 | 0x00080000 | 0x00200000;

enum class DuplicateMode { SameWrite, AfterPool, Compressed };

MYSQL* admin = nullptr;
bool added_server = false;
bool added_user = false;
const std::string frontend_username = "unread_backend_bytes_test";
const std::string frontend_password = "unread_backend_bytes_test";
std::string advertised_address;

void append_u16(std::string& out, uint16_t value) {
	out.push_back(static_cast<char>(value));
	out.push_back(static_cast<char>(value >> 8));
}

void append_u24(std::string& out, uint32_t value) {
	out.push_back(static_cast<char>(value));
	out.push_back(static_cast<char>(value >> 8));
	out.push_back(static_cast<char>(value >> 16));
}

uint32_t read_u24(const unsigned char* bytes) {
	return static_cast<uint32_t>(bytes[0]) |
		(static_cast<uint32_t>(bytes[1]) << 8) |
		(static_cast<uint32_t>(bytes[2]) << 16);
}

bool write_all(int fd, const char* bytes, size_t length) {
	size_t written = 0;
	while (written < length) {
		ssize_t n = send(fd, bytes + written, length - written, MSG_NOSIGNAL);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) return false;
		written += static_cast<size_t>(n);
	}
	return true;
}

bool read_all(int fd, char* bytes, size_t length) {
	size_t received = 0;
	while (received < length) {
		ssize_t n = recv(fd, bytes + received, length - received, 0);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) return false;
		received += static_cast<size_t>(n);
	}
	return true;
}

std::string packet(uint8_t sequence, const std::string& payload) {
	std::string out;
	append_u24(out, static_cast<uint32_t>(payload.size()));
	out.push_back(static_cast<char>(sequence));
	out += payload;
	return out;
}

std::string lenenc_string(const std::string& value) {
	std::string out;
	if (value.size() < 251) {
		out.push_back(static_cast<char>(value.size()));
	} else {
		out.push_back(static_cast<char>(0xfc));
		append_u16(out, static_cast<uint16_t>(value.size()));
	}
	out += value;
	return out;
}

std::string ok_packet() {
	std::string out("\0\0\0", 3);
	append_u16(out, status_autocommit);
	append_u16(out, 0);
	return out;
}

std::string eof_packet(uint16_t status) {
	std::string out("\xfe\0\0", 3);
	append_u16(out, status);
	return out;
}

std::string column_definition() {
	std::string out;
	for (const char* field : {"def", "demo", "values", "values", "value", "value"})
		out += lenenc_string(field);
	out.push_back(static_cast<char>(0x0c));
	append_u16(out, 33);
	out.append("\xff\0\0\0", 4);
	out.push_back(static_cast<char>(253));
	append_u16(out, 0);
	out.push_back('\0');
	out.append("\0\0", 2);
	return out;
}

std::vector<std::string> selected_values(const std::string& sql) {
	std::vector<std::string> values;
	const std::string prefix = "SELECT '";
	const std::string suffix = "' AS value";
	size_t offset = 0;
	while ((offset = sql.find(prefix, offset)) != std::string::npos) {
		const size_t value_start = offset + prefix.size();
		const size_t value_end = sql.find(suffix, value_start);
		if (value_end == std::string::npos) break;
		values.push_back(sql.substr(value_start, value_end - value_start));
		offset = value_end + suffix.size();
	}
	return values;
}

std::string result_sets(const std::vector<std::string>& values) {
	std::string out;
	uint8_t sequence = 1;
	for (size_t i = 0; i < values.size(); ++i) {
		const uint16_t status = status_autocommit |
			(i + 1 < values.size() ? status_more_results : 0);
		for (const std::string& payload : {
			std::string("\x01", 1), column_definition(), eof_packet(status_autocommit),
			lenenc_string(values[i]), eof_packet(status)})
			out += packet(sequence++, payload);
	}
	return out;
}

sockaddr_in address(const char* host, int port) {
	addrinfo hints{};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	addrinfo* result = nullptr;
	if (getaddrinfo(host, std::to_string(port).c_str(), &hints, &result) || !result)
		BAIL_OUT("Cannot resolve %s:%d", host, port);
	sockaddr_in out = *reinterpret_cast<sockaddr_in*>(result->ai_addr);
	freeaddrinfo(result);
	return out;
}

std::string local_address(const CommandLine& cl) {
	sockaddr_in peer = address(cl.host, cl.port);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	sockaddr_in local{};
	socklen_t length = sizeof(local);
	const bool valid = fd >= 0 &&
		connect(fd, reinterpret_cast<sockaddr*>(&peer), sizeof(peer)) == 0 &&
		getsockname(fd, reinterpret_cast<sockaddr*>(&local), &length) == 0;
	if (fd >= 0) close(fd);
	char ip[INET_ADDRSTRLEN]{};
	if (!valid || !inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip)))
		BAIL_OUT("Cannot discover an address reachable by ProxySQL");
	return ip;
}

std::string handshake_packet() {
	const std::string salt = "unread-backend-bytes-salt";
	std::string out;
	out.push_back(10);
	out += "8.0.0-unread-backend-bytes";
	out.push_back('\0');
	out.append("\x01\0\0\0", 4);
	out.append(salt.data(), 8);
	out.push_back('\0');
	append_u16(out, static_cast<uint16_t>(client_capabilities));
	out.push_back(45);
	append_u16(out, status_autocommit);
	append_u16(out, static_cast<uint16_t>(client_capabilities >> 16));
	out.push_back(21);
	out.append(10, '\0');
	out.append(salt.data() + 8, 12);
	out.push_back('\0');
	out += "mysql_native_password";
	out.push_back('\0');
	return out;
}

bool read_classic_packet(int fd, std::string& payload) {
	unsigned char header[4];
	if (!read_all(fd, reinterpret_cast<char*>(header), sizeof(header))) return false;
	const uint32_t length = read_u24(header);
	payload.resize(length);
	return read_all(fd, payload.data(), payload.size());
}

bool read_compressed_packet(int fd, std::string& buffered, std::string& payload, uint8_t& response_sequence) {
	while (buffered.size() < 4 || buffered.size() < read_u24(
		reinterpret_cast<const unsigned char*>(buffered.data())) + 4) {
		unsigned char header[7];
		if (!read_all(fd, reinterpret_cast<char*>(header), sizeof(header))) return false;
		const uint32_t compressed_length = read_u24(header);
		response_sequence = static_cast<uint8_t>(header[3] + 1);
		const uint32_t uncompressed_length = read_u24(header + 4);
		std::string frame(compressed_length, '\0');
		if (!read_all(fd, frame.data(), frame.size())) return false;
		if (uncompressed_length == 0) {
			buffered += frame;
		} else {
			std::string inflated(uncompressed_length, '\0');
			uLongf inflated_length = uncompressed_length;
			if (uncompress(reinterpret_cast<Bytef*>(inflated.data()), &inflated_length,
				reinterpret_cast<const Bytef*>(frame.data()), frame.size()) != Z_OK ||
				inflated_length != uncompressed_length)
				return false;
			buffered += inflated;
		}
	}
	const uint32_t length = read_u24(reinterpret_cast<const unsigned char*>(buffered.data()));
	payload.assign(buffered.data() + 4, length);
	buffered.erase(0, length + 4);
	return true;
}

bool write_compressed_packet(int fd, uint8_t sequence, const std::string& bytes) {
	// An uncompressed frame keeps both replies together for the buffered-byte case.
	std::string frame;
	append_u24(frame, static_cast<uint32_t>(bytes.size()));
	frame.push_back(static_cast<char>(sequence));
	append_u24(frame, 0);
	frame += bytes;
	return write_all(fd, frame.data(), frame.size());
}

class FakeBackend {
	int listener_ = -1;
	std::thread accept_thread_;
	std::vector<std::thread> handlers_;
	std::vector<int> sockets_;
	std::atomic<bool> stopping_{false};
	std::mutex mutex_;
	std::condition_variable changed_;
	int late_socket_ = -1;
	std::string late_reply_;
	bool compressed_negotiated_ = false;

	size_t compressed_reply_size_ = 0;
	size_t compressed_followup_packet_size_ = 0;
	DuplicateMode mode_;

	void serve(int fd) {
		const std::string greeting = packet(0, handshake_packet());
		std::string packet_bytes;
		if (!write_all(fd, greeting.data(), greeting.size()) ||
			!read_classic_packet(fd, packet_bytes) || packet_bytes.size() < 4)
			return;
		const auto* login = reinterpret_cast<const unsigned char*>(packet_bytes.data());
		const uint32_t capabilities = static_cast<uint32_t>(login[0]) |
			(static_cast<uint32_t>(login[1]) << 8) |
			(static_cast<uint32_t>(login[2]) << 16) |
			(static_cast<uint32_t>(login[3]) << 24);
		const bool compressed = (capabilities & client_compress) != 0;
		const std::string auth_ok = packet(2, ok_packet());
		if (!write_all(fd, auth_ok.data(), auth_ok.size())) return;

		std::string buffered;
		while (!stopping_) {
			std::string command;
			uint8_t response_sequence = 1;
			const bool received = compressed
				? read_compressed_packet(fd, buffered, command, response_sequence)
				: read_classic_packet(fd, command);
			if (!received || command.empty()) return;
			const uint8_t command_type = static_cast<uint8_t>(command[0]);
			if (command_type == 1) return;

			std::string response;
			if (command_type == 3) {
				const std::string sql = command.substr(1);
				const std::vector<std::string> values = selected_values(sql);
				const std::string reply = values.empty() ? packet(1, ok_packet()) : result_sets(values);
				if (mode_ == DuplicateMode::Compressed && sql.find("SELECT 'second' AS value") != std::string::npos) {
					std::lock_guard<std::mutex> lock(mutex_);
					compressed_followup_packet_size_ = command.size() + 4;
				}
				if (sql.find("SELECT 'first' AS value") != std::string::npos) {
					if (mode_ == DuplicateMode::Compressed) {
						std::lock_guard<std::mutex> lock(mutex_);
						compressed_negotiated_ = compressed;
						compressed_reply_size_ = reply.size();
					}
					if (mode_ == DuplicateMode::SameWrite || mode_ == DuplicateMode::Compressed) {
						response = reply + reply;
					} else {
						response = reply;
						std::lock_guard<std::mutex> lock(mutex_);
						late_socket_ = fd;
						late_reply_ = reply;
						changed_.notify_all();
					}
				} else {
					response = reply;
				}
			} else if (command_type == 0x1b) {
				response = packet(1, eof_packet(status_autocommit));
			} else {
				response = packet(1, ok_packet());
			}
			if (compressed) {
				if (!write_compressed_packet(fd, response_sequence, response)) return;
			} else if (!write_all(fd, response.data(), response.size())) {
				return;
			}
		}
	}

	void accept_connections() {
		while (!stopping_) {
			pollfd p{listener_, POLLIN, 0};
			const int rc = poll(&p, 1, 100);
			if (rc <= 0 || !p.revents) continue;
			int fd = accept(listener_, nullptr, nullptr);
			if (fd < 0) continue;
			int one = 1;
			setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
			timeval timeout{10, 0};
			setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
			setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
			sockets_.push_back(fd);
			handlers_.emplace_back([this, fd] { serve(fd); });
		}
	}

public:
	int port = 0;

	FakeBackend(DuplicateMode mode) : mode_(mode) {
		listener_ = socket(AF_INET, SOCK_STREAM, 0);
		sockaddr_in local{};
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = htonl(INADDR_ANY);
		local.sin_port = 0;
		socklen_t length = sizeof(local);
		if (listener_ < 0 || bind(listener_, reinterpret_cast<sockaddr*>(&local), length) != 0 ||
			listen(listener_, 16) != 0 ||
			getsockname(listener_, reinterpret_cast<sockaddr*>(&local), &length) != 0)
			BAIL_OUT("Cannot listen for fake backend: %s", strerror(errno));
		port = ntohs(local.sin_port);
		accept_thread_ = std::thread([this] { accept_connections(); });
	}
	~FakeBackend() {
		stopping_ = true;
		if (listener_ >= 0) {
			shutdown(listener_, SHUT_RDWR);
			close(listener_);
		}
		if (accept_thread_.joinable()) accept_thread_.join();
		{
			std::lock_guard<std::mutex> lock(mutex_);
			for (int fd : sockets_) shutdown(fd, SHUT_RDWR);
		}
		changed_.notify_all();
		for (std::thread& handler : handlers_) if (handler.joinable()) handler.join();
		for (int fd : sockets_) close(fd);
	}

	bool send_duplicate() {
		std::unique_lock<std::mutex> lock(mutex_);
		if (!changed_.wait_for(lock, std::chrono::seconds(10), [&] { return late_socket_ >= 0; }))
			return false;
		const bool sent = write_all(late_socket_, late_reply_.data(), late_reply_.size());
		return sent;
	}

	bool compression_negotiated() {
		std::lock_guard<std::mutex> lock(mutex_);
		return compressed_negotiated_;
	}

	size_t compressed_reply_size() {
		std::lock_guard<std::mutex> lock(mutex_);
		return compressed_reply_size_;
	}

	size_t compressed_followup_packet_size() {
		std::lock_guard<std::mutex> lock(mutex_);
		return compressed_followup_packet_size_;
	}

};

MYSQL* connect_mysql(const CommandLine& cl, bool is_admin = false) {
	MYSQL* c = mysql_init(nullptr);
	unsigned int timeout = 10;
	mysql_options(c, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	mysql_options(c, MYSQL_OPT_READ_TIMEOUT, &timeout);
	mysql_options(c, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
	c->options.client_flag &= ~CLIENT_DEPRECATE_EOF;
	if (!mysql_real_connect(c, is_admin ? cl.admin_host : cl.host,
		is_admin ? cl.admin_username : frontend_username.c_str(),
		is_admin ? cl.admin_password : frontend_password.c_str(), nullptr,
		is_admin ? cl.admin_port : cl.port, nullptr,
		is_admin ? 0 : CLIENT_MULTI_STATEMENTS | CLIENT_MULTI_RESULTS))
		BAIL_OUT("Connect: %s", mysql_error(c));
	return c;
}

void query(MYSQL* c, const std::string& sql) {
	if (mysql_query(c, sql.c_str())) BAIL_OUT("%s: %s", sql.c_str(), mysql_error(c));
}

std::string scalar(MYSQL* c, const std::string& sql) {
	query(c, sql);
	MYSQL_RES* result = mysql_store_result(c);
	if (!result) BAIL_OUT("Missing result for %s: %s", sql.c_str(), mysql_error(c));
	MYSQL_ROW row = mysql_fetch_row(result);
	std::string value = row && row[0] ? row[0] : "";
	mysql_free_result(result);
	return value;
}


struct Results {
	std::vector<std::vector<std::string>> sets;
	unsigned int error = 0;
	std::string message;

	std::string describe() const {
		std::string out = "[";
		for (size_t i = 0; i < sets.size(); ++i) {
			if (i) out += ",";
			out += "[";
			for (size_t j = 0; j < sets[i].size(); ++j) {
				if (j) out += ",";
				out += sets[i][j];
			}
			out += "]";
		}
		return out + "] error=" + std::to_string(error) + " " + message;
	}
};

Results execute(MYSQL* c, const std::string& sql) {
	Results out;
	int rc = mysql_query(c, sql.c_str());
	while (rc == 0) {
		MYSQL_RES* result = mysql_store_result(c);
		if (result) {
			std::vector<std::string> values;
			MYSQL_ROW row;
			while ((row = mysql_fetch_row(result))) values.push_back(row[0] ? row[0] : "<NULL>");
			out.sets.push_back(std::move(values));
			mysql_free_result(result);
		} else if (mysql_field_count(c) != 0 || mysql_errno(c) != 0) {
			out.error = mysql_errno(c);
			out.message = mysql_error(c);
			return out;
		}
		rc = mysql_next_result(c);
	}
	if (rc > 0) {
		out.error = mysql_errno(c);
		out.message = mysql_error(c);
	}
	return out;
}

void restore() {
	if (admin) {
		std::vector<std::string> statements;
		if (added_server) {
			statements.push_back("DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(hostgroup));
			statements.push_back("LOAD MYSQL SERVERS TO RUNTIME");
		}
		if (added_user) {
			statements.push_back("DELETE FROM mysql_users WHERE username='" + frontend_username + "' AND frontend=1");
			statements.push_back("LOAD MYSQL USERS TO RUNTIME");
		}
		for (const std::string& sql : statements) {
			if (mysql_query(admin, sql.c_str())) {
				diag("Cleanup failed: %s: %s", sql.c_str(), mysql_error(admin));
				std::_Exit(EXIT_FAILURE);
			}
		}
		mysql_close(admin);
		admin = nullptr;
	}
}

void run_scenario(const CommandLine& cl, DuplicateMode mode, const char* label) {
	FakeBackend backend(mode);
	query(admin, "DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(hostgroup));
	added_server = true;
	query(admin, "INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,max_connections,use_ssl,compression) VALUES (" +
		std::to_string(hostgroup) + ",'" + advertised_address + "'," + std::to_string(backend.port) +",'ONLINE',1,0," +
		(mode == DuplicateMode::Compressed ? "1" : "0") + ")");
	query(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	const std::string first_sql = "SELECT 'first' AS value";
	const std::string standard_second_sql = "SELECT 'second-a' AS value; SELECT 'second-b' AS value; SELECT 'second-c' AS value";
	const std::string compressed_second_sql = "SELECT 'second' AS value";
	const std::string second_sql = mode == DuplicateMode::Compressed ? compressed_second_sql : standard_second_sql;
	const std::string third_sql = "SELECT 'third' AS value";
	MYSQL* first = connect_mysql(cl);
	Results first_result = execute(first, first_sql);
	mysql_close(first);
	const bool first_ok = first_result.error == 0 && first_result.sets == std::vector<std::vector<std::string>>{{"first"}} &&
		(mode != DuplicateMode::Compressed || backend.compression_negotiated());
	ok(first_ok, "%s: first client gets its own result: %s; compression=%d", label,
		first_result.describe().c_str(), backend.compression_negotiated());

	if (mode == DuplicateMode::AfterPool) {
		// Let ProxySQL return the completed backend exchange before the copy arrives.
		usleep(100000);
		const bool sent = backend.send_duplicate();
		// The checkout can only reject the connection once the copy reaches its socket.
		usleep(100000);
		if (!sent) diag("%s: fake backend could not send the delayed copy", label);
	}

	MYSQL* second = connect_mysql(cl);
	Results second_result = execute(second, second_sql);
	mysql_close(second);
	if (mode == DuplicateMode::Compressed) {
		ok(backend.compressed_reply_size() == 85 && backend.compressed_followup_packet_size() < 87,
			"%s: duplicate reply is 85 bytes and the next COM_QUERY packet (%zu bytes) "
			"is shorter than the 87 that would corrupt the copy's header",
			label, backend.compressed_followup_packet_size());
		ok(second_result.error == 0 && second_result.sets == std::vector<std::vector<std::string>>{{"second"}},
			"%s: second client gets its own result set: %s", label, second_result.describe().c_str());
	} else {
		ok(second_result.error == 0 && second_result.sets ==
			std::vector<std::vector<std::string>>{{"second-a"}, {"second-b"}, {"second-c"}},
			"%s: second client gets its three result sets: %s", label, second_result.describe().c_str());
	}

	MYSQL* third = connect_mysql(cl);
	Results third_result = execute(third, third_sql);
	mysql_close(third);
	ok(third_result.error == 0 && third_result.sets == std::vector<std::vector<std::string>>{{"third"}},
		"%s: third client gets its own result set: %s", label, third_result.describe().c_str());

	query(admin, "DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(hostgroup));
	query(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	added_server = false;
}
}

int main() {
	alarm(120);
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	plan(10);
	admin = connect_mysql(cl, true);
	if (std::atexit(restore)) BAIL_OUT("Cannot register cleanup");
	if (scalar(admin, "SELECT count(*) FROM mysql_servers WHERE hostgroup_id=" + std::to_string(hostgroup)) != "0")
		BAIL_OUT("Private test hostgroup already exists");
	const std::string user = "'" + frontend_username + "'";
	if (scalar(admin, "SELECT count(*) FROM mysql_users WHERE username=" + user + " AND frontend=1") != "0")
		BAIL_OUT("Private test user already exists");
	added_user = true;
	query(admin, "INSERT INTO mysql_users(username,password,active,default_hostgroup,transaction_persistent,fast_forward,frontend,backend) VALUES ('" +
		frontend_username + "','" + frontend_password + "',1," + std::to_string(hostgroup) + ",0,0,1,0)");
	query(admin, "LOAD MYSQL USERS TO RUNTIME");
	advertised_address = local_address(cl);
	run_scenario(cl, DuplicateMode::SameWrite, "same write");
	run_scenario(cl, DuplicateMode::AfterPool, "copy after pool return");
	run_scenario(cl, DuplicateMode::Compressed, "compressed packet");
	restore();
	return exit_status();
}
