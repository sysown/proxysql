/**
 * OFFLINE_HARD may replay an unanswered batch, but not a batch whose first
 * result has reached the client. The relay forwards real MySQL traffic and
 * holds bytes at the fault boundary without manufacturing protocol replies.
 */
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {
MYSQL* admin = nullptr;
bool saved_rules = false;
bool added_servers = false;

void query(MYSQL* c, const std::string& sql) {
	if (mysql_query(c, sql.c_str())) BAIL_OUT("%s: %s", sql.c_str(), mysql_error(c));
}

std::string scalar(MYSQL* c, const std::string& sql) {
	query(c, sql);
	MYSQL_RES* r = mysql_store_result(c);
	if (!r) BAIL_OUT("Missing result: %s", mysql_error(c));
	MYSQL_ROW row = mysql_fetch_row(r);
	std::string value = row && row[0] ? row[0] : "";
	mysql_free_result(r);
	return value;
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

// Select the runner's interface facing ProxySQL, not the runner's loopback.
std::string local_address(const CommandLine& cl) {
	sockaddr_in peer = address(cl.host, cl.port);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	sockaddr_in local{};
	socklen_t len = sizeof(local);
	bool valid = fd >= 0 && ::connect(fd, reinterpret_cast<sockaddr*>(&peer), sizeof(peer)) == 0
		&& getsockname(fd, reinterpret_cast<sockaddr*>(&local), &len) == 0;
	if (fd >= 0) close(fd);
	char ip[INET_ADDRSTRLEN]{};
	if (!valid || !inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip)))
		BAIL_OUT("Cannot discover a runner address reachable by ProxySQL");
	return ip;
}

class TrafficGate {
	struct Connection {
		int proxy = -1;
		int backend = -1;
		std::thread thread;
		std::string prefix;
	};
	int listener = -1;
	std::thread acceptor;
	std::vector<std::unique_ptr<Connection>> connections;
	std::atomic<bool> stopped{false};
	std::mutex mutex;
	std::condition_variable changed;
	Connection* target = nullptr;
	size_t response_bytes = 0;
	size_t remaining = 0;
	bool armed = false;
	bool response_direction = false;
	bool held = false;
	bool dropped = false;
	std::string blocked_request;
	sockaddr_in upstream{};

	bool forward(Connection* c, int direction, char* bytes, size_t length) {
		std::unique_lock<std::mutex> lock(mutex);
		if (direction == 0 && !target) {
			c->prefix.append(bytes, length);
			if (c->prefix.find("partial_retry_warm") != std::string::npos) target = c;
			if (c->prefix.size() > 4096) c->prefix.erase(0, c->prefix.size() - 4096);
		}
		if (target == c && armed && !response_direction && direction == 0) {
			blocked_request.append(bytes, length);
			if (blocked_request.size() < 4) return true;
			const unsigned char* header = reinterpret_cast<const unsigned char*>(blocked_request.data());
			const size_t packet_size = 4 + header[0] + (header[1] << 8) + (header[2] << 16);
			if (packet_size <= 65536 && blocked_request.size() < packet_size) return true;
			held = true;
			changed.notify_all();
			changed.wait(lock, [&] { return stopped || dropped; });
			return false;
		}
		size_t count = length;
		if (target == c && armed && response_direction && direction == 1)
			count = std::min(length, remaining);
		int fd = direction == 1 ? c->proxy : c->backend;
		size_t sent = 0;
		while (sent < count && !stopped) {
			ssize_t n = send(fd, bytes + sent, count - sent, MSG_NOSIGNAL);
			if (n < 0 && errno == EINTR) continue;
			if (n <= 0) return false;
			sent += n;
		}
		if (target == c && direction == 1) response_bytes += sent;
		if (target == c && armed && response_direction && direction == 1) {
			remaining -= sent;
			if (sent < length) {
				held = true;
				changed.notify_all();
				changed.wait(lock, [&] { return stopped || dropped; });
				return false;
			}
		}
		return sent == length;
	}

	void relay(Connection* c) {
		char buffer[8192];
		while (!stopped) {
			pollfd fds[2] = {{c->proxy, POLLIN, 0}, {c->backend, POLLIN, 0}};
			int rc = poll(fds, 2, 100);
			if (rc < 0 && errno == EINTR) continue;
			if (rc < 0) break;
			bool alive = true;
			for (int i = 0; i < 2 && alive; ++i) {
				if (!fds[i].revents) continue;
				ssize_t n = recv(fds[i].fd, buffer, sizeof(buffer), 0);
				alive = n > 0 && forward(c, i, buffer, n);
			}
			if (!alive) break;
		}
		std::lock_guard<std::mutex> lock(mutex);
		shutdown(c->proxy, SHUT_RDWR);
		shutdown(c->backend, SHUT_RDWR);
	}

public:
	int port = 0;
	TrafficGate(const std::string& bind_ip, const std::string& host, int backend_port) {
		upstream = address(host.c_str(), backend_port);
		listener = socket(AF_INET, SOCK_STREAM, 0);
		sockaddr_in local = address(bind_ip.c_str(), 0);
		socklen_t len = sizeof(local);
		if (listener < 0 || bind(listener, reinterpret_cast<sockaddr*>(&local), len)
			|| listen(listener, 16) || getsockname(listener, reinterpret_cast<sockaddr*>(&local), &len))
			BAIL_OUT("Cannot listen for backend relay: %s", strerror(errno));
		port = ntohs(local.sin_port);
		acceptor = std::thread([this] {
			while (!stopped) {
				pollfd p{listener, POLLIN, 0};
				if (poll(&p, 1, 100) <= 0 || !p.revents) continue;
				int client = accept(listener, nullptr, nullptr);
				if (client < 0) continue;
				int server = socket(AF_INET, SOCK_STREAM, 0);
				int flags = server >= 0 ? fcntl(server, F_GETFL, 0) : -1;
				bool connected = false;
				if (flags >= 0 && fcntl(server, F_SETFL, flags | O_NONBLOCK) == 0) {
					int rc = ::connect(server, reinterpret_cast<sockaddr*>(&upstream), sizeof(upstream));
					if (rc == 0) connected = true;
					else if (errno == EINPROGRESS) {
						pollfd p{server, POLLOUT, 0};
						int error = 0;
						socklen_t len = sizeof(error);
						connected = poll(&p, 1, 5000) > 0
							&& getsockopt(server, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0;
					}
				}
				timeval timeout{5, 0};
				if (!connected || fcntl(server, F_SETFL, flags)
					|| setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))
					|| setsockopt(server, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) {
					close(client);
					if (server >= 0) close(server);
					continue;
				}
				std::unique_ptr<Connection> c(new Connection);
				c->proxy = client;
				c->backend = server;
				std::lock_guard<std::mutex> lock(mutex);
				c->thread = std::thread([this, ptr = c.get()] { relay(ptr); });
				connections.push_back(std::move(c));
			}
		});
	}
	~TrafficGate() {
		{
			std::lock_guard<std::mutex> lock(mutex);
			stopped = true;
		}
		changed.notify_all();
		if (acceptor.joinable()) acceptor.join();
		for (const auto& c : connections) {
			shutdown(c->proxy, SHUT_RDWR);
			shutdown(c->backend, SHUT_RDWR);
		}
		for (const auto& c : connections) {
			c->thread.join();
			close(c->proxy);
			close(c->backend);
		}
		if (listener >= 0) close(listener);
	}
	size_t bytes() {
		std::lock_guard<std::mutex> lock(mutex);
		return response_bytes;
	}
	bool arm(bool response, size_t prefix) {
		std::lock_guard<std::mutex> lock(mutex);
		if (!target) return false;
		response_direction = response;
		remaining = prefix;
		armed = true;
		return true;
	}
	bool wait_held() {
		std::unique_lock<std::mutex> lock(mutex);
		return changed.wait_for(lock, std::chrono::seconds(10), [&] { return held; });
	}
	bool request_is(const char* sql) {
		std::lock_guard<std::mutex> lock(mutex);
		return blocked_request.size() == strlen(sql) + 5 && blocked_request[4] == 3
			&& blocked_request.compare(5, std::string::npos, sql) == 0;
	}
	void drop() {
		std::lock_guard<std::mutex> lock(mutex);
		dropped = true;
		if (target) {
			shutdown(target->proxy, SHUT_RDWR);
			shutdown(target->backend, SHUT_RDWR);
		}
		changed.notify_all();
	}
};
std::unique_ptr<TrafficGate> gate;

void restore() {
	gate.reset();
	if (!admin) return;
	std::vector<std::string> statements;
	if (added_servers) {
		statements.push_back("DELETE FROM mysql_servers WHERE hostgroup_id=946541");
		statements.push_back("LOAD MYSQL SERVERS TO RUNTIME");
	}
	if (saved_rules) {
		for (const char* sql : {
			"DELETE FROM mysql_query_rules",
			"INSERT INTO mysql_query_rules SELECT * FROM partial_retry_runtime_rules",
			"DELETE FROM mysql_query_rules_fast_routing",
			"INSERT INTO mysql_query_rules_fast_routing SELECT * FROM partial_retry_runtime_fast",
			"LOAD MYSQL QUERY RULES TO RUNTIME",
			"DELETE FROM mysql_query_rules",
			"INSERT INTO mysql_query_rules SELECT * FROM partial_retry_memory_rules",
			"DELETE FROM mysql_query_rules_fast_routing",
			"INSERT INTO mysql_query_rules_fast_routing SELECT * FROM partial_retry_memory_fast",
			"DROP TABLE partial_retry_runtime_rules", "DROP TABLE partial_retry_memory_rules",
			"DROP TABLE partial_retry_runtime_fast", "DROP TABLE partial_retry_memory_fast"})
			statements.push_back(sql);
	}
	for (const auto& sql : statements) {
		if (mysql_query(admin, sql.c_str())) {
			diag("Cleanup failed: %s: %s", sql.c_str(), mysql_error(admin));
			fflush(stdout);
			std::_Exit(EXIT_FAILURE);
		}
	}
	mysql_close(admin);
	admin = nullptr;
}

MYSQL* connect(const CommandLine& cl, bool is_admin = false) {
	MYSQL* c = mysql_init(nullptr);
	unsigned int timeout = 10;
	mysql_options(c, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	mysql_options(c, MYSQL_OPT_READ_TIMEOUT, &timeout);
	mysql_options(c, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
	c->options.client_flag &= ~CLIENT_DEPRECATE_EOF;
	if (!mysql_real_connect(c, is_admin ? cl.admin_host : cl.host,
		is_admin ? cl.admin_username : cl.username, is_admin ? cl.admin_password : cl.password,
		nullptr, is_admin ? cl.admin_port : cl.port, nullptr, is_admin ? 0 : CLIENT_MULTI_STATEMENTS))
		BAIL_OUT("Connect: %s", mysql_error(c));
	return c;
}

struct Results {
	std::vector<std::string> markers;
	unsigned int error = 0;
	std::string message;
	std::string describe() const {
		std::string out = "[";
		for (const auto& marker : markers) out += (out == "[" ? "" : ",") + marker;
		return out + "] error=" + std::to_string(error) + " " + message;
	}
};

void take_result(MYSQL* c, Results& out) {
	MYSQL_RES* r = mysql_store_result(c);
	if (r) {
		MYSQL_ROW row = mysql_fetch_row(r);
		out.markers.push_back(row && row[0] ? row[0] : "<missing marker>");
		if (mysql_num_rows(r) != 1 || mysql_num_fields(r) != 1) out.markers.push_back("<unexpected shape>");
		mysql_free_result(r);
	} else if (mysql_errno(c)) {
		out.error = mysql_errno(c);
		out.message = mysql_error(c);
	}
}

void finish(MYSQL* c, Results& out, int rc) {
	while (rc == 0) {
		take_result(c, out);
		if (out.error) return;
		rc = mysql_next_result(c);
	}
	if (rc > 0) {
		out.error = mysql_errno(c);
		out.message = mysql_error(c);
	}
}

const char* batch = "/* query_retries=1 */ SELECT 41 AS partial_retry_marker; SELECT 42 AS partial_retry_marker";

void idle() {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	do {
		if (scalar(admin, "SELECT COALESCE(SUM(ConnFree),0) FROM stats_mysql_connection_pool "
			"WHERE hostgroup=946541") == "1") return;
		usleep(10000);
	} while (std::chrono::steady_clock::now() < deadline);
	BAIL_OUT("Private backend connection did not return to the pool");
}
}

int main() {
	alarm(120);
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	plan(8);
	admin = connect(cl, true);
	if (std::atexit(restore)) BAIL_OUT("Cannot register cleanup");
	if (scalar(admin, "SELECT count(*) FROM mysql_servers WHERE hostgroup_id=946541") != "0"
		|| scalar(admin, "SELECT count(*) FROM runtime_mysql_servers WHERE hostgroup_id=946541") != "0")
		BAIL_OUT("Private hostgroup already exists");
	const std::string host = scalar(admin,
		"SELECT hostname FROM mysql_servers WHERE status='ONLINE' AND use_ssl=0 ORDER BY hostgroup_id LIMIT 1");
	const int port = atoi(scalar(admin,
		"SELECT port FROM mysql_servers WHERE status='ONLINE' AND use_ssl=0 ORDER BY hostgroup_id LIMIT 1").c_str());
	if (host.empty() || !port) BAIL_OUT("No real plaintext MySQL backend available");
	const std::string bind_ip = local_address(cl);
	scalar(admin, "SELECT count(*) FROM runtime_mysql_query_rules");
	scalar(admin, "SELECT count(*) FROM runtime_mysql_query_rules_fast_routing");
	query(admin, "CREATE TEMPORARY TABLE partial_retry_memory_rules AS SELECT * FROM mysql_query_rules");
	query(admin, "CREATE TEMPORARY TABLE partial_retry_runtime_rules AS SELECT * FROM runtime_mysql_query_rules");
	query(admin, "CREATE TEMPORARY TABLE partial_retry_memory_fast AS SELECT * FROM mysql_query_rules_fast_routing");
	query(admin, "CREATE TEMPORARY TABLE partial_retry_runtime_fast AS SELECT * FROM runtime_mysql_query_rules_fast_routing");
	saved_rules = true;
	query(admin, "DELETE FROM mysql_query_rules");
	query(admin, "DELETE FROM mysql_query_rules_fast_routing");
	query(admin, "INSERT INTO mysql_query_rules(rule_id,active,match_pattern,destination_hostgroup,apply) "
		"VALUES(946541,1,'partial_retry',946541,1)");
	query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	for (int scenario = 0; scenario < 3; ++scenario) {
		gate.reset(new TrafficGate(bind_ip, host, port));
		query(admin, "DELETE FROM mysql_servers WHERE hostgroup_id=946541");
		added_servers = true;
		query(admin, "INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,max_connections,use_ssl) VALUES "
			"(946541,'" + bind_ip + "'," + std::to_string(gate->port) + ",'ONLINE',1,0),"
			"(946541,'" + host + "'," + std::to_string(port) + ",'OFFLINE_HARD',1,0)");
		query(admin, "LOAD MYSQL SERVERS TO RUNTIME");
		MYSQL* c = connect(cl);
		if (scalar(c, "SELECT 0 AS partial_retry_warm") != "0") BAIL_OUT("Warmup failed");
		idle();
		const size_t before = gate->bytes();
		if (scalar(c, "SELECT 41 AS partial_retry_marker") != "41") BAIL_OUT("Calibration failed");
		idle();
		const size_t first_result_bytes = gate->bytes() - before;
		if (!first_result_bytes) BAIL_OUT("No calibration traffic traversed relay");
		Results out;
		if (scenario == 0) {
			finish(c, out, mysql_query(c, batch));
			ok(out.error == 0 && out.markers == std::vector<std::string>({"41", "42"}),
				"healthy batch returns exactly 41,42: %s", out.describe().c_str());
		} else {
			const size_t armed_bytes = gate->bytes();
			if (!gate->arm(scenario == 2, scenario == 2 ? first_result_bytes : 0))
				BAIL_OUT("Warm query did not traverse relay");
			if (mysql_send_query(c, batch, strlen(batch))) BAIL_OUT("Send: %s", mysql_error(c));
			if (scenario == 2) {
				if (mysql_read_query_result(c)) BAIL_OUT("First result: %s", mysql_error(c));
				take_result(c, out);
			}
			const bool held = gate->wait_held();
			const size_t forwarded = gate->bytes() - armed_bytes;
			const bool fault_ready = held && forwarded == (scenario == 1 ? 0 : first_result_bytes)
				&& (scenario == 1 ? gate->request_is(batch) : out.markers == std::vector<std::string>({"41"}));
			ok(fault_ready, "%s: actual %s traffic held, response bytes=%zu, first-result bytes=%zu",
				scenario == 1 ? "before output" : "after result 1",
				scenario == 1 ? "query" : "second-result", forwarded, first_result_bytes);
			if (!fault_ready) BAIL_OUT("Fault gate did not activate at the expected boundary");
			query(admin, "UPDATE mysql_servers SET status=CASE WHEN port=" + std::to_string(gate->port)
				+ " THEN 'OFFLINE_HARD' ELSE 'ONLINE' END WHERE hostgroup_id=946541");
			query(admin, "LOAD MYSQL SERVERS TO RUNTIME");
			const long long fallback_before = atoll(scalar(admin,
				"SELECT COALESCE(SUM(Queries),0) FROM stats_mysql_connection_pool WHERE hostgroup=946541 "
				"AND srv_port=" + std::to_string(port)).c_str());
			gate->drop();
			finish(c, out, scenario == 1 ? mysql_read_query_result(c) : mysql_next_result(c));
			const long long fallback_after = atoll(scalar(admin,
				"SELECT COALESCE(SUM(Queries),0) FROM stats_mysql_connection_pool WHERE hostgroup=946541 "
				"AND srv_port=" + std::to_string(port)).c_str());
			if (scenario == 1) {
				ok(out.error == 0 && out.markers == std::vector<std::string>({"41", "42"})
					&& fallback_after > fallback_before,
					"unanswered batch retries completely on fallback: %s fallback queries %lld->%lld",
					out.describe().c_str(), fallback_before, fallback_after);
			} else {
				ok(out.error != 0 && out.markers == std::vector<std::string>({"41"})
					&& fallback_after == fallback_before,
					"answered batch fails without replay or duplicate markers: %s fallback queries %lld->%lld",
					out.describe().c_str(), fallback_before, fallback_after);
			}
		}
		mysql_close(c);
		MYSQL* recovery = connect(cl);
		ok(scalar(recovery, "SELECT 42 AS partial_retry_recovery") == "42",
			"scenario %d: new client succeeds after batch", scenario);
		mysql_close(recovery);
		gate.reset();
	}
	restore();
	return exit_status();
}
