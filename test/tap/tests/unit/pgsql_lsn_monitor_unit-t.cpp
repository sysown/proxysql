#include "PgSQL_LSN_Monitor.h"
#include "tap.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

using namespace pgsql_lsn;
static Micros now_us() {
	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
static void u32(std::string& s, uint32_t n) { n = htonl(n); s.append(reinterpret_cast<char*>(&n), 4); }
static void u16(std::string& s, uint16_t n) { n = htons(n); s.append(reinterpret_cast<char*>(&n), 2); }
static void cstr(std::string& s, const std::string& value) { s += value; s.push_back(0); }

// Actual libpq talks to this server. Only the external PostgreSQL wire peer is
// simulated, so missing ReadyForQuery exercises the production async IO loop.
class ScriptedServer {
	int listen_fd_ = -1;
	std::atomic<int> peer_{-1};
	std::thread thread_;
	std::mutex mutex_;
	std::condition_variable cv_;
	std::atomic<bool> stop_{false};
	bool read_exact(int fd, void* out, size_t size) {
		char* p = static_cast<char*>(out);
		while (size && !stop_) {
			pollfd poll_fd{fd, POLLIN, 0};
			if (poll(&poll_fd, 1, 50) <= 0) continue;
			ssize_t n = recv(fd, p, size, 0);
			if (n <= 0) return false;
			p += n; size -= n;
		}
		return !size;
	}
	bool send_message(int fd, char type, const std::string& payload) {
		std::string wire(1, type); u32(wire, payload.size() + 4); wire += payload;
		size_t off = 0;
		while (off < wire.size()) {
			ssize_t n = send(fd, wire.data() + off, wire.size() - off, MSG_NOSIGNAL);
			if (n <= 0) return false;
			off += n;
		}
		return true;
	}
	void serve() {
		pollfd ready{listen_fd_, POLLIN, 0};
		while (!stop_ && poll(&ready, 1, 50) <= 0) {}
		if (stop_) return;
		int fd = accept(listen_fd_, nullptr, nullptr); peer_ = fd;
		if (fd < 0) return;
		uint32_t size;
		if (!read_exact(fd, &size, 4)) return;
		size = ntohl(size);
		if (size < 8 || size > 10000) return;
		std::string startup(size - 4, '\0');
		if (!read_exact(fd, &startup[0], startup.size())) return;
		replication_mode = startup.find(std::string("replication\0database\0", 21)) != std::string::npos;
		std::string auth; u32(auth, 0);
		send_message(fd, 'R', auth);
		std::string parameter; cstr(parameter, "server_version"); cstr(parameter, "17.0"); send_message(fd, 'S', parameter);
		parameter.clear(); cstr(parameter, "client_encoding"); cstr(parameter, "UTF8"); send_message(fd, 'S', parameter);
		send_message(fd, 'Z', "I");
		while (!stop_) {
			char type;
			if (!read_exact(fd, &type, 1) || !read_exact(fd, &size, 4)) break;
			size = ntohl(size);
			if (size < 4 || size > 10000 || type != 'Q') break;
			std::string query(size - 4, '\0');
			if (!read_exact(fd, &query[0], query.size())) break;
			const bool identify = query.find("IDENTIFY_SYSTEM") == 0;
			std::vector<std::string> values = identify ? std::vector<std::string>{"12345", "1", "0/FFFF", "postgres"}
				: std::vector<std::string>{"1000", "f", format_lsn(position.load())};
			std::string description; u16(description, values.size());
			for (size_t i = 0; i < values.size(); ++i) {
				cstr(description, "field" + std::to_string(i)); u32(description, 0); u16(description, 0);
				u32(description, 25); u16(description, 0xffff); u32(description, 0xffffffff); u16(description, 0);
			}
			send_message(fd, 'T', description);
			std::string row; u16(row, values.size());
			for (auto& value : values) { u32(row, value.size()); row += value; }
			send_message(fd, 'D', row);
			std::string tag; cstr(tag, identify ? "IDENTIFY_SYSTEM" : "SELECT 1"); send_message(fd, 'C', tag);
			++commands;
			if (hold.load()) {
				waiting = true;
				std::unique_lock<std::mutex> lock(mutex_);
				cv_.wait(lock, [&] { return !hold.load() || stop_.load(); });
				waiting = false;
			}
			if (!send_message(fd, 'Z', "I")) break;
		}
	}
public:
	uint16_t port = 0;
	std::atomic<bool> hold{true}, waiting{false}, replication_mode{false};
	std::atomic<unsigned> commands{0};
	std::atomic<Lsn> position{0x100};
	ScriptedServer() {
		listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
		sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) || listen(listen_fd_, 4)) std::abort();
		socklen_t len = sizeof(addr); getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len); port = ntohs(addr.sin_port);
		thread_ = std::thread([this] { serve(); });
	}
	void release() { std::lock_guard<std::mutex> lock(mutex_); hold = false; cv_.notify_all(); }
	~ScriptedServer() {
		stop_ = true; release(); shutdown(listen_fd_, SHUT_RDWR);
		if (peer_ >= 0) shutdown(peer_, SHUT_RDWR);
		thread_.join();
		if (peer_ >= 0) close(peer_);
		close(listen_fd_);
	}
};

int main() {
	plan(NO_PLAN);
	ScriptedServer server;
	Endpoint endpoint{"127.0.0.1", server.port};
	PgSQL_LSN_Manager manager;
	manager.reconcile_groups({{10, 20, true, {endpoint}, {}}});
	PgSQL_LSN_Monitor monitor(manager, [&](const Endpoint& e) -> std::optional<std::string> {
		return "hostaddr=127.0.0.1 port=" + std::to_string(e.port) +
			" user=test dbname=postgres sslmode=disable gssencmode=disable replication=database";
	});
	auto until = [&](const std::function<bool()>& condition) {
		const auto deadline = now_us() + 2000000;
		while (!condition() && now_us() < deadline) { monitor.tick(now_us(), 1000, 1000000, 1000000); monitor.wait(1000); }
		return condition();
	};
	ok(until([&] { return server.waiting.load(); }), "real libpq receives partial identity response");
	for (int i = 0; i < 10; ++i) { monitor.tick(now_us(), 1000, 1000000, 1000000); monitor.wait(1000); }
	ok(!manager.snapshot(10).writer, "withheld ReadyForQuery neither blocks scheduler nor certifies identity");
	server.release();
	ok(until([&] { return manager.snapshot(10).writer.has_value(); }), "complete identity sandwich certifies writer");
	ok(server.replication_mode, "dedicated connection starts in database replication mode");
	if (!manager.snapshot(10).writer) return exit_status();
	const auto writer = *manager.snapshot(10).writer;
	const auto initial_commands = server.commands.load();
	for (int i = 0; i < 10; ++i) { monitor.tick(now_us(), 1000, 1000000, 1000000); monitor.wait(1000); }
	ok(server.commands == initial_commands && initial_commands == 3, "certified idle writer sends no position probes");
	server.position = 0x200; server.hold = true;
	auto before = manager.observe_completion(writer, {});
	ok(until([&] { return server.waiting.load(); }), "pending completion triggers shared writer sample");
	auto after = manager.observe_completion(writer, {});
	server.release();
	ok(until([&] { return manager.resolve(before).state == DependencyState::Ready; }), "sample resolves earlier completion");
	ok(manager.resolve(before).required_lsn == 0x200, "dependency uses writer insertion sample");
	ok(manager.resolve(after).state == DependencyState::Pending, "sample reply cannot include post-dispatch completion");
	ok(server.commands == initial_commands + 2, "continuous connection needs only SQL and final identity");
	monitor.reset();
	ok(manager.resolve(before).state == DependencyState::Ready, "monitor reset preserves known writer history");
	bool certified = false;
	for (const auto& p : manager.snapshot(10).servers) certified |= p.valid;
	ok(!certified, "monitor reset withdraws all endpoint certification");
	{
		ScriptedServer blocked, healthy;
		healthy.release();
		Endpoint slow{"127.0.0.1", blocked.port}, fast{"127.0.0.1", healthy.port};
		PgSQL_LSN_Manager peers;
		peers.reconcile_groups({{10,20,true,{slow},{}},{30,40,true,{fast},{}},{50,60,true,{fast},{}}});
		PgSQL_LSN_Monitor driver(peers, [&](const Endpoint& e) -> std::optional<std::string> {
			return "hostaddr=127.0.0.1 port=" + std::to_string(e.port) +
				" user=test dbname=postgres sslmode=disable gssencmode=disable replication=database";
		});
		const auto deadline = now_us() + 2000000;
		while (!peers.snapshot(30).writer && now_us() < deadline) {
			driver.tick(now_us(), 1000, 1000000, 1000000); driver.wait(1000);
		}
		ok(blocked.waiting && peers.snapshot(30).writer, "partial response on one endpoint cannot block another");
		ok(peers.snapshot(50).writer && healthy.commands == 3, "groups sharing an endpoint share one probe connection");
		driver.tick(now_us() + 2000000, 1000, 1000000, 1000000);
		ok(!peers.snapshot(10).writer, "probe timeout cannot publish partial certification");
		const auto begin_reset = now_us();
		driver.reset();
		ok(now_us() - begin_reset < 100000, "shutdown closes withheld responses without waiting for server");
	}
	return exit_status();
}
