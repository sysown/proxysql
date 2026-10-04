#include "PgSQL_LSN_Monitor.h"
#include "tap.h"
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace pgsql_lsn;
static Micros now_us() {
	return std::chrono::duration_cast<std::chrono::microseconds>(
			   std::chrono::steady_clock::now().time_since_epoch())
		.count();
}
static void u32(std::string &s, uint32_t n) {
	n = htonl(n);
	s.append(reinterpret_cast<char *>(&n), 4);
}
static void u16(std::string &s, uint16_t n) {
	n = htons(n);
	s.append(reinterpret_cast<char *>(&n), 2);
}
static void cstr(std::string &s, const std::string &value) {
	s += value;
	s.push_back(0);
}

// Actual libpq talks to this server. Only the external PostgreSQL wire peer is
// simulated, so missing ReadyForQuery exercises the production async IO loop.
class ScriptedServer {
	int listen_fd_ = -1;
	std::atomic<int> peer_{-1};
	std::thread thread_;
	std::mutex mutex_;
	std::condition_variable cv_;
	std::atomic<bool> stop_{false};
	bool read_exact(int fd, void *out, size_t size) {
		char *p = static_cast<char *>(out);
		while (size && !stop_) {
			pollfd poll_fd{fd, POLLIN, 0};
			if (poll(&poll_fd, 1, 50) <= 0)
				continue;
			ssize_t n = recv(fd, p, size, 0);
			if (n <= 0)
				return false;
			p += n;
			size -= n;
		}
		return !size;
	}
	bool send_message(int fd, char type, const std::string &payload) {
		std::string wire(1, type);
		u32(wire, payload.size() + 4);
		wire += payload;
		size_t off = 0;
		while (off < wire.size()) {
			ssize_t n = send(fd, wire.data() + off, wire.size() - off, MSG_NOSIGNAL);
			if (n <= 0)
				return false;
			off += n;
		}
		return true;
	}
	void serve() {
		pollfd ready{listen_fd_, POLLIN, 0};
		while (!stop_ && poll(&ready, 1, 50) <= 0) {
		}
		if (stop_)
			return;
		int fd = accept(listen_fd_, nullptr, nullptr);
		peer_ = fd;
		if (fd < 0)
			return;
		uint32_t size;
		if (!read_exact(fd, &size, 4))
			return;
		size = ntohl(size);
		if (size < 8 || size > 10000)
			return;
		std::string startup(size - 4, '\0');
		if (!read_exact(fd, &startup[0], startup.size()))
			return;
		replication_mode =
			startup.find(std::string("replication\0database\0", 21)) != std::string::npos;
		std::string auth;
		u32(auth, 0);
		send_message(fd, 'R', auth);
		std::string parameter;
		cstr(parameter, "server_version");
		cstr(parameter, "17.0");
		send_message(fd, 'S', parameter);
		parameter.clear();
		cstr(parameter, "client_encoding");
		cstr(parameter, "UTF8");
		send_message(fd, 'S', parameter);
		send_message(fd, 'Z', "I");
		while (!stop_) {
			char type;
			if (!read_exact(fd, &type, 1) || !read_exact(fd, &size, 4))
				break;
			size = ntohl(size);
			if (size < 4 || size > 10000 || type != 'Q')
				break;
			std::string query(size - 4, '\0');
			if (!read_exact(fd, &query[0], query.size()))
				break;
			const bool identify = query.find("IDENTIFY_SYSTEM") == 0;
			const bool metadata = query.find("pg_control_init()") != std::string::npos;
			if (metadata)
				++metadata_commands;
			std::vector<std::string> values =
				identify   ? std::vector<std::string>{"12345", "1", "0/FFFF", "postgres"}
				: metadata ? std::vector<std::string>{"8", "8192", "16777216", "170000"}
						   : std::vector<std::string>{"1000", "f", format_lsn(position.load())};
			std::string description;
			u16(description, values.size());
			for (size_t i = 0; i < values.size(); ++i) {
				cstr(description, "field" + std::to_string(i));
				u32(description, 0);
				u16(description, 0);
				u32(description, 25);
				u16(description, 0xffff);
				u32(description, 0xffffffff);
				u16(description, 0);
			}
			send_message(fd, 'T', description);
			std::string row;
			u16(row, values.size());
			for (auto &value : values) {
				u32(row, value.size());
				row += value;
			}
			send_message(fd, 'D', row);
			std::string tag;
			cstr(tag, identify ? "IDENTIFY_SYSTEM" : "SELECT 1");
			send_message(fd, 'C', tag);
			++commands;
			if (hold.load()) {
				waiting = true;
				std::unique_lock<std::mutex> lock(mutex_);
				cv_.wait(lock, [&] { return !hold.load() || stop_.load(); });
				waiting = false;
			}
			if (!send_message(fd, 'Z', "I"))
				break;
		}
	}

  public:
	uint16_t port = 0;
	std::atomic<bool> hold{true}, waiting{false}, replication_mode{false};
	std::atomic<unsigned> commands{0}, metadata_commands{0};
	std::atomic<Lsn> position{0x100};
	ScriptedServer() {
		listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (bind(listen_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) ||
			listen(listen_fd_, 4))
			std::abort();
		socklen_t len = sizeof(addr);
		getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&addr), &len);
		port = ntohs(addr.sin_port);
		thread_ = std::thread([this] { serve(); });
	}
	void release() {
		std::lock_guard<std::mutex> lock(mutex_);
		hold = false;
		cv_.notify_all();
	}
	~ScriptedServer() {
		stop_ = true;
		release();
		shutdown(listen_fd_, SHUT_RDWR);
		if (peer_ >= 0)
			shutdown(peer_, SHUT_RDWR);
		thread_.join();
		if (peer_ >= 0)
			close(peer_);
		close(listen_fd_);
	}
};

int main() {
	plan(NO_PLAN);
	ScriptedServer server;
	Endpoint endpoint{"localhost", server.port};
	PgSQL_LSN_Manager manager;
	manager.reconcile_endpoints({endpoint, endpoint});
	unsigned housekeeping = 0;
	PgSQL_LSN_Monitor monitor(
		manager,
		[&](const Endpoint &e) -> std::optional<std::string> {
			return "host=localhost port=" + std::to_string(e.port) +
				   " user=test dbname=postgres sslmode=disable gssencmode=disable "
				   "replication=database";
		},
		now_us,
		[&](Micros now) {
			++housekeeping;
			manager.prune_before(now > 60000000 ? now - 60000000 : 0);
		});
	auto until = [&](const std::function<bool()> &condition, Micros interval = 10000) {
		const auto deadline = now_us() + 2000000;
		while (!condition() && now_us() < deadline) {
			monitor.tick(now_us(), {endpoint, endpoint}, interval, 1000000, 1000000);
			monitor.wait(1000);
		}
		return condition();
	};
	ok(until([&] { return server.waiting.load(); }),
	   "DNS-cache-disabled hostname establishes background libpq connection");
	for (int i = 0; i < 10; ++i) {
		monitor.tick(now_us(), {endpoint}, 10000, 1000000, 1000000);
		monitor.wait(1000);
	}
	ok(!manager.latest(endpoint),
	   "delayed final ReadyForQuery cannot publish partial identity response");
	ok(housekeeping > 10, "cleanup continues while endpoint response is stalled");
	server.release();
	ok(until([&] { return manager.latest(endpoint).has_value(); }),
	   "full identity sandwich publishes valid insertion sample");
	ok(server.replication_mode, "background connection uses database replication identity command");
	if (!manager.latest(endpoint))
		return exit_status();
	auto first = *manager.latest(endpoint);
	ok(first.valid && first.sample.lsn == 0x100,
	   "insertion sample is selected without routing-role state");
	ok(server.metadata_commands == 1, "WAL layout fetched once on first connection");
	unsigned initial_commands = server.commands;
	ok(until([&] { return server.commands.load() >= initial_commands + 2; }),
	   "idle endpoint polls periodically without session demand");
	ok(server.metadata_commands == 1,
	   "later polls reuse WAL layout without another metadata query");
	ok(manager.latest_all().size() == 1,
	   "duplicate endpoint membership keeps one physical progress row");
	auto before = now_us();
	monitor.reset();
	ok(now_us() - before < 100000 && !manager.latest(endpoint)->valid,
	   "disable/reset closes connections promptly and withdraws eligibility");
	{
		ScriptedServer blocked, healthy;
		healthy.release();
		Endpoint slow{"127.0.0.1", blocked.port}, fast{"127.0.0.1", healthy.port};
		PgSQL_LSN_Manager peers;
		peers.reconcile_endpoints({slow, fast});
		unsigned cleanups = 0;
		PgSQL_LSN_Monitor driver(
			peers,
			[&](const Endpoint &e) -> std::optional<std::string> {
				return "hostaddr=127.0.0.1 port=" + std::to_string(e.port) +
					   " user=test dbname=postgres sslmode=disable "
					   "gssencmode=disable "
					   "replication=database";
			},
			now_us,
			[&](Micros) {
				++cleanups;
				peers.prune_before(250);
			});
		const auto deadline = now_us() + 2000000;
		while (!peers.latest(fast) && now_us() < deadline) {
			driver.tick(now_us(), {slow, fast, fast}, 10000, 1000000, 1000000);
			driver.wait(1000);
		}
		ok(blocked.waiting && peers.latest(fast),
		   "withheld response on one endpoint cannot block another");
		unsigned slow_commands = blocked.commands;
		for (int i = 0; i < 5; ++i)
			driver.tick(now_us(), {slow, fast}, 1, 1000000, 1000000);
		ok(blocked.commands == slow_commands,
		   "missed ticks never create a second outstanding operation");
		driver.tick(now_us() + 2000000, {slow, fast}, 10000, 1000000, 1000000);
		ok(!peers.latest(slow) && cleanups > 1,
		   "bounded poll timeout withdraws partial result while cleanup continues");
		blocked.release();
		driver.tick(now_us(), {}, 10000, 1000000, 1000000);
		ok(!peers.latest(slow),
		   "late result from retired connection cannot revive removed endpoint");
		const auto reset_at = now_us();
		driver.reset();
		ok(now_us() - reset_at < 100000, "shutdown does not wait for final protocol response");
	}
	{
		ScriptedServer peer;
		peer.release();
		Endpoint endpoint{"127.0.0.1", peer.port};
		PgSQL_LSN_Manager history;
		history.reconcile_endpoints({endpoint});
		Micros clock_offset = 0;
		bool expire_during_housekeeping = false;
		PgSQL_LSN_Monitor driver(
			history,
			[&](const Endpoint &e) -> std::optional<std::string> {
				return "hostaddr=127.0.0.1 port=" + std::to_string(e.port) +
					   " user=test dbname=postgres sslmode=disable "
					   "gssencmode=disable replication=database";
			},
			[&] { return now_us() + clock_offset; },
			[&](Micros) {
				if (expire_during_housekeeping)
					clock_offset = 2000000;
			});
		auto advance_until = [&](const std::function<bool()> &ready) {
			const auto limit = now_us() + 2000000;
			while (!ready() && now_us() < limit) {
				driver.tick(now_us() + clock_offset, {endpoint}, 10000, 1000000, 1000000);
				driver.wait(1000);
			}
			return ready();
		};
		ok(advance_until([&] { return history.latest(endpoint).has_value(); }),
		   "fresh-clock deadline fixture establishes a valid initial sample");
		peer.hold = true;
		ok(advance_until([&] { return peer.waiting.load(); }),
		   "fresh-clock deadline fixture stalls the next sample response");
		expire_during_housekeeping = true;
		driver.tick(now_us(), {endpoint}, 10000, 1000000, 1000000);
		ok(history.latest(endpoint) && !history.latest(endpoint)->valid,
		   "deadline expiration during housekeeping withdraws eligibility in the "
		   "same tick");
	}
	{
		PgSQL_LSN_Manager history;
		Endpoint e{"down", 5432};
		history.reconcile_endpoints({e});
		history.publish({e, {1, 1}, 1, {100, 12330}, true});
		history.publish({e, {1, 1}, 1, {200, 12339}, true});
		history.publish({e, {1, 1}, 1, {300, 12345}, true});
		PgSQL_LSN_Monitor failed(
			history, [](const Endpoint &) -> std::optional<std::string> { return {}; }, now_us,
			[&](Micros now) { history.prune_before(now); });
		failed.tick(250, {e}, 1, 100, 100);
		// Restore current eligibility with a real new observation; retained old
		// samples are checked below.
		history.publish({e, {1, 1}, 1, {400, 12346}, true});
		ok(history.lookup_after(e, 150).required &&
			   history.lookup_after(e, 150).required->lsn == 12339,
		   "failed-probe housekeeping independently prunes old prefix");
		failed.tick(1000, {}, 1, 100, 100);
		history.publish({e, {1, 1}, 1, {1100, 12347}, true});
		ok(history.lookup_after(e, 150).required &&
			   history.lookup_after(e, 150).required->lsn == 12346,
		   "age cleanup keeps only newest old anchor without progress floor");
	}
	return exit_status();
}
