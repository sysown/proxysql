// Opt-in load characterization; correctness is asserted, speed is reported.
#include "duckdb_replica_test_utils.h"
#include "json.hpp"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <mutex>
#include <sstream>

using namespace duckdb_replica_test;
using Clock = std::chrono::steady_clock;
using Json = nlohmann::json;
namespace {
int option(const char* name, int fallback, int low, int high) {
	const char* value = std::getenv(name);
	if (!value || !*value)
		return fallback;
	char* end = nullptr;
	errno = 0;
	long parsed = std::strtol(value, &end, 10);
	if (errno || end == value || *end || parsed < low || parsed > high)
		BAIL_OUT("%s must be between %d and %d", name, low, high);
	return static_cast<int>(parsed);
}
struct Config {
	int rows = option("REPLICA_BENCH_ROWS", 200000, 1000, 1000000);
	int seconds = option("REPLICA_BENCH_SECONDS", 8, 1, 300);
	int rate = option("REPLICA_BENCH_RATE", 50, 1, 1000);
	int txn_rows = option("REPLICA_BENCH_TXN_ROWS", 20, 1, rows);
	int readers = option("REPLICA_BENCH_READERS", 2, 1, 16);
	int large_rows = option("REPLICA_BENCH_LARGE_TXN_ROWS", std::min(5000, rows), 1, rows);
	int timeout = option("REPLICA_BENCH_TIMEOUT", std::max(180, seconds + 1), seconds + 1, 1800);
};
double milliseconds(Clock::duration elapsed) {
	return std::chrono::duration<double, std::milli>(elapsed).count();
}
double percentile(std::vector<double> samples, double p) {
	if (samples.empty())
		return 0;
	std::sort(samples.begin(), samples.end());
	return samples[static_cast<size_t>(std::ceil(p * samples.size())) - 1];
}
uint64_t rss(pid_t pid) {
	std::ifstream input("/proc/" + std::to_string(pid) + "/status");
	std::string line;
	while (std::getline(input, line)) {
		if (line.rfind("VmRSS:", 0) != 0)
			continue;
		std::istringstream bytes(line.substr(6));
		uint64_t kb = 0;
		bytes >> kb;
		return kb * 1024;
	}
	return 0;
}
struct MemorySampler {
	std::atomic<bool> stop{false};
	std::atomic<uint64_t> peak{0};
	uint64_t baseline;
	std::thread worker;
	explicit MemorySampler(pid_t pid) : baseline(rss(pid)) {
		peak = baseline;
		worker = std::thread([this, pid] {
			while (!stop) {
				const uint64_t bytes = rss(pid);
				if (bytes > peak)
					peak = bytes;
				std::this_thread::sleep_for(std::chrono::milliseconds(20));
			}
		});
	}
	void finish() {
		stop = true;
		if (worker.joinable())
			worker.join();
	}
	~MemorySampler() {
		finish();
	}
};
void emit(const Json& value) {
	diag("REPLICA_BENCH %s", value.dump().c_str());
	fflush(stdout);
}

bool snapshot(Fixture& f, const Config& cfg) {
	MemorySampler memory(f.pid);
	const Rows target = f.source_position();
	const auto start = Clock::now();
	bool ready =
		!target.empty() && query(f.admin, "START DUCKDB REPLICA") &&
		wait_for(
			[&] {
				return cell(f.admin, "SELECT state FROM stats_duckdb_replica") == "applying" &&
					   f.position() == target;
			},
			cfg.timeout);
	const auto end = Clock::now();
	memory.finish();
	if (!check(ready && memory.baseline > 0 && memory.peak > 0,
			   "snapshot becomes durable within benchmark timeout"))
		return false;
	emit({{"phase", "snapshot"},
		  {"seed_rows", cfg.rows + 1},
		  {"elapsed_ms", milliseconds(end - start)},
		  {"rows_per_s", (cfg.rows + 1) * 1000.0 / milliseconds(end - start)},
		  {"rss_baseline_bytes", memory.baseline},
		  {"rss_peak_bytes", memory.peak.load()}});
	return check(f.matches(),
				 "snapshot rows and file/position/GTID match source outside timed interval");
}

// Each transaction inserts a distinct ledger row after the data updates.
// Observing its row proves those updates committed; retaining all ledger rows
// accounts for every transaction even when several are applied in one flush.
bool phase(Fixture& f, const Config& cfg, int index, int readers, bool large) {
	const int transactions = large ? 1 : cfg.seconds * cfg.rate;
	const int rows_per_txn = large ? cfg.large_rows : cfg.txn_rows;
	const int first_marker = index * 1000000;
	std::vector<Clock::time_point> committed(transactions);
	std::mutex committed_mutex;
	std::atomic<bool> stop{false}, go{false}, failed{false};
	std::atomic<int> ready{0}, observed{0};
	std::vector<double> visibility;
	std::vector<std::vector<double>> reader_latencies(readers);
	std::vector<std::thread> workers;

	auto await_start = [&] {
		++ready;
		while (!go && !stop)
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
	};
	workers.emplace_back([&] {
		mysql_thread_init();
		MYSQL* c = connect("127.0.0.1", f.duck_port, "recovery_client", "recovery_client");
		if (!c)
			failed = true;
		await_start();
		while (!stop && !failed && observed < transactions) {
			Rows rows;
			if (!query(c,
					   "SELECT id FROM " + f.table("z_tail", true) + " WHERE id >= " +
						   std::to_string(first_marker + observed.load()) + " AND id < " +
						   std::to_string(first_marker + transactions) + " ORDER BY id",
					   &rows)) {
				failed = true;
				break;
			}
			const auto seen = Clock::now();
			for (const auto& row : rows) {
				const int seq = std::stoi(row[0]) - first_marker;
				if (seq != observed) {
					failed = true;
					break;
				}
				Clock::time_point commit;
				{
					std::lock_guard<std::mutex> lock(committed_mutex);
					commit = committed[seq];
				}
				// An observer can race the source COMMIT response/publication.
				// Retry this marker instead of losing it or reporting negative lag.
				if (commit == Clock::time_point{} || commit > seen)
					break;
				visibility.push_back(milliseconds(seen - commit));
				++observed;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
		if (c)
			mysql_close(c);
		mysql_thread_end();
	});
	for (int i = 0; i < readers; ++i)
		workers.emplace_back([&, i] {
			mysql_thread_init();
			MYSQL* c = connect("127.0.0.1", f.duck_port, "recovery_client", "recovery_client");
			if (!c)
				failed = true;
			await_start();
			while (!stop && !failed) {
				const auto start = Clock::now();
				if (!query(c, "SELECT id%32 AS bucket,COUNT(*),SUM(val),SUM(length(note)) FROM " +
								  f.table("a_bulk", true) + " GROUP BY 1 ORDER BY 1")) {
					failed = true;
					break;
				}
				if (!stop)
					reader_latencies[i].push_back(milliseconds(Clock::now() - start));
			}
			if (c)
				mysql_close(c);
			mysql_thread_end();
		});

	bool admitted = wait_for([&] { return ready == readers + 1; }, 10) && !failed;
	MemorySampler memory(f.pid);
	diag("starting replica benchmark workload %s", large ? "large_transaction" : readers ? "paced_with_readers" : "paced");
	fflush(stdout);
	const auto start = Clock::now();
	const auto deadline = start + std::chrono::seconds(cfg.timeout);
	go = true;
	int written = 0;
	for (int seq = 0; admitted && seq < transactions && !failed && Clock::now() < deadline; ++seq) {
		if (!large)
			std::this_thread::sleep_until(
				start + std::chrono::duration_cast<Clock::duration>(
							std::chrono::duration<double>(static_cast<double>(seq) / cfg.rate)));
		if (failed || Clock::now() >= deadline)
			break;
		const int first = 1 + (static_cast<int64_t>(seq) * rows_per_txn) % cfg.rows;
		const int last = std::min(cfg.rows, first + rows_per_txn - 1);
		bool sent =
			query(f.source, "BEGIN") &&
			query(f.source, "UPDATE " + f.table("a_bulk") + " SET val=val+1 WHERE id BETWEEN " +
								std::to_string(first) + " AND " + std::to_string(last));
		const int remaining = rows_per_txn - (last - first + 1);
		if (sent && remaining)
			sent = query(f.source, "UPDATE " + f.table("a_bulk") +
									   " SET val=val+1 WHERE id BETWEEN 1 AND " +
									   std::to_string(remaining));
		sent = sent &&
			   query(f.source, "INSERT INTO " + f.table("z_tail") + " VALUES(" +
								   std::to_string(first_marker + seq) + "," +
								   std::to_string(rows_per_txn) + ",'commit marker')") &&
			   query(f.source, "COMMIT");
		if (!sent) {
			failed = true;
			query(f.source, "ROLLBACK");
			break;
		}
		{
			std::lock_guard<std::mutex> lock(committed_mutex);
			committed[seq] = Clock::now();
		}
		++written;
	}
	const auto source_end = Clock::now();
	while (!failed && observed < written && Clock::now() < deadline)
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	const auto durable_end = Clock::now();
	stop = true;
	for (auto& worker : workers)
		worker.join();
	memory.finish();
	if (!check(admitted && !failed && written == transactions && observed == transactions &&
				   memory.baseline > 0 && memory.peak > 0,
			   "every committed marker becomes visible without worker errors or timeout"))
		return false;
	std::vector<double> read_samples;
	for (const auto& samples : reader_latencies)
		read_samples.insert(read_samples.end(), samples.begin(), samples.end());
	const double elapsed_ms = milliseconds(durable_end - start);
	emit({{"phase", large	  ? "large_transaction"
					: readers ? "paced_with_readers"
							  : "paced"},
		  {"transactions", transactions},
		  {"data_rows_per_txn", rows_per_txn},
		  {"readers", readers},
		  {"elapsed_ms", elapsed_ms},
		  {"source_elapsed_ms", milliseconds(source_end - start)},
		  {"drain_ms", std::max(0.0, milliseconds(durable_end - source_end))},
		  {"requested_txns_per_s", large ? 0 : cfg.rate},
		  {"achieved_source_txns_per_s", transactions * 1000.0 / milliseconds(source_end - start)},
		  {"durable_data_rows_per_s",
		   static_cast<double>(transactions) * rows_per_txn * 1000.0 / elapsed_ms},
		  {"visibility_samples", visibility.size()},
		  {"visibility_p50_ms", percentile(visibility, .5)},
		  {"visibility_p95_ms", percentile(visibility, .95)},
		  {"visibility_p99_ms", percentile(visibility, .99)},
		  {"visibility_max_ms", *std::max_element(visibility.begin(), visibility.end())},
		  {"read_queries", read_samples.size()},
		  {"read_qps", read_samples.size() * 1000.0 / elapsed_ms},
		  {"read_p50_ms", percentile(read_samples, .5)},
		  {"read_p99_ms", percentile(read_samples, .99)},
		  {"rss_baseline_bytes", memory.baseline},
		  {"rss_peak_bytes", memory.peak.load()}});
	return check(f.matches(),
				 "exact source rows and file/position/GTID agree after timed workload");
}

bool run(Fixture& f, const Config& cfg) {
	if (!check(f.bootstrap() && f.source_setup(cfg.rows) && f.configure(),
			   "prepare isolated benchmark source and ProxySQL"))
		return false;
	emit({{"phase", "config"},
		  {"rows", cfg.rows},
		  {"seconds", cfg.seconds},
		  {"txns_per_s", cfg.rate},
		  {"data_rows_per_txn", cfg.txn_rows},
		  {"readers", cfg.readers},
		  {"duckdb_threads", 2},
		  {"large_txn_data_rows", cfg.large_rows},
		  {"timeout_s", cfg.timeout},
		  {"source_version", cell(f.source, "SELECT VERSION()")},
		  {"duckdb_version", cell(f.duck, "SELECT version()")}});
	return snapshot(f, cfg) && phase(f, cfg, 1, 0, false) && phase(f, cfg, 2, cfg.readers, false) &&
		   phase(f, cfg, 3, 0, true);
}
} // namespace

int main() {
	const char* enabled = std::getenv("RUN_DUCKDB_REPLICA_BENCH");
	if (!enabled || std::string(enabled) != "1") {
		plan(1);
		skip(1, "set RUN_DUCKDB_REPLICA_BENCH=1 to characterize replica load");
		return exit_status();
	}
#ifndef __linux__
	plan(1);
	skip(1, "replica RSS characterization currently requires Linux /proc");
	return exit_status();
#endif
	CommandLine cl;
	if (cl.getEnv())
		return EXIT_FAILURE;
	Config cfg;
	plan(NO_PLAN);
	{
		Fixture f(cl);
		f.complete = run(f, cfg);
		ok(f.complete, "replica load characterization completed");
	}
	return exit_status();
}
