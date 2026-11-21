/*
 * Prometheus projection for the native TCP proxy.
 *
 * One bounded sampler thread reads Engine snapshots.  It performs no SQL or
 * network operations, and every read/conversion failure is
 * contained at the sampler thread boundary.
 *
 * Family ownership: the core process registry uses the default Merge insertion
 * behavior and cannot report whether Register() created a family or returned a
 * preexisting one (especially when that family is empty and therefore absent
 * from Collect()).  The plugin therefore never removes a Family.  The ten
 * stable tcp_proxy families are retained by the core library for the process
 * lifetime and the plugin owns only the samples it adds.  Compatible empty
 * families are borrowed/rebound on restart; a visible conflicting name or an
 * existing foreign sample label is rejected instead of adopted.
 *
 * Every family carries the fixed constant label component="tcp_proxy".  The
 * tcp_proxy metric namespace and its sample labels have exactly one writer: the
 * serialized plugin lifecycle plus this sampler.  Family::Has()/Add() are not
 * atomic against a malicious parallel writer, so that exclusivity is part of
 * the module contract.
 *
 * Cumulative Engine values (accepted/rejected/connect errors/matched and byte
 * totals) are exported as Prometheus Counter families.  Because the
 * Engine snapshot carries cumulative totals, the sampler keeps the last value
 * per series and only adds the positive delta.  A decreased value (Engine
 * counter reset) recreates that series from zero so the exposed counter stays
 * sane.  Point-in-time values (active/retired connections, generation and
 * running state) remain Gauges.
 *
 * Per-ID series are pruned when the corresponding identity disappears from the
 * Engine snapshot, so configuration churn cannot grow label cardinality without
 * bound.  Retired rows are kept while the Engine still reports them (sessions
 * are draining) and disappear with them.
 *
 * Core v4 resets counters only after Admin, plugins and workers have stopped.
 * The sampler must not take the Admin SQL mutex: fast SHUTDOWN/KILL can exit
 * while owning that mutex and join this thread during plugin teardown.
 */

#include "tcp_proxy_plugin.h"

#include "prometheus/counter.h"
#include "prometheus/gauge.h"
#include "prometheus/registry.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace tcp_proxy_plugin {

struct MetricsRuntime {
	struct GaugeSeries {
		prometheus::Family<prometheus::Gauge>* family { nullptr };
		std::map<std::string, prometheus::Gauge*> samples;
	};

	struct CounterSeries {
		prometheus::Family<prometheus::Counter>* family { nullptr };
		std::map<std::string, prometheus::Counter*> samples;
		/* Last cumulative Engine value observed for each owned series. */
		std::map<std::string, double> last;
	};

	prometheus::Registry* registry { nullptr };

	GaugeSeries active;
	CounterSeries accepted;
	CounterSeries rejected;
	CounterSeries connect_errors;
	CounterSeries matched;
	CounterSeries bytes_client_to_server;
	CounterSeries bytes_server_to_client;

	prometheus::Family<prometheus::Gauge>* generation_family { nullptr };
	prometheus::Gauge* generation { nullptr };
	prometheus::Family<prometheus::Gauge>* running_family { nullptr };
	prometheus::Gauge* running { nullptr };
	prometheus::Family<prometheus::Gauge>* retired_family { nullptr };
	prometheus::Gauge* retired { nullptr };
};

namespace {

constexpr auto kSampleInterval = std::chrono::milliseconds(1000);
constexpr std::size_t kRetainedFamilyCount = 10;
constexpr std::size_t kMaxDiagnosticLength = 512;
constexpr const char* kComponentLabel = "tcp_proxy";

/* Fixed component label: it names this module's namespace without any
 * per-instance UUID/address label, so restarts rebind the same families. */
const prometheus::Labels& component_labels() {
	static const prometheus::Labels labels { { "component", kComponentLabel } };
	return labels;
}

struct FamilySpec {
	const char* name;
	bool counter;
};

constexpr FamilySpec kFamilySpecs[] {
	{ "proxysql_tcp_active_connections", false },
	{ "proxysql_tcp_accepted_total", true },
	{ "proxysql_tcp_rejected_total", true },
	{ "proxysql_tcp_connect_errors_total", true },
	{ "proxysql_tcp_matched_total", true },
	{ "proxysql_tcp_bytes_client_to_server_total", true },
	{ "proxysql_tcp_bytes_server_to_client_total", true },
	{ "proxysql_tcp_generation", false },
	{ "proxysql_tcp_running", false },
	{ "proxysql_tcp_retired_connections", false },
};

static_assert(sizeof(kFamilySpecs) / sizeof(kFamilySpecs[0]) ==
	kRetainedFamilyCount, "retained family list must stay exactly ten");

constexpr int kFaultGaugeAfterStage = 1;
constexpr int kFaultGaugeAfterAdd = 2;
constexpr int kFaultCounterAfterStage = 3;
constexpr int kFaultCounterAfterLastStage = 4;
constexpr int kFaultCounterAfterAdd = 5;
constexpr int kFaultScalarBase = 10;

#ifdef TCP_PROXY_METRICS_TESTING
/* Test-only allocation-failure injection.  Production builds do not compile
 * this path; the admin unit target defines TCP_PROXY_METRICS_TESTING. */
std::atomic<int> g_fault_stage { -1 };

void maybe_fail(int stage) {
	if (g_fault_stage.load(std::memory_order_acquire) != stage) return;
	g_fault_stage.store(-1, std::memory_order_release);
	throw std::bad_alloc();
}
#else
inline void maybe_fail(int) noexcept {}
#endif

std::string series_key(const std::string& scope, const std::string& id) {
	return scope + '\x1f' + id;
}

/* Reject any already-visible tcp_proxy family before mutation.  A compatible
 * empty family cannot be seen here and will be merged/borrowed by Register();
 * an incompatible empty family makes Register() throw.  Either way this plugin
 * never removes a family it did not create. */
bool reject_visible_conflicts(prometheus::Registry& registry,
		std::string& error) {
	const std::vector<prometheus::MetricFamily> visible = registry.Collect();
	for (const FamilySpec& spec : kFamilySpecs) {
		for (const prometheus::MetricFamily& family : visible) {
			if (family.name == spec.name) {
				error = std::string("metric family '") + spec.name +
					"' is already published by another writer";
				return false;
			}
		}
	}
	return true;
}

/* Adds one owned gauge sample.  The tracking node is staged before Add(), and
 * a sample returned by Add() is removed again if later tracking fails, so a
 * failure can never leave an untracked series behind.  An existing sample with
 * the same labels but no tracking entry belongs to a foreign writer and is
 * rejected rather than adopted. */
prometheus::Gauge& obtain_gauge(MetricsRuntime::GaugeSeries& series,
		const prometheus::Labels& labels, const std::string& key) {
	auto found = series.samples.find(key);
	if (found != series.samples.end()) return *found->second;

	auto staged = series.samples.emplace(key, nullptr);
	if (!staged.second) return *staged.first->second;

	prometheus::Gauge* created = nullptr;
	try {
		maybe_fail(kFaultGaugeAfterStage);
		if (series.family->Has(labels)) {
			throw std::runtime_error(
				"metric sample labels already exist under a foreign writer");
		}
		created = &series.family->Add(labels);
		maybe_fail(kFaultGaugeAfterAdd);
		staged.first->second = created;
		return *created;
	} catch (...) {
		if (created != nullptr) series.family->Remove(created);
		series.samples.erase(staged.first);
		throw;
	}
}

/* Counter variant: both the sample and last-value tracking nodes are staged
 * before Add(), and a newly created sample plus its last-value node are removed
 * on any tracking failure. */
prometheus::Counter& obtain_counter(MetricsRuntime::CounterSeries& series,
		const prometheus::Labels& labels, const std::string& key,
		double value) {
	auto found = series.samples.find(key);
	if (found != series.samples.end()) return *found->second;

	auto staged = series.samples.emplace(key, nullptr);
	if (!staged.second) return *staged.first->second;

	auto staged_last = series.last.end();
	prometheus::Counter* created = nullptr;
	try {
		maybe_fail(kFaultCounterAfterStage);
		const auto inserted = series.last.emplace(key, 0.0);
		staged_last = inserted.first;
		if (!inserted.second) {
			throw std::runtime_error("inconsistent metric counter bookkeeping");
		}
		maybe_fail(kFaultCounterAfterLastStage);
		if (series.family->Has(labels)) {
			throw std::runtime_error(
				"metric sample labels already exist under a foreign writer");
		}
		created = &series.family->Add(labels);
		maybe_fail(kFaultCounterAfterAdd);
		staged.first->second = created;
		staged_last->second = value;
		if (value > 0) created->Increment(value);
		return *created;
	} catch (...) {
		if (created != nullptr) series.family->Remove(created);
		if (staged_last != series.last.end()) series.last.erase(staged_last);
		series.samples.erase(staged.first);
		throw;
	}
}

void set_gauge(MetricsRuntime::GaugeSeries& series, const std::string& scope,
		const std::string& id, double value, std::set<std::string>& seen) {
	const std::string key = series_key(scope, id);
	const prometheus::Labels labels { { "scope", scope }, { "id", id } };
	prometheus::Gauge& gauge = obtain_gauge(series, labels, key);
	gauge.Set(value);
	seen.insert(key);
}

void set_counter(MetricsRuntime::CounterSeries& series, const std::string& scope,
		const std::string& id, double value, std::set<std::string>& seen) {
	const std::string key = series_key(scope, id);
	const prometheus::Labels labels { { "scope", scope }, { "id", id } };
	auto found = series.samples.find(key);
	if (found == series.samples.end()) {
		obtain_counter(series, labels, key, value);
		seen.insert(key);
		return;
	}

	auto previous = series.last.find(key);
	if (previous == series.last.end()) {
		/* Keep the invariant "tracked sample implies tracked last value"
		 * before touching the sample. */
		const auto inserted = series.last.emplace(key, 0.0);
		if (!inserted.second) {
			throw std::runtime_error("inconsistent metric counter bookkeeping");
		}
		previous = inserted.first;
	}

	const double last = previous->second;
	if (value < last) {
		/* Engine counter reset: drop our old series and start from zero.  The
		 * new series is staged through obtain_counter(); if that fails the
		 * tracking state is clean and the next publish retries. */
		series.family->Remove(found->second);
		series.samples.erase(found);
		series.last.erase(previous);
		obtain_counter(series, labels, key, value);
	} else if (value > last) {
		found->second->Increment(value - last);
		previous->second = value;
	}
	seen.insert(key);
}

void prune_gauges(MetricsRuntime::GaugeSeries& series,
		const std::set<std::string>& seen) {
	for (auto it = series.samples.begin(); it != series.samples.end();) {
		if (seen.count(it->first) == 0) {
			series.family->Remove(it->second);
			it = series.samples.erase(it);
		} else {
			++it;
		}
	}
}

void prune_counters(MetricsRuntime::CounterSeries& series,
		const std::set<std::string>& seen) {
	for (auto it = series.samples.begin(); it != series.samples.end();) {
		if (seen.count(it->first) == 0) {
			series.family->Remove(it->second);
			series.last.erase(it->first);
			it = series.samples.erase(it);
		} else {
			++it;
		}
	}
}

void publish(Context& ctx, MetricsRuntime& runtime) {
	std::shared_ptr<tcp_proxy::Engine> engine = copy_engine(ctx);
	tcp_proxy::Snapshot snapshot;
	if (engine) snapshot = engine->snapshot();

	std::set<std::string> active_seen;
	std::set<std::string> accepted_seen;
	std::set<std::string> rejected_seen;
	std::set<std::string> connect_seen;
	std::set<std::string> matched_seen;
	std::set<std::string> c2s_seen;
	std::set<std::string> s2c_seen;

	set_gauge(runtime.active, "global", "0", snapshot.active_connections,
		active_seen);
	set_counter(runtime.accepted, "global", "0", snapshot.accepted_total,
		accepted_seen);
	set_counter(runtime.rejected, "global", "0", snapshot.rejected_total,
		rejected_seen);
	set_counter(runtime.connect_errors, "global", "0", snapshot.connect_errors,
		connect_seen);
	set_counter(runtime.bytes_client_to_server, "global", "0",
		snapshot.bytes_client_to_server, c2s_seen);
	set_counter(runtime.bytes_server_to_client, "global", "0",
		snapshot.bytes_server_to_client, s2c_seen);

	for (const auto& listener : snapshot.listeners) {
		const std::string id = std::to_string(listener.listener_id);
		set_gauge(runtime.active, "listener", id, listener.active_connections,
			active_seen);
		set_counter(runtime.accepted, "listener", id, listener.accepted_total,
			accepted_seen);
		set_counter(runtime.rejected, "listener", id, listener.rejected_total,
			rejected_seen);
		set_counter(runtime.connect_errors, "listener", id,
			listener.connect_errors, connect_seen);
		set_counter(runtime.bytes_client_to_server, "listener", id,
			listener.bytes_client_to_server, c2s_seen);
		set_counter(runtime.bytes_server_to_client, "listener", id,
			listener.bytes_server_to_client, s2c_seen);
	}

	for (const auto& rule : snapshot.rules) {
		const std::string id = std::to_string(rule.rule_id);
		set_gauge(runtime.active, "rule", id, rule.active_connections, active_seen);
		set_counter(runtime.rejected, "rule", id, rule.rejected_total,
			rejected_seen);
		set_counter(runtime.matched, "rule", id, rule.matched_total, matched_seen);
		set_counter(runtime.bytes_client_to_server, "rule", id,
			rule.bytes_client_to_server, c2s_seen);
		set_counter(runtime.bytes_server_to_client, "rule", id,
			rule.bytes_server_to_client, s2c_seen);
	}

	prune_gauges(runtime.active, active_seen);
	prune_counters(runtime.accepted, accepted_seen);
	prune_counters(runtime.rejected, rejected_seen);
	prune_counters(runtime.connect_errors, connect_seen);
	prune_counters(runtime.matched, matched_seen);
	prune_counters(runtime.bytes_client_to_server, c2s_seen);
	prune_counters(runtime.bytes_server_to_client, s2c_seen);

	runtime.generation->Set(static_cast<double>(snapshot.generation));
	runtime.running->Set(snapshot.running ? 1 : 0);
	runtime.retired->Set(static_cast<double>(snapshot.retired_connections));
}

/* Bounded status-only diagnostic.  Never takes the Engine/Admin/SQL locks and
 * never throws at the sampler thread boundary. */
void record_sampler_failure(Context& ctx, const char* message) noexcept {
	try {
		std::string text = message != nullptr ? message : "unknown metric error";
		if (text.size() > kMaxDiagnosticLength) {
			text.resize(kMaxDiagnosticLength);
		}
		std::lock_guard<std::mutex> guard(ctx.status_mutex);
		ctx.metrics_diagnostic = std::move(text);
	} catch (...) {
		/* Diagnostics must never terminate the sampler. */
	}
}

/* No Admin lock is acquired here.  Teardown can join this sampler even when
 * fast process exit begins on an Admin thread holding the global SQL mutex. */
void publish_guarded(Context& ctx, MetricsRuntime& runtime) noexcept {
	try {
		publish(ctx, runtime);
	} catch (const std::exception& exception) {
		record_sampler_failure(ctx, exception.what());
	} catch (...) {
		record_sampler_failure(ctx, "unknown metric publish failure");
	}
}

void remove_owned_samples(MetricsRuntime& runtime) noexcept {
	auto remove_gauges = [](MetricsRuntime::GaugeSeries& series) {
		if (series.family != nullptr) {
			for (auto& entry : series.samples) {
				if (entry.second != nullptr) series.family->Remove(entry.second);
			}
		}
		series.samples.clear();
	};
	auto remove_counters = [](MetricsRuntime::CounterSeries& series) {
		if (series.family != nullptr) {
			for (auto& entry : series.samples) {
				if (entry.second != nullptr) series.family->Remove(entry.second);
			}
		}
		series.samples.clear();
		series.last.clear();
	};

	remove_gauges(runtime.active);
	remove_counters(runtime.accepted);
	remove_counters(runtime.rejected);
	remove_counters(runtime.connect_errors);
	remove_counters(runtime.matched);
	remove_counters(runtime.bytes_client_to_server);
	remove_counters(runtime.bytes_server_to_client);

	if (runtime.retired != nullptr && runtime.retired_family != nullptr) {
		runtime.retired_family->Remove(runtime.retired);
	}
	runtime.retired = nullptr;
	if (runtime.running != nullptr && runtime.running_family != nullptr) {
		runtime.running_family->Remove(runtime.running);
	}
	runtime.running = nullptr;
	if (runtime.generation != nullptr && runtime.generation_family != nullptr) {
		runtime.generation_family->Remove(runtime.generation);
	}
	runtime.generation = nullptr;
}

} // namespace

#ifdef TCP_PROXY_METRICS_TESTING
void metrics_test_set_failure_stage(int stage) {
	g_fault_stage.store(stage, std::memory_order_release);
}

bool metrics_test_publish_once(Context& ctx, std::string& error) {
	std::shared_ptr<MetricsRuntime> runtime = ctx.metrics;
	if (!runtime) {
		error = "no metrics runtime";
		return false;
	}
	try {
		publish(ctx, *runtime);
		error.clear();
		return true;
	} catch (const std::exception& exception) {
		error = exception.what();
		return false;
	} catch (...) {
		error = "unknown metric publish failure";
		return false;
	}
}
#endif

bool metrics_init(ProxySQL_PluginServices& services, Context& ctx, std::string& error) {
	if (ctx.metrics) return true;
	if (services.get_prometheus_registry == nullptr) {
		error = "Prometheus registry service is unavailable";
		return false;
	}
	prometheus::Registry* registry = services.get_prometheus_registry();
	if (registry == nullptr) {
		error = "Prometheus registry is unavailable";
		return false;
	}
	try {
		std::shared_ptr<MetricsRuntime> runtime =
			std::make_shared<MetricsRuntime>();
		runtime->registry = registry;

		/* Reject another writer's visible families before any mutation.  Empty
		 * compatible families are invisible here and are borrowed by Register();
		 * incompatible empty families make Register() throw below. */
		if (!reject_visible_conflicts(*registry, error)) return false;

		auto register_gauge = [&](const char* name, const char* help) {
			return &prometheus::BuildGauge()
				.Name(name)
				.Help(help)
				.Labels(component_labels())
				.Register(*registry);
		};
		auto register_counter = [&](const char* name, const char* help) {
			return &prometheus::BuildCounter()
				.Name(name)
				.Help(help)
				.Labels(component_labels())
				.Register(*registry);
		};

		runtime->active.family = register_gauge(
			"proxysql_tcp_active_connections",
			"Current TCP proxy connections by scope and identity.");
		runtime->accepted.family = register_counter(
			"proxysql_tcp_accepted_total",
			"Accepted TCP proxy connections by scope and identity.");
		runtime->rejected.family = register_counter(
			"proxysql_tcp_rejected_total",
			"Rejected TCP proxy connections by scope and identity.");
		runtime->connect_errors.family = register_counter(
			"proxysql_tcp_connect_errors_total",
			"Backend connect errors by scope and identity.");
		runtime->matched.family = register_counter(
			"proxysql_tcp_matched_total",
			"Routing-rule matches by rule identity.");
		runtime->bytes_client_to_server.family = register_counter(
			"proxysql_tcp_bytes_client_to_server_total",
			"Bytes forwarded from clients to backends by scope and identity.");
		runtime->bytes_server_to_client.family = register_counter(
			"proxysql_tcp_bytes_server_to_client_total",
			"Bytes forwarded from backends to clients by scope and identity.");
		runtime->generation_family = register_gauge(
			"proxysql_tcp_generation",
			"Active TCP proxy configuration generation.");
		runtime->running_family = register_gauge(
			"proxysql_tcp_running",
			"Whether the TCP proxy Engine is running (1) or stopped (0).");
		runtime->retired_family = register_gauge(
			"proxysql_tcp_retired_connections",
			"Live connections pinned to older TCP proxy generations.");

		/* Scalars have empty sample labels, so Has({}) reveals a foreign sample
		 * left in a compatible merged family.  Track locally until the whole
		 * runtime is committed and undo only samples created here. */
		prometheus::Gauge* generation = nullptr;
		prometheus::Gauge* running = nullptr;
		prometheus::Gauge* retired = nullptr;
		try {
			if (runtime->generation_family->Has({})) {
				throw std::runtime_error(
					"generation metric sample belongs to a foreign writer");
			}
			maybe_fail(kFaultScalarBase + 1);
			generation = &runtime->generation_family->Add({});
			if (runtime->running_family->Has({})) {
				throw std::runtime_error(
					"running metric sample belongs to a foreign writer");
			}
			maybe_fail(kFaultScalarBase + 2);
			running = &runtime->running_family->Add({});
			if (runtime->retired_family->Has({})) {
				throw std::runtime_error(
					"retired metric sample belongs to a foreign writer");
			}
			maybe_fail(kFaultScalarBase + 3);
			retired = &runtime->retired_family->Add({});
		} catch (...) {
			if (retired != nullptr) runtime->retired_family->Remove(retired);
			if (running != nullptr) runtime->running_family->Remove(running);
			if (generation != nullptr) {
				runtime->generation_family->Remove(generation);
			}
			throw;
		}
		runtime->generation = generation;
		runtime->running = running;
		runtime->retired = retired;

		ctx.metrics = std::move(runtime);
		error.clear();
		return true;
	} catch (const std::exception& exception) {
		error = exception.what();
		ctx.metrics.reset();
		return false;
	} catch (...) {
		error = "unknown metric registration failure";
		ctx.metrics.reset();
		return false;
	}
}

bool metrics_start(Context& ctx) {
	if (!ctx.metrics || ctx.metrics_thread.joinable()) return true;
	ctx.metrics_stop_requested.store(false, std::memory_order_release);
	std::shared_ptr<MetricsRuntime> runtime = ctx.metrics;
	try {
		ctx.metrics_thread = std::thread([&ctx, runtime]() {
			for (;;) {
				if (ctx.metrics_stop_requested.load(std::memory_order_acquire)) break;
				publish_guarded(ctx, *runtime);
				std::unique_lock<std::mutex> lock(ctx.metrics_wait_mutex);
				ctx.metrics_wait_cv.wait_for(lock, kSampleInterval, [&ctx]() {
					return ctx.metrics_stop_requested.load(std::memory_order_acquire);
				});
			}
		});
	} catch (const std::exception& exception) {
		set_last_error(ctx, std::string("cannot start metric sampler: ") + exception.what());
		return false;
	} catch (...) {
		set_last_error(ctx, "cannot start metric sampler");
		return false;
	}
	return true;
}

void metrics_stop_sampler(Context& ctx) {
	ctx.metrics_stop_requested.store(true, std::memory_order_release);
	ctx.metrics_wait_cv.notify_all();
	/* The sampler never takes Admin's SQL mutex, including during fast exit. */
	if (ctx.metrics_thread.joinable()) ctx.metrics_thread.join();
}

void metrics_unregister(Context& ctx) {
	std::shared_ptr<MetricsRuntime> runtime = ctx.metrics;
	if (!runtime) return;
	/* Families are process-owned by the core library and are never removed.
	 * Only samples created by this plugin are dropped.  Lifecycle callers have
	 * already joined the sampler and drained Admin before reaching here. */
	remove_owned_samples(*runtime);
	ctx.metrics.reset();
}

} // namespace tcp_proxy_plugin
