/*
 * Native TCP proxy plugin descriptor and lifecycle.
 *
 * Phase B declares Admin schema/commands without touching DB handles.  Phase E
 * reads the restored editable configuration and prepares metrics; Phase F
 * validates core listener reservations and starts the production Engine.
 */

#include "tcp_proxy_plugin.h"

#include "sqlite3db.h"

#include "json.hpp"

#include <chrono>
#include <cstdio>
#include <exception>
#include <memory>
#include <string>
#include <utility>

namespace tcp_proxy_plugin {

bool plugin_init(ProxySQL_PluginServices* services) {
	Context& ctx = context();
	if (services == nullptr) return false;
	if (ctx.initialized.load()) return true;

	ctx.services = services;
	{
		std::lock_guard<std::mutex> guard(ctx.engine_mutex);
		ctx.engine.reset();
		// The ABI-18 getter is live after Phase B.  An older header (or a
		// Phase-B-style stub returning nullptr) yields no provider, so any
		// configured tcp_hostgroups start/apply fails with a clear diagnostic.
		ctx.backend_provider = core_backend_provider(services);
	}
	{
		std::lock_guard<std::mutex> guard(ctx.config_mutex);
		ctx.initial_config = tcp_proxy::Config {};
		ctx.has_initial_config = false;
	}

	auto fail_init = [&](const std::string& error) {
		set_last_error(ctx, error);
		set_state(ctx, "initialization_error");
		metrics_unregister(ctx);
		if (services->log_message != nullptr) {
			services->log_message(3, ("tcp_proxy initialization failed: " + error).c_str());
		}
		ctx.backend_provider.reset();
		ctx.services = nullptr;
		return false;
	};

	try {
		if (services->get_admindb == nullptr) {
			return fail_init("admin DB service is unavailable");
		}
		SQLite3DB* admindb = services->get_admindb();
		if (admindb == nullptr) {
			return fail_init("admin DB handle is unavailable");
		}

		std::string error;
		if (!reject_legacy_artifacts(*admindb, "disk", error)) {
			return fail_init("invalid persisted TCP configuration: " + error);
		}
		if (!seed_settings_defaults(*admindb, error)) return fail_init(error);

		tcp_proxy::Config restored;
		if (!read_config(*admindb, restored, error)) {
			return fail_init("invalid persisted TCP configuration: " + error);
		}
		if (!tcp_proxy::validate_config(restored, error)) {
			return fail_init("invalid persisted TCP configuration: " + error);
		}

		if (!metrics_init(*services, ctx, error)) {
			return fail_init("metric registration failed: " + error);
		}

		{
			std::lock_guard<std::mutex> guard(ctx.config_mutex);
			ctx.initial_config = std::move(restored);
			ctx.has_initial_config = true;
		}
		clear_last_error(ctx);
		set_state(ctx, "initialized");
		ctx.initialized.store(true);
		return true;
	} catch (const std::exception& exception) {
		return fail_init(std::string("unexpected initialization exception: ") +
			exception.what());
	} catch (...) {
		return fail_init("unexpected initialization exception");
	}
}

bool plugin_start() {
	Context& ctx = context();
	if (!ctx.initialized.load()) return false;
	if (ctx.started.load()) return true;

	try {
		tcp_proxy::Config config;
		{
			std::lock_guard<std::mutex> guard(ctx.config_mutex);
			if (!ctx.has_initial_config) {
				set_last_error(ctx, "no validated startup configuration is available");
				set_state(ctx, "start_failed");
				return false;
			}
			config = ctx.initial_config;
		}

		std::string error;
		if (!tcp_proxy::validate_config(config, error)) {
			set_last_error(ctx, error);
			set_state(ctx, "start_failed");
			return false;
		}

		std::shared_ptr<tcp_proxy::BackendProvider> provider;
		{
			std::lock_guard<std::mutex> guard(ctx.engine_mutex);
			provider = ctx.backend_provider;
		}
		if (!config.hostgroups.empty() &&
			(!provider || !provider->available())) {
			set_last_error(ctx, "tcp_hostgroups require the core raw backend "
				"service (ABI 18), which is unavailable");
			set_state(ctx, "start_failed");
			return false;
		}

		const std::string interfaces = tcp_proxy::listener_interfaces(config);
		if (ctx.services != nullptr &&
			ctx.services->validate_listener_interfaces != nullptr) {
			if (!ctx.services->validate_listener_interfaces(
					"tcp_proxy", interfaces.c_str(), error)) {
				set_last_error(ctx, error);
				set_state(ctx, "start_failed");
				return false;
			}
		} else if (!interfaces.empty()) {
			set_last_error(ctx,
				"listener reservation validation service is unavailable");
			set_state(ctx, "start_failed");
			return false;
		}

		std::shared_ptr<tcp_proxy::Engine> engine;
		if (provider) {
			engine = std::make_shared<tcp_proxy::Engine>(std::move(provider));
		} else {
			engine = std::make_shared<tcp_proxy::Engine>();
		}
		if (!engine->start(config, error)) {
			set_last_error(ctx, error);
			set_state(ctx, "start_failed");
			return false;
		}

		{
			std::lock_guard<std::mutex> guard(ctx.engine_mutex);
			ctx.engine = engine;
		}
		if (!metrics_start(ctx)) {
			engine->stop();
			{
				std::lock_guard<std::mutex> guard(ctx.engine_mutex);
				ctx.engine.reset();
			}
			set_state(ctx, "start_failed");
			return false;
		}
		clear_last_error(ctx);
		set_state(ctx, "running");
		ctx.started.store(true);
		return true;
	} catch (const std::exception& exception) {
		{
			std::lock_guard<std::mutex> guard(ctx.engine_mutex);
			ctx.engine.reset();
		}
		set_last_error(ctx,
			std::string("unexpected start exception: ") + exception.what());
		set_state(ctx, "start_failed");
		return false;
	} catch (...) {
		{
			std::lock_guard<std::mutex> guard(ctx.engine_mutex);
			ctx.engine.reset();
		}
		set_last_error(ctx, "unexpected start exception");
		set_state(ctx, "start_failed");
		return false;
	}
}

bool plugin_stop() {
	Context& ctx = context();

	set_state(ctx, "stopping");
	ctx.started.store(false);

	/* Stop snapshot publication before Engine shutdown, then join before any
	 * worker/driver teardown can invalidate the sampler. */
	metrics_stop_sampler(ctx);

	std::shared_ptr<tcp_proxy::Engine> engine;
	std::shared_ptr<tcp_proxy::BackendProvider> provider;
	{
		std::lock_guard<std::mutex> guard(ctx.engine_mutex);
		engine = std::move(ctx.engine);
		ctx.engine.reset();
	}
	if (engine) engine->stop();
	{
		std::lock_guard<std::mutex> guard(ctx.engine_mutex);
		provider = std::move(ctx.backend_provider);
		ctx.backend_provider.reset();
	}
	provider.reset();

	/* Remove owned metric samples after worker shutdown, before DSO unload. */
	metrics_unregister(ctx);

	{
		std::lock_guard<std::mutex> guard(ctx.config_mutex);
		ctx.initial_config = tcp_proxy::Config {};
		ctx.has_initial_config = false;
	}
	ctx.initialized.store(false);
	ctx.services = nullptr;
	clear_last_error(ctx);
	set_state(ctx, "stopped");
	return true;
}

bool runtime_ready(ProxySQL_PluginRuntimeContext* runtime_context) {
	if (runtime_context == nullptr || runtime_context->services == nullptr) return false;
	Context& ctx = context();
	return ctx.started.load() && engine_is_running(ctx);
}

const char* status_json() {
	Context& ctx = context();
	static const char* const kFallback =
		"{\"plugin\":\"tcp_proxy\",\"state\":\"error\",\"running\":false,"
		"\"generation\":0,\"last_error\":\"status unavailable\","
		"\"active_connections\":0,\"retired_connections\":0,"
		"\"accepted_total\":0,\"rejected_total\":0,\"connect_errors\":0,"
		"\"bytes_client_to_server\":0,\"bytes_server_to_client\":0,"
		"\"listeners\":0,\"rules\":0}";

	std::string serialized;
	try {
		std::string state;
		std::string last_error;
		{
			std::lock_guard<std::mutex> guard(ctx.status_mutex);
			state = ctx.state;
			last_error = ctx.last_error;
		}
		tcp_proxy::Snapshot snapshot;
		std::shared_ptr<tcp_proxy::Engine> engine = copy_engine(ctx);
		if (engine) snapshot = engine->snapshot();

		nlohmann::json body {
			{ "plugin", "tcp_proxy" },
			{ "state", state },
			{ "running", snapshot.running },
			{ "generation", snapshot.generation },
			{ "last_error", last_error },
			{ "active_connections", snapshot.active_connections },
			{ "retired_connections", snapshot.retired_connections },
			{ "accepted_total", snapshot.accepted_total },
			{ "rejected_total", snapshot.rejected_total },
			{ "connect_errors", snapshot.connect_errors },
			{ "bytes_client_to_server", snapshot.bytes_client_to_server },
			{ "bytes_server_to_client", snapshot.bytes_server_to_client },
			{ "listeners", snapshot.listeners.size() },
			{ "rules", snapshot.rules.size() },
		};
		serialized = body.dump(-1, ' ', false,
			nlohmann::json::error_handler_t::replace);
	} catch (...) {
		/* Static literal: no allocation can fail on this error path. */
		return kFallback;
	}

	/* Context-owned storage keeps the returned pointer valid for the module
	 * lifetime and until the next status_json() call, without a thread_local
	 * std::string whose destructor can run before the chassis stop callback. */
	try {
		std::lock_guard<std::mutex> guard(ctx.status_json_mutex);
		ctx.status_json_buffer = std::move(serialized);
		return ctx.status_json_buffer.c_str();
	} catch (...) {
		return kFallback;
	}
}

} // namespace tcp_proxy_plugin

namespace {

bool init(ProxySQL_PluginServices* services) {
	return tcp_proxy_plugin::plugin_init(services);
}

bool start() {
	return tcp_proxy_plugin::plugin_start();
}

bool stop() {
	return tcp_proxy_plugin::plugin_stop();
}

bool register_schemas(ProxySQL_PluginServices* services) {
	return services != nullptr && tcp_proxy_plugin::register_schemas(*services);
}

const ProxySQL_PluginDescriptor descriptor {
	"tcp_proxy",
	PROXYSQL_PLUGIN_ABI_VERSION,
	&init,
	&start,
	&stop,
	&tcp_proxy_plugin::status_json,
	&register_schemas,
	nullptr,
	nullptr,
	&tcp_proxy_plugin::runtime_ready,
	nullptr,
};

} // namespace

extern "C" __attribute__((visibility("default")))
const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1() {
	return &descriptor;
}
