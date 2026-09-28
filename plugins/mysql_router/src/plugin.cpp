#include "mysql_router_admin.h"
#include "mysql_router_bootstrap.h"
#include "mysql_router_config.h"
#include "mysql_router_plugin.h"
#include "mysql_router_metadata.h"

#include <cstdio>
#include <unistd.h>

namespace {

void close_router_gates_noexcept(MysqlRouterContext& context, std::string_view reason) noexcept {
	if (!context.reconcile_backend) return;
	try {
		context.reconcile_backend->set_gates(false, reason);
	} catch (...) {
	}
}

void mark_initialization_failed(MysqlRouterContext& context, std::string_view error) noexcept {
	context.reconciler.reset();
	context.reconcile_backend.reset();
	context.runtime_ready.store(false);
	context.started.store(false);
	context.initialized.store(false);
	context.services = nullptr;
	std::lock_guard<std::mutex> guard(context.status_mutex);
	context.status.state = "initialization_error";
	context.status.last_error.assign(error);
}

bool register_cli_options(ProxySQL_PluginCLIRegistry* registry) {
	return mysql_router_register_cli_options(registry);
}

ProxySQL_PluginEarlyActionResult early_action(
		const ProxySQL_PluginEarlyActionContext& action_context) {
	try {
		BootstrapOptions options = parse_bootstrap_options(action_context);
		if (!options.requested) return ProxySQL_PluginEarlyActionResult::not_requested;
		if (action_context.services == nullptr) throw std::runtime_error("plugin services are unavailable");
		char hostname[256] {};
		if (gethostname(hostname, sizeof(hostname) - 1) != 0 || hostname[0] == '\0') {
			throw std::runtime_error("cannot determine Router hostname");
		}
		if (options.router_name.empty()) options.router_name = std::string(hostname) + "_proxysql";
		SecureBytes password = read_bootstrap_password(options);
		auto session = ConnectorCMetadataSession::connect(options.seed, options.tls, password, 5);
		DesiredTopology topology = MetadataV2_2::read_innodb_cluster(*session, {}, 0);
		BootstrapResult result = run_mysql_router_bootstrap(options, *session,
			std::move(topology), hostname, *action_context.services);
		if (!result.success) throw std::runtime_error(result.error);
		std::fprintf(stdout,
			"MySQL Router bootstrap complete\nRouter: %s\nTopology: %s (InnoDB Cluster)\n"
			"Classic endpoints: RW=%u RO=%u R/W-split=%u\nStart ProxySQL normally to activate routing.\n",
			options.router_name.c_str(), result.topology_uuid.c_str(),
			options.listeners.rw_port, options.listeners.ro_port,
			options.listeners.rw_split_port);
		return ProxySQL_PluginEarlyActionResult::exit_success;
	} catch (const std::exception& exception) {
		MysqlRouterContext& context = mysql_router_context();
		const std::string message = "mysql_router bootstrap failed: " +
			std::string(exception.what());
		{
			std::lock_guard<std::mutex> guard(context.status_mutex);
			context.status.last_error = exception.what();
		}
		if (action_context.services != nullptr &&
			action_context.services->log_message != nullptr) {
			action_context.services->log_message(3, message.c_str());
		}
		return ProxySQL_PluginEarlyActionResult::exit_failure;
	}
}

bool init(ProxySQL_PluginServices* services) {
	if (services == nullptr) return false;
	MysqlRouterContext& context = mysql_router_context();
	context.services = services;
	if (!mysql_router_register_metrics(*services)) {
		mark_initialization_failed(context, "metric registration failed");
		return false;
	}
	try {
		context.reconcile_backend = create_mysql_router_reconcile_backend(*services);
		if (context.reconcile_backend) {
			context.reconciler = std::make_unique<MysqlRouterReconciler>(
				*context.reconcile_backend, context.reconcile_backend->schedule(),
				context.reconcile_backend->initial_topology_generation(),
				context.reconcile_backend->initial_user_generation());
		}
	} catch (const std::exception& error) {
		if (services->log_message != nullptr) {
			const std::string message = "mysql_router initialization failed: " +
				std::string(error.what());
			services->log_message(3, message.c_str());
		}
		mark_initialization_failed(context, error.what());
		return false;
	}
	context.initialized.store(true);
	{
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.state = "initialized";
		context.status.last_error.clear();
	}
	return true;
}

bool start() {
	MysqlRouterContext& context = mysql_router_context();
	if (!context.initialized.load()) return false;
	context.started.store(true);
	{
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.state = "started";
	}
	return true;
}

bool runtime_ready(ProxySQL_PluginRuntimeContext* runtime_context) {
	if (runtime_context == nullptr || runtime_context->services == nullptr) return false;
	MysqlRouterContext& context = mysql_router_context();
	if (!context.started.load()) return false;
	try {
		context.runtime_ready.store(true);
		if (!context.reconciler || !context.reconcile_backend) {
			const MysqlRouterRuntimeConfig defaults;
			for (uint16_t port : {defaults.rw_port, defaults.ro_port, defaults.rw_split_port}) {
				const ProxySQL_PluginListenerGate gate {"mysql_router", defaults.bind_address.c_str(), port,
					ProxySQL_PluginListenerState::closed, "MySQL Router is not bootstrapped"};
				if (runtime_context->services->set_listener_gate != nullptr) {
					(void)runtime_context->services->set_listener_gate(gate);
				}
			}
			std::lock_guard<std::mutex> guard(context.status_mutex);
			context.status.state = "unconfigured";
			context.status.gates_ready = false;
			return true;
		}
		context.reconcile_backend->set_gates(false, "initial topology validation in progress");
		const ReconcileResult result = context.reconciler->refresh({true, true});
		{
			std::lock_guard<std::mutex> guard(context.status_mutex);
			context.status.topology_generation = result.topology_generation;
			context.status.user_generation = result.user_generation;
			context.status.metadata_available = result.metadata_available;
			context.status.registration_exists = result.registration_exists;
			context.status.gates_ready = result.gates_ready;
			if (!result.topology_error.empty()) context.status.last_error = result.topology_error;
			else if (!result.user_error.empty()) context.status.last_error = result.user_error;
			context.status.state = result.gates_ready && context.status.last_error.empty()
				? "ready" : "degraded";
		}
		return context.reconciler->start(false);
	} catch (const std::exception& error) {
		context.runtime_ready.store(false);
		close_router_gates_noexcept(context, "Router runtime initialization failed");
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.state = "runtime_error";
		context.status.gates_ready = false;
		context.status.last_error = error.what();
		return false;
	} catch (...) {
		context.runtime_ready.store(false);
		close_router_gates_noexcept(context, "Router runtime initialization failed");
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.state = "runtime_error";
		context.status.gates_ready = false;
		context.status.last_error = "unknown Router runtime-ready failure";
		return false;
	}
}

bool stop() {
	MysqlRouterContext& context = mysql_router_context();
	if (context.reconciler) context.reconciler->stop();
	close_router_gates_noexcept(context, "MySQL Router plugin is stopping");
	context.reconciler.reset();
	context.reconcile_backend.reset();
	context.runtime_ready.store(false);
	context.started.store(false);
	context.initialized.store(false);
	context.services = nullptr;
	{
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.state = "stopped";
		context.status.gates_ready = false;
	}
	return true;
}

ProxySQL_PluginCommandResult force_reconcile(
		const ProxySQL_PluginCommandContext& command_context) {
	MysqlRouterContext& context = mysql_router_context();
	if (!context.reconciler) return {1, 0, "MySQL Router is not bootstrapped"};
	bool released = false;
	try {
		if (command_context.release_admin_mutex != nullptr &&
			command_context.acquire_admin_mutex != nullptr) {
			command_context.release_admin_mutex(command_context.admin_mutex_context);
			released = true;
		}
		const ReconcileResult result = context.reconciler->refresh({true, true});
		if (released) {
			command_context.acquire_admin_mutex(command_context.admin_mutex_context);
			released = false;
		}
		{
			std::lock_guard<std::mutex> guard(context.status_mutex);
			context.status.topology_generation = result.topology_generation;
			context.status.user_generation = result.user_generation;
			context.status.metadata_available = result.metadata_available;
			context.status.registration_exists = result.registration_exists;
			context.status.gates_ready = result.gates_ready;
			if (!result.topology_error.empty()) context.status.last_error = result.topology_error;
			else if (!result.user_error.empty()) context.status.last_error = result.user_error;
			context.status.state = result.gates_ready && context.status.last_error.empty()
				? "ready" : "degraded";
		}
		const bool success = result.topology_error.empty() && result.user_error.empty();
		uint64_t collisions = 0;
		{
			std::lock_guard<std::mutex> guard(context.status_mutex);
			collisions = context.status.user_collisions;
		}
		return {success ? 0 : 1, 0,
			"topology_generation=" + std::to_string(result.topology_generation) +
			" user_generation=" + std::to_string(result.user_generation) +
			" collisions=" + std::to_string(collisions)};
	} catch (const std::exception& error) {
		if (released) command_context.acquire_admin_mutex(command_context.admin_mutex_context);
		return {1, 0, error.what()};
	}
}

bool register_schemas(ProxySQL_PluginServices* services) {
	return services != nullptr && mysql_router_register_admin_schema(*services);
}

const ProxySQL_PluginDescriptor descriptor {
	"mysql_router",
	PROXYSQL_PLUGIN_ABI_VERSION,
	&init,
	&start,
	&stop,
	&mysql_router_status_json,
	&register_schemas,
	&register_cli_options,
	&early_action,
	&runtime_ready,
};

} // namespace

ProxySQL_PluginCommandResult mysql_router_reconcile_command(
	const ProxySQL_PluginCommandContext& command_context, const char*) {
	return force_reconcile(command_context);
}

MysqlRouterContext& mysql_router_context() {
	static MysqlRouterContext context;
	return context;
}

extern "C" __attribute__((visibility("default")))
const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1() {
	return &descriptor;
}
