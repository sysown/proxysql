// Azure Entra ID token provider for MySQL backend authentication (#6649).
#include "ProxySQL_Plugin.h"

#include "curl_transport.h"
#include "entra_token_source.h"

#include <dlfcn.h>

#include <cstdlib>
#include <string>

namespace {

ProxySQL_PluginServices *g_services = nullptr;
bool g_installed = false;

void log_line(int level, const std::string& message) {
	if (g_services != nullptr && g_services->log_message != nullptr) {
		g_services->log_message(level, message.c_str());
	}
}

void destroy_source(AwsIamTokenSource *source) {
	delete source;
}

// An extra reference to this module: core keeps it until every lease has
// drained and destroy_source() has run (doc/PLUGIN_API.md, ABI 13 and 17).
void *own_module_handle() {
	Dl_info info {};
	if (dladdr(reinterpret_cast<void *>(&destroy_source), &info) == 0 || info.dli_fname == nullptr) {
		return nullptr;
	}
	return dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD);
}

bool init(ProxySQL_PluginServices *services) {
	g_services = services;
	if (services == nullptr || services->install_azure_entra_token_source == nullptr) {
		log_line(3, "azure_entra: this ProxySQL core has no Azure Entra token-source service (ABI 17)");
		return false;
	}
	EntraConfig cfg;
	std::string error;
	if (!load_entra_config([](const char *name) { return std::getenv(name); }, cfg, error)) {
		log_line(3, "azure_entra: " + error);
		return false;
	}
	size_t max_total_waiters = 1;
	size_t max_waiters_per_key = 1;
	if (services->get_aws_iam_limits != nullptr) {
		services->get_aws_iam_limits(&max_total_waiters, &max_waiters_per_key);
	}
	void *module_handle = own_module_handle();
	if (module_handle == nullptr) {
		log_line(3, "azure_entra: cannot retain the plugin module handle");
		return false;
	}
	auto *source = new AzureEntraTokenSource(cfg, make_curl_post(),
		AwsIamRuntimeConfig { max_total_waiters, max_waiters_per_key },
		file_assertion_reader(cfg.federated_token_file));
	if (!services->install_azure_entra_token_source(source, &destroy_source, module_handle)) {
		delete source;
		dlclose(module_handle);
		log_line(3, "azure_entra: the Azure Entra token-source slot is already in use");
		return false;
	}
	g_installed = true;
	log_line(1, "azure_entra: token source installed for client " + cfg.client_id +
		" in tenant " + cfg.tenant_id);
	return true;
}

bool start() { return true; }

// Core retires the source at process shutdown.
bool stop() { return true; }

const char *status_json() {
	return g_installed ? "{\"name\":\"azure_entra\",\"installed\":true}"
		: "{\"name\":\"azure_entra\",\"installed\":false}";
}

const ProxySQL_PluginDescriptor descriptor {
	"azure_entra",
	PROXYSQL_PLUGIN_ABI_VERSION,
	&init,
	&start,
	&stop,
	&status_json,
};

} // namespace

extern "C" __attribute__((visibility("default")))
const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1() {
	return &descriptor;
}
