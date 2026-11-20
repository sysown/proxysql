#include "entra_config.h"

#include <locale>

namespace {

bool is_guid(const std::string& value) {
	if (value.size() != 36) return false;
	for (size_t i = 0; i < value.size(); ++i) {
		const bool dash_position = i == 8 || i == 13 || i == 18 || i == 23;
		if (dash_position ? value[i] != '-' : !std::isxdigit(value[i], std::locale::classic())) {
			return false;
		}
	}
	return true;
}

} // namespace

bool load_entra_config(const std::function<const char *(const char *)>& getenv_fn,
	EntraConfig& out, std::string& error) {
	const auto get = [&getenv_fn](const char *name) {
		const char *value = getenv_fn(name);
		return std::string(value != nullptr ? value : "");
	};
	EntraConfig cfg;
	cfg.tenant_id = get("AZURE_TENANT_ID");
	cfg.client_id = get("AZURE_CLIENT_ID");
	cfg.federated_token_file = get("AZURE_FEDERATED_TOKEN_FILE");
	cfg.authority_host = get("AZURE_AUTHORITY_HOST");
	cfg.scope = get("PROXYSQL_AZURE_ENTRA_SCOPE");

	if (!is_guid(cfg.tenant_id)) {
		error = "AZURE_TENANT_ID must be set to a GUID";
		return false;
	}
	if (!is_guid(cfg.client_id)) {
		error = "AZURE_CLIENT_ID must be set to a GUID";
		return false;
	}
	if (cfg.federated_token_file.empty()) {
		error = "AZURE_FEDERATED_TOKEN_FILE must be set (AKS workload identity)";
		return false;
	}
	if (cfg.authority_host.empty()) cfg.authority_host = "https://login.microsoftonline.com/";
	if (cfg.authority_host.rfind("https://", 0) != 0) {
		error = "AZURE_AUTHORITY_HOST must use https";
		return false;
	}
	if (cfg.authority_host.back() != '/') cfg.authority_host += '/';
	if (cfg.scope.empty()) cfg.scope = "https://ossrdbms-aad.database.windows.net/.default";

	out = std::move(cfg);
	return true;
}
