#ifndef AZURE_ENTRA_CONFIG_H
#define AZURE_ENTRA_CONFIG_H

#include <functional>
#include <string>

/** @brief AKS workload identity settings for the Azure Entra token provider (#6649). */
struct EntraConfig {
	std::string tenant_id;
	std::string client_id;
	std::string federated_token_file;
	std::string authority_host; // always ends with '/'
	std::string scope;
};

/**
 * @brief Read the provider settings from the environment.
 * @details AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_FEDERATED_TOKEN_FILE are
 *   required (the AKS workload identity webhook sets them). AZURE_AUTHORITY_HOST
 *   defaults to the public cloud and must use https. PROXYSQL_AZURE_ENTRA_SCOPE
 *   overrides the Azure Database for MySQL scope. Tenant and client IDs must be
 *   GUIDs, because they become part of the token URL and form.
 * @return false with 'error' naming the bad variable.
 */
bool load_entra_config(const std::function<const char *(const char *)>& getenv_fn,
	EntraConfig& out, std::string& error);

#endif // AZURE_ENTRA_CONFIG_H
