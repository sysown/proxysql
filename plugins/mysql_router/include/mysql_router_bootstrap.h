#ifndef PROXYSQL_MYSQL_ROUTER_BOOTSTRAP_H
#define PROXYSQL_MYSQL_ROUTER_BOOTSTRAP_H

#include "ProxySQL_Plugin.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

enum class AccountCreatePolicy : uint8_t {
	if_not_exists = 0,
	always = 1,
	never = 2,
};

enum class MetadataTlsMode : uint8_t {
	disabled = 0,
	preferred = 1,
	required = 2,
	verify_ca = 3,
	verify_identity = 4,
};

struct MetadataEndpoint {
	std::string username;
	std::string host;
	uint16_t port {3306};
};

struct ListenerProfile {
	std::string bind_address {"0.0.0.0"};
	uint16_t rw_port {6446};
	uint16_t ro_port {6447};
	uint16_t rw_split_port {6450};
	bool use_sockets {false};
	bool skip_tcp {false};
};

struct TlsOptions {
	MetadataTlsMode mode {MetadataTlsMode::preferred};
	std::string ca;
	std::string capath;
	std::string cert;
	std::string key;
	std::string cipher;
	std::string crl;
	std::string crlpath;
};

struct BootstrapOptions {
	bool requested {false};
	MetadataEndpoint seed;
	std::string router_name;
	std::string service_account;
	AccountCreatePolicy account_create {AccountCreatePolicy::if_not_exists};
	std::string account_host {"%"};
	unsigned password_retries {20};
	std::optional<int> password_fd;
	bool force {false};
	bool replace_topology {false};
	ListenerProfile listeners;
	TlsOptions tls;
};

class SecureBytes {
public:
	SecureBytes() = default;
	explicit SecureBytes(std::vector<unsigned char> bytes);
	~SecureBytes();
	SecureBytes(const SecureBytes&) = delete;
	SecureBytes& operator=(const SecureBytes&) = delete;
	SecureBytes(SecureBytes&& other) noexcept;
	SecureBytes& operator=(SecureBytes&& other) noexcept;

	const unsigned char* data() const { return bytes_.data(); }
	std::size_t size() const { return bytes_.size(); }
	bool empty() const { return bytes_.empty(); }

private:
	void cleanse();
	std::vector<unsigned char> bytes_;
};

bool mysql_router_register_cli_options(ProxySQL_PluginCLIRegistry* registry);
MetadataEndpoint parse_metadata_uri(std::string_view uri);
BootstrapOptions parse_bootstrap_options(
	const ProxySQL_PluginEarlyActionContext& context);
SecureBytes read_bootstrap_password(const BootstrapOptions& options);

#endif
