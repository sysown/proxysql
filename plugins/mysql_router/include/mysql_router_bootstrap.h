#ifndef PROXYSQL_MYSQL_ROUTER_BOOTSTRAP_H
#define PROXYSQL_MYSQL_ROUTER_BOOTSTRAP_H

#include "ProxySQL_Plugin.h"
#include "mysql_router_types.h"

#include <json.hpp>

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

/** @brief Canonical MySQL Router spelling of a metadata TLS mode (e.g. "VERIFY_CA"). */
inline const char* metadata_tls_mode_name(MetadataTlsMode mode) {
	switch (mode) {
		case MetadataTlsMode::disabled: return "DISABLED";
		case MetadataTlsMode::preferred: return "PREFERRED";
		case MetadataTlsMode::required: return "REQUIRED";
		case MetadataTlsMode::verify_ca: return "VERIFY_CA";
		case MetadataTlsMode::verify_identity: return "VERIFY_IDENTITY";
	}
	return "PREFERRED";
}

/** @brief Parses a canonical metadata TLS mode name; std::nullopt for any other spelling. */
inline std::optional<MetadataTlsMode> metadata_tls_mode_from_name(std::string_view name) {
	for (MetadataTlsMode mode : {MetadataTlsMode::disabled, MetadataTlsMode::preferred,
		MetadataTlsMode::required, MetadataTlsMode::verify_ca, MetadataTlsMode::verify_identity}) {
		if (name == metadata_tls_mode_name(mode)) return mode;
	}
	return std::nullopt;
}

/**
 * @brief Returns why a metadata TLS configuration is unusable, or an empty string.
 * @details Certificate verification needs a trust anchor the operator chose: like
 *   MySQL Router and libmysqlclient, VERIFY_CA and VERIFY_IDENTITY require a CA file
 *   or directory instead of silently falling back to the system trust store.
 */
inline std::string metadata_tls_problem(const TlsOptions& tls) {
	if ((tls.mode == MetadataTlsMode::verify_ca || tls.mode == MetadataTlsMode::verify_identity) &&
		tls.ca.empty() && tls.capath.empty()) {
		return std::string("TLS mode ") + metadata_tls_mode_name(tls.mode) +
			" requires a CA certificate (ssl-ca or ssl-capath)";
	}
	if (tls.cert.empty() != tls.key.empty()) {
		return "a TLS client certificate and its key must be configured together";
	}
	return {};
}

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

class IMetadataSession;
struct AccountSnapshot;

struct RouterRegistration {
	int64_t router_id {0};
	std::string product_name;
	std::string version;
	nlohmann::json attributes;
};

enum class BootstrapPhase : uint8_t {
	discovered,
	account_ready,
	registered,
	local_configured,
	complete,
};

struct BootstrapJournal {
	std::string topology_uuid;
	std::string router_name;
	BootstrapPhase phase {BootstrapPhase::discovered};
	int64_t router_id {0};
	std::string metadata_user;
	std::string last_error;
};

struct BootstrapIdentity {
	std::string topology_uuid;
	std::string topology_name;
	int64_t router_id {0};
	std::string router_name;
	std::string router_address;
	std::string metadata_user;
	std::string metadata_host;
	uint16_t metadata_port {3306};
	uint64_t topology_generation {0};
	uint64_t user_generation {0};
};

struct BootstrapResult {
	bool success {false};
	int64_t router_id {0};
	std::string topology_uuid;
	std::string metadata_user;
	std::string error;
};

class IBootstrapStore {
public:
	virtual ~IBootstrapStore() = default;
	virtual std::optional<BootstrapJournal> load_journal(std::string_view topology_uuid) = 0;
	virtual std::optional<BootstrapIdentity> load_identity() = 0;
	virtual void save_journal(const BootstrapJournal& journal) = 0;
	virtual void put_secret(std::string_view name, const std::vector<uint8_t>& value) = 0;
	virtual std::optional<std::vector<uint8_t>> get_secret(std::string_view name) = 0;
	virtual uint64_t publish_topology(const DesiredTopology& topology,
		const ListenerProfile& listeners, uint64_t generation) = 0;
	virtual uint64_t publish_users(const DesiredTopology& topology,
		const ListenerProfile& listeners, const AccountSnapshot& snapshot,
		std::string_view metadata_user, uint64_t generation) = 0;
	/** Persists the local Router identity, listener profile and metadata TLS settings. */
	virtual void save_complete(const BootstrapIdentity& identity,
		const ListenerProfile& listeners, const TlsOptions& tls) = 0;
};

class MysqlRouterBootstrap {
public:
	MysqlRouterBootstrap(IMetadataSession& session, IBootstrapStore& store,
		DesiredTopology topology, std::string router_address);
	BootstrapResult run(const BootstrapOptions& options);

private:
	IMetadataSession& session_;
	IBootstrapStore& store_;
	DesiredTopology topology_;
	std::string router_address_;
};

bool mysql_router_register_cli_options(ProxySQL_PluginCLIRegistry* registry);
MetadataEndpoint parse_metadata_uri(std::string_view uri);
BootstrapOptions parse_bootstrap_options(
	const ProxySQL_PluginEarlyActionContext& context);
SecureBytes read_bootstrap_password(const BootstrapOptions& options);
RouterRegistration register_or_adopt_router(
	IMetadataSession& session, const DesiredTopology& topology,
	const BootstrapOptions& options, std::string_view address,
	std::string_view metadata_user);
BootstrapResult run_mysql_router_bootstrap(
	const BootstrapOptions& options, IMetadataSession& session,
	DesiredTopology topology, std::string router_address,
	ProxySQL_PluginServices& services);
uint64_t publish_mysql_router_topology(ProxySQL_PluginServices& services,
	IMetadataSession& session, const DesiredTopology& topology,
	const EffectiveTopology& effective, const ListenerProfile& listeners,
	uint64_t generation);
uint64_t publish_mysql_router_users(ProxySQL_PluginServices& services,
	IMetadataSession& session, const DesiredTopology& topology,
	const EffectiveTopology& effective, const ListenerProfile& listeners,
	const AccountSnapshot& snapshot, std::string_view metadata_user,
	uint64_t generation);

#endif
