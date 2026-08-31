#ifndef PROXYSQL_MYSQL_ROUTER_METADATA_H
#define PROXYSQL_MYSQL_ROUTER_METADATA_H

#include "mysql_router_types.h"
#include "mysql_router_bootstrap.h"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

using SqlValue = std::variant<int64_t, std::string>;
using SqlCell = std::optional<std::string>;
using QueryRow = std::map<std::string, SqlCell>;

struct QueryResult {
	std::vector<QueryRow> rows;
};

struct ExecResult {
	bool ok {false};
	uint64_t affected_rows {0};
	std::string error;
};

struct ServerVersion {
	int major {0};
	int minor {0};
	int patch {0};
};

class IMetadataSession {
public:
	virtual ~IMetadataSession() = default;
	virtual QueryResult query(std::string_view sql, const std::vector<SqlValue>& params) = 0;
	virtual ExecResult execute(std::string_view sql, const std::vector<SqlValue>& params) = 0;
	virtual ServerVersion server_version() const = 0;
	virtual std::string quote_sql_string(std::string_view value) const {
		std::string quoted("'");
		quoted.reserve(value.size() + 2);
		for (char character : value) {
			if (character == '\'' || character == '\\') quoted.push_back(character);
			quoted.push_back(character);
		}
		quoted.push_back('\'');
		return quoted;
	}
};

class ConnectorCMetadataSession final : public IMetadataSession {
public:
	static std::unique_ptr<ConnectorCMetadataSession> connect(
		const MetadataEndpoint& endpoint, const TlsOptions& tls,
		const SecureBytes& password, unsigned timeout_seconds);
	~ConnectorCMetadataSession() override;
	ConnectorCMetadataSession(const ConnectorCMetadataSession&) = delete;
	ConnectorCMetadataSession& operator=(const ConnectorCMetadataSession&) = delete;

	QueryResult query(std::string_view sql, const std::vector<SqlValue>& params) override;
	ExecResult execute(std::string_view sql, const std::vector<SqlValue>& params) override;
	ServerVersion server_version() const override;
	std::string quote_sql_string(std::string_view value) const override;

private:
	struct Impl;
	explicit ConnectorCMetadataSession(std::unique_ptr<Impl> impl);
	std::unique_ptr<Impl> impl_;
};

struct MetadataCapabilities {
	MetadataVersion version;
	bool router_options_view {false};
	bool router_stats {false};
	bool routing_guidelines {false};
};

MetadataCapabilities probe_metadata(IMetadataSession& session);

class MetadataV2_2 {
public:
	static DesiredTopology read_innodb_cluster(
		IMetadataSession& session, std::string_view cluster_uuid, int64_t router_id);
};

class GrHealthReader {
public:
	static ObservedHealth read(IMetadataSession& session);
};

bool calculate_gr_quorum(const std::map<std::string, ObservedMember>& members);
EffectiveTopology evaluate_innodb_cluster(
	const DesiredTopology& desired, const ObservedHealth& observed);

#endif
