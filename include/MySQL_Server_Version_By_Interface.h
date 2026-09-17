#ifndef MYSQL_SERVER_VERSION_BY_INTERFACE_H
#define MYSQL_SERVER_VERSION_BY_INTERFACE_H

#include <memory>
#include <string>
#include <unordered_map>

using MySQLServerVersionByInterfaceMap = std::unordered_map<std::string, std::string>;

struct MySQLServerVersionByInterfaceParseResult {
	std::shared_ptr<const MySQLServerVersionByInterfaceMap> catalog;
	std::string error;

	bool accepted() const noexcept;
};

MySQLServerVersionByInterfaceParseResult parse_mysql_server_version_by_interface(
	const std::string& value
);

std::string resolve_mysql_server_version_for_interface(
	const MySQLServerVersionByInterfaceMap& catalog,
	const std::string& interface_id,
	const std::string& fallback
);

#endif // MYSQL_SERVER_VERSION_BY_INTERFACE_H
