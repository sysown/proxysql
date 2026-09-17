#include "MySQL_Server_Version_By_Interface.h"

#include <json.hpp>

#include <unordered_set>

bool MySQLServerVersionByInterfaceParseResult::accepted() const noexcept {
	return catalog != nullptr && error.empty();
}

MySQLServerVersionByInterfaceParseResult parse_mysql_server_version_by_interface(
	const std::string& value
) {
	using json = nlohmann::json;

	bool duplicate_key = false;
	std::unordered_set<std::string> keys;
	const json::parser_callback_t reject_duplicate_keys =
		[&duplicate_key, &keys](int, json::parse_event_t event, json& parsed) {
			if (event == json::parse_event_t::key) {
				const std::string& key = parsed.get_ref<const std::string&>();
				if (!keys.insert(key).second) {
					duplicate_key = true;
				}
			}
			return true;
		};

	json parsed;
	try {
		parsed = json::parse(value, reject_duplicate_keys);
	} catch (const json::exception& error) {
		return { nullptr, error.what() };
	}

	if (duplicate_key) {
		return { nullptr, "duplicate interface key" };
	}
	if (!parsed.is_object()) {
		return { nullptr, "value must be a JSON object" };
	}

	auto catalog = std::make_shared<MySQLServerVersionByInterfaceMap>();
	catalog->reserve(parsed.size());
	for (const auto& item : parsed.items()) {
		const std::string& interface_id = item.key();
		if (interface_id.empty()) {
			return { nullptr, "interface key must not be empty" };
		}
		if (interface_id.find('\0') != std::string::npos) {
			return { nullptr, "interface key must not contain NUL" };
		}
		if (!item.value().is_string()) {
			return { nullptr, "server version must be a string" };
		}

		const std::string& server_version = item.value().get_ref<const std::string&>();
		if (server_version.empty()) {
			return { nullptr, "server version must not be empty" };
		}
		if (server_version.find('\0') != std::string::npos) {
			return { nullptr, "server version must not contain NUL" };
		}
		catalog->emplace(interface_id, server_version);
	}

	return { std::move(catalog), {} };
}

std::string resolve_mysql_server_version_for_interface(
	const MySQLServerVersionByInterfaceMap& catalog,
	const std::string& interface_id,
	const std::string& fallback
) {
	const auto mapping = catalog.find(interface_id);
	return mapping == catalog.end() ? fallback : mapping->second;
}
