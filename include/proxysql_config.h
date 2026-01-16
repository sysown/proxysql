#ifndef __PROXYSQL_CONFIG_H__
#define __PROXYSQL_CONFIG_H__

#include <string>
#include <libconfig.h++>
#include <vector>
#include <unordered_set>

class SQLite3DB;
extern const char* config_header;

enum proxysql_config_type {
	PROXYSQL_CONFIG_MYSQL_USERS,
	PROXYSQL_CONFIG_PGSQL_USERS,
	PROXYSQL_CONFIG_MYSQL_SERVERS,
	PROXYSQL_CONFIG_PGSQL_SERVERS,
	PROXYSQL_CONFIG_PROXY_SERVERS,
};

/**
 * @brief Configuration management class for ProxySQL.
 *
 * Handles reading and writing configuration from/to SQLite database and config files.
 * This class provides methods to load configuration sections (variables, users, servers,
 * query rules, scheduler, restapi) from config files into the database and vice versa.
 *
 * The class supports automatic prefix stripping for configuration variables to handle
 * cases where users mistakenly include the module prefix (e.g., "mysql-") in variable names.
 */
class ProxySQL_Config {
public:
	SQLite3DB* admindb;
	/** @brief Constructs ProxySQL_Config with a database handle */
	ProxySQL_Config(SQLite3DB* db);
	/** @brief Virtual destructor */
	virtual ~ProxySQL_Config();

	/** @copydoc ProxySQL_Config::Read_Global_Variables_from_configfile */
	int Read_Global_Variables_from_configfile(const char *prefix);
	int Read_MySQL_Users_from_configfile(std::string& error);
	int Read_MySQL_Query_Rules_from_configfile();
	int Read_MySQL_Servers_from_configfile(std::string& error);
	int Read_PgSQL_Servers_from_configfile(std::string& error);
	int Read_PgSQL_Users_from_configfile(std::string& error);
	int Read_PgSQL_Query_Rules_from_configfile();
	int Read_Scheduler_from_configfile();
	int Read_Restapi_from_configfile();
	int Read_ProxySQL_Servers_from_configfile(std::string& error);

	void addField(std::string& data, const char* name, const char* value, const char* dq="\"");
	int Write_Global_Variables_to_configfile(std::string& data);
	int Write_MySQL_Users_to_configfile(std::string& data);
	int Write_MySQL_Query_Rules_to_configfile(std::string& data);
	int Write_MySQL_Servers_to_configfile(std::string& data);
	int Write_PgSQL_Servers_to_configfile(std::string& data);
	int Write_PgSQL_Users_to_configfile(std::string& data);
	int Write_PgSQL_Query_Rules_to_configfile(std::string& data);
	int Write_Scheduler_to_configfile(std::string& data);
	int Write_Restapi_to_configfile(std::string& data);
	int Write_ProxySQL_Servers_to_configfile(std::string& data);

// Configuration validation methods
	void add_validation_error(const std::string& section, const std::string& location,
	                          const std::string& field, const std::string& message,
	                          const std::string& suggestion = "", bool is_fatal = true);
	void add_validation_warning(const std::string& section, const std::string& location,
	                            const std::string& field, const std::string& message);
	void report_validation_results();
	bool validate_config_fields(const libconfig::Setting& section, const std::string& section_name,
	                            const std::unordered_set<std::string>& valid_fields);
	std::string find_closest_match(const std::string& input, const std::unordered_set<std::string>& candidates);

// Configuration validation
	struct ConfigValidationError {
		std::string section;       // e.g., "mysql_query_rules"
		std::string location;      // e.g., "rule_id 100" or "line 42"
		std::string field;         // e.g., "mathc_pattern"
		std::string message;       // Error message
		std::string suggestion;    // Suggested correction (optional)
		bool is_fatal;             // If true, causes exit in strict mode
	};

	std::vector<ConfigValidationError> validation_errors;
	std::vector<ConfigValidationError> validation_warnings;

private:
	bool validate_backend_users(proxysql_config_type type, const libconfig::Setting& config, std::string& error);
	bool validate_backend_servers(proxysql_config_type type, const libconfig::Setting& config, std::string& error);
	bool validate_proxysql_servers(const libconfig::Setting& config, std::string& error);
};

#endif
