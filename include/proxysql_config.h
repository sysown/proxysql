#ifndef __PROXYSQL_CONFIG_H__
#define __PROXYSQL_CONFIG_H__

#include <string>
#include <libconfig.h++>

class SQLite3DB;
extern const char* config_header;

enum proxysql_config_type {
	PROXYSQL_CONFIG_MYSQL_USERS,
	PROXYSQL_CONFIG_PGSQL_USERS,
	PROXYSQL_CONFIG_MYSQL_SERVERS,
	PROXYSQL_CONFIG_PGSQL_SERVERS,
	PROXYSQL_CONFIG_PROXY_SERVERS,
};

class ProxySQL_Config {
public:
	SQLite3DB* admindb;
	ProxySQL_Config(SQLite3DB* db);
	virtual ~ProxySQL_Config();

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

private:
	bool validate_backend_users(proxysql_config_type type, const libconfig::Setting& config, std::string& error);
	bool validate_backend_servers(proxysql_config_type type, const libconfig::Setting& config, std::string& error);
	bool validate_proxysql_servers(const libconfig::Setting& config, std::string& error);
};

#endif
