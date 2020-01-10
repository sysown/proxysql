#ifndef __PROXYSQL_CONFIG_H__
#define __PROXYSQL_CONFIG_H__

#include <string>

class SQLite3DB;
extern const char* config_header;

class ProxySQL_Config {
	SQLite3DB* admindb;
public:
	ProxySQL_Config(SQLite3DB* db);
	virtual ~ProxySQL_Config();

	int Read_Global_Variables_from_configfile(const char *prefix);
	int Read_MySQL_Users_from_configfile();
	int Read_MySQL_Query_Rules_from_configfile();
	int Read_MySQL_Servers_from_configfile();
	int Read_Scheduler_from_configfile();
	int Read_ProxySQL_Servers_from_configfile();

	void addField(std::string& data, const char* name, const char* value, const char* dq="\"");
	int Write_Global_Variables_to_configfile(std::string& data);
	int Write_MySQL_Users_to_configfile(std::string& data);
	int Write_MySQL_Query_Rules_to_configfile(std::string& data);
	int Write_MySQL_Servers_to_configfile(std::string& data);
	int Write_Scheduler_to_configfile(std::string& data);
	int Write_ProxySQL_Servers_to_configfile(std::string& data);
};

#endif
