#ifndef COMMAND_LINE_H
#define COMMAND_LINE_H

#include <cstdint>
#include <string.h>
#include <string>

class CommandLine {
	public:
	CommandLine();
	~CommandLine();

	bool checksum = true;
	bool no_write = false;
	int silent = false;

	// unpriviliged test connection
	char* host = strdup("127.0.0.1");
	int port = 6033;
	char* username = strdup("testuser");
	char* password = strdup("testuser");

	// priviliged test connection
	char* root_host = strdup("127.0.0.1");
	int root_port = 6033;
	char* root_username = strdup("root");
	char* root_password = strdup("root");

	// proxysql admin connection
	char* admin_host = strdup("127.0.0.1");
	int admin_port = 6032;
	char* admin_username = strdup("admin");
	char* admin_password = strdup("admin");

	// mysql admin connection
	char* mysql_host = strdup("127.0.0.1");
	int mysql_port = 3306;
	char* mysql_username = strdup("root");
	char* mysql_password = strdup("root");

	// proxysql postgresql admin connection
	char* pgsql_admin_host = strdup("127.0.0.1");
	int   pgsql_admin_port = 6132;

	// pgsql server connection
	char* pgsql_server_host = strdup("127.0.0.1");
	int   pgsql_server_port = 5432;
	char* pgsql_server_username = strdup("postgres");
	char* pgsql_server_password = strdup("postgres");

	// unpriviliged test connection
	char* pgsql_host = strdup("127.0.0.1");
	int   pgsql_port = 6133;
	char* pgsql_username = strdup("testuser");
	char* pgsql_password = strdup("testuser");

	// priviliged test connection
	char* pgsql_root_host = strdup("127.0.0.1");
	int	  pgsql_root_port = 6133;
	char* pgsql_root_username = strdup("postgres");
	char* pgsql_root_password = strdup("postgres");

	char* workdir = strdup("./");

	uint64_t client_flags = 0;

	int getEnv();
	int parse(int argc, char** argv);
};

#endif // #ifndef COMMAND_LINE_H

