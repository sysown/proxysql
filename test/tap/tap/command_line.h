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

	char* workdir = strdup("./");

	uint64_t client_flags = 0;

	int getEnv();
	int parse(int argc, char** argv);
};

#endif // #ifndef COMMAND_LINE_H

