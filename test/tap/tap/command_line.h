#ifndef COMMAND_LINE_H
#define COMMAND_LINE_H

#include <string.h>
#include <string>

class CommandLine {
	public:
	CommandLine();
	~CommandLine();

	int parse(int argc, char** argv);
	bool checksum = true;
	bool no_write = false;
	int silent = false;

	char* host = strdup("127.0.0.1");
	char* username = strdup("root");
	char* password = strdup("");
	char* admin_username = strdup("admin");
	char* admin_password = strdup("admin");

	int	port = 6033;
	int admin_port = 6032;
	char* workdir = strdup("./tests/");

	uint64_t client_flags = 0;
	int getEnv();
};

#endif // #ifndef COMMAND_LINE_H

