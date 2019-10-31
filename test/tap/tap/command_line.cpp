#include <string>
#include <fstream>

#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <cstdio>

#include "tap.h"
#include "command_line.h"
#include "json.hpp"

using nlohmann::json;

CommandLine::CommandLine() :
	host(NULL), username(NULL), password(NULL) {}

CommandLine::~CommandLine() {
	if (host)
		free(host);
	if (username)
		free(username);
	if (password)
		free(password);
}

int CommandLine::parse(int argc, char** argv) {
	int opt;
	while ((opt = getopt(argc, argv, "ncsu:p:h:P:")) != -1) {
		switch (opt) {
			case 'c':
				checksum = true;
				break;
			case 'u':
				username = strdup(optarg);
				break;
			case 'p':
				password = strdup(optarg);
				break;
			case 'A':
				admin_port = atoi(optarg);
				break;
			case 'h':
				host = strdup(optarg);
				break;
			case 'P':
				port = atoi(optarg);
				break;
			case 's':
				silent = 1;
				break;
			case 'n':
				no_write = true;
				break;
			default: /* '?' */
				fprintf(stderr, "Usage: %s -u username -p password -h host [ -P port ] [ -A port ] [ -c ] [ -s ] [ -n ]\n", argv[0]);
				return 0;
		}
	}
	if (
			(username == NULL) ||
			(password == NULL)
	   ) {
	   	return read("");
	}
	return 0;

}

int CommandLine::read(const std::string& file) {
/*	const char* config_file = NULL;

	if (file.empty())
		config_file = getenv("MYTAPCONFIG");

	std::ifstream ifs(config_file);
	if (ifs.fail()) {
		fprintf(stderr, "Error openning config file\n");
		return -1;
	}
	json j = json::parse(ifs);

	host = strdup(j["host"].get<std::string>().c_str());
	checksum = j["checksum"].get<bool>();
	username = strdup(j["username"].get<std::string>().c_str());
	password = strdup(j["password"].get<std::string>().c_str());
	port = j["port"].get<int>();*/

	host = strdup("127.0.0.1");
	port = 6033;
	admin_port = 6032;
	username = strdup("root");
	password = strdup("a");
	return 0;
}

int CommandLine::getEnv() {
	char* value;

	value=getenv("TAP_HOST");
	if(!value) return -1;
	host = strdup(value);

	value=getenv("TAP_USERNAME");
	if(!value) return -1;
	username=strdup(value);

	value=getenv("TAP_PASSWORD");
	if(!value) return -1;
	password=strdup(value);

	port=6033;
	checksum=true;

	int env_port=0;
	char* endstr;
	value=getenv("TAP_PORT");
	if(value)
		env_port=strtol(value, &endstr, 10);
	if(env_port>0 && env_port<65536)
		port=env_port;

	value=getenv("TAP_ADMINPORT");
	if(value)
		env_port=strtol(value, &endstr, 10);
	if(env_port>0 && env_port<65536)
		admin_port=env_port;

	return 0;
}
