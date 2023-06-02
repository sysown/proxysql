#include <climits>
#include <string>
#include <fstream>

#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <cstdio>

#include "tap.h"
#include "command_line.h"
#include "json.hpp"

#include "dotenv.h"

using nlohmann::json;
using dotenv::env;
//using namespace dotenv;

CommandLine::CommandLine() {}

CommandLine::~CommandLine() {
	if (host)
		free(host);
	if (username)
		free(username);
	if (password)
		free(password);
	if (admin_username)
		free(admin_username);
	if (admin_password)
		free(admin_password);
	if (workdir)
		free(workdir);
}

int CommandLine::parse(int argc, char** argv) {
	int opt;
	while ((opt = getopt(argc, argv, "ncsu:p:h:P:W:")) != -1) {
		switch (opt) {
			case 'c':
				checksum = true;
				break;
			case 'u':
				if (username) {
					free(username);
				}
				username = strdup(optarg);
				break;
			case 'p':
				if (password) {
					free(password);
				}
				password = strdup(optarg);
				break;
			case 'A':
				admin_port = atoi(optarg);
				break;
			case 'h':
				if (host) {
					free(host);
				}
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
			case 'U':
				if (admin_username) {
					free(admin_username);
				}
				admin_username = strdup(optarg);
				break;
			case 'W':
				workdir = strdup(optarg);
				break;
			case 'S':
				if (admin_password) {
					free(admin_password);
				}
				admin_password = strdup(optarg);
				break;
			default: /* '?' */
				fprintf(stderr, "Usage: %s -u username -p password -h host [ -P port ] [ -A port ] [ -U admin_username ] [ -S admin_password ] [ -W workdir] [ -c ] [ -s ] [ -n ]\n", argv[0]);
				return 0;
		}
	}
	return 0;
}

int CommandLine::getEnv() {
	char* value = NULL;

	const auto replace_str_field = [] (char** field, char* value) -> void {
		if (field && *field) {
			free(*field);
		}
		*field = strdup(value);
	};

	{
//		char dir_name[256]
//		getcwd(dir_name, sizeof(dir_name);
//		strcat(dir_name,".env")
//		env.load_dotenv(".env", true).load_dotenv(dir_name, true);

		char temp[PATH_MAX];
		std::string dir_name = getcwd(temp, sizeof(temp)) ? std::string( temp ) : std::string("");
		env.load_dotenv(".env", true);
		env.load_dotenv((dir_name.substr(dir_name.find_last_of('/') + 1) + ".env").c_str(), true);
		fprintf(stdout, ">>> %s %s <<<\n", (dir_name + ".env").c_str(), (dir_name.substr(dir_name.find_last_of('/') + 1) + ".env").c_str());

		std::string exe_name;
		std::ifstream("/proc/self/comm") >> exe_name;
		env.load_dotenv((exe_name + ".env").c_str(), true);
		env.load_dotenv((exe_name.substr(0, exe_name.size() - 2) + ".env").c_str(), true);
		fprintf(stdout, ">>> %s %s <<<\n", (exe_name + ".env").c_str(), (exe_name.substr(0, exe_name.size() - 2) + ".env").c_str());
	}

	value=getenv("TAP_HOST");
	if(!value) return -1;
	replace_str_field(&this->host, value);

	value=getenv("TAP_USERNAME");
	if(!value) return -1;
	replace_str_field(&this->username, value);

	value=getenv("TAP_PASSWORD");
	if(!value) return -1;
	replace_str_field(&this->password, value);

	value=getenv("TAP_ADMINUSERNAME");
	if (value) {
		replace_str_field(&this->admin_username, value);
	}

	value=getenv("TAP_ADMINPASSWORD");
	if (value) {
		replace_str_field(&this->admin_password, value);
	}

	int env_port=0;
	value=getenv("TAP_PORT");
	if(value)
		env_port=strtol(value, NULL, 10);
	else
		env_port=6033;
	if(env_port>0 && env_port<65536)
		port=env_port;

	value=getenv("TAP_ADMINPORT");
	if(value)
		env_port=strtol(value, NULL, 10);
	else
		env_port=6032;
	if(env_port>0 && env_port<65536)
		admin_port=env_port;

	value=getenv("TAP_WORKDIR");
	if(!value) return -1;
	replace_str_field(&this->workdir, value);

	value=getenv("TAP_CLIENT_FLAGS");
	if (value) {
		char* end = NULL;
		uint64_t env_c_flags = strtoul(value, &end, 10);

		const char* errmsg { NULL };

		if (env_c_flags == 0 && value == end)  {
			errmsg = "Invalid string to parse";
		} else if (env_c_flags == ULONG_MAX && errno == ERANGE) {
			errmsg = strerror(errno);
		}

		if (errmsg) {
			fprintf(stderr, "Failed to parse env variable 'CLIENT_FLAGS' with error: '%s'\n", strerror(errno));
			return -1;
		} else {
			this->client_flags = env_c_flags;
		}
	}

	return 0;
}
