#include <climits>
#include <string>

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


CommandLine::CommandLine() {}

CommandLine::~CommandLine() {
	if (host)
		free(host);
	if (username)
		free(username);
	if (password)
		free(password);

	if (root_host)
		free(root_host);
	if (root_username)
		free(root_username);
	if (root_password)
		free(root_password);

	if (admin_host)
		free(admin_host);
	if (admin_username)
		free(admin_username);
	if (admin_password)
		free(admin_password);

	if (mysql_host)
		free(mysql_host);
	if (mysql_username)
		free(mysql_username);
	if (mysql_password)
		free(mysql_password);

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
		// load environment
		char temp[PATH_MAX];
		ssize_t len = readlink("/proc/self/exe", temp, sizeof(temp));
		std::string exe_path = (len > 0) ? std::string(temp, len) : std::string("");
		std::string exe_name = exe_path.substr(exe_path.find_last_of('/') + 1);
		std::string dir_path = exe_path.substr(0, exe_path.find_last_of('/'));
		std::string dir_name = dir_path.substr(dir_path.find_last_of('/') + 1);

		env.load_dotenv((dir_path + "/.env").c_str(), true);
		bool loaded1 = env.loaded;

		env.load_dotenv((dir_path + "/" + dir_name + ".env").c_str(), true);
		bool loaded2 = env.loaded;

		env.load_dotenv((exe_path + ".env").c_str(), true);
		bool loaded3 = env.loaded;

		bool quiet = (bool) getenv("TAP_QUIET_ENVLOAD");
		if (loaded1 && ! quiet)
			diag("loaded: %s", (dir_path + "/.env").c_str());
		if (loaded2 && ! quiet)
			diag("loaded: %s", (dir_path + "/" + dir_name + ".env").c_str());
		if (loaded3 && ! quiet)
			diag("loaded: %s", (exe_path + ".env").c_str());
	}

	int env_port = 0;
	{
		// unprivileged test connection
		value = getenv("TAP_HOST");
		if (value)
			replace_str_field(&this->host, value);

		value = getenv("TAP_PORT");
		if (value) {
			env_port = strtol(value, NULL, 10);
			if (env_port > 0 && env_port < 65536)
				port = env_port;
		}

		value = getenv("TAP_USERNAME");
		if (value)
			replace_str_field(&this->username, value);

		value = getenv("TAP_PASSWORD");
		if (value)
			replace_str_field(&this->password, value);
	}

	{
		// privileged test connection
		value = getenv("TAP_ROOTHOST");
		if (value)
			replace_str_field(&this->root_host, value);

		value = getenv("TAP_ROOTPORT");
		if (value) {
			env_port = strtol(value, NULL, 10);
			if (env_port > 0 && env_port < 65536)
				root_port = env_port;
		}

		value = getenv("TAP_ROOTUSERNAME");
		if (value)
			replace_str_field(&this->root_username, value);

		value = getenv("TAP_ROOTPASSWORD");
		if (value)
			replace_str_field(&this->root_password, value);
	}

	{
		// proxysql admin connection
		value = getenv("TAP_ADMINHOST");
		if (value)
			replace_str_field(&this->admin_host, value);

		value = getenv("TAP_ADMINPORT");
		if (value) {
			env_port = strtol(value, NULL, 10);
			if (env_port > 0 && env_port < 65536)
				admin_port = env_port;
		}

		value = getenv("TAP_ADMINUSERNAME");
		if (value)
			replace_str_field(&this->admin_username, value);

		value = getenv("TAP_ADMINPASSWORD");
		if (value)
			replace_str_field(&this->admin_password, value);
	}

	{
		// mysql admin connection
		value = getenv("TAP_MYSQLHOST");
		if (value)
			replace_str_field(&this->mysql_host, value);

		value = getenv("TAP_MYSQLPORT");
		if (value) {
			env_port = strtol(value, NULL, 10);
			if (env_port > 0 && env_port < 65536)
				mysql_port = env_port;
		}

		value = getenv("TAP_MYSQLUSERNAME");
		if (value)
			replace_str_field(&this->mysql_username, value);

		value = getenv("TAP_MYSQLPASSWORD");
		if (value)
			replace_str_field(&this->mysql_password, value);
	}


	value = getenv("TAP_WORKDIR");
	if (value)
		replace_str_field(&this->workdir, value);

	value = getenv("TAP_CLIENT_FLAGS");
	if (value) {
		char* end = NULL;
		uint64_t env_c_flags = strtoul(value, &end, 10);

		const char* errmsg { NULL };

		if (env_c_flags == 0 && value == end) {
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
