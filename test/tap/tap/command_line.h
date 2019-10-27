#ifndef COMMAND_LINE_H
#define COMMAND_LINE_H

class CommandLine {
	public:
	CommandLine();
	~CommandLine();

	int parse(int argc, char** argv);
	bool checksum;
	bool no_write;
	int silent;
	char* host;
	char* username;
	char* password;
	int	 port;

	int read(const std::string& file);
	int getEnv();
};

#endif // #ifndef COMMAND_LINE_H

