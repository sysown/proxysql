#ifndef __CLASS_PROXYSQL_CLI_H
#define __CLASS_PROXYSQL_CLI_H

// Entry point for proxysql-cli mode.
// Called when argv[0] ends with "proxysql-cli".
// Returns the exit code (0 success, 1 error).
int proxysql_cli_main(int argc, const char* argv[]);

#endif // __CLASS_PROXYSQL_CLI_H
