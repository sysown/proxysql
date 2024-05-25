/*
 * Usage:
 * Prepare PostgreSQL server:
 * sudo -u postgres createuser --pwprompt testuser
 * sudo -u postgres createdb testuser --owner testuser
 * prepend to pg_hba.conf: "host all testuser 127.0.0.1/32 scram-sha-256"
 * systemctl restart postgresql
 * Run the test:
 * TAP_PORT=5432 ./libpq-t
 */

#include "command_line.h"
#include "tap.h"

#include <stdlib.h>
#include <libpq-fe.h>

int main() {
	plan(1);

	CommandLine cl;
	if(cl.getEnv()) {
		return exit_status();
	}

	PGconn *conn;
	PGresult *res;
	char *conninfo;
	int r;
	// assumes dbname=username
	// optionally, for traffic analysis: sslmode=disable
	r = asprintf(&conninfo, "host=%s port=%u user=%s password=%s", cl.host, cl.port, cl.username, cl.password);

	// Establish connection
	conn = PQconnectdb(conninfo);

	// Check if connection succeeded
	ok(PQstatus(conn) == CONNECTION_OK, "Connection to database should succeed");
	PQfinish(conn);
	return exit_status();
}
