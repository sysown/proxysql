#include <cstdlib>
#include <cstring>

#include <sys/socket.h>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"

namespace {

constexpr unsigned char kComStmtClose = 0x19;
constexpr unsigned char kMalformedStmtClosePacket[] = {
	0x01, 0x00, 0x00, 0x00,
	kComStmtClose
};

MYSQL* connect_proxy(const CommandLine& cl) {
	MYSQL* mysql = mysql_init(nullptr);
	if (mysql == nullptr) {
		return nullptr;
	}

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		mysql_close(mysql);
		return nullptr;
	}

	return mysql;
}

bool query_returns_one(MYSQL* mysql) {
	if (mysql_query(mysql, "SELECT 1")) {
		return false;
	}

	MYSQL_RES* result = mysql_store_result(mysql);
	if (result == nullptr) {
		return false;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	const bool ok = row != nullptr && row[0] != nullptr && strcmp(row[0], "1") == 0;
	mysql_free_result(result);
	return ok;
}

bool prepared_select_returns_42(MYSQL* mysql) {
	MYSQL_STMT* stmt = mysql_stmt_init(mysql);
	if (stmt == nullptr) {
		return false;
	}

	const char query[] = "SELECT 42";
	if (mysql_stmt_prepare(stmt, query, sizeof(query) - 1)) {
		mysql_stmt_close(stmt);
		return false;
	}

	if (mysql_stmt_execute(stmt)) {
		mysql_stmt_close(stmt);
		return false;
	}

	int value = 0;
	unsigned long value_len = 0;
	my_bool is_null = 0;

	MYSQL_BIND bind {};
	bind.buffer_type = MYSQL_TYPE_LONG;
	bind.buffer = &value;
	bind.buffer_length = sizeof(value);
	bind.length = &value_len;
	bind.is_null = &is_null;

	if (mysql_stmt_bind_result(stmt, &bind)) {
		mysql_stmt_close(stmt);
		return false;
	}

	if (mysql_stmt_store_result(stmt)) {
		mysql_stmt_close(stmt);
		return false;
	}

	const int fetch_rc = mysql_stmt_fetch(stmt);
	const bool ok = fetch_rc == 0 && is_null == 0 && value == 42;
	mysql_stmt_free_result(stmt);
	mysql_stmt_close(stmt);
	return ok;
}

bool send_all(int fd, const unsigned char* data, size_t len) {
	size_t total_sent = 0;

	while (total_sent < len) {
		const ssize_t sent = send(fd, data + total_sent, len - total_sent, MSG_NOSIGNAL);
		if (sent <= 0) {
			return false;
		}
		total_sent += sent;
	}

	return true;
}

bool send_malformed_stmt_close(MYSQL* mysql) {
	return send_all(mysql->net.fd, kMalformedStmtClosePacket, sizeof(kMalformedStmtClosePacket));
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(6);

	MYSQL* attack = connect_proxy(cl);
	ok(attack != nullptr, "Authenticated frontend connection succeeds");
	if (attack == nullptr) {
		skip(5, "Cannot continue without an authenticated frontend connection");
		return exit_status();
	}

	ok(prepared_select_returns_42(attack), "Baseline prepared statement succeeds before malformed COM_STMT_CLOSE");

	ok(
		send_malformed_stmt_close(attack),
		"Malformed COM_STMT_CLOSE packet is written to the live connection"
	);

	usleep(200000);

	ok(
		prepared_select_returns_42(attack),
		"Prepared statements still execute after malformed COM_STMT_CLOSE"
	);

	ok(
		query_returns_one(attack),
		"Same connection still serves queries after malformed COM_STMT_CLOSE"
	);

	MYSQL* fresh = connect_proxy(cl);
	ok(fresh != nullptr && query_returns_one(fresh), "Fresh connection still succeeds after malformed COM_STMT_CLOSE");

	if (fresh != nullptr) {
		mysql_close(fresh);
	}
	mysql_close(attack);

	return exit_status();
}
