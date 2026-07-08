#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

// Regression test for https://github.com/sysown/proxysql/issues/5639
//
// A COM_STMT_EXECUTE whose binary packet exceeds mysql-max_allowed_packet
// reaches MySQL_Session::handler_WCD_SS_MCQ_qpo_LargePacket
// (lib/MySQL_Session.cpp:6370) via
// handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_EXECUTE
// -> handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo
// at lib/MySQL_Session.cpp:6405-6406. The reporter observes a SIGSEGV in
// that frame on v3.0.1/v3.0.6/v3.0.7. This test exercises that path and
// asserts ProxySQL rejects the packet cleanly with ER_NET_PACKET_TOO_LARGE
// (1153), keeps the offending connection usable, and stays alive for new
// connections.

namespace {

constexpr unsigned int kMaxAllowedPacket = 8192;  // minimum allowed by ProxySQL
constexpr size_t kBoundStringSize = 12 * 1024;    // guarantees pkt > kMaxAllowedPacket
constexpr unsigned int kRestoreMaxAllowedPacket = 67108864;  // ProxySQL default

MYSQL* connect_admin(const CommandLine& cl) {
	MYSQL* admin = mysql_init(nullptr);
	if (admin == nullptr) {
		return nullptr;
	}
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
			nullptr, cl.admin_port, nullptr, 0)) {
		diag("admin mysql_real_connect failed: %s", mysql_error(admin));
		mysql_close(admin);
		return nullptr;
	}
	return admin;
}

MYSQL* connect_proxy(const CommandLine& cl) {
	MYSQL* mysql = mysql_init(nullptr);
	if (mysql == nullptr) {
		return nullptr;
	}
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password,
			nullptr, cl.port, nullptr, 0)) {
		diag("proxy mysql_real_connect failed: %s", mysql_error(mysql));
		mysql_close(mysql);
		return nullptr;
	}
	return mysql;
}

bool simple_select_works(MYSQL* mysql) {
	if (mysql_query(mysql, "SELECT 1")) {
		return false;
	}
	MYSQL_RES* res = mysql_store_result(mysql);
	if (res == nullptr) {
		return false;
	}
	MYSQL_ROW row = mysql_fetch_row(res);
	const bool ok_ret = row != nullptr && row[0] != nullptr && strcmp(row[0], "1") == 0;
	mysql_free_result(res);
	return ok_ret;
}

void restore_max_allowed_packet(MYSQL* admin) {
	char buf[128];
	snprintf(buf, sizeof(buf), "SET mysql-max_allowed_packet=%u", kRestoreMaxAllowedPacket);
	mysql_query(admin, buf);
	mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
}

} // namespace

int main(int /*argc*/, char** /*argv*/) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(8);

	// --- 1. Lower mysql-max_allowed_packet to the minimum (8192) ---
	MYSQL* admin = connect_admin(cl);
	const bool admin_ok = admin != nullptr;
	ok(admin_ok, "Connect to ProxySQL admin");
	if (!admin_ok) {
		return exit_status();
	}

	{
		char buf[128];
		snprintf(buf, sizeof(buf), "SET mysql-max_allowed_packet=%u", kMaxAllowedPacket);
		MYSQL_QUERY(admin, buf);
	}
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(true, "Lowered mysql-max_allowed_packet to %u", kMaxAllowedPacket);

	// --- 2. Frontend connection used to send the oversized STMT_EXECUTE ---
	MYSQL* sess = connect_proxy(cl);
	const bool sess_ok = sess != nullptr;
	ok(sess_ok, "Connect to ProxySQL frontend");
	if (!sess_ok) {
		restore_max_allowed_packet(admin);
		mysql_close(admin);
		return exit_status();
	}

	// --- 3. Prepare a trivial stmt with one VARCHAR parameter ---
	MYSQL_STMT* stmt = mysql_stmt_init(sess);
	const char prep[] = "SELECT ? AS x";
	const bool prepared = stmt != nullptr &&
		mysql_stmt_prepare(stmt, prep, sizeof(prep) - 1) == 0;
	ok(prepared, "Prepared 'SELECT ? AS x'");
	if (!prepared) {
		if (stmt) {
			diag("mysql_stmt_prepare failed: %s", mysql_stmt_error(stmt));
			mysql_stmt_close(stmt);
		}
		mysql_close(sess);
		restore_max_allowed_packet(admin);
		mysql_close(admin);
		return exit_status();
	}

	// --- 4. Bind a parameter large enough that the binary STMT_EXECUTE
	// packet exceeds kMaxAllowedPacket. The total wire packet for a single
	// VARCHAR parameter is roughly payload_size + ~16 bytes of stmt header;
	// kBoundStringSize > kMaxAllowedPacket comfortably crosses the limit. ---
	std::string big(kBoundStringSize, 'A');
	unsigned long big_len = static_cast<unsigned long>(big.size());

	MYSQL_BIND bind {};
	bind.buffer_type = MYSQL_TYPE_STRING;
	bind.buffer = const_cast<char*>(big.data());
	bind.buffer_length = static_cast<unsigned long>(big.size());
	bind.length = &big_len;
	bind.is_null = nullptr;

	if (mysql_stmt_bind_param(stmt, &bind)) {
		diag("mysql_stmt_bind_param failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		mysql_close(sess);
		restore_max_allowed_packet(admin);
		mysql_close(admin);
		ok(false, "mysql_stmt_bind_param");
		return exit_status();
	}

	// --- 5. Execute. ProxySQL must reject with ER_NET_PACKET_TOO_LARGE
	// instead of crashing in handler_WCD_SS_MCQ_qpo_LargePacket. ---
	const int rc = mysql_stmt_execute(stmt);
	const unsigned int err = mysql_stmt_errno(stmt);
	const char* errstr = mysql_stmt_error(stmt);

	ok(rc != 0, "mysql_stmt_execute is rejected for oversized binary packet (rc=%d)", rc);
	ok(
		err == 1153,
		"Error is ER_NET_PACKET_TOO_LARGE (1153); got %u (%s)",
		err, errstr ? errstr : "(no message)"
	);

	mysql_stmt_close(stmt);

	// --- 6. The connection that sent the oversized packet must remain usable. ---
	ok(simple_select_works(sess), "Same frontend connection still serves queries");

	// --- 7. ProxySQL still accepts new connections (process alive). ---
	MYSQL* fresh = connect_proxy(cl);
	ok(
		fresh != nullptr && simple_select_works(fresh),
		"Fresh frontend connection works after oversized STMT_EXECUTE"
	);
	if (fresh != nullptr) {
		mysql_close(fresh);
	}

	mysql_close(sess);

	// --- 8. Restore default max_allowed_packet so the run does not bleed
	// state into other tests in the same group. ---
	restore_max_allowed_packet(admin);
	mysql_close(admin);

	return exit_status();
}
