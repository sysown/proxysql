/**
 * @file reg_test_pp1_unknown_spoof-t.cpp
 * @brief Regression for GHSA-gw94-85m2-x8v2: PROXY-Protocol v1 UNKNOWN
 *        frames must not let a peer spoof the recorded client address.
 *
 * Before the fix, "PROXY UNKNOWN 10.0.0.5 1.2.3.4 12345 3306\r\n" was
 * parsed the same as a TCP4 frame and the forged source IP was written
 * into addr.addr, which is what Query_Processor's client_addr rule
 * matcher reads and what stats/event_log report. This test reproduces
 * the reporter's PoC payload and asserts that PROXYSQL INTERNAL SESSION
 * does NOT record "10.0.0.5" as the client address.
 *
 * Secondary case: "PROXY TCP4xyz ..." — the previous prefix-only memcmp
 * accepted it as TCP4. The fix requires a space delimiter after the
 * protocol token, so this header must be ignored entirely.
 */

#include <string>
#include <stdio.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

using std::string;
using nlohmann::json;

static MYSQL* connect_admin(const CommandLine& cl) {
	MYSQL* admin = mysql_init(nullptr);
	if (!admin) return nullptr;
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		diag("Admin connection failed: %s", mysql_error(admin));
		mysql_close(admin);
		return nullptr;
	}
	return admin;
}

static MYSQL* connect_with_proxy_header(const CommandLine& cl, const string& header) {
	MYSQL* proxy = mysql_init(nullptr);
	if (!proxy) return nullptr;
	mysql_optionsv(proxy, MARIADB_OPT_PROXY_HEADER, header.c_str(), header.size());
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		diag("Connection with PROXY header failed: %s", mysql_error(proxy));
		mysql_close(proxy);
		return nullptr;
	}
	return proxy;
}

// Returns the recorded client address (from PROXYSQL INTERNAL SESSION's
// client.client_addr.address) or empty string on failure.
static string fetch_recorded_client_addr(MYSQL* proxy) {
	json session = fetch_internal_session(proxy, false);
	auto client = session.find("client");
	if (client == session.end()) return "";
	auto client_addr = client->find("client_addr");
	if (client_addr == client->end()) return "";
	auto address = client_addr->find("address");
	if (address == client_addr->end()) return "";
	if (!address->is_string()) return "";
	return address->get<string>();
}

// Returns the PROXY_V1 source_address recorded in the session JSON, or
// empty string when no PROXY_V1 block was recorded.
static string fetch_pp1_source_address(MYSQL* proxy) {
	json session = fetch_internal_session(proxy, false);
	auto client = session.find("client");
	if (client == session.end()) return "";
	auto pv1 = client->find("PROXY_V1");
	if (pv1 == client->end()) return "";
	auto src = pv1->find("source_address");
	if (src == pv1->end() || !src->is_string()) return "";
	return src->get<string>();
}

static bool session_has_proxy_v1(MYSQL* proxy) {
	json session = fetch_internal_session(proxy, false);
	auto client = session.find("client");
	if (client == session.end()) return false;
	return client->find("PROXY_V1") != client->end();
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(8);

	MYSQL* admin = connect_admin(cl);
	if (!admin) return exit_status();

	MYSQL_QUERY(admin, "SET mysql-proxy_protocol_networks='*'");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// -------------------------------------------------------------
	// Case 1: PoC from the advisory.
	// PROXY UNKNOWN <forged> ... must NOT spoof client_addr.
	// -------------------------------------------------------------
	{
		const string forged_ip = "10.0.0.5";
		const string header = "PROXY UNKNOWN " + forged_ip + " 1.2.3.4 12345 3306\r\n";

		MYSQL* c = connect_with_proxy_header(cl, header);
		ok(c != nullptr, "PoC: connection with PROXY UNKNOWN <forged> header succeeds");
		if (c) {
			const string recorded = fetch_recorded_client_addr(c);
			diag("Recorded client_addr.address after UNKNOWN-spoof: '%s'", recorded.c_str());
			ok(recorded != forged_ip,
				"PoC: client_addr.address is NOT the forged '%s' (security: GHSA-gw94-85m2-x8v2 closed)",
				forged_ip.c_str());

			const string pp1_src = fetch_pp1_source_address(c);
			diag("Recorded PROXY_V1.source_address after UNKNOWN-spoof: '%s'", pp1_src.c_str());
			ok(pp1_src != forged_ip,
				"PoC: PROXY_V1.source_address is NOT the forged '%s'",
				forged_ip.c_str());

			mysql_close(c);
		} else {
			ok(false, "PoC: skipping client_addr check (connection failed)");
			ok(false, "PoC: skipping PROXY_V1.source_address check (connection failed)");
		}
	}

	// -------------------------------------------------------------
	// Case 2: secondary bug — "PROXY TCP4xyz <forged> ..." used to
	// pass the 4-byte prefix-match memcmp. The space delimiter check
	// must reject it.
	// -------------------------------------------------------------
	{
		const string forged_ip = "10.0.0.5";
		const string header = "PROXY TCP4xyz " + forged_ip + " 1.2.3.4 12345 3306\r\n";

		MYSQL* c = connect_with_proxy_header(cl, header);
		ok(c != nullptr, "TCP4xyz: connection with bogus protocol token succeeds (header skipped)");
		if (c) {
			ok(session_has_proxy_v1(c) == false,
				"TCP4xyz: malformed header is NOT recorded as PROXY_V1");

			const string recorded = fetch_recorded_client_addr(c);
			diag("Recorded client_addr.address after TCP4xyz: '%s'", recorded.c_str());
			ok(recorded != forged_ip,
				"TCP4xyz: client_addr.address is NOT the forged '%s'",
				forged_ip.c_str());

			mysql_close(c);
		} else {
			ok(false, "TCP4xyz: skipping PROXY_V1 absence check (connection failed)");
			ok(false, "TCP4xyz: skipping client_addr check (connection failed)");
		}
	}

	// -------------------------------------------------------------
	// Case 3: positive control — a valid TCP4 frame still works and
	// the parsed source IP is what we expect. This guards against an
	// over-tight fix that breaks legitimate PP1.
	// -------------------------------------------------------------
	{
		const string legit_ip = "192.168.0.1";
		const string header = "PROXY TCP4 " + legit_ip + " 192.168.0.11 56324 443\r\n";

		MYSQL* c = connect_with_proxy_header(cl, header);
		ok(c != nullptr, "TCP4: legitimate TCP4 header still accepted");
		if (c) {
			const string pp1_src = fetch_pp1_source_address(c);
			diag("Recorded PROXY_V1.source_address after legitimate TCP4: '%s'", pp1_src.c_str());
			ok(pp1_src == legit_ip,
				"TCP4: PROXY_V1.source_address parsed as '%s'",
				legit_ip.c_str());

			mysql_close(c);
		} else {
			ok(false, "TCP4: skipping source_address check (connection failed)");
		}
	}

	MYSQL_QUERY(admin, "SET mysql-proxy_protocol_networks=''");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	mysql_close(admin);

	return exit_status();
}
