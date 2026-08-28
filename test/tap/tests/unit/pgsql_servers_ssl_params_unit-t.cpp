/**
 * @file pgsql_servers_ssl_params_unit-t.cpp
 * @brief Unit tests for Servers_SslParams base class, PgSQLServers_SslParams
 *        derived class, and PgSQL_HostGroups_Manager SSL params lookup.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "Servers_SslParams.h"

#include <string>
#include <unordered_map>

using std::string;
using std::unordered_map;

extern PgSQL_HostGroups_Manager *PgHGM;

// ============================================================================
// 1. Servers_SslParams constructors
// ============================================================================

static void test_base_constructor_string() {
	Servers_SslParams p(
		string("db1.example.com"), 5432, string("appuser"),
		string("/certs/ca.crt"), string("/certs/client.crt"), string("/certs/client.key"),
		string("/certs/capath"), string("/certs/crl.pem"), string("/certs/crlpath"),
		string("ECDHE-RSA-AES256-GCM-SHA384"), string("TLSv1.2-TLSv1.3"),
		string("test comment")
	);

	ok(p.hostname == "db1.example.com", "string ctor: hostname");
	ok(p.port == 5432, "string ctor: port");
	ok(p.username == "appuser", "string ctor: username");
	ok(p.ssl_ca == "/certs/ca.crt", "string ctor: ssl_ca");
	ok(p.ssl_cert == "/certs/client.crt", "string ctor: ssl_cert");
	ok(p.ssl_key == "/certs/client.key", "string ctor: ssl_key");
	ok(p.ssl_capath == "/certs/capath", "string ctor: ssl_capath");
	ok(p.ssl_crl == "/certs/crl.pem", "string ctor: ssl_crl");
	ok(p.ssl_crlpath == "/certs/crlpath", "string ctor: ssl_crlpath");
	ok(p.ssl_cipher == "ECDHE-RSA-AES256-GCM-SHA384", "string ctor: ssl_cipher");
	ok(p.tls_version == "TLSv1.2-TLSv1.3", "string ctor: tls_version");
	ok(p.comment == "test comment", "string ctor: comment");
}

static void test_base_constructor_3arg() {
	Servers_SslParams p(string("db3.example.com"), 5434, string("readonly"));

	ok(p.hostname == "db3.example.com", "3-arg ctor: hostname");
	ok(p.port == 5434, "3-arg ctor: port");
	ok(p.username == "readonly", "3-arg ctor: username");
	ok(p.ssl_ca == "", "3-arg ctor: ssl_ca defaults to empty");
	ok(p.ssl_cert == "", "3-arg ctor: ssl_cert defaults to empty");
	ok(p.ssl_key == "", "3-arg ctor: ssl_key defaults to empty");
	ok(p.ssl_capath == "", "3-arg ctor: ssl_capath defaults to empty");
	ok(p.ssl_crl == "", "3-arg ctor: ssl_crl defaults to empty");
	ok(p.ssl_crlpath == "", "3-arg ctor: ssl_crlpath defaults to empty");
	ok(p.ssl_cipher == "", "3-arg ctor: ssl_cipher defaults to empty");
	ok(p.tls_version == "", "3-arg ctor: tls_version defaults to empty");
	ok(p.comment == "", "3-arg ctor: comment defaults to empty");
}

static void test_base_constructor_charptr() {
	char h[] = "db2.example.com";
	char u[] = "admin";
	char ca[] = "/ca.crt";
	char cert[] = "/cert.crt";
	char key[] = "/key.pem";
	char capath[] = "";
	char crl[] = "";
	char crlpath[] = "";
	char cipher[] = "";
	char tls[] = "TLSv1.3";
	char comment[] = "char test";

	Servers_SslParams p(h, 5433, u, ca, cert, key, capath, crl, crlpath, cipher, tls, comment);

	ok(p.hostname == "db2.example.com", "char* ctor: hostname");
	ok(p.port == 5433, "char* ctor: port");
	ok(p.username == "admin", "char* ctor: username");
	ok(p.ssl_ca == "/ca.crt", "char* ctor: ssl_ca");
	ok(p.ssl_cert == "/cert.crt", "char* ctor: ssl_cert");
	ok(p.ssl_key == "/key.pem", "char* ctor: ssl_key");
	ok(p.ssl_capath == "", "char* ctor: ssl_capath empty");
	ok(p.tls_version == "TLSv1.3", "char* ctor: tls_version");
}

// ============================================================================
// 2. getMapKey
// ============================================================================

static void test_getMapKey() {
	Servers_SslParams p(
		string("myhost"), 5432, string("myuser"),
		string(""), string(""), string(""), string(""),
		string(""), string(""), string(""), string(""), string("")
	);

	string key = p.getMapKey(":");
	ok(key == "myhost:5432:myuser", "getMapKey produces hostname:port:username");

	// Second call returns cached value
	string key2 = p.getMapKey(":");
	ok(key == key2, "getMapKey returns cached value on second call");
}

static void test_getMapKey_empty_username() {
	Servers_SslParams p(
		string("myhost"), 5432, string(""),
		string(""), string(""), string(""), string(""),
		string(""), string(""), string(""), string(""), string("")
	);

	string key = p.getMapKey(":");
	ok(key == "myhost:5432:", "getMapKey with empty username ends with delimiter");
}

// ============================================================================
// 3. PgSQLServers_SslParams derived class
// ============================================================================

static void test_pgsql_derived_class() {
	PgSQLServers_SslParams p(
		string("pghost"), 5432, string("pguser"),
		string("/pg/ca.crt"), string("/pg/cert.crt"), string("/pg/key.pem"),
		string(""), string(""),
		string("TLSv1.2-TLSv1.3"), string("pg comment")
	);

	ok(p.hostname == "pghost", "PgSQL derived: hostname inherited");
	ok(p.ssl_ca == "/pg/ca.crt", "PgSQL derived: ssl_ca inherited");
	ok(p.tls_version == "TLSv1.2-TLSv1.3", "PgSQL derived: tls_version inherited");
	ok(p.ssl_min_protocol_version == "TLSv1.2", "PgSQL derived: parsed min from range");
	ok(p.ssl_max_protocol_version == "TLSv1.3", "PgSQL derived: parsed max from range");

	string key = p.getMapKey("|");
	ok(key == "pghost|5432|pguser", "PgSQL derived: getMapKey inherited");

	// Single token pins both ends
	PgSQLServers_SslParams pin(
		string("pinhost"), 5432, string(""),
		string(""), string(""), string(""),
		string(""), string(""),
		string("TLSv1.3"), string("")
	);
	ok(pin.ssl_min_protocol_version == "TLSv1.3", "PgSQL derived: single-token pin -> min");
	ok(pin.ssl_max_protocol_version == "TLSv1.3", "PgSQL derived: single-token pin -> max");

	// Empty tls_version leaves both empty
	PgSQLServers_SslParams empty(
		string("eh"), 5432, string(""),
		string(""), string(""), string(""),
		string(""), string(""),
		string(""), string("")
	);
	ok(empty.ssl_min_protocol_version == "", "PgSQL derived: empty tls_version -> empty min");
	ok(empty.ssl_max_protocol_version == "", "PgSQL derived: empty tls_version -> empty max");

	// One-sided range: min-only ("TLSv1.2-") sets min, leaves max empty
	PgSQLServers_SslParams min_only(
		string("bh"), 5432, string(""),
		string(""), string(""), string(""),
		string(""), string(""),
		string("TLSv1.2-"), string("")
	);
	ok(min_only.ssl_min_protocol_version == "TLSv1.2", "PgSQL derived: min-only range -> min set");
	ok(min_only.ssl_max_protocol_version == "", "PgSQL derived: min-only range -> max empty");

	// One-sided range: max-only ("-TLSv1.3") sets max, leaves min empty
	PgSQLServers_SslParams max_only(
		string("bh2"), 5432, string(""),
		string(""), string(""), string(""),
		string(""), string(""),
		string("-TLSv1.3"), string("")
	);
	ok(max_only.ssl_min_protocol_version == "", "PgSQL derived: max-only range -> min empty");
	ok(max_only.ssl_max_protocol_version == "TLSv1.3", "PgSQL derived: max-only range -> max set");

	// Bare dash is malformed: both stay empty (logged as warning)
	PgSQLServers_SslParams bare_dash(
		string("bh3"), 5432, string(""),
		string(""), string(""), string(""),
		string(""), string(""),
		string("-"), string("")
	);
	ok(bare_dash.ssl_min_protocol_version == "", "PgSQL derived: bare dash -> empty min");
	ok(bare_dash.ssl_max_protocol_version == "", "PgSQL derived: bare dash -> empty max");
}

static void test_pgsql_storable_in_map() {
	unordered_map<string, PgSQLServers_SslParams> m;

	PgSQLServers_SslParams p1(
		string("host1"), 5432, string("user1"),
		string("/ca1"), string(""), string(""),
		string(""), string(""),
		string(""), string("")
	);
	PgSQLServers_SslParams p2(
		string("host2"), 5433, string("user2"),
		string("/ca2"), string(""), string(""),
		string(""), string(""),
		string(""), string("")
	);

	m.emplace("key1", p1);
	m.emplace("key2", p2);

	ok(m.size() == 2, "PgSQL params storable in unordered_map");
	ok(m.at("key1").ssl_ca == "/ca1", "map lookup returns correct params for key1");
	ok(m.at("key2").hostname == "host2", "map lookup returns correct params for key2");
}

// ============================================================================
// 4. PgSQL_HostGroups_Manager::get_Server_SSL_Params lookup
// ============================================================================

static void populate_ssl_params() {
	// Schema columns: hostname, port, username, ssl_ca, ssl_cert, ssl_key,
	// ssl_crl, ssl_crlpath, ssl_protocol_version_range, comment
	SQLite3_result *result = new SQLite3_result(10);

	char *row1[] = {
		(char*)"host1", (char*)"5432", (char*)"testuser",
		(char*)"/certs/ca1.crt", (char*)"/certs/cert1.crt", (char*)"/certs/key1.pem",
		(char*)"", (char*)"",
		(char*)"TLSv1.3", (char*)"exact match row"
	};
	result->add_row(row1);

	char *row2[] = {
		(char*)"host1", (char*)"5432", (char*)"",
		(char*)"/certs/ca_fallback.crt", (char*)"/certs/cert_fb.crt", (char*)"/certs/key_fb.pem",
		(char*)"", (char*)"",
		(char*)"", (char*)"fallback row"
	};
	result->add_row(row2);

	char *row3[] = {
		(char*)"host2", (char*)"5433", (char*)"admin",
		(char*)"/certs/ca2.crt", (char*)"", (char*)"",
		(char*)"", (char*)"",
		(char*)"TLSv1.2-TLSv1.3", (char*)"host2 row"
	};
	result->add_row(row3);

	PgHGM->save_incoming_pgsql_table(result, "pgsql_servers_ssl_params");
	PgHGM->commit({}, {}, false, false);
}

static void test_lookup_exact_match() {
	PgSQLServers_SslParams *p = PgHGM->get_Server_SSL_Params(
		(char*)"host1", 5432, (char*)"testuser"
	);
	ok(p != NULL, "exact match: found");
	if (p) {
		ok(p->ssl_ca == "/certs/ca1.crt", "exact match: ssl_ca correct");
		ok(p->ssl_cert == "/certs/cert1.crt", "exact match: ssl_cert correct");
		ok(p->tls_version == "TLSv1.3", "exact match: tls_version correct");
		ok(p->comment == "exact match row", "exact match: comment correct");
		delete p;
	} else {
		skip(4, "exact match not found, skipping field checks");
	}
}

static void test_lookup_username_fallback() {
	PgSQLServers_SslParams *p = PgHGM->get_Server_SSL_Params(
		(char*)"host1", 5432, (char*)"unknown_user"
	);
	ok(p != NULL, "username fallback: found");
	if (p) {
		ok(p->ssl_ca == "/certs/ca_fallback.crt", "username fallback: ssl_ca from fallback row");
		ok(p->comment == "fallback row", "username fallback: comment from fallback row");
		delete p;
	} else {
		skip(2, "fallback not found, skipping field checks");
	}
}

static void test_lookup_miss() {
	PgSQLServers_SslParams *p = PgHGM->get_Server_SSL_Params(
		(char*)"nonexistent_host", 9999, (char*)"nobody"
	);
	ok(p == NULL, "miss: returns NULL for unknown host");
}

static void test_lookup_returns_copy() {
	PgSQLServers_SslParams *p1 = PgHGM->get_Server_SSL_Params(
		(char*)"host2", 5433, (char*)"admin"
	);
	ok(p1 != NULL, "copy test: found host2");
	if (p1) {
		p1->ssl_ca = "MODIFIED";

		PgSQLServers_SslParams *p2 = PgHGM->get_Server_SSL_Params(
			(char*)"host2", 5433, (char*)"admin"
		);
		ok(p2 != NULL, "copy test: second fetch succeeded");
		if (p2) {
			ok(p2->ssl_ca == "/certs/ca2.crt", "copy test: original value unmodified");
			delete p2;
		} else {
			skip(1, "second fetch failed");
		}
		delete p1;
	} else {
		skip(2, "host2 not found");
	}
}

static void test_lookup_different_host() {
	PgSQLServers_SslParams *p = PgHGM->get_Server_SSL_Params(
		(char*)"host2", 5433, (char*)"admin"
	);
	ok(p != NULL, "different host: found host2:5433:admin");
	if (p) {
		ok(p->ssl_ca == "/certs/ca2.crt", "different host: ssl_ca correct");
		ok(p->tls_version == "TLSv1.2-TLSv1.3", "different host: tls_version correct");
		ok(p->ssl_min_protocol_version == "TLSv1.2", "different host: parsed min");
		ok(p->ssl_max_protocol_version == "TLSv1.3", "different host: parsed max");
		delete p;
	} else {
		skip(4, "host2 not found");
	}
}

// ============================================================================
// main
// ============================================================================

int main() {
	plan(71);

	test_init_minimal();

	test_base_constructor_string();
	test_base_constructor_3arg();
	test_base_constructor_charptr();
	test_getMapKey();
	test_getMapKey_empty_username();
	test_pgsql_derived_class();
	test_pgsql_storable_in_map();

	test_init_query_processor();
	test_init_hostgroups();
	populate_ssl_params();

	test_lookup_exact_match();
	test_lookup_username_fallback();
	test_lookup_miss();
	test_lookup_returns_copy();
	test_lookup_different_host();

	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_minimal();

	return exit_status();
}
