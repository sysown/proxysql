#ifndef PROXYSQL_SERVERS_SSL_PARAMS_H
#define PROXYSQL_SERVERS_SSL_PARAMS_H

#include <string>

using std::string;
using std::to_string;

class Servers_SslParams {
	public:
	string hostname;
	int port;
	string username;
	string ssl_ca;
	string ssl_cert;
	string ssl_key;
	string ssl_capath;
	string ssl_crl;
	string ssl_crlpath;
	string ssl_cipher;
	string tls_version;
	string comment;
	string MapKey;
	Servers_SslParams(string _h, int _p, string _u,
		string ca, string cert, string key, string capath,
		string crl, string crlpath, string cipher, string tls,
		string c)
		: hostname(_h), port(_p), username(_u), ssl_ca(ca), ssl_cert(cert),
		  ssl_key(key), ssl_capath(capath), ssl_crl(crl), ssl_crlpath(crlpath),
		  ssl_cipher(cipher), tls_version(tls), comment(c), MapKey("") {}
	Servers_SslParams(char * _h, int _p, char * _u,
		char * ca, char * cert, char * key, char * capath,
		char * crl, char * crlpath, char * cipher, char * tls,
		char * c)
		: hostname(_h ? _h : ""), port(_p), username(_u ? _u : ""),
		  ssl_ca(ca ? ca : ""), ssl_cert(cert ? cert : ""),
		  ssl_key(key ? key : ""), ssl_capath(capath ? capath : ""),
		  ssl_crl(crl ? crl : ""), ssl_crlpath(crlpath ? crlpath : ""),
		  ssl_cipher(cipher ? cipher : ""), tls_version(tls ? tls : ""),
		  comment(c ? c : ""), MapKey("") {}
	Servers_SslParams(string _h, int _p, string _u)
		: Servers_SslParams(_h, _p, _u, "", "", "", "", "", "", "", "", "") {}
	virtual ~Servers_SslParams() = default;
	string getMapKey(const char *del) {
		if (MapKey == "") {
			MapKey = hostname + string(del) + to_string(port) + string(del) + username;
		}
		return MapKey;
	}
};

class MySQLServers_SslParams : public Servers_SslParams {
	public:
	using Servers_SslParams::Servers_SslParams;
};

class PgSQLServers_SslParams : public Servers_SslParams {
	public:
	// Pre-parsed from tls_version (= the SQL column ssl_protocol_version_range).
	// Populated once at construction so the data path does not have to re-parse
	// the range string on every backend connection. Empty when tls_version is
	// empty or malformed (in which case libpq defaults apply).
	string ssl_min_protocol_version;
	string ssl_max_protocol_version;

	// PgSQL-specific constructors. libpq has no equivalent for the base class
	// ssl_capath / ssl_cipher fields, so they are not exposed here — the base
	// class members are forwarded as empty strings and stay unused on the
	// PgSQL backend path.
	PgSQLServers_SslParams(string _h, int _p, string _u,
		string ca, string cert, string key,
		string crl, string crlpath, string tls, string c)
		: Servers_SslParams(_h, _p, _u, ca, cert, key, "", crl, crlpath, "", tls, c) {
		parse_tls_version();
	}
	PgSQLServers_SslParams(char * _h, int _p, char * _u,
		char * ca, char * cert, char * key,
		char * crl, char * crlpath, char * tls, char * c)
		: Servers_SslParams(_h, _p, _u, ca, cert, key, (char*)"", crl, crlpath, (char*)"", tls, c) {
		parse_tls_version();
	}
	PgSQLServers_SslParams(string _h, int _p, string _u)
		: Servers_SslParams(_h, _p, _u) {}

	private:
	// Parse tls_version into ssl_min_protocol_version / ssl_max_protocol_version.
	// Format: "MIN-MAX" for a range, "MIN-" for min-only, "-MAX" for max-only,
	// or a single token to pin both ends. A bare "-" is malformed and logged.
	void parse_tls_version() {
		if (tls_version.empty()) return;
		size_t dash_pos = tls_version.find('-');
		if (dash_pos == string::npos) {
			ssl_min_protocol_version = tls_version;
			ssl_max_protocol_version = tls_version;
			return;
		}
		string min_ver = tls_version.substr(0, dash_pos);
		string max_ver = tls_version.substr(dash_pos + 1);
		if (min_ver.empty() && max_ver.empty()) {
			proxy_warning("Malformed ssl_protocol_version_range '%s' for %s:%d — ignoring\n",
				tls_version.c_str(), hostname.c_str(), port);
			return;
		}
		ssl_min_protocol_version = min_ver;
		ssl_max_protocol_version = max_ver;
	}
};

#endif // __CLASS_SERVERS_SSL_PARAMS_H
