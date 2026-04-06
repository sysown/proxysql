#ifndef __CLASS_SERVERS_SSL_PARAMS_H
#define __CLASS_SERVERS_SSL_PARAMS_H

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
		string c) {
		hostname = _h;
		port = _p;
		username = _u;
		ssl_ca = ca;
		ssl_cert = cert;
		ssl_key = key;
		ssl_capath = capath;
		ssl_crl = crl;
		ssl_crlpath = crlpath;
		ssl_cipher = cipher;
		tls_version = tls;
		comment = c;
		MapKey = "";
	}
	Servers_SslParams(char * _h, int _p, char * _u,
		char * ca, char * cert, char * key, char * capath,
		char * crl, char * crlpath, char * cipher, char * tls,
		char * c) {
		hostname = string(_h);
		port = _p;
		username = string(_u);
		ssl_ca = string(ca);
		ssl_cert = string(cert);
		ssl_key = string(key);
		ssl_capath = string(capath);
		ssl_crl = string(crl);
		ssl_crlpath = string(crlpath);
		ssl_cipher = string(cipher);
		tls_version = string(tls);
		comment = string(c);
		MapKey = "";
	}
	Servers_SslParams(string _h, int _p, string _u) {
		Servers_SslParams(_h, _p, _u, "", "", "", "", "", "", "", "", "");
	}
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
	using Servers_SslParams::Servers_SslParams;
};

#endif // __CLASS_SERVERS_SSL_PARAMS_H
