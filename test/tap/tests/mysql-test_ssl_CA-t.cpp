#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include "mysql.h"
#include <dirent.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

CommandLine cl;

/*
This TAP test:
- configures SSL on various hostgroups
- it happends AWS Aurora bundle PEM certificates to ProxySQL's mysql-ssl_p2s_ca
- creates new connections
*/

inline unsigned long long monotonic_time() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

int main(int argc, char** argv) {

	char * p_infra_datadir = std::getenv("REGULAR_INFRA_DATADIR");
	if (p_infra_datadir == NULL) {
		// quick exit
		plan(1);
		ok(0, "REGULAR_INFRA_DATADIR not defined");
		return exit_status();
	}

	std::vector<int> hgs = {};
	std::vector<std::string> pemfiles = {};
	{
		DIR *d;
		struct dirent *dir;
		std::string path = std::string(cl.workdir) + "/aws_ssl_certs/";
		d = opendir(path.c_str());
		if (d) {
			while ((dir = readdir(d)) != NULL) {
				std::string n = std::string(dir->d_name);
				if (n.size() > 4) {
					std::string ext = n.substr(n.size() - 4);
					if (ext == ".pem") {
					}
					diag("Retrieved PEM: %s", dir->d_name);
					pemfiles.push_back(dir->d_name);
				}
			}
			closedir(d);
		}
	}

	if (pemfiles.size() == 0) {
		// quick exit
		plan(1);
		ok(0, "No PEM files found");
		return exit_status();
	}

	MYSQL* mysqladmin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysqladmin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysqladmin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysqladmin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysqladmin->net.compress, "Compression: (%d)", mysqladmin->net.compress);
	}

	MYSQL_RES *res;


	{
//		const char *q = "SELECT DISTINCT hostgroup_id FROM runtime_mysql_servers WHERE status='ONLINE' AND hostgroup_id IN (0,1,10,11,20,30,31,50,60,1710,1711)";
		const char *q = "SELECT DISTINCT hostgroup_id FROM runtime_mysql_servers WHERE status='ONLINE' AND comment LIKE '%mysql%'";
		diag("Running query: %s", q);
		MYSQL_QUERY(mysqladmin, q);
		res = mysql_store_result(mysqladmin);
		MYSQL_ROW row;
		unsigned long long num_rows = mysql_num_rows(res);
		while ((row = mysql_fetch_row(res))) {
				int hg = atoi(row[0]);
				diag("Retrieve HG id: %d", hg);
				hgs.push_back(hg);
		}	
		mysql_free_result(res);
	}

	if (hgs.size() > 0 ) {
		plan(2 + 3 * hgs.size()*pemfiles.size());
	} else {
		// quick exit
		plan(2 + 1);
		ok(0, "No hostgroups found");
		return exit_status();
	}

	diag("Setting use_ssl=1 on mysql_servers");
	// HG 0,1 - docker-mysql-proxysql - default
	// HG 10,11 - docker-mysql-gr-proxysql
	// HG 20 - docker-mysql-galera-proxysql
	// HG 30,31 - docker-mysql8-proxysql
	// HG 50,60 - docker-mysql-binlog_reader
	// HG 1710,1711 - docker-mariadb
//	MYSQL_QUERY(mysqladmin, "UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id IN (0,1,10,11,20,30,31,50,60,1710,1711)");
	MYSQL_QUERY(mysqladmin, "UPDATE mysql_servers SET use_ssl=1");
	MYSQL_QUERY(mysqladmin, "LOAD MYSQL SERVERS TO RUNTIME");

	{
		diag("Setting mysql-ssl_p2s_ca");
		std::string ca_full_path = "SET mysql-ssl_p2s_ca='" + std::string(p_infra_datadir) + "/cert-bundle-rnd.pem'";
		MYSQL_QUERY(mysqladmin, ca_full_path.c_str());
		MYSQL_QUERY(mysqladmin, "LOAD MYSQL VARIABLES TO RUNTIME");
	}

	for (std::vector<std::string>::iterator it = pemfiles.begin(); it != pemfiles.end(); it++ ) {
		std::string cmd = "cat " + std::string(cl.workdir) + "/aws_ssl_certs/" + *it + " >> " + p_infra_datadir + "/cert-bundle-rnd.pem";
		diag("Running shell command: %s", cmd.c_str());
		system(cmd.c_str()); 
		for (int i=0; i<hgs.size(); i++) {

			MYSQL* mysql = mysql_init(NULL);
			diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
			if (cl.use_ssl)
				mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
			if (cl.compression)
				mysql_options(mysql, MYSQL_OPT_COMPRESS, NULL);
			if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
				fprintf(stderr, "Failed to connect to database: Error: %s\n",
					mysql_error(mysql));
				return exit_status();
			} else {
				const char * c = mysql_get_ssl_cipher(mysql);
				ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
				ok(cl.compression == mysql->net.compress, "Compression: (%d)", mysql->net.compress);
			}

			std::string q = "SELECT /* hostgroup=" + std::to_string(hgs[i]) + ";create_new_connection=1 */ 200";
			diag("Running query: %s", q.c_str());
			int rc=mysql_query(mysql,q.c_str());
			ok(rc==0, "Query executed with%s error: %s", rc==0 ? "out" : "" , rc==0 ? "" : mysql_error(mysql));
			// we close without even retrieving the result
			mysql_close(mysql);
		}
	}

	return exit_status();
}

