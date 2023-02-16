#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "cpp.h"
#include "ProxySQL_HTTP_Server.hpp" // HTTP server
#include "ProxySQL_Statistics.hpp"
#include "SQLite3_Server.h"
#include "MySQL_Authentication.hpp"

#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <pthread.h>
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include <fcntl.h>
#include <sys/utsname.h>

#include "platform.h"
#include "microhttpd.h"
#include "curl/curl.h"

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_HTTP_SERVER_VERSION "1.4.1031" DEB


extern ProxySQL_Statistics *GloProxyStats;
extern MySQL_Threads_Handler *GloMTH;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Authentication *GloMyAuth;
extern SQLite3_Server *GloSQLite3Server;
#ifdef PROXYSQLCLICKHOUSE
extern ClickHouse_Server *GloClickHouseServer;
#endif

extern char * Chart_bundle_js_c;
extern char * font_awesome;
extern char * main_bundle_min_css_c;
#define RATE_LIMIT_PAGE "<html><head><title>Rate Limit Page</title></head><body>Rate Limit Reached</body></html>"


#define DENIED "<html><head><title>ProxySQL status page</title></head><body>Access denied</body></html>"
#define OPAQUE "733b20011778ce330631c9afof70a870baddd964"

struct MemoryStruct {
	char *memory;
	size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;
	mem->memory = (char *)realloc(mem->memory, mem->size + realsize + 1);
	assert(mem->memory);

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}

static char * check_latest_version() {
	CURL *curl_handle;
	CURLcode res;
	struct MemoryStruct chunk;
	chunk.memory = (char *)malloc(1);
	chunk.size = 0;
	curl_global_init(CURL_GLOBAL_ALL);

	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, "https://www.proxysql.com/latest");
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYSTATUS, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_RANGE, "0-31");
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

	string s = "proxysql-agent/";
	s += PROXYSQL_VERSION;
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, s.c_str());
	curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 10);
	curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 10);

	res = curl_easy_perform(curl_handle);

	if (res != CURLE_OK) {
		proxy_error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		free(chunk.memory);
		chunk.memory = NULL;
	}
	curl_easy_cleanup(curl_handle);
	curl_global_cleanup();
	return chunk.memory;
}

static char *div1= (char *)"<div style=\"margin-bottom: 1px;\"><a href=stats?metric=";
static char *style1 = (char *)" style=\"color: #2969a5 ; background-color: white; font-weight: bold; font-size: 13px; font-family: Verdana, sans-serif; border: 0px; text-decoration: none; padding-left: 5px; padding-right: 5px;\">";
static char *style2 = (char *)" style=\"color: #2969a5 ; background-color: white; font-size: 12px; font-family: Verdana, sans-serif; border: 0px; text-decoration: none; padding-left: 5px; padding-right: 5px;\">";

static char *generate_home() {
	char *s = NULL;
	string html = "";
	html.append("<div class=\"menu\" style=\"height: auto;\">\n");
	html.append("<span style=\"float: left; width: 50%;\">\n");
	html.append("<div style=\"margin-top: 15px;\"><a href=\"/\""); html.append(style2); html.append("Home</a>\n");
	html.append("<a href=stats?metric=system"); html.append(style2); html.append("System</a>\n");
	html.append("<a href=stats?metric=mysql"); html.append(style2); html.append("MySQL</a>\n");
	html.append("<a href=stats?metric=cache"); html.append(style2); html.append("Query Cache</a></div>\n");
	html.append("</span>\n</div>\n");

	html.append("<span style=\"float: left; width: 100%;\">\n");
	html.append("<div style=\"height: auto;\">\n");
	html.append("<p></p>\n");
	html.append("<p></p>\n");
	html.append("<h2 style=\"font-size: 25px; margin-top: 0em; margin-bottom: 0em;\">General information</h2>\n<hr style=\"align: centre\" width=\"100%\">\n");
	html.append("<table style=\"font-size: 15px;\" border=0 width=\"100%\">\n");
	html.append("<tr width=\"100%\">\n");
	html.append("<td width=\"33%\">\n");
	html.append("<b>Uptime = </b>");
	{
		unsigned long long t1=monotonic_time();
		char buf1[50];
		unsigned long long uptime = (t1-GloVars.global.start_time)/1000/1000;
		unsigned long long days = uptime / 86400;
		unsigned long long hours = (uptime - days*86400)/3600;
		unsigned long long mins = (uptime % 3600)/60;
		unsigned long long secs = uptime % 60;
		sprintf(buf1,"%llud %02lluh%02llum%02llus", days, hours, mins, secs);
		html.append(buf1);
	}
	html.append("<br>\n");
	html.append("<b>OS version = </b>");
	{
		struct utsname unameData;
		int rc;
		rc=uname(&unameData);
		if (rc==0) {
			html.append(unameData.sysname); html.append(" ");
			html.append(unameData.nodename); html.append(" ");
			html.append(unameData.release); html.append(" ");
			html.append(unameData.machine);
        } else {
			html.append("UNKNOWN");
		}
	}
	html.append("<br>\n");
	html.append("<b>Worker threads = </b>");
	{
		char buf[16];
		sprintf(buf,"%u",GloMTH->num_threads);
		html.append(buf);
	}
	html.append("<br>\n");
	html.append("<b>Idle threads = </b>");
	if (glovars.idle_threads) {
		html.append("<span style=\"color: green;\">enabled</span>");
	} else {
		html.append("<span style=\"background-color: red;\"> disabled </span>");
	}
	html.append("<br>\n");
	html.append("<b>Monitor = </b>");
	{
		char *en = GloMTH->get_variable((char *)"monitor_enabled");
		if (en && strcmp(en,"true")==0) {
			html.append("<span style=\"color: green;\">enabled</span>");
		} else {
			html.append("<span style=\"background-color: red;\"> disabled </span>");
		}
		if (en) {
			free(en);
		}
	}
	html.append("<br>\n");
	html.append("</td>\n");
	html.append("<td width=\"33%\">\n");
	{
		char *en = GloAdmin->get_variable((char *)"mysql_ifaces");
		if (en) {
			html.append("<b>Admin interface(s)</b> = ");
			html.append(en);
			html.append("<br>\n");
			free(en);
		}
	}
#ifdef PROXYSQLCLICKHOUSE
	if (GloVars.global.clickhouse_server==false) {
		html.append("<b>ClickHouse = </b><span style=\"background-color: yellow;\"> Disabled </span><br>\n");
	} else {
		char *en = GloClickHouseServer->get_variable((char *)"mysql_ifaces");
		if (en) {
			html.append("<b>ClickHouse interface</b> = ");
			html.append(en);
			html.append("<br>\n");
			free(en);
		}
	}
#else
	html.append("<b>ClickHouse = </b><span style=\"background-color: red;\"> support not compiled </span><br>\n");
#endif
	if (GloMTH) {
		char *en = GloMTH->get_variable((char *)"interfaces");
		if (en) {
			html.append("<b>MySQL interface(s)</b> = ");
			html.append(en);
			html.append("<br>\n");
			free(en);
		}
	} else {
		html.append("<b>MySQL interface(s)</b> = <span style=\"background-color: red;\"> Not started </span><br>");
	}
	if (GloVars.global.sqlite3_server==false) {
		html.append("<b>SQLite3 = </b><span style=\"background-color: yellow;\"> Disabled </span><br>\n");
	} else {
		char *en = GloSQLite3Server->get_variable((char *)"mysql_ifaces");
		if (en) {
			html.append("<b>SQLite3 interface(s)</b> = ");
			html.append(en);
			html.append("<br>\n");
			free(en);
		}
	}
	html.append("</td>\n");
	html.append("<td width=\"33%\">\n");
	html.append("<b>ProxySQL version = </b>"); html.append(PROXYSQL_VERSION); html.append("<br>\n");
	html.append("<b>ProxySQL latest  = </b>");
	{
		GloAdmin->AdminHTTPServer->check_latest_version_http();
		if (GloAdmin->AdminHTTPServer->variables.proxysql_latest_version == NULL) {
			html.append("unknown");
		} else {
			html.append(GloAdmin->AdminHTTPServer->variables.proxysql_latest_version);
		}
	}
	html.append("<br>\n");
	html.append("</td>\n");
	html.append("</tr>\n");
	html.append("</table>\n");
	html.append("</div></span>\n");
	s = strdup(html.c_str());
	return s;
}

static char *generate_buttons(char *base) {
	char *s = NULL;
        string html = "<div class=\"menu\" style=\"height: auto;\"><span style=\"float: left; width: 100%;\">\n";
        html.append("<div style=\"margin-top: 15px;\">");
        html.append("<a href=\"/\""); html.append(style2); html.append("Home</a>\n");
        html.append("<a href=stats?metric=system"); html.append(style2); html.append("System</a>\n");
        html.append("<a href=stats?metric=mysql"); html.append(style2); html.append("MySQL</a>\n");
        html.append("<a href=stats?metric=cache"); html.append(style2); html.append("Query Cache</a>\n");
	html.append("</div></span>");

	html.append("<div class=\"menu\" style=\"height: auto;\">\n<span style=\"float: left;\">\n");
        html.append("<p></p>\n");
        html.append("<p></p>\n");
        html.append("<h2 style=\"font-size: 25px; margin-top: 0em; margin-bottom: 0em;\">Statistics:</h2>\n<hr style=\"align: centre\" width=\"100%\">\n");

        html.append("<div class=\"menu\" style=\"height: auto;\">\n<span style=\"float: left;\">\n<div style=\"border-bottom-style: solid; border-bottom-color: #2969a5; border-bottom-width: 0px; margin-bottom: 1px; color: #2969a5 ; background-color: white; font-size: 15px; font-family: Verdana, sans-serif; font-weight: bold; text-decoration: none; padding-left: 5px; padding-right: 5px;\"></div>\n");
        html.append(div1); html.append(base); html.append("&interval=1800"); html.append(style1); html.append("Last 1/2 hour</a></div>\n");
        html.append(div1); html.append(base); html.append("&interval=3600"); html.append(style1); html.append("Last 1 hour</a></div>\n");
        html.append(div1); html.append(base); html.append("&interval=7200"); html.append(style1); html.append("Last 2 hours</a></div>\n");
        html.append("</span>\n</div>\n");

	html.append("<div class=\"menu\" style=\"height: auto;\">\n<span style=\"float: left;\">\n<div style=\"border-bottom-style: solid; border-bottom-color: #2969a5; border-bottom-width: 0px; margin-bottom: 1px; color: #2969a5 ; background-color: white; font-size: 15px; font-family: Verdana, sans-serif; font-weight: bold; text-decoration: none; padding-left: 5px; padding-right: 5px;\"></div>\n");
        html.append(div1); html.append(base); html.append("&interval=28800"); html.append(style1); html.append("Last 8 hours</a></div>\n");
        html.append(div1); html.append(base); html.append("&interval=86400"); html.append(style1); html.append("Last 1 day</a></div>\n");
        html.append(div1); html.append(base); html.append("&interval=259200"); html.append(style1); html.append("Last 3 days</a></div>\n");
        html.append("</span>\n</div>\n");

        html.append("<div class=\"menu\" style=\"height: auto;\">\n<span style=\"float: left;\">\n<div style=\"border-bottom-style: solid; border-bottom-color: #2969a5; border-bottom-width: 0px; margin-bottom: 1px; color: #2969a5 ; background-color: white; font-size: 15px; font-family: Verdana, sans-serif; font-weight: bold; text-decoration: none; padding-left: 5px; padding-right: 5px;\"></div>\n");

	html.append(div1); html.append(base); html.append("&interval=604800"); html.append(style1); html.append("Last 7 days</a></div>\n");
	html.append(div1); html.append(base); html.append("&interval=2592000"); html.append(style1); html.append("Last 1 month</a></div>\n");
	html.append(div1); html.append(base); html.append("&interval=7776000"); html.append(style1); html.append("Last 3 months</a></div>\n");
	html.append("</span>\n</div>\n");

	s = strdup(html.c_str());

	return s;
}

void ProxySQL_HTTP_Server::check_latest_version_http() {
	pthread_mutex_lock(&check_version_mutex);
	time_t now = time(NULL);
	if (now > last_check_version + 300) {
		if (variables.proxysql_latest_version) {
			if (now > last_check_version + 3600) {
				free(variables.proxysql_latest_version);
				variables.proxysql_latest_version = NULL;
			}
		}
		if (variables.proxysql_latest_version == NULL) {
			variables.proxysql_latest_version = check_latest_version();
			last_check_version = now;
		}
	}
	pthread_mutex_unlock(&check_version_mutex);
}

char * ProxySQL_HTTP_Server::extract_values(SQLite3_result *result, int idx, bool relative, double mult) {
	string s = "[";
	int i;
	for ( i= (relative ? 1 : 0) ; i < result->rows_count ; i++) {
		SQLite3_row *r1 = ( relative ? result->rows[i-1] : NULL );
		SQLite3_row *r2 = result->rows[i];
		double v;
		if (relative) {
			double d2 = atol(r2->fields[idx]);
			double d1 = atol(r1->fields[idx]);
			double diff = (atol(r2->fields[1])-atol(r1->fields[1]));
			v = (d2-d1)/diff;
		} else {
			v = atol(r2->fields[idx]);
		}
		v *= mult;
		if (v<0) v=0;
		s.append(std::to_string(v));
		if (i != result->rows_count-1) {
			s.append(", ");
		}
	}
	s.append("];");
	char *ret=strdup(s.c_str());
	return ret;
}

char * ProxySQL_HTTP_Server::extract_ts(SQLite3_result *result, bool relative) {
	string s = "[";
	int i;
	for ( i= (relative ? 1 : 0) ; i < result->rows_count ; i++) {
		SQLite3_row *r2 = result->rows[i];
		s.append("\"");
		s.append(r2->fields[0]);
		s.append("\"");
		if (i != result->rows_count-1) {
			s.append(", ");
		}
	}
	s.append("];");
	char *ret=strdup(s.c_str());
	return ret;
}


void ProxySQL_HTTP_Server::init() {
}

void ProxySQL_HTTP_Server::print_version() {
	fprintf(stderr,"Standard ProxySQL HTTP Server Handler rev. %s -- %s -- %s\n", PROXYSQL_HTTP_SERVER_VERSION, __FILE__, __TIMESTAMP__);
}

#define EMPTY_PAGE "<html><head><title>File not found</title></head><body>File not found<br/><a href=\"/\">Go back home</a></body></html>"

int ProxySQL_HTTP_Server::handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr) {

	struct MHD_Response *response;
	int ret;


	char *username;
	char *password = NULL;
	const char *realm = "Access to ProxySQL status page";

	username = MHD_digest_auth_get_username(connection);
	if (username == NULL) {
		response = MHD_create_response_from_buffer(strlen(DENIED), (void *)DENIED, MHD_RESPMEM_PERSISTENT);
		ret = MHD_queue_auth_fail_response(connection, realm, OPAQUE, response, MHD_NO);
		MHD_destroy_response(response);
		return ret;
	}
	{
		int default_hostgroup = -1;
		char *default_schema = NULL;
		bool schema_locked;
		bool transaction_persistent;
		bool fast_forward;
		bool _ret_use_ssl = false;
		int max_connections;
		void *sha1_pass = NULL;
		password=GloMyAuth->lookup(username, USERNAME_FRONTEND, &_ret_use_ssl, &default_hostgroup, &default_schema, &schema_locked, &transaction_persistent, &fast_forward, &max_connections, &sha1_pass, NULL);
		if (default_schema) { // unused
			free(default_schema);
		}
		if (sha1_pass) { // unused
			free(sha1_pass);
		}
		if (
			(default_hostgroup != STATS_HOSTGROUP)
			||
			(password == NULL)
		) {
			if (password) {
				free(password); // cleanup
			}
			free(username); // cleanup
			response = MHD_create_response_from_buffer(strlen(DENIED), (void *)DENIED, MHD_RESPMEM_PERSISTENT);
			ret = MHD_queue_auth_fail_response(connection, realm, OPAQUE, response, MHD_NO);
			MHD_destroy_response(response);
			return ret;
		}
	}
	ret = MHD_digest_auth_check(connection, realm, username, password, 300);
	free(username);
	free(password);
	if ( (ret == MHD_INVALID_NONCE) || (ret == MHD_NO) ) {
		response = MHD_create_response_from_buffer(strlen(DENIED), (void *)DENIED, MHD_RESPMEM_PERSISTENT);
		if (NULL == response)
			return MHD_NO;
		ret = MHD_queue_auth_fail_response(connection, realm, OPAQUE, response, (ret == MHD_INVALID_NONCE) ? MHD_YES : MHD_NO);
		MHD_destroy_response(response);
		return ret;
    }





	char *valmetric = NULL;
	char *interval_s = NULL;
	int interval_i = 1800;

	time_t now = time(NULL);
	if (now != cur_time) {
		page_sec = 0;
		cur_time = now;
	}
	page_sec++;
	if (page_sec > ProxySQL_HTTP_Server_Rate_Limit) {
		response = MHD_create_response_from_buffer(strlen(RATE_LIMIT_PAGE), (void *) RATE_LIMIT_PAGE, MHD_RESPMEM_PERSISTENT); 
  		ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  		MHD_destroy_response (response);
		return ret;
	}

	if (0 != strcmp (method, "GET"))
		return MHD_NO;              /* unexpected method */

	if (strcmp(url,"/stats")==0) {
		valmetric = (char *)MHD_lookup_connection_value (connection, MHD_GET_ARGUMENT_KIND, (char *)"metric");
		interval_s = (char *)MHD_lookup_connection_value (connection, MHD_GET_ARGUMENT_KIND, (char *)"interval");
		if (valmetric == NULL) {
			response = MHD_create_response_from_buffer (strlen (EMPTY_PAGE), (void *) EMPTY_PAGE, MHD_RESPMEM_PERSISTENT);
			ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response (response);
			return ret;
		}
		int tmp_ = 0;
		if (interval_s) {
			tmp_ = atoi(interval_s);
		}
		switch (tmp_) {
			case 1800:
			case 3600:
			case 7200:
			case 28800:
			case 86400:
			case 259200:
			case 604800:
			case 2592000:
			case 7776000:
				interval_i = tmp_;
				break;
			default:
				break;
		}
/*
		if (valunit == NULL) {
			valunit = (char *)"second";
		}
		if ( (strcmp(valunit,"second")) && (strcmp(valunit,"hour")) && (strcmp(valunit,"day")) ) {
			response = MHD_create_response_from_buffer (strlen (EMPTY_PAGE), (void *) EMPTY_PAGE, MHD_RESPMEM_PERSISTENT);
			ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response (response);
			return ret;
		}
		if (valinterval == NULL) {
			if ((strcmp(valunit,(char *)"second") == 0)) {
				valinterval = (char *)"14400";
			}
			if ((strcmp(valunit,(char *)"hour") == 0)) {
				valinterval = (char *)"720";
			}
			if ((strcmp(valunit,"day") == 0)) {
				valinterval = (char *)"365";
			}
		}
*/
		if (strcmp(valmetric,"system")==0) {
			string *s = generate_header((char *)"ProxySQL Graphs");
			char *buttons = generate_buttons((char *)"system");
			s->append(buttons);
			free(buttons);
			s->append("<div class=\"graphs\" style=\"clear: both; height: auto;\">\n");
			string *s1 = generate_canvas((char *)"myChart1");
			s->append(s1->c_str());
			s->append("<p></p>\n");
			s1 = generate_canvas((char *)"myChart2");
			s->append(s1->c_str());
			s->append("<p></p>\n");
			s1 = generate_canvas((char *)"myChart3");
			s->append(s1->c_str());
			s->append("<p></p>\n");
			s1 = generate_canvas((char *)"myChart4");
			s->append(s1->c_str());
			s->append("</div>\n");
			SQLite3_result *cpu_sqlite = GloProxyStats->get_system_cpu_metrics(interval_i);
#ifndef NOJEM
			SQLite3_result *memory_sqlite = GloProxyStats->get_system_memory_metrics(interval_i);
#endif
			char **nm = NULL;
			char **nl = NULL;
			char **nv = NULL;
			char *ts = NULL;

			nm = (char **)malloc(sizeof(char *)*2);
			nm[0] = (char *)"utime";
			nm[1] = (char *)"stime";
			nl = (char **)malloc(sizeof(char *)*2);
			nl[0] = (char *)"User Time";
			nl[1] = (char *)"System Time";
			nv = (char **)malloc(sizeof(char *)*2);
			nv[0] = extract_values(cpu_sqlite,2,true,(double)1/sysconf(_SC_CLK_TCK));
			nv[1] = extract_values(cpu_sqlite,3,true,(double)1/sysconf(_SC_CLK_TCK));
			ts = extract_ts(cpu_sqlite,true);
			s1 = generate_chart((char *)"myChart1",ts,2,nm,nl,nv);
			s->append(s1->c_str());
			free(nm);
			free(nl);
			free(nv[0]);
			free(nv[1]);
			free(nv);
			free(ts);
			

#ifndef NOJEM
			nm = (char **)malloc(sizeof(char *)*5);
			nm[0] = (char *)"allocated";
			nm[1] = (char *)"resident";
			nm[2] = (char *)"active";
			nm[3] = (char *)"mapped";
			nm[4] = (char *)"metadata";
			nl = (char **)malloc(sizeof(char *)*5);
			nl[0] = (char *)"Allocated";
			nl[1] = (char *)"Resident";
			nl[2] = (char *)"Active";
			nl[3] = (char *)"Mapped";
			nl[4] = (char *)"Metadata";
			nv = (char **)malloc(sizeof(char *)*5);
			nv[0] = extract_values(memory_sqlite,2,false);
			nv[1] = extract_values(memory_sqlite,3,false);
			nv[2] = extract_values(memory_sqlite,4,false);
			nv[3] = extract_values(memory_sqlite,5,false);
			nv[4] = extract_values(memory_sqlite,6,false);
			ts = extract_ts(cpu_sqlite,true);
			s1 = generate_chart((char *)"myChart2",ts,5,nm,nl,nv);
			s->append(s1->c_str());
			free(nm);
			free(nl);
			free(nv[0]);
			free(nv[1]);
			free(nv[2]);
			free(nv[3]);
			free(nv[4]);
			free(nv);
			free(ts);
#endif
			
			s->append("</body></html>");
	 		response = MHD_create_response_from_buffer(s->length(), (void *) s->c_str(), MHD_RESPMEM_PERSISTENT); 
  			ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  			MHD_destroy_response (response);
			return ret;
		}

		if (strcmp(valmetric,"mysql")==0) {
			string *s = generate_header((char *)"ProxySQL Graphs");
			char *buttons = generate_buttons((char *)"mysql");
			s->append(buttons);
			free(buttons);
			s->append("<div class=\"graphs\" style=\"clear: both; height: auto;\">\n");
			string *s1 = generate_canvas((char *)"myChart1");
			s->append(s1->c_str());
			s->append("<p></p>\n");
			s1 = generate_canvas((char *)"myChart2");
			s->append(s1->c_str());
			s->append("<p></p>\n");
			s1 = generate_canvas((char *)"myChart3");
			s->append(s1->c_str());
			s->append("<p></p>\n");
			s1 = generate_canvas((char *)"myChart4");
			s->append(s1->c_str());
			s->append("</div>\n");
			char **nm = NULL;
			char **nl = NULL;
			char **nv = NULL;
			char *ts = NULL;

			SQLite3_result *mysql_metrics_sqlite = GloProxyStats->get_mysql_metrics(interval_i);
			nm = (char **)malloc(sizeof(char *)*6);
			nm[0] = (char *)"Client_Connections_aborted";
			nm[1] = (char *)"Client_Connections_connected";
			nm[2] = (char *)"Client_Connections_created";
			nm[3] = (char *)"Server_Connections_aborted";
			nm[4] = (char *)"Server_Connections_connected";
			nm[5] = (char *)"Server_Connections_created";
			nl = (char **)malloc(sizeof(char *)*6);
			nl[0] = (char *)"Client Connections aborted";
			nl[1] = (char *)"Client Connections connected";
			nl[2] = (char *)"Client Connections created";
			nl[3] = (char *)"Server Connections aborted";
			nl[4] = (char *)"Server Connections connected";
			nl[5] = (char *)"Server Connections created";
			nv = (char **)malloc(sizeof(char *)*6);
			nv[0] = extract_values(mysql_metrics_sqlite,2,true,(double)1);
			nv[1] = extract_values(mysql_metrics_sqlite,3,false,(double)1);
			nv[2] = extract_values(mysql_metrics_sqlite,4,true,(double)1);
			nv[3] = extract_values(mysql_metrics_sqlite,5,true,(double)1);
			nv[4] = extract_values(mysql_metrics_sqlite,6,false,(double)1);
			nv[5] = extract_values(mysql_metrics_sqlite,7,true,(double)1);
			ts = extract_ts(mysql_metrics_sqlite,true);
			s1 = generate_chart((char *)"myChart1",ts,6,nm,nl,nv);
			s->append(s1->c_str());
			free(nm);
			free(nl);
			for (int aa=0 ; aa<6 ; aa++) {
				free(nv[aa]);
			}
			free(nv);
			free(ts);


			nm = (char **)malloc(sizeof(char *)*6);
			nm[0] = (char *)"ConnPool_get_conn_failure";
			nm[1] = (char *)"ConnPool_get_conn_immediate";
			nm[2] = (char *)"ConnPool_get_conn_success";
			nm[3] = (char *)"Questions";
			nm[4] = (char *)"Slow_queries";
			nm[5] = (char *)"GTID_consistent_queries";
			nl = (char **)malloc(sizeof(char *)*6);
			nl[0] = (char *)"ConnPool failure";
			nl[1] = (char *)"ConnPool immediate";
			nl[2] = (char *)"ConnPool success";
			nl[3] = (char *)"Questions";
			nl[4] = (char *)"Slow Queries";
			nl[5] = (char *)"GTID Consistent Queries";
			nv = (char **)malloc(sizeof(char *)*6);
			nv[0] = extract_values(mysql_metrics_sqlite,8,true);
			nv[1] = extract_values(mysql_metrics_sqlite,9,true);
			nv[2] = extract_values(mysql_metrics_sqlite,10,true);
			nv[3] = extract_values(mysql_metrics_sqlite,11,true);
			nv[4] = extract_values(mysql_metrics_sqlite,12,true);
			nv[5] = extract_values(mysql_metrics_sqlite,13,true);
			ts = extract_ts(mysql_metrics_sqlite,true);
			s1 = generate_chart((char *)"myChart2",ts,6,nm,nl,nv);
			s->append(s1->c_str());
			free(nm);
			free(nl);
			for (int aa=0 ; aa<6 ; aa++) {
				free(nv[aa]);
			}
			free(nv);
			free(ts);


			SQLite3_result *myhgm_metrics_sqlite = GloProxyStats->get_myhgm_metrics(interval_i);
			nm = (char **)malloc(sizeof(char *)*5);
			nm[0] = (char *)"MyHGM_myconnpoll_destroy";
			nm[1] = (char *)"MyHGM_myconnpoll_get";
			nm[2] = (char *)"MyHGM_myconnpoll_get_ok";
			nm[3] = (char *)"MyHGM_myconnpoll_push";
			nm[4] = (char *)"MyHGM_myconnpoll_reset";
			nl = (char **)malloc(sizeof(char *)*5);
			nl[0] = (char *)"MyHGM ConnPoll Destroy";
			nl[1] = (char *)"MyHGM ConnPoll Get";
			nl[2] = (char *)"MyHGM ConnPoll Get OK";
			nl[3] = (char *)"MyHGM ConnPoll Push";
			nl[4] = (char *)"MyHGM ConnPoll Reset";
			nv = (char **)malloc(sizeof(char *)*5);
			nv[0] = extract_values(myhgm_metrics_sqlite,2,true);
			nv[1] = extract_values(myhgm_metrics_sqlite,3,true);
			nv[2] = extract_values(myhgm_metrics_sqlite,4,true);
			nv[3] = extract_values(myhgm_metrics_sqlite,5,true);
			nv[4] = extract_values(myhgm_metrics_sqlite,6,true);
			ts = extract_ts(myhgm_metrics_sqlite,true);
			s1 = generate_chart((char *)"myChart3",ts,5,nm,nl,nv);
			s->append(s1->c_str());
			free(nm);
			free(nl);
			for (int aa=0 ; aa<5 ; aa++) {
				free(nv[aa]);
			}
			free(nv);
			free(ts);



			s->append("</body></html>");
			response = MHD_create_response_from_buffer(s->length(), (void *) s->c_str(), MHD_RESPMEM_MUST_COPY);
			ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
			MHD_destroy_response (response);
			delete s;
			return ret;
		}
		if (strcmp(valmetric,"cache")==0) {
			string *s = generate_header((char *)"ProxySQL Graphs");
			char *buttons = generate_buttons((char *)"cache");
			s->append(buttons);
			free(buttons);
			s->append("<div class=\"graphs\" style=\"clear: both; height: auto;\">\n");
			string *s1 = generate_canvas((char *)"myChart1");
			s->append(s1->c_str());
			s->append("<p></p>\n");
			s1 = generate_canvas((char *)"myChart2");
			s->append(s1->c_str());
			s->append("<p></p>\n");
			s1 = generate_canvas((char *)"myChart3");
			s->append(s1->c_str());
			s->append("<p></p>\n");
			s1 = generate_canvas((char *)"myChart4");
			s->append(s1->c_str());
			s->append("</div>\n");
			SQLite3_result *mysql_metrics_sqlite = GloProxyStats->get_MySQL_Query_Cache_metrics(interval_i);
			char **nm = NULL;
			char **nl = NULL;
			char **nv = NULL;
			char *ts = NULL;

			nm = (char **)malloc(sizeof(char *)*5);
			nm[0] = (char *)"count_GET";
			nm[1] = (char *)"count_GET_OK";
			nm[2] = (char *)"count_SET";
			nm[3] = (char *)"Entries_Purged";
			nm[4] = (char *)"Entries_In_Cache";
			nl = (char **)malloc(sizeof(char *)*5);
			nl[0] = (char *)"Count GET";
			nl[1] = (char *)"Count GET OK";
			nl[2] = (char *)"Count SET";
			nl[3] = (char *)"Entries Purged";
			nl[4] = (char *)"Entries In Cache";
			nv = (char **)malloc(sizeof(char *)*6);
			nv[0] = extract_values(mysql_metrics_sqlite,2,true,(double)1);
			nv[1] = extract_values(mysql_metrics_sqlite,3,true,(double)1);
			nv[2] = extract_values(mysql_metrics_sqlite,4,true,(double)1);
			nv[3] = extract_values(mysql_metrics_sqlite,7,true,(double)1);
			nv[4] = extract_values(mysql_metrics_sqlite,8,false,(double)1);
			ts = extract_ts(mysql_metrics_sqlite,true);
			s1 = generate_chart((char *)"myChart1",ts,5,nm,nl,nv);
			s->append(s1->c_str());
			free(nm);
			free(nl);
			for (int aa=0 ; aa<5 ; aa++) {
				free(nv[aa]);
			}
			free(nv);
			free(ts);


			nm = (char **)malloc(sizeof(char *)*3);
			nm[0] = (char *)"bytes_IN";
			nm[1] = (char *)"bytes_OUT";
			nm[2] = (char *)"Memory_Bytes";
			nl = (char **)malloc(sizeof(char *)*3);
			nl[0] = (char *)"KB IN";
			nl[1] = (char *)"KB OUT";
			nl[2] = (char *)"QC size MB";
			nv = (char **)malloc(sizeof(char *)*3);
			nv[0] = extract_values(mysql_metrics_sqlite,5,true,(double)1/1024);
			nv[1] = extract_values(mysql_metrics_sqlite,6,true,(double)1/1024);
			nv[2] = extract_values(mysql_metrics_sqlite,9,false,(double)1/1024/1024);
			ts = extract_ts(mysql_metrics_sqlite,true);
			s1 = generate_chart((char *)"myChart2",ts,3,nm,nl,nv);
			s->append(s1->c_str());
			free(nm);
			free(nl);
			for (int aa=0 ; aa<3 ; aa++) {
				free(nv[aa]);
			}
			free(nv);
			free(ts);

			s->append("</body></html>");
			response = MHD_create_response_from_buffer(s->length(), (void *) s->c_str(), MHD_RESPMEM_MUST_COPY);
			ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
			MHD_destroy_response (response);
			delete s;
			return ret;
		}
	}

	if (strcmp(url,"/Chart.bundle.js")==0) {
		response = MHD_create_response_from_buffer(strlen(Chart_bundle_js_c), Chart_bundle_js_c, MHD_RESPMEM_PERSISTENT);
  		ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  		MHD_destroy_response (response);
		return ret;
	}
	if (strcmp(url,"/font-awesome.min.css")==0) {
		response = MHD_create_response_from_buffer(strlen(font_awesome), font_awesome, MHD_RESPMEM_PERSISTENT);
		ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
		MHD_destroy_response (response);
		return ret;
	}
	if (strcmp(url,"/main-bundle.min.css")==0) {
		response = MHD_create_response_from_buffer(strlen(main_bundle_min_css_c), main_bundle_min_css_c, MHD_RESPMEM_PERSISTENT);
		ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
		MHD_destroy_response (response);
		return ret;
	}
	if (strcmp(url,"/")==0) {
		string *s = generate_header((char *)"ProxySQL Home");
		char *home = generate_home();
		s->append(home);
		free(home);
		s->append("</body></html>");
		response = MHD_create_response_from_buffer(s->length(), (void *) s->c_str(), MHD_RESPMEM_MUST_COPY);
		ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
		MHD_destroy_response (response);
		delete s;
		return ret;
	}
	response = MHD_create_response_from_buffer (strlen (EMPTY_PAGE), (void *) EMPTY_PAGE, MHD_RESPMEM_PERSISTENT);
	ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
	MHD_destroy_response (response);

	return ret;
}

string * ProxySQL_HTTP_Server::generate_header(char *s) {
	string *a = new string();
	a->append("<!DOCTYPE html><head>\n<title>");
	a->append(s);
	a->append("</title>\n");
	a->append("<link rel=\"stylesheet\" href=\"https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,600,900|Fira+Mono\"/>\n");
	a->append("<link rel=\"stylesheet\" href=\"/main-bundle.min.css\"/>\n");
	a->append("<link rel=\"stylesheet\" href=\"/font-awesome.min.css\"/>\n");
	a->append("<script src=\"/Chart.bundle.js\"></script>\n</head>\n<body style=\"background-color: white;\">\n");
	a->append("<header class=\"header cf \" role=\"banner\">\n<a class=\"brand\" href=\"http://www.proxysql.com\"><span><strong>Proxy</strong>SQL</span>\n</a>");
	return a;
}

string * ProxySQL_HTTP_Server::generate_canvas(char *s) {
	string *a = new string();
	a->append("<div class=\"wrapper\" style=\"width: 750px; height: 350px\"><canvas id=\"");
	a->append(s);
	a->append("\" width=\"700\" height=\"330\"></canvas></div>\n");
	return a;
}
ProxySQL_HTTP_Server::ProxySQL_HTTP_Server() {
	page_sec = 0;
	cur_time = time(NULL);
	last_check_version = 0;
	pthread_mutex_init(&check_version_mutex,NULL);
	variables.proxysql_latest_version = NULL;
}

ProxySQL_HTTP_Server::~ProxySQL_HTTP_Server() {
	if (variables.proxysql_latest_version) {
		free(variables.proxysql_latest_version);
		variables.proxysql_latest_version = NULL;
	}
}

string * ProxySQL_HTTP_Server::generate_chart(char *chart_name, char *ts, int nsets, char **dname, char **llabel, char **values) {
	char *h=(char *)"0123456789abcdef";
	string *ret= new string();
	int i;
	ret->append("<script>\n");
	ret->append("var ts = ");
	ret->append(ts);
	ret->append("\n");
	for (i=0;i<nsets;i++) {
		ret->append("var ");
		ret->append(dname[i]);
		ret->append(" = ");
		ret->append(values[i]);
		ret->append("\n");
	}
	ret->append("var ctx = document.getElementById(\"");
	ret->append(chart_name);
	ret->append("\");\nvar ");
	ret->append(chart_name);
	ret->append(" = new Chart(ctx, { \n");
	ret->append("type: 'line', \n");
	ret->append("  data: { \n");
	ret->append("    labels: ts,\n");
	ret->append("    datasets: [ \n");
	for (i=0;i<nsets;i++) {
		ret->append("      {\n");
		ret->append("        data: "); ret->append(dname[i]); ret->append(",\n");
		ret->append("        label: \""); ret->append(llabel[i]); ret->append("\",\n");
		int j;
		char pal[7];
		for (j=0; j<6; j++) { pal[j]=h[rand()%16]; }
		pal[6]='\0';
		ret->append("        borderColor: \"#"); ret->append(pal); ret->append("\",\n");
		ret->append("        fill: false\n");
		ret->append("      }");
		if (i<nsets-1) {
			ret->append(",");
		}
		ret->append("\n");
	}
	ret->append("    ]\n");
	ret->append("  },\n");
	ret->append("options: {\n");
        ret->append("    scales: {\n");
        ret->append("      xAxes: [{\n");
        ret->append("        ticks: {\n");
//        ret->append("          autoSkip: true,\n");
//        ret->append("          maxRotation: 0,\n");
//        ret->append("          minRotation: 0\n");
        ret->append("        }\n");
        ret->append("      }]\n");
        ret->append("    }\n");
        ret->append("  }\n");
	ret->append("});\n");
	ret->append("</script>\n");
	return ret;
	
}
