#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <map>

#include "curl/curl.h"
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

struct memory {
   char *response;
   size_t size;
};

static size_t cb(void *data, size_t size, size_t nmemb, void *userp) {
   size_t realsize = size * nmemb;
   struct memory *mem = (struct memory *)userp;

   char *ptr = (char *)realloc((void *)mem->response, mem->size + realsize + 1);
   if(ptr == NULL)
	 return 0;

   mem->response = ptr;
   memcpy(&(mem->response[mem->size]), data, realsize);
   mem->size += realsize;
   mem->response[mem->size] = 0;

   return realsize;
}

static void drain_results(MYSQL* mysql) {
	MYSQL_RES* res;
	while (1) {
		res = mysql_store_result(mysql);
		if (res) mysql_free_result(res);
		if (mysql_next_result(mysql) != 0) break;
	}
}

long http_get(const char *url, string &response_out, const char* userpwd = "stats:stats") {
	struct memory chunk;
	chunk.response = NULL;
	chunk.size = 0;

	curl_global_init(CURL_GLOBAL_ALL);
	CURL *curl_handle;
	curl_handle = curl_easy_init();

	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, cb);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_USERPWD, userpwd);
	curl_easy_setopt(curl_handle, CURLOPT_HTTPAUTH, (long)CURLAUTH_DIGEST);

	CURLcode res;
	res = curl_easy_perform(curl_handle);
	long response_code = 0;
	if(res == CURLE_OK) {
		curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code);
		if (chunk.response) {
			response_out = string(chunk.response);
		}
	} else {
		diag("libcurl error for %s: %s", url, curl_easy_strerror(res));
	}

	if (chunk.response) free(chunk.response);
	curl_easy_cleanup(curl_handle);
	return response_code;
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(10);

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Connection failed: %s", mysql_error(admin));
		return EXIT_FAILURE;
	}

	// 1. Enable TSDB and REST API
	diag("Enabling TSDB, Web, and REST API...");
	mysql_query(admin, "SET tsdb-enabled='1'");
	mysql_query(admin, "SET tsdb-sample_interval='1'");
	mysql_query(admin, "SET admin-restapi_enabled='1'");
	mysql_query(admin, "SET admin-web_enabled='1'");
	mysql_query(admin, "LOAD TSDB VARIABLES TO RUNTIME");
	mysql_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	drain_results(admin);

	// 2. Wait for background loops to collect data and HTTP server to start
	diag("Waiting for initialization and data collection (7s)...");
	sleep(7);

	string base_url = "https://127.0.0.1:6080";
	string rest_url = "http://127.0.0.1:6070";
	string response;
	long rc;

	// 3. Test /tsdb Dashboard (HTML)
	diag("Testing GET /tsdb");
	// Retry once if server returned nothing
	for (int i=0; i<3; i++) {
		rc = http_get((base_url + "/tsdb").c_str(), response);
		if (rc != 0) break;
		diag("Retry %d for /tsdb...", i+1);
		sleep(2);
	}
	
	ok(rc == 200, "Dashboard /tsdb returns 200 (got %ld)", rc);
	ok(response.find("ProxySQL TSDB Dashboard") != string::npos, "Dashboard contains title");
	ok(response.find("tsdbChart") != string::npos, "Dashboard contains canvas element");

	// 4. Test /api/tsdb/status
	diag("Testing GET /api/tsdb/status");
	rc = http_get((rest_url + "/api/tsdb/status").c_str(), response, "admin:admin");
	ok(rc == 200, "API /api/tsdb/status returns 200");
	ok(response.find("total_datapoints") != string::npos, "Status contains total_datapoints");
	diag("Status response: %s", response.c_str());

	// 5. Test /api/tsdb/metrics
	diag("Testing GET /api/tsdb/metrics");
	rc = http_get((rest_url + "/api/tsdb/metrics").c_str(), response, "admin:admin");
	ok(rc == 200, "API /api/tsdb/metrics returns 200");
	ok(response.length() > 2, "Metrics list is not empty");

	// 6. Test /api/tsdb/query
	diag("Testing GET /api/tsdb/query for proxysql_uptime_seconds_total");
	rc = http_get((rest_url + "/api/tsdb/query?metric=proxysql_uptime_seconds_total").c_str(), response, "admin:admin");
	ok(rc == 200, "API /api/tsdb/query returns 200");
	ok(response.find("\"metric\":\"proxysql_uptime_seconds_total\"") != string::npos, "Query result contains metric name");
	ok(response.find("\"value\":") != string::npos, "Query result contains data values");
	diag("Query response (first 100 chars): %s", response.substr(0, 100).c_str());

	mysql_close(admin);
	return exit_status();
}
