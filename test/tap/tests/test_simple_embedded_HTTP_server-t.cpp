#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <tuple>

#include <curl/curl.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;


struct memory {
   char *response;
   size_t size;
};

static size_t cb(void *data, size_t size, size_t nmemb, void *userp) {
   size_t realsize = size * nmemb;
   struct memory *mem = (struct memory *)userp;

   char *ptr = (char *)realloc((void *)mem->response, mem->size + realsize + 1);
   if(ptr == NULL)
	 return 0;  /* out of memory! */

   mem->response = ptr;
   memcpy(&(mem->response[mem->size]), data, realsize);
   mem->size += realsize;
   mem->response[mem->size] = 0;

   return realsize;
}


void run_request(const char *url) {
	struct memory chunk;
	chunk.response = NULL;
	chunk.size = 0;

	CURL *curl_handle;
	char errbuf[CURL_ERROR_SIZE];
	unsigned int ret = 0;
	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();

	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, cb);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_USERPWD, "stats:stats");
	curl_easy_setopt(curl_handle, CURLOPT_HTTPAUTH, (long)CURLAUTH_DIGEST);
	curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errbuf);

	CURLcode res1;
	res1 = curl_easy_perform(curl_handle);
	if(res1 == CURLE_OK) {
		long response_code;
		curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code);
		ok(response_code==200,"Response code: %ld for %s", response_code, url);
	} else {
		size_t len = strlen(errbuf);
		diag("libcurl: (%d) ", res1);
		if(len)
			diag("%s%s", errbuf, ((errbuf[len - 1] != '\n') ? "\n" : ""));
		else
			diag("%s", curl_easy_strerror(res1));
		ok(0,"Failure for %s", url);
	}
	curl_easy_cleanup(curl_handle);
}

int main() {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(4);

	MYSQL* proxysql_admin = mysql_init(NULL);
	// Initialize connections
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	MYSQL_QUERY(proxysql_admin, "SET admin-web_enabled='true'");
	MYSQL_QUERY(proxysql_admin, "SET admin-web_port=6080");
	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	run_request("https://127.0.0.1:6080");
	run_request("https://127.0.0.1:6080/stats?metric=system");
	run_request("https://127.0.0.1:6080/stats?metric=mysql");
	run_request("https://127.0.0.1:6080/stats?metric=cache");
	return exit_status();
}
