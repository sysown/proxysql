#ifndef CLASS_PROXYSQL_HTTP_SERVER_H
#define CLASS_PROXYSQL_HTTP_SERVER_H
#include "proxysql.h"
#include "cpp.h"
#include <string>

#define ProxySQL_HTTP_Server_Rate_Limit 100

class ProxySQL_HTTP_Server {
	unsigned int page_sec;
	time_t cur_time;
	pthread_mutex_t check_version_mutex;
	time_t last_check_version;
	std::string * generate_header(char *);
	std::string * generate_canvas(char *);
	std::string * generate_chart(char *chart_name, char *ts, int nsets, char **dname, char **llabel, char **values);
	char *extract_values(SQLite3_result *result, int idx, bool relative, double mult=1);
	char *extract_ts(SQLite3_result *result, bool relative);
	public:
	struct {
		char *proxysql_latest_version;
	} variables;
	ProxySQL_HTTP_Server();
	~ProxySQL_HTTP_Server();
	void init();
	int handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr);
	void print_version();
	void check_latest_version_http();
};

#endif /* CLASS_PROXYSQL_HTTP_SERVER */
