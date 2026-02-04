#define PROXYSQL_EXTERN

#include "proxysql.h"
#include "MySQL_Variables_Utils.h"

#include <vector>
#include <string>

using std::vector;
using std::string;

SSL_CTX * ProxySQL_GlobalVariables::get_SSL_ctx() {
	// take the mutex
	std::lock_guard<std::mutex> lock(global.ssl_mutex);
	return GloVars.global.ssl_ctx;
}

SSL * ProxySQL_GlobalVariables::get_SSL_new() {
	// take the mutex
	std::lock_guard<std::mutex> lock(global.ssl_mutex);
	return SSL_new(GloVars.global.ssl_ctx);
}

void ProxySQL_GlobalVariables::get_SSL_pem_mem(char **key, char **cert) {
	// take the mutex
	std::lock_guard<std::mutex> lock(global.ssl_mutex);
	*key = strdup(global.ssl_key_pem_mem);
	*cert = strdup(global.ssl_cert_pem_mem);
}

template <size_t N>
vector<string> filter_setting_vars(mysql_variable_st(&vars)[N]) {
	vector<string> res {};

	for (auto it = std::begin(vars); it != std::end(vars); it++) {
		if (it->status == SETTING_VARIABLE) {
			res.push_back(it->set_variable_name);
		}
	}

	return res;
}

vector<string> extend(const vector<string>& v1, const vector<string>& v2) {
	vector<string> res {};

	const auto d1 { std::distance(v1.begin(), v1.end()) };
	const auto d2 { std::distance(v2.begin(), v2.end()) };

	res.reserve(res.size() + d1 + d2);
	res.insert(std::end(res), std::begin(v1), std::end(v1));
	res.insert(std::end(res), std::begin(v2), std::end(v2));

	return res;
}

// Create a vector with the ordered tracked variables for 'p_match_regex_1'.
const s_vector<string> mysql_tracked_vars {
	extend(
		extend(
			filter_setting_vars(mysql_tracked_variables),
			get_mysql_ignore_vars()
		),
		{
			"SESSION_TRACK_GTIDS",
			"TX_ISOLATION",
			"TX_READ_ONLY",
			"TRANSACTION_ISOLATION",
			"TRANSACTION_READ_ONLY",
			"NAMES",
			"CHARSET"
		}
	)
};
