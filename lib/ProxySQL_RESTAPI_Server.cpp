#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "proxysql.h"
#include "cpp.h"
#include "httpserver.hpp"

#include <functional>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <strings.h>
#include <unistd.h>

#include "ProxySQL_RESTAPI_Server.hpp"
#include "ProxySQL_Statistics.hpp"
#include "proxysql_utils.h"

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_RESTAPI_SERVER_VERSION "2.0.1121" DEB

extern ProxySQL_Admin *GloAdmin;

using namespace httpserver;
//using nlohmann::json;

class sync_resource : public http_resource {
private:
	void add_headers(std::shared_ptr<http_response> &response) {
		response->with_header("Content-Type", "application/json");
		response->with_header("Access-Control-Allow-Origin", "*");
	}

	const std::shared_ptr<http_response> find_script(const http_request& req, std::string& script, int &interval_ms) {
		const string req_uri { req.get_path_piece(1) };
		const string req_path { req.get_path() };
		const string select_query { "SELECT * FROM runtime_restapi_routes WHERE uri=?1 AND method=?2 AND active=1" };

		std::unique_ptr<SQLite3_result> resultset = nullptr;
		char* error = NULL;
		int cols = 0;
		int affected_rows = 0;

		auto [rc, statement1] = GloAdmin->admindb->prepare_v2(select_query.c_str());
		ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
		rc = (*proxy_sqlite3_bind_text)(statement1.get(), 1, req_uri.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
		rc = (*proxy_sqlite3_bind_text)(statement1.get(), 2, req.get_method().c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
		resultset = std::unique_ptr<SQLite3_result>(GloAdmin->admindb->execute_prepared(statement1.get(), &error, &cols, &affected_rows));
		rc = (*proxy_sqlite3_clear_bindings)(statement1.get()); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
		rc = (*proxy_sqlite3_reset)(statement1.get()); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);

		if (!resultset) {
			proxy_error(
				"Cannot query script for given method [%s] and uri [%s]\n", req.get_method().c_str(), req_uri.c_str()
			);
			const string not_found_err_msg {
				"The script for method [" + req.get_method() + "] and route [" + req.get_path() + "] was not found."
			};
			json j_err_resp {};

			if (error) {
				j_err_resp = json { { "error", not_found_err_msg + " Error:" + error } };
				proxy_error("Path '%s', error '%s'\n", req_path.c_str(), error);
			} else {
				j_err_resp = json { { "error", not_found_err_msg } };
				proxy_error("Path '%s', error 'Path failed to be found on 'runtime_restapi_routes'\n", req_path.c_str());
			}

			auto response =
				std::shared_ptr<http_response>(new string_response(j_err_resp.dump(), http::http_utils::http_bad_request));
			add_headers(response);

			return response;
		} else if (resultset && resultset->rows_count != 1) {
			const string not_found_err_msg {
				"The script for method [" + req.get_method() + "] and route [" + req_path + "] was not found."
					" Rows count returned [" + std::to_string(resultset->rows_count) + "]"
			};
			json j_err_resp { { "error", not_found_err_msg } };

			proxy_error(
				"Script for method [%s] and uri [%s] was not found\n", req.get_method().c_str(), req_uri.c_str()
			);
			auto response =
				std::shared_ptr<http_response>(new string_response(j_err_resp.dump(), http::http_utils::http_bad_request));
			add_headers(response);

			return response;
		} else {
			script = resultset->rows[0]->fields[5];
			interval_ms = atoi(resultset->rows[0]->fields[2]);

			return std::shared_ptr<http_response>(nullptr);
		}
	}

    const std::shared_ptr<http_response> process_request(const http_request& req, const std::string& _params) {
		std::string params = req.get_content();
		const string req_path { req.get_path() };

		if (params.empty())
			params = _params;
		if (params.empty()) {
			proxy_error("Path '%s', error 'Supplied empty parameters'\n", req_path.c_str());
			json j_err_resp { { "type", "in" }, { "error", "Empty parameters" } };
			auto response = std::shared_ptr<http_response>(
				new string_response(j_err_resp.dump(), http::http_utils::http_bad_request)
			);

			add_headers(response);
			return response;
		}

		try {
			nlohmann::json valid=nlohmann::json::parse(params);
		} catch(nlohmann::json::exception& e) {
			const string p_err_msg {
				"parsing input JSON parameters - params: `" + params + "`, error: '" + e.what() + "'"
			};
			json j_err_resp { { "type", "in" }, { "error", "Error " + p_err_msg } };
			proxy_error("Path '%s', error %s\n", req_path.c_str(), p_err_msg.c_str());

			auto response = std::shared_ptr<http_response>(
				new string_response(j_err_resp.dump(), http::http_utils::http_bad_request)
			);
			add_headers(response);
			return response;
		}

		std::string script;
		int interval_ms = 1;
		auto result=find_script(req, script, interval_ms);

		// result == nullpts means that script was found and we can execute it. continue.
		if (nullptr!=result)
			return result;

		to_opts_t wexecvp_opts {};
		wexecvp_opts.timeout_us = (interval_ms * 1000);
		wexecvp_opts.poll_to_us = 100*1000;
		wexecvp_opts.waitpid_delay_us = 500*1000;
		wexecvp_opts.sigkill_to_us = 3000 * 1000;

		std::string script_stdout {""};
		std::string script_stderr {""};

		const std::vector<const char*> args { const_cast<const char*>(params.c_str()), NULL};
		proxy_debug(PROXY_DEBUG_RESTAPI, 2, "Starting script exec - script: '%s', params: `%s`\n", script.c_str(), params.c_str());
		int script_err = wexecvp(script.c_str(), args, wexecvp_opts, script_stdout, script_stderr);
		proxy_debug(PROXY_DEBUG_RESTAPI, 2, "Finished script exec - script: '%s', params: `%s`\n", script.c_str(), params.c_str());
		int script_errno = errno;

		std::string str_response_err {};
		bool internal_error = false;

		// 'execvp' failed to be executed, the error code comes directly from the child process
		if (script_err > 255) {
			json j_err_resp {
				{ "type", "out" },
				{ "error", "Script failed to be executed" },
				{ "error_code", std::to_string(script_err / 256) },
				{ "script_stdout", script_stdout },
				{ "script_stderr", script_stderr }
			};
			str_response_err = j_err_resp.dump();
			proxy_error(
				"Script '%s' exited with errcode '%d': \n- script_stdout:\n'''\n%s'''\n- script_stderr:\n'''\n%s'''\n",
				script.c_str(),
				script_err / 256,
				script_stdout.c_str(),
				script_stderr.c_str()
			);
		}
		// there was an internal error while calling the executable, or request timedout.
		else if (script_err < 256 && script_err != 0) {
			if (script_err == ETIME) {
				json j_err_resp {
					{ "type", "out" },
					{ "error", "Script execution timed out" },
					{ "error_code", std::to_string(ETIME) }
				};
				str_response_err = j_err_resp.dump();
				proxy_error("Request to execute script '%s' timed out.\n", script.c_str());
			} else if (script_err < 0) {
				// there was an internal error unrelated to script execution
				internal_error = true;

				std::string failed_syscall { "" };

				switch (script_err) {
					case -1:
						failed_syscall = "pipe()"; break;
					case -2:
						failed_syscall = "fork()"; break;
					case -3:
						failed_syscall = "fcntl()"; break;
					case -4:
						failed_syscall = "resource exhaustion (maxfd >= FD_SETSIZE)"; break;
					case -5:
						failed_syscall = "select()"; break;
					case -6:
						failed_syscall = "read()"; break;
					default:
						failed_syscall = "unknown"; break;
				}

				json j_err_resp {
					{ "type", "out" },
					{ "error", "Internal error while executing script, '" + failed_syscall + "' syscall failed" },
					{ "error_code", std::to_string(script_errno) }
				};
				str_response_err = j_err_resp.dump();
				proxy_error(
					"Internal error while executing script '%s'. '%s' syscall failed with error code: '%d'.\n",
					script.c_str(),
					failed_syscall.c_str(),
					script_errno
				);
			} else {
				json j_err_resp {
					{ "type", "out" },
					{ "error", "Terminated without exit code. Child exit status reported in 'error_code'" },
					{ "error_code", std::to_string(script_err) }
				};
				str_response_err = j_err_resp.dump();
				proxy_error("Error while executing script '%s'. Child exit status: '%d'.\n", script.c_str(), script_err);
			}
		}
		// script returned and empty output, invalid output, no need to parse it.
		else if (script_stdout.empty()) {
			json j_err_resp {
				{ "type", "out" },
				{ "error", "Script response is empty, only valid JSONs are accepted" },
				{ "error_code", std::to_string(0) }
			};
			str_response_err = j_err_resp.dump();
			proxy_error("Invalid empty response from script: '%s'\n", script.c_str());
		}
		// execution completed successfully without timing out.
		else {
			try {
				nlohmann::json j { nlohmann::json::parse(script_stdout.c_str()) };
			} catch(nlohmann::json::exception& e) {
				json j_err_resp {
					{ "type", "out" },
					{ "error", e.what() },
					{ "error_code", std::to_string(script_err / 256) },
					{ "script_stdout", script_stdout },
					{ "script_stderr", script_stderr }
				};
				str_response_err = j_err_resp.dump();
				proxy_error(
					"Error parsing script output from script: '%s'\n- script_stdout:\n'''\n%s'''\n",
					script.c_str(), script_stdout.c_str()
				);
			}
		}

		if (!str_response_err.empty()) {
			std::shared_ptr<http_response> response { nullptr };

			if (internal_error) {
				response = std::shared_ptr<http_response>(
					new string_response(str_response_err, http::http_utils::http_internal_server_error)
				);
			} else {
				response = std::shared_ptr<http_response>(
					new string_response(str_response_err, http::http_utils::http_failed_dependency)
				);
			}

			add_headers(response);
			return response;
		} else {
			auto response = std::shared_ptr<http_response>(
				new string_response(script_stdout.c_str(), http::http_utils::http_ok)
			);
			add_headers(response);
			return response;
		}
    }

public:
	const std::shared_ptr<http_response> render(const http_request& req) {
		proxy_info("Render generic request with method %s for uri %s\n", req.get_method().c_str(), req.get_path().c_str());
		json j_err_resp {{ "error", "HTTP method " + req.get_method() + " is not implemented" }};
        auto response = std::shared_ptr<http_response>(new string_response(j_err_resp.dump()));
        response->with_header("Content-Type", "application/json");
        response->with_header("Access-Control-Allow-Origin", "*");

        return response;
    }

	const std::shared_ptr<http_response> render_GET(const http_request& req) {
		const auto args = req.get_args();

		// Explicit object creation, otherwise 'array' is initialized
		json input_params = json::object();
		for (const auto& arg : args) {
			input_params.push_back({arg.first, arg.second});
		}

		const string s_params { input_params.dump() };

#ifdef DEBUG
		const char* req_path { req.get_path().c_str() };
		const char* p_params { s_params.c_str() };
		proxy_debug(PROXY_DEBUG_RESTAPI, 1, "Processing GET - req: '%s', params: `%s`\n", req_path, p_params);
#endif

		return process_request(req, s_params);
	}

	const std::shared_ptr<http_response> render_POST(const http_request& req) {
		std::string req_path = req.get_path();
		std::string req_body = req.get_content();
		std::string content_type = req.get_header(http::http_utils::http_header_content_type);

		// validate Context-Type header
		// reject unsupported content types
		if (!content_type.empty() &&
			content_type.find("application/json") == std::string::npos &&
			content_type.find("text/json") == std::string::npos &&
			content_type.find("text/plain") == std::string::npos) {
#ifdef DEBUG
			proxy_debug(PROXY_DEBUG_RESTAPI, 1, "Rejected POST - req: '%s', content-type: '%s', req_body: `%s`\n",
			                                              req_path.c_str(), content_type.c_str(), req_body.c_str());
#endif
			auto response = std::shared_ptr<http_response>(new string_response(
				"{\"error\": \"Unsupported Content-Type\"}",
				http::http_utils::http_unsupported_media_type
			));
			add_headers(response);
			return response;
		}

#ifdef DEBUG
		proxy_debug(PROXY_DEBUG_RESTAPI, 1, "Processing POST - req: '%s', params: `%s`\n", req_path.c_str(), req_body.c_str());
#endif
		return process_request(req, req_body);
	}

};

extern ProxySQL_Statistics *GloProxyStats;

#ifdef PROXYSQLTSDB
class tsdb_resource : public http_resource {
private:
    void add_headers(std::shared_ptr<http_response> &response) {
        response->with_header("Content-Type", "application/json");
        response->with_header("Access-Control-Allow-Origin", "*");
    }

public:
    const std::shared_ptr<http_response> render_GET(const http_request& req) override {
        const string req_path { req.get_path() };
        json j_resp;

        if (req_path == "/api/tsdb/metrics") {
            if (!GloProxyStats || !GloProxyStats->statsdb_disk) {
                j_resp = json {{"error", "TSDB not initialized"}};
                auto response = std::shared_ptr<http_response>(new string_response(j_resp.dump(), http::http_utils::http_internal_server_error));
                add_headers(response);
                return response;
            }
            
            SQLite3_result *res = GloProxyStats->list_tsdb_metric_names();
            if (!res) {
                j_resp = json {{"error", "Unable to list TSDB metrics"}};
            } else {
                std::vector<string> metrics;
                for (int i = 0; i < res->rows_count; i++) {
                    metrics.push_back(res->rows[i]->fields[0]);
                }
                delete res;
                j_resp = metrics;
            }
        } else if (req_path == "/api/tsdb/query") {
            if (!GloProxyStats || !GloProxyStats->statsdb_disk) {
                j_resp = json {{"error", "TSDB not initialized"}};
                auto response = std::shared_ptr<http_response>(new string_response(j_resp.dump(), http::http_utils::http_internal_server_error));
                add_headers(response);
                return response;
            }
            string metric = req.get_arg("metric");
            if (metric.empty()) {
                j_resp = json {{"error", "Missing 'metric' parameter"}};
                auto response = std::shared_ptr<http_response>(new string_response(j_resp.dump(), http::http_utils::http_bad_request));
                add_headers(response);
                return response;
            }

            time_t now = time(NULL);
            time_t from = now - 3600;
            time_t to = now;

            string s_from = req.get_arg("from");
            if (!s_from.empty()) from = atol(s_from.c_str());
            string s_to = req.get_arg("to");
            if (!s_to.empty()) to = atol(s_to.c_str());
            string agg = req.get_arg("agg");

            std::map<string, string> labels;
            auto all_args = req.get_args();
            for (auto const& [key, val] : all_args) {
                if (key != "metric" && key != "from" && key != "to" && key != "agg") {
                    labels[key] = val;
                }
            }

		SQLite3_result *res = GloProxyStats->query_tsdb_metrics(metric, labels, from, to, agg);
            if (!res) {
                j_resp = json::array();
            } else {
                for (int i = 0; i < res->rows_count; i++) {
                    json row;
                    row["ts"] = atol(res->rows[i]->fields[0]);
                    row["metric"] = res->rows[i]->fields[1];
                    try {
                        row["labels"] = json::parse(res->rows[i]->fields[2]);
                    } catch (const json::parse_error& e) {
                        row["labels"] = res->rows[i]->fields[2];
                    }
                    row["value"] = atof(res->rows[i]->fields[3]);
                    j_resp.push_back(row);
                }
                delete res;
            }
	} else if (req_path == "/api/tsdb/status") {
		if (!GloProxyStats) {
			j_resp = json {{"error", "TSDB not initialized"}};
			auto response = std::shared_ptr<http_response>(new string_response(j_resp.dump(), http::http_utils::http_internal_server_error));
			add_headers(response);
			return response;
		}
		ProxySQL_Statistics::tsdb_status_t status = GloProxyStats->get_tsdb_status();
		j_resp["total_series"] = status.total_series;
		j_resp["total_datapoints"] = status.total_datapoints;
		j_resp["disk_size_bytes"] = status.disk_size_bytes;
		j_resp["oldest_datapoint"] = status.oldest_datapoint;
		j_resp["newest_datapoint"] = status.newest_datapoint;
        } else {
            return std::shared_ptr<http_response>(new string_response("Not Found", http::http_utils::http_not_found));
        }

        auto response = std::shared_ptr<http_response>(new string_response(j_resp.dump(), http::http_utils::http_ok));
        add_headers(response);
        return response;
    }
};

/* The TSDB dashboard HTML and its Chart.bundle.js asset are served from
 * the REST API port so the dashboard's fetch('/api/tsdb/...') calls are
 * same-origin and resolve to the real handlers above. See issue #5684. */
extern const char* TSDB_Dashboard_html_c;
extern char* Chart_bundle_js_c;

class tsdb_dashboard_resource : public http_resource {
public:
    const std::shared_ptr<http_response> render_GET(const http_request& /*req*/) override {
        auto response = std::shared_ptr<http_response>(new string_response(TSDB_Dashboard_html_c, http::http_utils::http_ok));
        response->with_header("Content-Type", "text/html; charset=utf-8");
        return response;
    }
};

class tsdb_chart_js_resource : public http_resource {
public:
    const std::shared_ptr<http_response> render_GET(const http_request& /*req*/) override {
        auto response = std::shared_ptr<http_response>(new string_response(Chart_bundle_js_c, http::http_utils::http_ok));
        response->with_header("Content-Type", "application/javascript; charset=utf-8");
        return response;
    }
};
#endif

class gen_get_endpoint : public http_resource {
private:
	std::function<std::shared_ptr<http_response>(const http_request&)> _get_fn {};
public:
	gen_get_endpoint(std::function<std::shared_ptr<http_response>(const http_request&)> get_fn) :
		_get_fn(get_fn)
	{}

	const std::shared_ptr<http_response> render_GET(const http_request& req) override {
		return this->_get_fn(req);
	}
};

using std::vector;
using std::pair;
using std::function;
using std::shared_ptr;

static std::string trim_restapi_interface(const std::string& value) {
	size_t first = value.find_first_not_of(" \t\r\n");
	if (first == std::string::npos) {
		return {};
	}
	size_t last = value.find_last_not_of(" \t\r\n");
	return value.substr(first, last - first + 1);
}

bool ProxySQL_RESTAPI_parse_bind_address(
	const std::string& interface_name,
	uint16_t port,
	bool& has_bind_address,
	struct sockaddr_storage& addr,
	socklen_t& addr_len,
	std::string& unix_socket_path,
	std::string& error
) {
	has_bind_address = false;
	addr = sockaddr_storage {};
	addr_len = 0;
	unix_socket_path.clear();
	error.clear();

	std::string value = trim_restapi_interface(interface_name);
	if (value.empty()) {
		return true;
	}

	bool unix_prefixed = false;
	if (value.size() > 5 && strncasecmp(value.c_str(), "unix:", 5) == 0) {
		unix_prefixed = true;
		value = trim_restapi_interface(value.substr(5));
	}

	if (!value.empty() && value[0] == '/') {
		if (value.size() + 1 > sizeof(((struct sockaddr_un*)0)->sun_path)) {
			error = "Unix socket path is too long: '" + value + "'";
			return false;
		}
		struct sockaddr_un un {};
		un.sun_family = AF_UNIX;
		memcpy(un.sun_path, value.c_str(), value.size() + 1);
		memcpy(&addr, &un, sizeof(un));
		addr_len = static_cast<socklen_t>(
			offsetof(struct sockaddr_un, sun_path) + value.size() + 1);
		has_bind_address = true;
		unix_socket_path = value;
		return true;
	}
	if (unix_prefixed) {
		error = "admin-restapi_interface 'unix:' requires an absolute socket path";
		return false;
	}

	std::string host = value;
	if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
		host = host.substr(1, host.size() - 2);
	}

	struct sockaddr_in addr4 {};
	if (inet_pton(AF_INET, host.c_str(), &addr4.sin_addr) == 1) {
		addr4.sin_family = AF_INET;
		addr4.sin_port = htons(port);
		memcpy(&addr, &addr4, sizeof(addr4));
		addr_len = sizeof(addr4);
		has_bind_address = true;
		return true;
	}

	struct sockaddr_in6 addr6 {};
	if (inet_pton(AF_INET6, host.c_str(), &addr6.sin6_addr) == 1) {
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(port);
		memcpy(&addr, &addr6, sizeof(addr6));
		addr_len = sizeof(addr6);
		has_bind_address = true;
		return true;
	}

	error = "Invalid admin-restapi_interface '" + interface_name +
		"': expected a numeric IPv4/IPv6 address or an absolute Unix socket path";
	return false;
}

void ProxySQL_RESTAPI_Server::cleanup_unix_socket() {
	if (unix_socket_path_owned && !unix_socket_path.empty()) {
		struct stat st {};
		if (lstat(unix_socket_path.c_str(), &st) == 0 &&
			S_ISSOCK(st.st_mode) &&
			st.st_dev == unix_socket_dev &&
			st.st_ino == unix_socket_ino) {
			unlink(unix_socket_path.c_str());
		}
	}
	unix_socket_path_owned = false;
}

// Unix paths are never replaced. Rejecting any pre-existing path avoids
// probing/unlinking a foreign or stale socket and lets MHD create the listener
// from a sockaddr (with an exact MHD_OPTION_SOCK_ADDR_LEN) like any TCP bind.
static bool ensure_unix_socket_path_available(const std::string& path, std::string& error) {
	struct stat st {};
	if (lstat(path.c_str(), &st) == 0) {
		error = "Unix socket path '" + path + "' already exists; refusing to replace it";
		return false;
	}
	if (errno != ENOENT) {
		error = "Cannot inspect Unix socket path '" + path + "': " + strerror(errno);
		return false;
	}
	return true;
}

static ProxySQL_RESTAPI_Config make_default_restapi_config(int port) {
	ProxySQL_RESTAPI_Config config {};
	config.port = port;
	return config;
}

ProxySQL_RESTAPI_Server::ProxySQL_RESTAPI_Server(
	int p,
	vector<pair<std::string, function<shared_ptr<http_response>(const http_request&)>>> endpoints
) : ProxySQL_RESTAPI_Server(make_default_restapi_config(p), std::move(endpoints)) {
}

ProxySQL_RESTAPI_Server::ProxySQL_RESTAPI_Server(
	const ProxySQL_RESTAPI_Config& config_,
	vector<pair<std::string, function<shared_ptr<http_response>(const http_request&)>>> endpoints
) : port(config_.port) {
	std::string parse_error;
	if (!ProxySQL_RESTAPI_parse_bind_address(
			config_.interface_name, static_cast<uint16_t>(config_.port),
			has_bind_address, bind_addr, bind_addr_len, unix_socket_path, parse_error)) {
		proxy_error("Unable to start 'ProxySQL_RestAPI_Server': %s\n", parse_error.c_str());
		return;
	}

	if (config_.verify_client && !config_.use_ssl) {
		proxy_error(
			"Unable to start 'ProxySQL_RestAPI_Server': "
			"admin-restapi_ssl_verify_client=true requires admin-restapi_use_ssl=true. "
			"Refusing to serve plain HTTP.\n"
		);
		return;
	}
	if (config_.use_ssl && (config_.ssl_key_pem.empty() || config_.ssl_cert_pem.empty())) {
		proxy_error(
			"Unable to start 'ProxySQL_RestAPI_Server': SSL certificates are not loaded. "
			"Refusing to fall back to plain HTTP.\n"
		);
		return;
	}
	if (config_.verify_client && config_.ssl_ca_pem.empty()) {
		proxy_error(
			"Unable to start 'ProxySQL_RestAPI_Server': client certificate verification "
			"requires a non-empty CA (admin-restapi_ssl_ca or ProxySQL's CA PEM).\n"
		);
		return;
	}

	if (!unix_socket_path.empty()) {
		std::string unix_error;
		if (!ensure_unix_socket_path_available(unix_socket_path, unix_error)) {
			proxy_error("Unable to start 'ProxySQL_RestAPI_Server': %s\n", unix_error.c_str());
			return;
		}
	}

	try {
		// NOTE: Right now ProxySQL is using the simplest mode of 'libhttpserver' for serving 'REST' queries,
		// in the current mode concurrency on serving requests is low, and throughput is directly related with
		// the time required to execute the target script, since each of the calls are blocking.
#if defined(__FreeBSD__) || defined(__APPLE__)
		auto server_config = create_webserver(port)
			.no_post_process()
			.start_method(http::http_utils::start_method_T::THREAD_PER_CONNECTION);
#else
		auto server_config = create_webserver(port).no_post_process();
#endif
		if (config_.use_ssl) {
			server_config.use_ssl()
				.raw_https_mem_key(config_.ssl_key_pem)
				.raw_https_mem_cert(config_.ssl_cert_pem);
			if (config_.verify_client) {
				// Only mTLS listeners install a trust store; ordinary HTTPS
				// must not request a client certificate.
				server_config.raw_https_mem_trust(config_.ssl_ca_pem)
					.require_client_cert();
			}
		} else {
			server_config.no_ssl();
		}
		if (has_bind_address) {
			if (bind_addr.ss_family == AF_INET6) {
				server_config.use_ipv6();
			}
			server_config.bind_address(
				reinterpret_cast<const struct sockaddr*>(&bind_addr), bind_addr_len);
		}

		ws = std::unique_ptr<httpserver::webserver>(new webserver(server_config));
	} catch (const std::exception& e) {
		proxy_error("Unable to create 'ProxySQL_RestAPI_Server': %s\n", e.what());
		cleanup_unix_socket();
		return;
	}

	auto sr = new sync_resource();

	endpoint = std::unique_ptr<httpserver::http_resource>(sr);

	ws->register_resource("/sync", endpoint.get(), true);

#ifdef PROXYSQLTSDB
	auto tsdb_res = new tsdb_resource();
	tsdb_endpoint = std::unique_ptr<httpserver::http_resource>(tsdb_res);
	ws->register_resource("/api/tsdb/metrics", tsdb_endpoint.get(), true);
	ws->register_resource("/api/tsdb/query", tsdb_endpoint.get(), true);
	ws->register_resource("/api/tsdb/status", tsdb_endpoint.get(), true);

	/* Serve the dashboard HTML and its Chart.bundle.js asset on the
	 * same port as the API, so the dashboard's relative fetch() calls
	 * are same-origin. See issue #5684. */
	tsdb_dashboard_endpoint = std::unique_ptr<httpserver::http_resource>(new tsdb_dashboard_resource());
	tsdb_chart_js_endpoint = std::unique_ptr<httpserver::http_resource>(new tsdb_chart_js_resource());
	ws->register_resource("/tsdb", tsdb_dashboard_endpoint.get(), true);
	ws->register_resource("/Chart.bundle.js", tsdb_chart_js_endpoint.get(), true);
#endif
	for (const auto& id_endpoint : endpoints) {
		const std::string& endpoint_route = id_endpoint.first;
		auto endpoint_fn = id_endpoint.second;
		std::unique_ptr<httpserver::http_resource> endpoint_res =
			std::unique_ptr<httpserver::http_resource>(new gen_get_endpoint(endpoint_fn));

		ws->register_resource(endpoint_route, endpoint_res.get(), true);
		_endpoints.push_back({endpoint_route, std::move(endpoint_res)});
	}

	// Finish constructing and registering resources before requests can read them.
	// Start non-blocking so bind/TLS/CA failures are reported here instead of
	// escaping a thread and calling std::terminate.
	try {
		ws->start(false);
	} catch (const std::exception& e) {
		proxy_error("Unable to start 'ProxySQL_RestAPI_Server' on port %d: %s\n", port, e.what());
		ws.reset();
		cleanup_unix_socket();
		return;
	}
	if (!ws->is_running()) {
		proxy_error("Unable to start 'ProxySQL_RestAPI_Server' on port %d\n", port);
		ws.reset();
		cleanup_unix_socket();
		return;
	}
	if (!unix_socket_path.empty()) {
		struct stat st {};
		if (lstat(unix_socket_path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) {
			unix_socket_dev = st.st_dev;
			unix_socket_ino = st.st_ino;
			unix_socket_path_owned = true;
		} else {
			proxy_error(
				"Unable to verify Unix socket '%s' after listener start: %s\n",
				unix_socket_path.c_str(), strerror(errno));
		}
	}
	proxy_info(
		"Started 'ProxySQL_RestAPI_Server' on %s (%s%s)\n",
		unix_socket_path.empty() ? std::to_string(port).c_str() : unix_socket_path.c_str(),
		config_.use_ssl ? "HTTPS" : "HTTP",
		config_.verify_client ? ", client certificates required" : ""
	);
}

ProxySQL_RESTAPI_Server::~ProxySQL_RESTAPI_Server() {
	if (ws) {
		ws->stop();
	}
	cleanup_unix_socket();
}

bool ProxySQL_RESTAPI_Server::is_running() const {
	return ws && ws->is_running();
}

void ProxySQL_RESTAPI_Server::init() {
}

void ProxySQL_RESTAPI_Server::print_version() {
    fprintf(stderr,"Standard ProxySQL REST API Server Handler rev. %s -- %s -- %s\n", PROXYSQL_RESTAPI_SERVER_VERSION, __FILE__, __TIMESTAMP__);
}
