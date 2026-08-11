#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "proxysql.h"
#include "cpp.h"
#include "httpserver.hpp"

#include <functional>

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
            
            char *error = NULL;
            int cols, rows;
            SQLite3_result *res = NULL;
            GloProxyStats->statsdb_disk->execute_statement("SELECT DISTINCT metric_name FROM tsdb_metrics", &error, &cols, &rows, &res);
            
            if (error) {
                j_resp = json {{"error", error}};
                free(error);
            } else {
                std::vector<string> metrics;
                if (res) {
                    for (int i = 0; i < res->rows_count; i++) {
                        metrics.push_back(res->rows[i]->fields[0]);
                    }
                    delete res;
                }
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
            string node = req.get_arg("node");

            std::map<string, string> labels;
            auto all_args = req.get_args();
            for (auto const& [key, val] : all_args) {
                if (key != "metric" && key != "from" && key != "to" && key != "agg" && key != "node") {
                    labels[key] = val;
                }
            }

		SQLite3_result *res = GloProxyStats->query_tsdb_metrics(metric, labels, from, to, agg, node);
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
		j_resp["cluster_aggregation_active"] = GloProxyStats->tsdb_agg_active.load();
		j_resp["cluster_rows_replicated"] = GloProxyStats->tsdb_agg_rows_total.load();
		j_resp["cluster_last_cycle"] = GloProxyStats->tsdb_agg_last_cycle_ts.load();
		j_resp["cluster_cap_hit_last_cycle"] = GloProxyStats->tsdb_agg_cap_hit_last_cycle.load();
	} else if (req_path == "/api/tsdb/nodes") {
		if (!GloProxyStats || !GloProxyStats->statsdb_disk) {
			j_resp = json {{"error", "TSDB not initialized"}};
			auto response = std::shared_ptr<http_response>(new string_response(j_resp.dump(), http::http_utils::http_internal_server_error));
			add_headers(response);
			return response;
		}
		json nodes_arr = json::array();
		SQLite3_result *res = GloProxyStats->get_tsdb_cluster_nodes();
		time_t now = time(NULL);
		if (res) {
			for (std::vector<SQLite3_row *>::iterator it = res->rows.begin(); it != res->rows.end(); ++it) {
				SQLite3_row *r = *it;
				json jn;
				jn["node"] = r->fields[0];
				long last_ts = atol(r->fields[1]);
				jn["last_timestamp"] = last_ts;
				jn["watermark_age_s"] = (long)now - last_ts;
				jn["datapoints"] = atoll(r->fields[2]);
				nodes_arr.push_back(jn);
			}
			delete res;
		}
		j_resp = nodes_arr;
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

void * restapi_server_thread(void *arg) {
	set_thread_name("RESTAPI_Server", GloVars.set_thread_name);
	httpserver::webserver * ws = (httpserver::webserver *)arg;
    ws->start(true);
	return NULL;
}

using std::vector;
using std::pair;
using std::function;
using std::shared_ptr;

ProxySQL_RESTAPI_Server::ProxySQL_RESTAPI_Server(
	int p,
	vector<pair<std::string, function<shared_ptr<http_response>(const http_request&)>>> endpoints
) {
	// NOTE: Right now ProxySQL is using the simplest mode of 'libhttpserver' for serving 'REST' queries,
	// in the current mode concurrency on serving requests is low, and throughput is directly related with
	// the time required to execute the target script, since each of the calls are blocking.
#if defined(__FreeBSD__) || defined(__APPLE__)
	ws = std::unique_ptr<httpserver::webserver>(new webserver(
		create_webserver(p)
			.no_post_process()
			.start_method(http::http_utils::start_method_T::THREAD_PER_CONNECTION)
	));
#else
	ws = std::unique_ptr<httpserver::webserver>(new webserver(
		create_webserver(p).no_post_process()
	));
#endif
	// NOTE: Enable for benchmarking purposes. In this mode each request will be served by it's own thread.
	// ws = std::unique_ptr<httpserver::webserver>(new webserver(create_webserver(p).start_method(http::http_utils::start_method_T::THREAD_PER_CONNECTION)));
	auto sr = new sync_resource();

	endpoint = std::unique_ptr<httpserver::http_resource>(sr);

    ws->register_resource("/sync", endpoint.get(), true);

#ifdef PROXYSQLTSDB
	auto tsdb_res = new tsdb_resource();
	tsdb_endpoint = std::unique_ptr<httpserver::http_resource>(tsdb_res);
	ws->register_resource("/api/tsdb/metrics", tsdb_endpoint.get(), true);
	ws->register_resource("/api/tsdb/query", tsdb_endpoint.get(), true);
	ws->register_resource("/api/tsdb/status", tsdb_endpoint.get(), true);
	ws->register_resource("/api/tsdb/nodes", tsdb_endpoint.get(), true);

	/* Serve the dashboard HTML and its Chart.bundle.js asset on the
	 * same port as the API, so the dashboard's relative fetch() calls
	 * are same-origin. See issue #5684. */
	tsdb_dashboard_endpoint = std::unique_ptr<httpserver::http_resource>(new tsdb_dashboard_resource());
	tsdb_chart_js_endpoint = std::unique_ptr<httpserver::http_resource>(new tsdb_chart_js_resource());
	ws->register_resource("/tsdb", tsdb_dashboard_endpoint.get(), true);
	ws->register_resource("/Chart.bundle.js", tsdb_chart_js_endpoint.get(), true);
#endif
	if (pthread_create(&thread_id, NULL, restapi_server_thread, ws.get()) !=0 ) {
		perror("Thread creation");
		exit(EXIT_FAILURE);
	}

	for (const auto& id_endpoint : endpoints) {
		const std::string& endpoint_route = id_endpoint.first;
		auto endpoint_fn = id_endpoint.second;
		std::unique_ptr<httpserver::http_resource> endpoint_res =
			std::unique_ptr<httpserver::http_resource>(new gen_get_endpoint(endpoint_fn));

		ws->register_resource(endpoint_route, endpoint_res.get(), true);
		_endpoints.push_back({endpoint_route, std::move(endpoint_res)});
	}
}

ProxySQL_RESTAPI_Server::~ProxySQL_RESTAPI_Server() {
	if (ws) {
    	ws->stop();
		pthread_join(thread_id, NULL);
	}
}

void ProxySQL_RESTAPI_Server::init() {
}

void ProxySQL_RESTAPI_Server::print_version() {
    fprintf(stderr,"Standard ProxySQL REST API Server Handler rev. %s -- %s -- %s\n", PROXYSQL_RESTAPI_SERVER_VERSION, __FILE__, __TIMESTAMP__);
}
