#include "proxysql.h"
#include "cpp.h"
#include "httpserver.hpp"

#include <functional>
#include <sstream>

#include "ProxySQL_RESTAPI_Server.hpp"
#include "proxysql_utils.h"

using namespace httpserver;


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_RESTAPI_SERVER_VERSION "2.0.1121" DEB

extern ProxySQL_Admin *GloAdmin;

class sync_resource : public http_resource {
private:
	void add_headers(std::shared_ptr<http_response> &response) {
		response->with_header("Content-Type", "application/json");
		response->with_header("Access-Control-Allow-Origin", "*");
	}

	const std::shared_ptr<http_response> find_script(const http_request& req, std::string& script, int &interval_ms) {
		char *error=NULL;
		std::stringstream ss;
		ss << "SELECT * FROM runtime_restapi_routes WHERE uri='" << req.get_path_piece(1) << "' and method='" << req.get_method() << "' and active=1";
		std::unique_ptr<SQLite3_result> resultset = std::unique_ptr<SQLite3_result>(GloAdmin->admindb->execute_statement(ss.str().c_str(), &error));
		if (!resultset) {
			proxy_error("Cannot query script for given method [%s] and uri [%s]\n", req.get_method().c_str(), req.get_path_piece(1).c_str());
			std::stringstream ss;
			if (error) {
				ss << "{\"error\":\"The script for method [" << req.get_method() << "] and route [" << req.get_path() << "] was not found. Error: " << error << "Error: \"}";
				proxy_error("Path %s, error %s\n", req.get_path().c_str(), error);
			}
			else {
				ss << "{\"error\":\"The script for method [" << req.get_method() << "] and route [" << req.get_path() << "] was not found.\"}";
				proxy_error("Path %s\n", req.get_path().c_str());
			}
			auto response = std::shared_ptr<http_response>(new string_response(ss.str(), http::http_utils::http_bad_request));
			add_headers(response);
			return response;
		}
		if (resultset && resultset->rows_count != 1) {
			std::stringstream ss;
			ss << "{\"error\":\"The script for method [" << req.get_method() << "] and route [" << req.get_path() << "] was not found. Rows count returned [" << resultset->rows_count << "]\" }";
			proxy_error("Script for method [%s] and route [%s] was not found\n", req.get_method().c_str(), req.get_path().c_str());
			auto response = std::shared_ptr<http_response>(new string_response(ss.str(), http::http_utils::http_bad_request));
			add_headers(response);
			return response;
		}
		script = resultset->rows[0]->fields[5];
		interval_ms = atoi(resultset->rows[0]->fields[2]);
		return std::shared_ptr<http_response>(nullptr);
	}

    const std::shared_ptr<http_response> process_request(const http_request& req, const std::string& _params) {
		std::string params = req.get_content();
		if (params.empty())
			params = _params;
		if (params.empty()) {
			proxy_error("Empty parameters\n");

			auto response = std::shared_ptr<http_response>(
				new string_response("{\"error\":\"Empty parameters\"}", http::http_utils::http_bad_request)
			);
			add_headers(response);
			return response;
		}

		try {
			nlohmann::json valid=nlohmann::json::parse(params);
		}
		catch(nlohmann::json::exception& e) {
			std::stringstream ss;
			ss << "{\"type\":\"in\", \"error\":\"" << e.what() << "\"}";
			proxy_error("Error parsing input json parameters. %s\n", ss.str().c_str());

			auto response = std::shared_ptr<http_response>(
				new string_response(ss.str(), http::http_utils::http_bad_request)
			);
			add_headers(response);
			return response;
		}

		std::string script;
		int interval_ms;
		auto result=find_script(req, script, interval_ms);

		// result == nullpts means that script was found and we can execute it. continue.
		if (nullptr!=result)
			return result;

		to_opts wexecvp_opts {};
		wexecvp_opts.timeout_us = (interval_ms * 1000);
		wexecvp_opts.select_to_us = 100*1000;
		wexecvp_opts.it_delay_us = 500*1000;
		wexecvp_opts.sigkill_timeout_us = 3000 * 1000;

		std::string script_stdout {""};
		std::string script_stderr {""};

		const std::vector<const char*> args { const_cast<const char*>(params.c_str()), NULL};
		int script_err = wexecvp(script.c_str(), args, &wexecvp_opts, script_stdout, script_stderr);
		int script_errno = errno;

		std::string str_response_err {};
		bool internal_error = false;

		// 'execvp' failed to be executed, the error code comes directly from the child process
		if (script_err > 255) {
			str_response_err =
				std::string { "{\"type\":\"out\", \"error\":\"Script failed to be executed.\", \"error_code\":\"" }
				+ std::to_string(script_err / 256)
				+ "\"}";
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
				str_response_err =
					std::string { "{\"type\":\"out\", \"error\":\"Script execution timed out.\", \"error_code\":\"" }
					+ std::to_string(ETIME)
					+ "\"}";

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

				str_response_err =
					std::string {
						"{\"type\":\"out\"," } +
							"\"error\":\"Internal error while executing script, '" + failed_syscall + "' syscall failed.\", " +
							"\"error_code\":\"" + std::to_string(script_errno)
						+ "\"}";
				proxy_error(
					"Internal error while executing script '%s'. '%s' syscall failed with error code: '%d'.\n",
					script.c_str(),
					failed_syscall.c_str(),
					script_errno
				);
			} else {
				str_response_err =
					"{\"type\":\"out\", \"error\":\"Terminated without exit code. Child exit status reported in"
						" 'error_code'\", \"error_code\":\"" + std::to_string(script_err) + "\"}";
				proxy_error(
					"Error while executing script '%s'. Child exit status: '%d'.\n", script.c_str(), script_err
				);
			}
		}
		// script returned and empty output, invalid output, no need to parse it.
		else if (script_stdout.empty()) {
			str_response_err =
				std::string {
					"{\"type\":\"out\"," } +
						"\"error\":\"Script response is empty, only valid JSONs are accepted.\", " +
						"\"error_code\":\"" + std::to_string(0)
					+ "\"}";
			proxy_error("Invalid empty response from script: '%s'\n", script.c_str());
		}
		// execution completed successfully without timing out.
		else {
			try {
				nlohmann::json j { nlohmann::json::parse(script_stdout.c_str()) };
			}
			catch(nlohmann::json::exception& e) {
				std::string escaped_stdout { replace_str(script_stdout, std::string { '"' }, "\\\"") };

				str_response_err =
					std::string { "{" } +
						std::string { "\"type\":\"out\", \"error\":\"" } + e.what() +
						std::string { ", \"error_code\":\"" } + std::to_string(script_err / 256) + "\"" +
						std::string { ", \"script_stdout\":\"" } + escaped_stdout + "\"" +
						std::string { ", \"script_stderr\":\"" } + script_stderr + "\"" +
					"}";
				proxy_error(
					"Error parsing script output from script: '%s'\n- script_stdout:\n'''\n%s'''\n",
					script.c_str(),
					script_stdout.c_str()
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
		std::stringstream ss;
		ss << "{\"error\":\"HTTP method " << req.get_method().c_str() << " is not implemented\"}";

        auto response = std::shared_ptr<http_response>(new string_response(ss.str().c_str()));
        response->with_header("Content-Type", "application/json");
        response->with_header("Access-Control-Allow-Origin", "*");
        return response;
    }

	const std::shared_ptr<http_response> render_GET(const http_request& req) {
		auto args = req.get_args();

		size_t last = 0;
		std::stringstream params;
		params << "{";
		for (auto arg : args) {
			params << "\"" << arg.first << "\":\"" << arg.second << "\"";
			if (last < args.size()-1) {
				params << ",";
				last++;
			}
		}
		params << "}";

		return process_request(req, params.str());
	}

	const std::shared_ptr<http_response> render_POST(const http_request& req) {
		std::string params=req.get_content();
		return process_request(req, params);
	}

};

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
	ws = std::unique_ptr<httpserver::webserver>(new webserver(create_webserver(p)));
	// NOTE: Enable for benchmarking purposes. In this mode each request will be served by it's own thread.
	// ws = std::unique_ptr<httpserver::webserver>(new webserver(create_webserver(p).start_method(http::http_utils::start_method_T::THREAD_PER_CONNECTION)));
	auto sr = new sync_resource();

	endpoint = std::unique_ptr<httpserver::http_resource>(sr);

    ws->register_resource("/sync", endpoint.get(), true);
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

