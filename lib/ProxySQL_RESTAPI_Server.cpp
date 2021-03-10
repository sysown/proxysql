#include "proxysql.h"
#include "cpp.h"
#include "httpserver.hpp"

#include <functional>
#include <fcntl.h>
#include <sstream>
#include <sys/time.h>


#include "ProxySQL_RESTAPI_Server.hpp"
using namespace httpserver;


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_RESTAPI_SERVER_VERSION "2.0.1121" DEB

extern ProxySQL_Admin *GloAdmin;

/**
 * @brief Kills the given process sending an initial 'SIGTERM' to it. If the process doesn't
 *   respond within 'timeout_us' to the initial signal a 'SIGKILL' is issued to it.
 *
 * @param child_pid The process pid to be terminated.
 * @param timeout_us The timeout to be waited after sending the initial 'SIGTERM' before
 *   signaling the process with SIGKILL.
 * @param it_sleep_us The microseconds to sleep while waiting for the process to terminate.
 *
 * @return The error returned by 'kill' in case of it failing.
 */
int kill_child_proc(pid_t child_pid, const uint timeout_us, const uint it_sleep_us) {
	uint err = 0;
	uint waited = 0;
	int child_status = 0;

	err = kill(child_pid, SIGTERM);

	while (waitpid(child_pid, &child_status, WNOHANG) == 0) {
		if (waited >= timeout_us) {
			kill(child_pid, SIGKILL);
			waited = 0;
		} else {
			waited += it_sleep_us;
		}

		usleep(it_sleep_us);
	}

	return err;
}

/**
 * @brief Read the contents of the pipe, appending the result to supplied the supplied
 *   'std::string' till 'read()' returns '0' or error.
 *
 * @param pipe_fd The file descriptor from which to read.
 * @param sbuffer An 'std::string' in which to append the data readed from the pipe.
 *
 * @return '0' if all the contents of the pipe were read properly, otherwise '-1' is
 *   returned and 'errno' holds the error code for the failed 'read()'.
 */
int read_pipe(int pipe_fd, std::string& sbuffer) {
	char buffer[128];
	ssize_t count = 0;
	int res = 1;

	for (;;) {
		count = read(pipe_fd, (void*)buffer, sizeof(buffer) - 1);
		if (count > 0) {
		buffer[count] = 0;
			sbuffer += buffer;
		} else if (count == 0){
			res = 0;
			break;
		} else {
			if (errno != EWOULDBLOCK && errno != EINTR) {
				res = -1;
			}
			break;
		}
	}

	return res;
}

/**
 * @brief Returns the current timestamp in microseconds.
 * @return The current timestamp in microseconds.
 */
uint64_t get_timestamp_us() {
	struct timeval start_tv {};
	gettimeofday(&start_tv, nullptr);
	uint64_t start_timestamp = (1000000ull * start_tv.tv_sec) + start_tv.tv_usec;

	return start_timestamp;
}

/**
 * @brief Simple struct that holds the 'timeout options' for 'wexecvp'.
 */
struct to_opts {
	/**
	 * @brief Timeout for the script execution to be completed, in case of being
	 *   exceeded, the script will be terminated.
	 */
	uint timeout_us;
	/**
	 * @brief Timeout used for 'select()' non blocking calls.
	 */
	uint select_to_us;
	/**
	 * @brief The duration of the sleeps between the checks being performed
	 *   on the child process waiting it to exit after being signaled to terminate,
	 *   before issuing 'SIGKILL'.
	 */
	uint it_delay_us;
	/**
	 * @brief The timeout to be waited on the child process after being signaled
	 *   with 'SIGTERM' before being forcely terminated by 'SIGKILL'.
	 */
	uint sigkill_timeout_us;
};

/**
 * @brief Helper function to launch an executable in a child process through 'fork()' and
 *   'execvp()' and retrieve their 'stderr' and 'stdout' to the caller toguether with
 *   the result of it's execution.
 *
 * @param file The file to be executed.
 * @param argv The arguments to be supplied to the file being executed.
 * @param opts Struct holding timeout options to consider for the launched process.
 * @param s_stdout Output string to hold the output 'stdout' of the child process.
 * @param s_stderr Output string to hold the output 'stderr' of the child process.
 *
 * @return 0 In case of success or one of the following error codes:
 *   - '-1' in case any 'pipe()' creation failed.
 *   - '-2' in case 'fork()' call failed.
 *   - '-3' in case 'fcntl()' call failed .
 *   - '-4' in case of resource exhaustion, file descriptors being used exceeds 'FD_SETSIZE'.
 *   - '-5' in case 'select()' call failed.
 *   - '-6' in case 'read()' from pipes failed with a non-expected error.
 *   - 'ETIME' in case the executable has exceeded the timeout supplied in 'opts.timeout_us'.
 *  In all this cases 'errno' is set to the error reported by the failing 'system call'.
 */
int wexecvp(
	const std::string& file,
	const std::vector<const char*>& argv,
	const to_opts* opts,
	std::string& s_stdout,
	std::string& s_stderr
) {
	// Pipes definition
	constexpr uint8_t NUM_PIPES = 3;
	constexpr uint8_t PARENT_WRITE_PIPE = 0;
	constexpr uint8_t PARENT_READ_PIPE  = 1;
	constexpr uint8_t PARENT_ERR_PIPE   = 2;
	int pipes[NUM_PIPES][2];
	// Pipe selection
	constexpr uint8_t READ_FD  = 0;
	constexpr uint8_t WRITE_FD = 1;
	// Parent pipes
	const auto& PARENT_READ_FD  = pipes[PARENT_READ_PIPE][READ_FD];
	const auto& PARENT_READ_ERR = pipes[PARENT_ERR_PIPE][READ_FD];
	const auto& PARENT_WRITE_FD = pipes[PARENT_WRITE_PIPE][WRITE_FD];
	// Child pipes
	const auto& CHILD_READ_FD   = pipes[PARENT_WRITE_PIPE][READ_FD];
	const auto& CHILD_WRITE_FD  = pipes[PARENT_READ_PIPE][WRITE_FD];
	const auto& CHILD_WRITE_ERR = pipes[PARENT_ERR_PIPE][WRITE_FD];

	int err = 0;
	to_opts to_opts { 0, 100*1000, 500*1000, 2000*1000 };

	if (opts) {
		to_opts.timeout_us = opts->timeout_us;
		to_opts.it_delay_us = opts->it_delay_us;
		to_opts.select_to_us = opts->select_to_us;
		to_opts.sigkill_timeout_us = opts->sigkill_timeout_us;
	}

	// Pipes for parent to write and read
	int read_p_err = pipe(pipes[PARENT_READ_PIPE]);
	int write_p_err = pipe(pipes[PARENT_WRITE_PIPE]);
	int err_p_err = pipe(pipes[PARENT_ERR_PIPE]);

	if (read_p_err || write_p_err || err_p_err) {
		return -1;
	}

	pid_t child_pid = fork();
	if (child_pid == -1) {
		return -2;
	}

	if(child_pid == 0) {
		int child_err = 0;
		std::vector<const char*> _argv = argv;

		// Append null to end of _argv for extra safety
		_argv.push_back(nullptr);
		// Duplicate file argument to avoid manual duplication
		_argv.insert(_argv.begin(), file.c_str());

		// Copy the pipe descriptors
		int dup_read_err = dup2(CHILD_READ_FD, STDIN_FILENO);
		int dup_write_err = dup2(CHILD_WRITE_FD, STDOUT_FILENO);
		int dup_err_err = dup2(CHILD_WRITE_ERR, STDERR_FILENO);

		if (dup_read_err == -1 || dup_write_err == -1 || dup_err_err == -1) {
			exit(errno);
		}

		// Close no longer needed pipes
		close(CHILD_READ_FD);
		close(CHILD_WRITE_FD);
		close(CHILD_WRITE_ERR);

		close(PARENT_READ_FD);
		close(PARENT_READ_ERR);
		close(PARENT_WRITE_FD);

		char** args = const_cast<char**>(_argv.data());
		child_err = execvp(file.c_str(), args);

		if (child_err) {
			exit(errno);
		} else {
			exit(0);
		}
	} else {
		int errno_cpy = 0;
		int pipe_err = 0;

		std::string stdout_ = "";
		std::string stderr_ = "";

		// Close no longer needed pipes
		close(CHILD_READ_FD);
		close(CHILD_WRITE_FD);
		close(CHILD_WRITE_ERR);

		// Set the pipes in non-blocking mode
		int cntl_non_err = fcntl(PARENT_READ_FD, F_SETFL, fcntl(PARENT_READ_FD, F_GETFL) | O_NONBLOCK);
		int cntl_err_err = fcntl(PARENT_READ_ERR, F_SETFL, fcntl(PARENT_READ_ERR, F_GETFL) | O_NONBLOCK);

		fd_set read_fds;
		int maxfd = PARENT_READ_FD > PARENT_READ_ERR ? PARENT_READ_FD : PARENT_READ_ERR;

		bool stdout_eof = false;
		bool stderr_eof = false;

		// Record the start timestamp
		uint64_t start_timestamp = get_timestamp_us();

		if ((cntl_err_err || cntl_non_err) || maxfd >= FD_SETSIZE) {
			close(PARENT_READ_FD);
			close(PARENT_READ_ERR);
			close(PARENT_WRITE_FD);

			if (cntl_err_err || cntl_non_err) {
				pipe_err = -3;
			} else {
				pipe_err = -4;
			}

			// Kill child and return error
			kill_child_proc(child_pid, to_opts.sigkill_timeout_us, to_opts.it_delay_us);
			// Recover errno before return
			errno = errno_cpy;
			// Avoid loop
			goto loop_exit;
		}

		while (!stdout_eof || !stderr_eof) {
			FD_ZERO(&read_fds);
			FD_SET(PARENT_READ_FD, &read_fds);
			FD_SET(PARENT_READ_ERR, &read_fds);

			// Wait for the pipes to be ready
			timeval select_to = { 0, to_opts.select_to_us };
			int select_err = select(maxfd + 1, &read_fds, NULL, NULL, &select_to);

			// Unexpected error while executing 'select'
			if (select_err < 0) {
				pipe_err = -5;
				// Backup read errno
				errno_cpy = errno;
				// Kill child and return error
				kill_child_proc(child_pid, to_opts.sigkill_timeout_us, to_opts.it_delay_us);
				// Recover errno before return
				errno = errno_cpy;
				// Exit the loop
				break;
			}

			if (FD_ISSET(PARENT_READ_FD, &read_fds) && stdout_eof == false) {
				int read_res = read_pipe(PARENT_READ_FD, stdout_);

				if (read_res == 0) {
					stdout_eof = true;
				}
				// Unexpected error while reading pipe
				if (read_res < 0) {
					pipe_err = -6;
					// Backup read errno
					errno_cpy = errno;
					// Kill child and return error
					kill_child_proc(child_pid, to_opts.sigkill_timeout_us, to_opts.it_delay_us);
					// Recover errno before return
					errno = errno_cpy;
					// Exit the loop
					break;
				}
			}

			if(FD_ISSET(PARENT_READ_ERR, &read_fds) && stderr_eof == false) {
				int read_res = read_pipe(PARENT_READ_ERR, stderr_);

				if (read_res == 0) {
					stderr_eof = true;
				}
				// Unexpected error while reading pipe
				if (read_res < 0) {
					pipe_err = -6;
					// Backup read errno
					errno_cpy = errno;
					// Kill child and return error
					kill_child_proc(child_pid, to_opts.sigkill_timeout_us, to_opts.it_delay_us);
					// Recover errno before return
					errno = errno_cpy;
					// Exit the loop
					break;
				}
			}

			// Check that the execution hasn't execeed the specified timeout
			if (to_opts.timeout_us != 0) {
				uint64_t current_timestamp = get_timestamp_us();
				if ((start_timestamp + to_opts.timeout_us) < current_timestamp) {
					// Backup read errno
					errno_cpy = errno;
					kill_child_proc(child_pid, to_opts.sigkill_timeout_us, to_opts.it_delay_us);
					// Recover errno before return
					errno = errno_cpy;
					// Set 'pipe_err' to 'ETIME' to reflect timeout
					pipe_err = ETIME;
					// Exit the loop
					break;
				}
			}
		}

loop_exit:

		// Close no longer needed pipes
		close(PARENT_READ_FD);
		close(PARENT_READ_ERR);
		close(PARENT_WRITE_FD);

		if (pipe_err == 0) {
			waitpid(child_pid, &err, 0);
		}

		if (pipe_err == 0) {
			s_stdout = stdout_;
			s_stderr = stderr_;
		} else {
			err = pipe_err;
		}
	}

	return err;
}

/**
 * @brief Helper function to replace all the occurrences in a string of a matching substring in favor
 *   of another string.
 *
 * @param str The string which copy is going to be searched for matches to be replaced.
 * @param match The substring to be matched inside the string.
 * @param repl The string for which matches are going to be replaced.
 *
 * @return A string in which all the matches of 'match' within 'str' has been replaced by 'repl'.
 */
std::string replace_str(const std::string& str, const std::string& match, const std::string& repl) {
	if(match.empty()) {
		return str;
	}

	std::string result = str;
	size_t start_pos = 0;

	while((start_pos = result.find(match, start_pos)) != std::string::npos) {
		result.replace(start_pos, match.length(), repl);
		start_pos += repl.length();
	}

	return result;
}

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
			} else {
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
	ws = std::unique_ptr<httpserver::webserver>(new webserver(create_webserver(p)));
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

