#include <chrono>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <sys/resource.h>
#include <unistd.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include "mysql.h"
#include "json.hpp"

using std::map;
using std::pair;
using std::string;
using std::vector;

using nlohmann::json;

#define TAP_NAME "TAP_THREAD_CONN_DIST___"

const int TEST_DURATION_SEC = get_env_int(TAP_NAME"TEST_DURATION_SEC", 20);
const int ITER_CONN_COUNT = get_env_int(TAP_NAME"ITER_CONN_COUNT", 256);

void incr_proc_limits(uint32_t MAX_CONN_COUNT) {
	diag("Elevating process limits if required for conns creation");

	struct rlimit limits { 0, 0 };
	getrlimit(RLIMIT_NOFILE, &limits);
	diag("Old process limits   rlim_cur=%ld rlim_max=%ld", limits.rlim_cur, limits.rlim_max);

	if (limits.rlim_cur < MAX_CONN_COUNT * 2) {
		diag("Updating process max FD limit");
		limits.rlim_cur = MAX_CONN_COUNT * 2;
		setrlimit(RLIMIT_NOFILE, &limits);
	}

	diag("New process limits   rlim_cur=%ld rlim_max=%ld", limits.rlim_cur, limits.rlim_max);
}

pair<uint32_t,vector<MYSQL*>> create_frontend_conns(CommandLine& cl, uint32_t CONNS_TOTAL) {
	vector<MYSQL*> conns {};

	for (int i = 0; i < CONNS_TOTAL; i++) {
		MYSQL* myconn = mysql_init(NULL);

		if (!mysql_real_connect(myconn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			diag(
				"Failed to connect   addr=%s port=%d user=%s pass=%s err=%s",
				cl.host, cl.port, cl.username, cl.password, mysql_error(myconn)
			);
			return { EXIT_FAILURE, {} };
		}

		conns.push_back(myconn);
	}

	return { EXIT_SUCCESS, conns };
}

void check_thread_conn_dist(const map<string,vector<MYSQL*>>& m_thread_conns) {
	size_t lo_count = 0;
	size_t hg_count = 0;

	diag("Dumping per-thread conn count:");
	for (const pair<string,vector<MYSQL*>>& thread_conns : m_thread_conns) {
		if (lo_count == 0 || thread_conns.second.size() < lo_count) {
			lo_count = thread_conns.second.size();
		}
		if (hg_count == 0 || thread_conns.second.size() > hg_count) {
			hg_count = thread_conns.second.size();
		}
		fprintf(stderr, "Map entry   thread=%s count=%ld\n", thread_conns.first.c_str(), thread_conns.second.size());
	}

	ok(
		hg_count / 2 < lo_count,
		"Half the highest conn count shouldn't be higher than lowest conn count"
		"   hg_count=%ld lo_count=%ld",
		hg_count, lo_count
	);
}

void update_conn_thread_map(vector<MYSQL*>& conns, map<string,vector<MYSQL*>>& m_thread_conns) {
	for (MYSQL* myconn : conns) {
		json j_session = fetch_internal_session(myconn, false);
		string thread_addr { j_session["thread"] };

		m_thread_conns[thread_addr].push_back(myconn);
	}
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(1);

	auto start = std::chrono::system_clock::now();
	std::chrono::duration<double> elapsed {};

	incr_proc_limits(ITER_CONN_COUNT);

	map<string,vector<MYSQL*>> m_thread_conns {};

	while (elapsed.count() < TEST_DURATION_SEC) {
		pair<uint32_t,vector<MYSQL*>> p_err_conns { create_frontend_conns(cl, ITER_CONN_COUNT) };
		if (p_err_conns.first) {
			diag("Frontend conn creation failed; aborting further testing   err=%d", p_err_conns.first);
			return EXIT_FAILURE;
		}

		update_conn_thread_map(p_err_conns.second, m_thread_conns);

		for (MYSQL* conn : p_err_conns.second) {
			mysql_close(conn);
		}

		auto it_end = std::chrono::system_clock::now();
		elapsed = it_end - start;
	}

	check_thread_conn_dist(m_thread_conns);
}
