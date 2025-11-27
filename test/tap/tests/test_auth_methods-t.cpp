/**
 * @file test_auth_methods-t.cpp
 * @brief Tests the different authentications methods supported by ProxySQL.
 * @details The exhaust all possible combinations of the following supported auths:
 *
 *  - 'clear_text_pass'
 *  - 'mysql_native_password'
 *  - 'caching_sha2_password'
 *
 * Checks take into account the following potential scenarios:
 *
 *  - Check for invalid passwords/users auth attempts.
 *  - Check of correcteness for:
 *      - Supported combinations of 'default_auth', 'requested_auth' and 'stored_pass'.
 *      - Number of auth switchs requested by ProxySQL.
 *      - Number of 'caching_sha2_password' full auths requested by ProxySQL.
 *  - Check for expected failures in concurrent conns to non-warmup ProxySQL (no cached clear_text_pass).
 *  - Check for expected successes in concurrent conns to non-warmup ProxySQL (no cached clear_text_pass).
 *  - Check for correct concurrent clear_text_pass caching ('caching_sha2_password').
 */

#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <sys/stat.h>
#include <utility>
#include <vector>
#include <string>
#include <stdio.h>
#include <thread>
#include <unistd.h>

#include "openssl/types.h"
#include "json.hpp"
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "utils_auth.h"

// Additional env variables
uint32_t MYSQL8_HG = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);
uint32_t NUM_CLIENT_THREADS = get_env_int("TAP_NUM_CLIENT_THREADS", 4);

using std::pair;
using std::string;
using std::vector;
using std::function;
using std::unique_ptr;

#define MYSQL_QUERY_T__(mysql, query) \
	do { \
		if (mysql_query_t(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql)); \
			return { EXIT_FAILURE, vector<user_creds_t> {} }; \
		} \
	} while(0)

#define MYSQL_QUERY_T_(mysql, query) \
	do { \
		if (mysql_query_t(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql)); \
			return { EXIT_FAILURE, user_def_t {} }; \
		} \
	} while(0)

/**
 * @brief TODO: Currently unused; move to utilities.
 */
string my_escape_string(MYSQL* mysql, const string& q) {
	size_t size = q.size();

	if (size <= 0) {
		return {};
	} else {
		std::unique_ptr<char[]> buf(new char[size * 2 + 1]);
		int res = mysql_real_escape_string(mysql, buf.get(), q.c_str(), q.size());
		return string(buf.get(), buf.get() + res);
	}
}

struct user_auth_stats_t {
	user_def_t user_def;
	uint64_t prim_pass_auths;
	uint64_t addl_pass_auths;
	uint64_t full_sha2_auths;
};

using auth_reg_t = std::unordered_map<string, user_auth_stats_t>;

/**
 * @brief Extracts a nested JSON element from the supplied path.
 * @param j The JSON from which to extract the element.
 * @param p The path in which the element should be found.
 * @return Pointer to the JSON element if found, 'nullptr' otherwise.
 */
const nlohmann::json* get_nested_elem(const nlohmann::json& j, const vector<string>& p) {
	if (j.is_discarded()) { return nullptr; }
	const nlohmann::json* next_step = &j;

	for (const auto& e : p) {
		 if (next_step->contains(e)) {
			  next_step = &next_step->at(e);
		 } else {
			  next_step = nullptr;
			  break;
		 }
	}

	return next_step;
}

struct sess_info_t {
	int sent_pkts;
	int recv_pkts;
	int switching_auth_sent;
	int full_sha2_auth;
};

sess_info_t ext_sess_info(MYSQL* proxy) {
	sess_info_t sess_info { -3, -3, -3 };
	nlohmann::json session { fetch_internal_session(proxy) };

	if (session.is_array() && !session.empty()) {
		session = session[0];

		sess_info.switching_auth_sent = get_nested_elem_val(session, {"client", "switching_auth_sent"}, -3);
		sess_info.recv_pkts = get_nested_elem_val(session, {"client", "stream", "pkts_recv"}, -3);
		sess_info.sent_pkts = get_nested_elem_val(session, {"client", "stream", "pkts_sent"}, -3);
	}

	return sess_info;
}

auth_reg_t create_auth_reg(const vector<user_creds_t>& users_creds) {
	auth_reg_t auth_reg {};

	for (const user_creds_t& creds : users_creds) {
		auth_reg.insert({ creds.user_def.name, { creds.user_def, 0, 0, 0 } });
	}

	return auth_reg;
}

using chk_exp_scs_t = function<bool(const test_conf_t&, const test_creds_t&)>;
using chk_exp_seq_scs_t = function<bool(const test_conf_t&, const test_creds_t&, const user_auth_stats_t&)>;

FILE* F_SSLKEYLOGFILE = nullptr;

void ssl_keylog_callback(SSL*, const char* line) {
	if (!F_SSLKEYLOGFILE) { return; }

	if (strlen(line) != 0) {
		fprintf(F_SSLKEYLOGFILE, "%s\n", line);
	}
}

string to_string(const sess_info_t& sess) {
	return "{ "
		"\"recv_pkts\":'" + std::to_string(sess.recv_pkts) + "', "
		"\"sent_pkts\":'" + std::to_string(sess.sent_pkts) + "', "
		"\"auth_switch_sent\":'" + std::to_string(sess.switching_auth_sent)  + "'"
	" }";
}

string to_string(const user_auth_stats_t& stats) {
	return "{ "
		"\"prim_pass_auths\":'" + std::to_string(stats.prim_pass_auths) + "', "
		"\"addl_pass_auths\":'" + std::to_string(stats.addl_pass_auths) + "', "
		"\"full_sha2_auths\":'" + std::to_string(stats.full_sha2_auths) +
	" }";
}

bool match_pass(const char* p1, const char* p2) {
	if (is_empty_pass(p1) && is_empty_pass(p2)) {
		return true;
	} else if (!is_empty_pass(p1) && !is_empty_pass(p2)) {
		return strcmp(p1, p2) == 0;
	} else {
		return false;
	}
}

PASS_TYPE::E get_matching_pass(const user_creds_t& creds, const char* p) {
	const char* prim_pass { creds.user_def.prim_pass.get() };
	const char* addl_pass { creds.user_def.addl_pass.get() };

	if (match_pass(prim_pass, p)) {
		return PASS_TYPE::PRIMARY;
	} else if (match_pass(addl_pass, p)) {
		// This is an impossible scenario for MySQL passwords; we exclude it in this section of the test.
		// Configuration should have enforced empty 'primary' and 'additional' passwords.
		if (is_empty_pass(prim_pass) && !is_empty_pass(addl_pass)) {
			return PASS_TYPE::UNKNOWN;
		} else {
			return PASS_TYPE::ADDITIONAL;
		}
	} else {
		return PASS_TYPE::UNKNOWN;
	}
}

test_creds_t map_user_creds(const vector<user_creds_t>& users_creds, const test_creds_t& test_creds) {
	const auto& creds_it {
		std::find_if(users_creds.begin(), users_creds.end(),
			[&test_creds] (const user_creds_t& creds) -> bool {
				return creds.user_def.name == test_creds.name;
			}
		)
	};

	// cover the possibility for unknown users to be tested
	if (creds_it == std::end(users_creds)) {
		test_creds_t new_creds { test_creds };
		new_creds.info.type = PASS_TYPE::UNKNOWN;
		new_creds.info.auth = {};

		return new_creds;
	} else {
		test_creds_t new_creds { test_creds };
		new_creds.info.auth = creds_it->user_def.auth;
		new_creds.info.type = get_matching_pass(*creds_it, test_creds.pass.get());

		return new_creds;
	}
}

bool chk_exp_scs_basic(const test_conf_t& conf, const test_creds_t& creds) {
	if (creds.info.type == PASS_TYPE::PRIMARY) {
		// empty passwords allowed for 'primary'
		if (!creds.pass || (creds.pass && strlen(creds.pass.get()) == 0)) {
			return true;
		}
	} else {
		// empty passwords not allowed for 'additional'
		if (!creds.pass || (creds.pass && strlen(creds.pass.get()) == 0)) {
			return false;
		}
	}

	// unknown passtype implies invalids creds; always a failure
	if (creds.info.type == PASS_TYPE::UNKNOWN) {
		return false;
	} else {
		return true;
	}
}

bool chk_exp_seq_fail_except(
	const test_conf_t& conf,
	const test_creds_t& creds,
	const user_auth_stats_t& auth_info
) {
	// Short circuit for empty pass; no exceptional failures
	if (is_empty_pass(creds.pass.get())) {
		return false;
	}

	// TODO: MAKE EXPLICIT TEST
	//
	// 'caching_sha2_password' auth should fail for NON-SSL if no previous scs auth:
	//  - No clear_text pass on ProxySQL side
	//  - Full authentication is required
	if (!conf.use_ssl && conf.hashed_pass && creds.info.auth == "caching_sha2_password") {
		if (creds.info.type == PASS_TYPE::PRIMARY) {
			return auth_info.prim_pass_auths == 0;
		} else {
			return auth_info.addl_pass_auths == 0;
		}
	}
	// TODO: MAKE EXPLICIT TEST
	//
	// Auth method requested by ProxySQL will be 'caching_sha2_password'; if the 'clear_text_pass'
	// is unknown, we are forced to request it from client, so a secure channel is needed. ProxySQL
	// doesn't infer that the credentials stored are SHA1, otherwise, could avoid SHA2 full-auth.
	if (
		!conf.use_ssl && conf.hashed_pass && creds.info.auth == "mysql_native_password"
		&& conf.req_auth == "caching_sha2_password" && conf.def_auth == "caching_sha2_password"
	) {
		if (creds.info.type == PASS_TYPE::PRIMARY) {
			return auth_info.prim_pass_auths == 0;
		} else {
			return auth_info.addl_pass_auths == 0;
		}
	}
	// TODO: MAKE EXPLICIT TEST
	//
	// Since the 'req_auth' is not "caching_sha2_password"; but pass is stored as SHA2 ProxySQL
	// will be forced to request an auth-switch to the user; and then proceed with caching_sha2
	// full auth; this is currently unsupported.
	if (
		conf.use_ssl && conf.hashed_pass && creds.info.auth == "caching_sha2_password"
		&& conf.req_auth != "caching_sha2_password"
	) {
		if (creds.info.type == PASS_TYPE::PRIMARY) {
			return auth_info.prim_pass_auths == 0;
		} else {
			return auth_info.addl_pass_auths == 0;
		}
	}
	// TODO: MAKE EXPLICIT TEST
	//
	// Since the pass store as SHA2, the clear-text is required, instead of initiating full-auth
	// ProxySQL requests an auth switch to the client to 'mysql_native_password'. After the switch
	// auth response, ProxySQL wont be able to verify the request, and auth will fail.
	if (
		conf.use_ssl && conf.hashed_pass && creds.info.auth == "caching_sha2_password"
		&& conf.req_auth == "caching_sha2_password" && conf.def_auth != "caching_sha2_password"
	) {
		if (creds.info.type == PASS_TYPE::PRIMARY) {
			return auth_info.prim_pass_auths == 0;
		} else {
			return auth_info.addl_pass_auths == 0;
		}
	}

	return false;
}

bool chk_seq_exp_scs(const test_conf_t& conf, const test_creds_t& creds, const user_auth_stats_t& auth_info) {
	return chk_exp_scs_basic(conf, creds) && !chk_exp_seq_fail_except(conf, creds, auth_info);
}

bool chk_exp_auth_switch(const test_conf_t& conf, const test_creds_t& creds) {
	return
		// TODO: Limitation; for empty passwords ProxySQL asks auth_switch
		// !is_empty_pass(creds.pass) &&
		conf.hashed_pass &&
		conf.req_auth != conf.def_auth &&
		conf.req_auth != creds.info.auth &&
		conf.req_auth != "mysql_clear_password";
}

string map_auth_switch(int64_t auth_switch) {
	if (auth_switch == 0) {
		return "mysql_native_password";
	} else if (auth_switch == 1) {
		return "mysql_clear_password";
	} else if (auth_switch == 2) {
		return "caching_sha2_password";
	} else {
		return "unknown_plugin";
	}
}

string get_exp_auth_switch(const test_conf_t& conf, const test_creds_t& creds, const sess_info_t& sess_info) {
	string exp_auth_switch_type {};

	if (chk_exp_auth_switch(conf, creds)) {
		// TODO: Limitation; for empty passwords ProxySQL asks auth_switch
		if (is_empty_pass(creds.pass.get())) {
			exp_auth_switch_type = "mysql_native_password";
		} else {
			exp_auth_switch_type = conf.def_auth;
		}
	} else {
		// TODO: Limitation; for empty passwords ProxySQL asks auth_switch
		if (
			is_empty_pass(creds.pass.get()) && conf.req_auth != conf.def_auth
			&& conf.req_auth != "mysql_clear_password"
		) {
			exp_auth_switch_type = "mysql_native_password";
		}
		// TODO: Limitation; ProxySQL asks for futile auth-switch. Example case:
		//  - creds:`{ "name":'dualpass9', "pass":'newpass9', "type":'PRIM' }`
		//  - conf:`{ "req_auth":'mysql_native_password', "def_auth":'caching_sha2_password', "hashed_pass":'1'"use_ssl":'0' }`
		//
		//  ProxySQL asks for a auth-switch to "mysql_native_password"; even if client requested.
		//  Then accepts the auth attempt with the auth-switch-response.
		else if (
			conf.hashed_pass && creds.info.auth == "mysql_native_password" &&
			conf.req_auth == "mysql_native_password" && conf.def_auth == "caching_sha2_password"
		) {
			exp_auth_switch_type = "mysql_native_password";
		}
		// TODO: Limitation; ProxySQL asks for futile auth-switch; password is 'clear_text'
		else if (
			(conf.req_auth == "mysql_native_password" && conf.def_auth == "caching_sha2_password") ||
			(conf.req_auth == "caching_sha2_password" && conf.def_auth == "mysql_native_password")
		) {
			exp_auth_switch_type = "mysql_native_password";
		} else {
			exp_auth_switch_type = "unknown_plugin";
		}
	}

	return exp_auth_switch_type;
}

bool detect_sha2_cached_auth(const sess_info_t& sess_info) {
	return
		sess_info.switching_auth_sent == -1 &&
		sess_info.recv_pkts == 4 && sess_info.sent_pkts == 3;
}

bool detect_sha2_full_auth(const sess_info_t& sess_info) {
	return
		sess_info.switching_auth_sent == -1 &&
		sess_info.recv_pkts == 4 && sess_info.sent_pkts == 3;
}

bool chk_exp_sha2_full_auth(
	const test_conf_t& conf, const test_creds_t& creds, const user_auth_stats_t& auth_info
) {
	// TODO: ProxySQL requires a full-auth everytime a dual-password is used. This is a limitation
	// on the current auth state-machine. This should be fixed in the next auth-rework. The
	// following code will be obsolete when this is implemented.
	///////////////////////////////////////////////////////////////////////////
	if (
		creds.info.type == PASS_TYPE::ADDITIONAL
		&& conf.req_auth == "caching_sha2_password"
		&& conf.def_auth == "caching_sha2_password"
		&& conf.hashed_pass == true
	) {
		diag("TODO-WARNING: The following check will FAKE pass - This limitation should be fixed");
		return true;
	}
	///////////////////////////////////////////////////////////////////////////

	if (!is_empty_pass(creds.pass.get()) && conf.hashed_pass && creds.info.auth == "caching_sha2_password") {
		if (creds.info.type == PASS_TYPE::PRIMARY) {
			return auth_info.prim_pass_auths == 0;
		} else {
			return auth_info.addl_pass_auths == 0;
		}
	}
	// TODO: MAKE EXPLICIT TEST
	//
	// ProxySQL fails to detect that the stored password is 'mysql_native_password';
	// instead of requesting the consequent auth switch, the clear_text password is required, so
	// full auth is requested.
	else if (
		!is_empty_pass(creds.pass.get()) && conf.hashed_pass &&
		conf.def_auth == "caching_sha2_password" &&
		conf.req_auth == "caching_sha2_password" &&
		creds.info.auth == "mysql_native_password"
	) {
		if (creds.info.type == PASS_TYPE::PRIMARY) {
			return auth_info.prim_pass_auths == 0;
		} else {
			return auth_info.addl_pass_auths == 0;
		}
	} else {
		return false;
	}
}

bool chk_exp_fail_except_no_warmup(const test_conf_t& conf, const test_creds_t& creds) {
	return chk_exp_seq_fail_except(conf, creds, user_auth_stats_t { {}, 0, 0 });
}

bool chk_exp_fail_no_warmup(const test_conf_t& conf, const test_creds_t& creds) {
	return !chk_exp_scs_basic(conf, creds) || chk_exp_fail_except_no_warmup(conf, creds);
}

bool chk_exp_scs_no_warmup(const test_conf_t& conf, const test_creds_t& creds) {
	return chk_exp_scs_basic(conf, creds) && !chk_exp_fail_except_no_warmup(conf, creds);
}

user_auth_stats_t update_auth_reg(MYSQL* mysql, const string& user, const char* pass, auth_reg_t& auth_reg) {
	user_auth_stats_t auth_info {};

	if (mysql) {
		auto it = auth_reg.find(user);

		if (it == auth_reg.end()) {
			std::cerr << "AuthRegistry; invalid user missing entry   user:'" << user << "'\n";
			auth_reg.insert({ user, {} });
		} else {
			auth_info = it->second;

			const char* user_prim_pass { it->second.user_def.prim_pass.get() };
			const char* user_addl_pass { it->second.user_def.addl_pass.get() };

			const char* def_auth { nullptr };
			mysql_get_option(mysql, MYSQL_DEFAULT_AUTH, &def_auth);

			if (def_auth && strcmp(def_auth, "caching_sha2_password") == 0) {
				if (is_empty_pass(pass) && is_empty_pass(user_prim_pass)) {
					it->second.prim_pass_auths += 1;
				} else if (is_empty_pass(pass) && is_empty_pass(user_addl_pass)) {
					it->second.addl_pass_auths += 1;
				} else if (pass && user_prim_pass && (strcmp(pass, user_prim_pass) == 0)) {
					it->second.prim_pass_auths += 1;
				} else if (pass && user_addl_pass && (strcmp(pass, user_addl_pass) == 0)) {
					it->second.addl_pass_auths += 1;
				} else {
					diag("WARNING: Auth worked using invalid password, failure expected");
				}
			}
		}
	}

	return auth_info;
}

pair<uint64_t,uint64_t> count_exp_scs(
	const vector<test_conf_t>& confs,
	const vector<user_creds_t>& user_creds,
	const vector<test_creds_t>& test_creds
) {
	pair<uint64_t,uint64_t> stats {};

	for (const test_conf_t& conf : confs) {
		auth_reg_t auth_reg { create_auth_reg(user_creds) };

		for (const test_creds_t& creds : test_creds) {
			test_creds_t f_creds { map_user_creds(user_creds, creds) };

			auto it = auth_reg.find(creds.name);
			if (it == auth_reg.end()) {
				std::cerr << "Testing invalid user for failure   user:'" << creds.name << "'\n";
				stats.second += 1;

				continue;
			}

			bool exp_scs = chk_seq_exp_scs(conf, f_creds, it->second);

			if (exp_scs) {
				MYSQL* mock = mysql_init(NULL);
				mysql_options(mock, MYSQL_DEFAULT_AUTH, conf.req_auth.c_str());
				update_auth_reg(mock, creds.name, creds.pass.get(), auth_reg);
				mysql_close(mock);

				stats.first += 1;
			} else {
				stats.second += 1;
			}
		}
	}

	return stats;
}

int config_mysql_conn(const CommandLine& cl, const test_conf_t& conf, MYSQL* proxy) {
	unsigned long cflags = 0;
	mysql_options(proxy, MYSQL_DEFAULT_AUTH, conf.req_auth.c_str());

	if (conf.req_auth == "mysql_clear_password") {
		bool enable_cleartext = true;
		mysql_options(proxy, MYSQL_ENABLE_CLEARTEXT_PLUGIN, &enable_cleartext);
	}

	if (conf.use_ssl) {
		mysql_ssl_set(proxy, NULL, NULL, NULL, NULL, NULL);
		cflags |= CLIENT_SSL;

		if (getenv("SSLKEYLOGFILE") && F_SSLKEYLOGFILE) {
			mysql_options(proxy, MARIADB_OPT_SSL_KEYLOG_CALLBACK, reinterpret_cast<void*>(ssl_keylog_callback));
		}
	}

	if (conf.use_comp) {
		cflags |= CLIENT_COMPRESS;
	}

	return cflags;
}

void test_creds_frontend_backend(
	const CommandLine& cl, const test_conf_t& conf, const test_creds_t& creds, auth_reg_t& auth_reg
) {
	MYSQL* proxy = mysql_init(NULL);
	int cflags = config_mysql_conn(cl, conf, proxy);

	diag("Performing connection attempt   creds:`%s`", to_string(creds).c_str());
	MYSQL* myconn {
		mysql_real_connect(proxy, cl.host, creds.name.c_str(), creds.pass.get(), NULL, cl.port, NULL, cflags)
	};

	user_auth_stats_t auth_info { update_auth_reg(myconn, creds.name, creds.pass.get(), auth_reg) };
	bool exp_success = chk_seq_exp_scs(conf, creds, auth_info);

	if (exp_success) {
		ok(
			myconn != nullptr,
			"Connection attempt should SUCCEED   creds:`%s`, conf:`%s`, auth_info:`%s`, error:'%s'",
			to_string(creds).c_str(), to_string(conf).c_str(), to_string(auth_info).c_str(), mysql_error(proxy)
		);

		sess_info_t sess_info { ext_sess_info(proxy) };
		diag("Extracted session info    sess_info:`%s`", to_string(sess_info).c_str());

		const string exp_auth_switch_type { get_exp_auth_switch(conf, creds, sess_info) };
		const string act_auth_switch_type { map_auth_switch(sess_info.switching_auth_sent) };

		ok(
			exp_auth_switch_type == act_auth_switch_type,
			"Found auth switch should match expected   exp:'%s', act:'%s'",
			exp_auth_switch_type.c_str(), act_auth_switch_type.c_str()
		);

		const bool exp_full_sha2 = chk_exp_sha2_full_auth(conf, creds, auth_info);
		const bool act_full_sha2 = detect_sha2_full_auth(sess_info);

		ok(
			exp_full_sha2 == act_full_sha2,
			"Found full 'caching_sha2' full auth should match expected   exp:'%d', act:'%d'",
			exp_full_sha2, act_full_sha2
		);

		// Check new connection creation on ProxySQL side
		int rc = mysql_query(proxy, "/* create_new_connection=1 */ DO 1");

		ok(
			rc == 0 && mysql_errno(proxy) == 0,
			"Query and backend connection creation should succeed   myerrno:'%d', myerror:'%s'",
			mysql_errno(proxy), mysql_error(proxy)
		);
	} else {
		const char* myerror = mysql_error(proxy);
		uint32_t myerrno = mysql_errno(proxy);

		ok(
			myconn == nullptr && mysql_errno(proxy),
			"Connection attempt should FAIL   creds:`%s`, conf:`%s`, auth_info:`%s`, errno:'%d', error:'%s'",
			to_string(creds).c_str(), to_string(conf).c_str(), to_string(auth_info).c_str(), myerrno, myerror
		);
	}

	mysql_close(proxy);
}

void test_creds_frontend(
	const CommandLine& cl,
	const test_conf_t& conf,
	const test_creds_t& creds,
	const chk_exp_scs_t& chk_exp_scs
) {
	MYSQL* proxy = mysql_init(NULL);
	int cflags = config_mysql_conn(cl, conf, proxy);

	const string creds_str { to_string(creds) };
	const uint64_t th_id { pthread_self() };

	diag("Performing connection attempt   thread:`%lu`, creds:`%s`", th_id, creds_str.c_str());
	MYSQL* myconn {
		mysql_real_connect(proxy, cl.host, creds.name.c_str(), creds.pass.get(), NULL, cl.port, NULL, cflags)
	};

	bool exp_scs = chk_exp_scs(conf, creds);
	if (exp_scs) {
		ok(
			myconn != nullptr,
			"Connection attempt should SUCCEED   thread:`%lu`, creds:`%s`, conf:`%s`, error:'%s'",
			pthread_self(), to_string(creds).c_str(), to_string(conf).c_str(), mysql_error(proxy)
		);

		sess_info_t sess_info { ext_sess_info(proxy) };
		diag("Extracted session info    thread:`%lu`, sess_info:`%s`", th_id, to_string(sess_info).c_str());

		const string exp_auth_switch_type { get_exp_auth_switch(conf, creds, sess_info) };
		const string act_auth_switch_type { map_auth_switch(sess_info.switching_auth_sent) };

		ok(
			exp_auth_switch_type == act_auth_switch_type,
			"Found auth switch should match expected   thread:`%lu`, exp:'%s', act:'%s'",
			pthread_self(), exp_auth_switch_type.c_str(), act_auth_switch_type.c_str()
		);
	} else {
		const char* myerror = mysql_error(proxy);
		uint32_t myerrno = mysql_errno(proxy);

		ok(
			myconn == nullptr && mysql_errno(proxy),
			"Connection attempt should FAIL   thread:`%lu`, creds:`%s`, conf:`%s`, errno:'%d', error:'%s'",
			pthread_self(), to_string(creds).c_str(), to_string(conf).c_str(), myerrno, myerror
		);
	}

	mysql_close(proxy);
}

user_auth_stats_t check_auth_creds(
	const CommandLine& cl, const test_conf_t& conf, const test_creds_t& creds
) {
	MYSQL* proxy = mysql_init(NULL);
	int cflags = config_mysql_conn(cl, conf, proxy);

	const string creds_str { to_string(creds) };
	const uint64_t th_id { pthread_self() };

	diag("Performing connection attempt   thread:`%lu`, creds:`%s`", th_id, creds_str.c_str());
	MYSQL* myconn {
		mysql_real_connect(proxy, cl.host, creds.name.c_str(), creds.pass.get(), NULL, cl.port, NULL, cflags)
	};

	user_auth_stats_t auth_stats {};

	if (myconn) {
		sess_info_t sess_info { ext_sess_info(proxy) };
		diag("Extracted session info    thread:`%lu`, sess_info:`%s`", th_id, to_string(sess_info).c_str());

		bool full_sha2_auth = detect_sha2_cached_auth(sess_info);

		if (creds.info.type == PASS_TYPE::PRIMARY) {
			auth_stats = user_auth_stats_t { user_def_t { creds.name }, 1, 0, full_sha2_auth };
		} else {
			auth_stats = user_auth_stats_t { user_def_t { creds.name }, 0, 1, full_sha2_auth };
		}
	} else {
		auth_stats = user_auth_stats_t { user_def_t { creds.name }, 0, 0, 0 };
	}

	mysql_close(proxy);

	return auth_stats;
}

const vector<user_def_t> backend_users {
	{ "dualpass1", MF_CHAR_(nullptr),    MF_CHAR_(nullptr),    "mysql_native_password", MYSQL8_HG },
	{ "dualpass2", MF_CHAR_(""),         MF_CHAR_(nullptr),    "mysql_native_password", MYSQL8_HG },
	{ "dualpass3", MF_CHAR_("newpass3"), MF_CHAR_(nullptr),    "mysql_native_password", MYSQL8_HG },
	{ "dualpass4", MF_CHAR_(nullptr),    MF_CHAR_(""),         "mysql_native_password", MYSQL8_HG },
	{ "dualpass5", MF_CHAR_(""),         MF_CHAR_(""),         "mysql_native_password", MYSQL8_HG },
	{ "dualpass6", MF_CHAR_("newpass6"), MF_CHAR_(""),         "mysql_native_password", MYSQL8_HG },
	{ "dualpass7", MF_CHAR_(""),         MF_CHAR_("oldpass7"), "mysql_native_password", MYSQL8_HG },
	{ "dualpass8", MF_CHAR_(""),         MF_CHAR_("oldpass8"), "mysql_native_password", MYSQL8_HG },
	{ "dualpass9", MF_CHAR_("newpass9"), MF_CHAR_("oldpass9"), "mysql_native_password", MYSQL8_HG },

	{ "dualpass11", MF_CHAR_(nullptr),     MF_CHAR_(nullptr),     "caching_sha2_password", MYSQL8_HG },
	{ "dualpass12", MF_CHAR_(""),          MF_CHAR_(nullptr),     "caching_sha2_password", MYSQL8_HG },
	{ "dualpass13", MF_CHAR_("newpass13"), MF_CHAR_(nullptr),     "caching_sha2_password", MYSQL8_HG },
	{ "dualpass14", MF_CHAR_(nullptr),     MF_CHAR_(""),          "caching_sha2_password", MYSQL8_HG },
	{ "dualpass15", MF_CHAR_(""),          MF_CHAR_(""),          "caching_sha2_password", MYSQL8_HG },
	{ "dualpass16", MF_CHAR_("newpass16"), MF_CHAR_(""),          "caching_sha2_password", MYSQL8_HG },
	{ "dualpass17", MF_CHAR_(""),          MF_CHAR_("oldpass17"), "caching_sha2_password", MYSQL8_HG },
	{ "dualpass18", MF_CHAR_(""),          MF_CHAR_("oldpass18"), "caching_sha2_password", MYSQL8_HG },
	{ "dualpass19", MF_CHAR_("newpass19"), MF_CHAR_("oldpass19"), "caching_sha2_password", MYSQL8_HG },
};

/**
 * @brief Minimal test cases for default backend users.
 */
const vector<test_creds_t> tests_creds {
	{ "dualpass1", MF_CHAR_("USE_PRIM_RAND_PASS") },
	{ "dualpass1", MF_CHAR_(nullptr) },
	{ "dualpass1", MF_CHAR_("") },
	{ "dualpass1", MF_CHAR_("inv_pass") },
	{ "dualpass1", MF_CHAR_("USE_PRIM_RAND_PASS") },
	{ "dualpass1", MF_CHAR_("USE_ADDL_RAND_PASS") },

	{ "dualpass2", MF_CHAR_(nullptr) },
	{ "dualpass2", MF_CHAR_("") },
	{ "dualpass2", MF_CHAR_("inv_pass") },

	{ "dualpass3", MF_CHAR_(nullptr) },
	{ "dualpass3", MF_CHAR_("") },
	{ "dualpass3", MF_CHAR_("inv_pass") },
	{ "dualpass3", MF_CHAR_("newpass3") },
	{ "dualpass3", MF_CHAR_("newpass3") },

	{ "dualpass4", MF_CHAR_(nullptr) },
	{ "dualpass4", MF_CHAR_("") },
	{ "dualpass4", MF_CHAR_("inv_pass") },

	{ "dualpass5", MF_CHAR_(nullptr) },
	{ "dualpass5", MF_CHAR_("") },
	{ "dualpass5", MF_CHAR_("inv_pass") },
	// Failure unless in RAND mode - Use fetched RAND_PASS
	{ "dualpass5", MF_CHAR_("USE_PRIM_RAND_PASS") },
	{ "dualpass5", MF_CHAR_("USE_PRIM_RAND_PASS") },
	{ "dualpass5", MF_CHAR_("USE_ADDL_RAND_PASS") },

	{ "dualpass6", MF_CHAR_(nullptr) },
	{ "dualpass6", MF_CHAR_("") },
	{ "dualpass6", MF_CHAR_("inv_pass") },
	{ "dualpass6", MF_CHAR_("newpass6") },
	{ "dualpass6", MF_CHAR_("newpass6") },

	{ "dualpass7", MF_CHAR_(nullptr) },
	{ "dualpass7", MF_CHAR_("") },
	{ "dualpass7", MF_CHAR_("inv_pass") },
	{ "dualpass7", MF_CHAR_("oldpass7") },
	// Failure unless in RAND mode - Use fetched RAND_PASS
	{ "dualpass7", MF_CHAR_("USE_PRIM_RAND_PASS") },
	{ "dualpass7", MF_CHAR_("USE_PRIM_RAND_PASS") },
	{ "dualpass7", MF_CHAR_("USE_ADDL_RAND_PASS") },

	{ "dualpass8", MF_CHAR_(nullptr) },
	{ "dualpass8", MF_CHAR_("") },
	{ "dualpass8", MF_CHAR_("inv_pass") },
	{ "dualpass8", MF_CHAR_("oldpass8") },

	{ "dualpass9", MF_CHAR_(nullptr) },
	{ "dualpass9", MF_CHAR_("") },
	{ "dualpass9", MF_CHAR_("inv_pass") },
	{ "dualpass9", MF_CHAR_("oldpass9") },
	{ "dualpass9", MF_CHAR_("newpass9") },
	{ "dualpass9", MF_CHAR_("newpass9") },
	{ "dualpass9", MF_CHAR_("USE_RAND_PASS") },

	{ "dualpass11", MF_CHAR_(nullptr) },
	{ "dualpass11", MF_CHAR_("") },
	{ "dualpass11", MF_CHAR_("inv_pass") },
	// Failure unless in RAND mode - Use fetched RAND_PASS
	{ "dualpass11", MF_CHAR_("USE_ADDL_RAND_PASS") },
	// Triggers limitation on 'full_auth' again; this should be improved
	{ "dualpass11", MF_CHAR_("USE_ADDL_RAND_PASS") },
	{ "dualpass11", MF_CHAR_("USE_PRIM_RAND_PASS") },

	{ "dualpass12", MF_CHAR_(nullptr) },
	{ "dualpass12", MF_CHAR_("") },
	{ "dualpass12", MF_CHAR_("inv_pass") },

	{ "dualpass13", MF_CHAR_(nullptr) },
	{ "dualpass13", MF_CHAR_("") },
	{ "dualpass13", MF_CHAR_("inv_pass") },
	{ "dualpass13", MF_CHAR_("newpass13") },
	{ "dualpass13", MF_CHAR_("newpass13") },

	{ "dualpass14", MF_CHAR_(nullptr) },
	{ "dualpass14", MF_CHAR_("") },
	{ "dualpass14", MF_CHAR_("inv_pass") },

	{ "dualpass15", MF_CHAR_(nullptr) },
	{ "dualpass15", MF_CHAR_("") },
	{ "dualpass15", MF_CHAR_("inv_pass") },

	{ "dualpass16", MF_CHAR_(nullptr) },
	{ "dualpass16", MF_CHAR_("") },
	{ "dualpass16", MF_CHAR_("inv_pass") },
	{ "dualpass16", MF_CHAR_("newpass16") },
	{ "dualpass16", MF_CHAR_("newpass16") },

	{ "dualpass17", MF_CHAR_(nullptr) },
	{ "dualpass17", MF_CHAR_("") },
	{ "dualpass17", MF_CHAR_("inv_pass") },
	{ "dualpass17", MF_CHAR_("oldpass17") },
	// Failure unless in RAND mode - Use fetched RAND_PASS
	{ "dualpass17", MF_CHAR_("USE_ADDL_RAND_PASS") },
	{ "dualpass17", MF_CHAR_("USE_ADDL_RAND_PASS") },
	{ "dualpass17", MF_CHAR_("USE_PRIM_RAND_PASS") },

	{ "dualpass18", MF_CHAR_(nullptr) },
	{ "dualpass18", MF_CHAR_("") },
	{ "dualpass18", MF_CHAR_("inv_pass") },
	{ "dualpass18", MF_CHAR_("oldpass18") },

	{ "dualpass19", MF_CHAR_(nullptr) },
	{ "dualpass19", MF_CHAR_("") },
	{ "dualpass19", MF_CHAR_("inv_pass") },
	{ "dualpass19", MF_CHAR_("newpass19") },
	{ "dualpass19", MF_CHAR_("newpass19") },

	{ "invuser20", MF_CHAR_(nullptr) },
	{ "invuser20", MF_CHAR_("") },
	{ "invuser20", MF_CHAR_("invpass20") },

	{ "invuser21", MF_CHAR_(nullptr) },
	{ "invuser21", MF_CHAR_("") },
	{ "invuser21", MF_CHAR_("invpass21") },
	{ "invuser21", MF_CHAR_("newpass19") }
};

int backend_conns_cleanup(MYSQL* admin) {
	diag("Cleaning up previous backend connections...");
	MYSQL_QUERY(admin,
		("UPDATE mysql_servers SET max_connections=0 "
			"WHERE hostgroup_id=" + std::to_string(MYSQL8_HG)).c_str()
	);
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// Wait for backend connection cleanup
	const string check_conn_cleanup {
		"SELECT IIF((SELECT SUM(ConnUsed + ConnFree) FROM stats.stats_mysql_connection_pool"
			" WHERE hostgroup=" + std::to_string(MYSQL8_HG) + ")=0, 'TRUE', 'FALSE')"
	};
	int w_res = wait_for_cond(admin, check_conn_cleanup, 10);
	if (w_res != EXIT_SUCCESS) {
		diag("Waiting for backend connections failed   res:'%d'", w_res);
		return EXIT_FAILURE;
	}

	diag("Setup new connection limit   max_connections='2000'");
	MYSQL_QUERY(admin,
		("UPDATE mysql_servers SET max_connections=2000 "
			"WHERE hostgroup_id=" + std::to_string(MYSQL8_HG)).c_str()
	);
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	return EXIT_SUCCESS;
}

vector<pair<test_conf_t, vector<test_creds_t>>> filter_tests(
	const vector<test_conf_t>& conf_combs,
	const vector<user_creds_t>& users_creds,
	const vector<test_creds_t>& tests_creds,
	const chk_exp_scs_t& filter
) {
	vector<pair<test_conf_t, vector<test_creds_t>>> non_warmup_tests {};

	for (const auto& conf : conf_combs) {
		vector<test_creds_t> conf_creds {};

		for (const auto& creds : tests_creds) {
			test_creds_t f_creds { map_user_creds(users_creds, creds) };

			if (filter(conf, f_creds)) {
				conf_creds.push_back(f_creds);
			}
		}

		if (!conf_creds.empty()) {
			non_warmup_tests.push_back({conf, conf_creds});
		}
	}

	return non_warmup_tests;
}

bool req_sha2_auth(const test_conf_t& conf, const test_creds_t& creds) {
	// otherwise SHA2 auth shouldn't take place
	if (!is_empty_pass(creds.pass.get()) && conf.hashed_pass && conf.use_ssl) {
		if (creds.info.auth == "caching_sha2_password") {
			return true;
		}
		// current limitation; auth switch shouldn't be requested to 'caching_sha2_password'; since
		// the pass isn't store as such; the real passtype should be requested
		else if (
			conf.def_auth == "caching_sha2_password" && conf.req_auth == "caching_sha2_password"
			&& creds.info.auth == "mysql_native_password"
		) {
			return true;
		}
		else {
			return false;
		}
	} else {
		return false;
	}
}

int test_confs_creds_combs_frontend(
	CommandLine& cl,
	MYSQL* admin,
	const vector<user_creds_t>& user_creds,
	const vector<pair<test_conf_t, vector<test_creds_t>>>& confs_creds_map,
	const chk_exp_scs_t& chk_exp_scs
) {
	for (const auto& p_conf_creds : confs_creds_map) {
		int rc = backend_conns_cleanup(admin);
		if (rc) { return EXIT_FAILURE; }

		// Need to use both; hashed and unhashed passwords for the backend
		int cres = config_proxysql_users(admin, p_conf_creds.first, user_creds);
		if (cres) { return EXIT_FAILURE; }

		diag("%s", ("Switching to '" + p_conf_creds.first.def_auth + "' on ProxySQL side").c_str());
		MYSQL_QUERY_T(admin,
			("SET mysql-default_authentication_plugin='" + p_conf_creds.first.def_auth + "'").c_str()
		);
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

		std::vector<std::thread> client_threads {};

		// Perform parallel fronted logging tests
		for (uint32_t i = 0; i < NUM_CLIENT_THREADS; i++) {
			client_threads.push_back(std::thread([&cl, &p_conf_creds, &chk_exp_scs] () {
				for (const auto& creds : p_conf_creds.second) {
					test_creds_frontend(cl, p_conf_creds.first, creds, chk_exp_scs);
				}
			}));
		}

		for (auto& cthread : client_threads) {
			cthread.join();
		}
	}

	return EXIT_SUCCESS;
}

int test_all_confs_creds(
	CommandLine& cl,
	MYSQL* admin,
	const vector<test_conf_t>& all_conf_combs,
	const vector<user_creds_t>& users_creds,
	const vector<test_creds_t>& tests_creds,
	uint64_t non_warmup_tests_scs_count
) {
	uint64_t auth_scs_total = 0;
	uint64_t full_sha2_total = 0;
	uint64_t exp_sha2_auths = 0;

	for (const auto& conf : all_conf_combs) {
		int rc = backend_conns_cleanup(admin);
		if (rc) { return EXIT_FAILURE; }

		// Need to use both; hashed and unhashed passwords for the backend
		int cres = config_proxysql_users(admin, conf, users_creds);
		if (cres) { return EXIT_FAILURE; }

		diag("%s", ("Switching to '" + conf.def_auth + "' on ProxySQL side").c_str());
		MYSQL_QUERY_T(admin,
			("SET mysql-default_authentication_plugin='" + conf.def_auth + "'").c_str()
		);
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

		std::vector<std::thread> client_thds {};
		std::vector<uint64_t> thds_exp_sha2_auths(NUM_CLIENT_THREADS);
		std::vector<auth_reg_t> thds_auth_regs {};

		for (uint32_t i = 0; i < NUM_CLIENT_THREADS; i++) {
			thds_auth_regs.push_back(create_auth_reg(users_creds));
		}

		for (uint32_t i = 0; i < NUM_CLIENT_THREADS; i++) {
			client_thds.push_back(
				std::thread(
					[&cl, &conf, &thds_auth_regs, &thds_exp_sha2_auths, i, &users_creds, &tests_creds] () {
						auth_reg_t& auth_reg { thds_auth_regs[i] };

						for (const auto& creds : tests_creds) {
							test_creds_t f_creds { map_user_creds(users_creds, creds) };
							user_auth_stats_t auth_stats { check_auth_creds(cl, conf, f_creds) };

							if (auth_stats.prim_pass_auths || auth_stats.addl_pass_auths) {
								auto user_stats_it = auth_reg.find(f_creds.name);

								if (user_stats_it != auth_reg.end()) {
									if (
										chk_exp_scs_basic(conf, f_creds) && req_sha2_auth(conf, f_creds)
										&& user_stats_it->second.prim_pass_auths == 0
									) {
										thds_exp_sha2_auths[i] += 1;
									}

									user_stats_it->second.prim_pass_auths += auth_stats.prim_pass_auths;
									user_stats_it->second.addl_pass_auths += auth_stats.addl_pass_auths;
									user_stats_it->second.full_sha2_auths += auth_stats.full_sha2_auths;
								}
							}
						}
					}
				)
			);
		}

		for (auto& cthread : client_thds) {
			cthread.join();
		}

		for (uint32_t i = 0; i < NUM_CLIENT_THREADS; i++) {
			auth_reg_t& auth_reg { thds_auth_regs[i] };

			for (const auto& auth_stats : auth_reg) {
				auth_scs_total += auth_stats.second.prim_pass_auths;
				auth_scs_total += auth_stats.second.addl_pass_auths;
				full_sha2_total += auth_stats.second.full_sha2_auths;
			}

			exp_sha2_auths += thds_exp_sha2_auths[i];
		}
	}

	uint64_t exp_scs_total = non_warmup_tests_scs_count * NUM_CLIENT_THREADS;
	uint64_t exp_full_sha2_total = exp_sha2_auths;

	ok(
		exp_scs_total == auth_scs_total,
		"Number of auth success should match expected   exp:'%lu', act:'%lu'",
		exp_scs_total, auth_scs_total
	);

	ok(
		full_sha2_total < exp_full_sha2_total,
		"Number of full SHA2 auths should be below expected   exp:'%lu', act:'%lu'",
		exp_full_sha2_total, full_sha2_total
	);

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* mysql = mysql_init(NULL);

	if (!mysql_real_connect(mysql, cl.host, cl.mysql_username, cl.mysql_password, NULL, cl.mysql_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// Setup SSLKEYLOGFILE for debugging purposes
	if (getenv("SSLKEYLOGFILE") != nullptr) {
		const string datadir { string { cl.workdir } + "/test_auth_methods_datadir" };
		const string fpath { datadir + "/sslkeylog.log" };
		int dres = mkdir(datadir.c_str(), 0777);

		if (dres == -1 && errno != EEXIST) {
			diag("Failed to create datadir   path: '%s', error: '%s'", fpath.c_str(), strerror(errno));
			return EXIT_FAILURE;
		}

		F_SSLKEYLOGFILE = fopen(fpath.c_str(), "a+");
		if (!F_SSLKEYLOGFILE) {
			diag("Failed to open SSLKEYLOG file   path: '%s', error: '%s'", fpath.c_str(), strerror(errno));
			return EXIT_FAILURE;
		}
	}

	// Backend users config
	const auto cbres { config_mysql_backend_users(mysql, ::backend_users) };
	if (cbres.first) { return EXIT_FAILURE; }

	vector<user_def_t> rnd_backend_users { ::backend_users };

	for (user_def_t& user_def : rnd_backend_users) {
		user_def.name = "rnd" + user_def.name;
		user_def.rand_pass = true;
	}

	const auto rnd_cbres { config_mysql_backend_users(mysql, rnd_backend_users) };
	if (rnd_cbres.first) { return EXIT_FAILURE; }

	vector<test_creds_t> rnd_tests_creds { ::tests_creds };

	for (test_creds_t& creds : rnd_tests_creds) {
		creds.name = "rnd" + creds.name;

		auto it = std::find_if(rnd_cbres.second.begin(), rnd_cbres.second.end(),
			[&creds] (const user_creds_t& user_creds) {
				return creds.name == user_creds.user_def.name;
			}
		);

		if (it != rnd_cbres.second.end()) {
			if (creds.pass && strcasecmp(creds.pass.get(), "USE_PRIM_RAND_PASS") == 0) {
				creds.pass = it->user_def.prim_pass ? MF_CHAR_(it->user_def.prim_pass.get()) : nullptr;
			} else if (creds.pass && strcasecmp(creds.pass.get(), "USE_ADDL_RAND_PASS") == 0) {
				creds.pass = it->user_def.addl_pass ? MF_CHAR_(it->user_def.addl_pass.get()) : nullptr;
			}
		}
	}

	uint32_t NUM_CLIENT_THREADS = 4;

	const vector<string> def_auths {
		"mysql_native_password",
		"caching_sha2_password"
	};
	const vector<string> req_auhts {
		"mysql_clear_password",
		"mysql_native_password",
		"caching_sha2_password"
	};
	const vector<bool> hash_pass { false, true };
	const vector<bool> use_ssl { false, true };
	const vector<bool> use_comp { false, true };

	// Sequential access tests; exercising full logic
	const vector<test_conf_t> all_conf_combs {
		get_auth_conf_combs(def_auths, req_auhts, hash_pass, use_ssl, use_comp)
	};
	const auto scs_stats { count_exp_scs(all_conf_combs, cbres.second, tests_creds) };

	pair<uint64_t,uint64_t> rnd_scs_stats {};

	if (getenv("TAP_DISABLE_SEQ_CHECKS_RAND_PASS") == nullptr) {
		rnd_scs_stats = count_exp_scs(all_conf_combs, rnd_cbres.second, rnd_tests_creds);
	}

	// Partial logic tests; no-warmup, expected failure concurrent access
	const vector<pair<test_conf_t, vector<test_creds_t>>> non_warmup_tests_fail {
		filter_tests(all_conf_combs, cbres.second, tests_creds, chk_exp_fail_no_warmup)
	};
	const vector<pair<test_conf_t, vector<test_creds_t>>> non_warmup_tests_scs {
		filter_tests(all_conf_combs, cbres.second, tests_creds, chk_exp_scs_no_warmup)
	};

	uint64_t non_warmup_tests_fail_count = 0;

	if (getenv("TAP_DISABLE_NON_WARMUP_EXP_FAILS") == nullptr) {
		for (const auto& p_conf_creds : non_warmup_tests_fail) {
			non_warmup_tests_fail_count += p_conf_creds.second.size();
		}
	}

	uint64_t non_warmup_tests_scs_count = 0;

	if (getenv("TAP_DISABLE_NON_WARMUP_EXP_SCS") == nullptr) {
		for (const auto& p_conf_creds : non_warmup_tests_scs) {
			non_warmup_tests_scs_count += p_conf_creds.second.size();
		}
	}

	uint64_t non_warmup_tests_scs_ratio = 0;

	if (getenv("TAP_DISABLE_NON_WARMUP_EXP_RATIO") == nullptr) {
		non_warmup_tests_scs_ratio = 2;
	}

	plan(
		scs_stats.first * 4 + scs_stats.second
		+ rnd_scs_stats.first * 4 + rnd_scs_stats.second
		+ non_warmup_tests_fail_count * NUM_CLIENT_THREADS
		+ non_warmup_tests_scs_count * NUM_CLIENT_THREADS * 2
		+ non_warmup_tests_scs_ratio
	);

	// sequential; verify correctness in the procedure; KNOWN passwords
	for (const auto& conf : all_conf_combs) {
		int rc = backend_conns_cleanup(admin);
		if (rc) { goto cleanup; }

		// Need to use both; hashed and unhashed passwords for the backend
		int cres = config_proxysql_users(admin, conf, cbres.second);
		if (cres) { return EXIT_FAILURE; }

		diag("%s", ("Switching to '" + conf.def_auth + "' on ProxySQL side").c_str());
		MYSQL_QUERY_T(admin, ("SET mysql-default_authentication_plugin='" + conf.def_auth + "'").c_str());
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

		auth_reg_t auth_reg { create_auth_reg(cbres.second) };

		for (const auto& creds : tests_creds) {
			test_creds_t f_creds { map_user_creds(cbres.second, creds) };
			test_creds_frontend_backend(cl, conf, f_creds, auth_reg);
		}
	}

	// sequential; verify correctness in the procedure; RANDOM passwords
	if (getenv("TAP_DISABLE_SEQ_CHECKS_RAND_PASS") == nullptr) {
		for (const auto& conf : all_conf_combs) {
			int rc = backend_conns_cleanup(admin);
			if (rc) { goto cleanup; }

			// Need to use both; hashed and unhashed passwords for the backend
			int cres = config_proxysql_users(admin, conf, rnd_cbres.second);
			if (cres) { return EXIT_FAILURE; }

			diag("%s", ("Switching to '" + conf.def_auth + "' on ProxySQL side").c_str());
			MYSQL_QUERY_T(admin, ("SET mysql-default_authentication_plugin='" + conf.def_auth + "'").c_str());
			MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
			MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

			auth_reg_t auth_reg { create_auth_reg(rnd_cbres.second) };

			for (const auto& creds : rnd_tests_creds) {
				test_creds_t f_creds { map_user_creds(rnd_cbres.second, creds) };
				test_creds_frontend_backend(cl, conf, f_creds, auth_reg);
			}
		}
	}

	// concurrent; known to fail tests cases; no previous auths
	if (getenv("TAP_DISABLE_NON_WARMUP_EXP_FAILS") == nullptr) {
		diag("Starting frontend non-warmup FAIL tests; expected all auths to FAIL");

		int res = test_confs_creds_combs_frontend(cl, admin, cbres.second, non_warmup_tests_fail,
			[] (const test_conf_t&, const test_creds_t&) { return false; }
		);

		if (res) { goto cleanup; }
	}

	// concurrent; known to succeed tests cases; no previous auths
	if (getenv("TAP_DISABLE_NON_WARMUP_EXP_SCS") == nullptr) {
		diag("Starting frontend non-warmup SUCCESS tests; expected all auths to SUCCEED");

		int res = test_confs_creds_combs_frontend(cl, admin, cbres.second, non_warmup_tests_scs,
			[] (const test_conf_t&, const test_creds_t&) { return true; }
		);

		if (res) { goto cleanup; }
	}

	// concurrent; warmup phase; only number of succeed/failures is pre-known
	if (getenv("TAP_DISABLE_NON_WARMUP_EXP_RATIO") == nullptr) {
		diag("Starting frontend non-warmup ALL_COMBS tests; predicting SUCCESS/FAILURE ratio");

		int res = test_all_confs_creds(
			cl, admin, all_conf_combs, cbres.second, tests_creds, non_warmup_tests_scs_count
		);

		if (res) { goto cleanup; }
	}

cleanup:

	mysql_close(mysql);
	mysql_close(admin);

	if (F_SSLKEYLOGFILE) {
		fclose(F_SSLKEYLOGFILE);
	}

	return exit_status();
}
