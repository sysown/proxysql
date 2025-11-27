#ifndef UTILS_AUTH_H
#define UTILS_AUTH_H

#include <utility>
#include <vector>

#include "proxysql_utils.h"
#include "mysql.h"

#include "utils.h"
#include "tap.h"

using std::pair;
using std::string;
using std::vector;

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

mf_unique_ptr<char> MF_CHAR_(const char* s) {
	return mf_unique_ptr<char> { s ? strdup(s) : nullptr };
}

struct user_def_t {
	string name {};
	mf_unique_ptr<char> prim_pass { nullptr };
	mf_unique_ptr<char> addl_pass { nullptr };
	string auth {};
	string def_db {};
	uint32_t def_hg { 0 };
	bool rand_pass {};

	user_def_t() {}
	user_def_t(const string& name_) : name(name_) {}

	user_def_t(
		const string& name_,
		mf_unique_ptr<char> prim_pass_,
		mf_unique_ptr<char> addl_pass_,
		const string& auth_,
		const uint32_t def_hg_ = 0,
		const string def_db_ = {},
		bool rand_pass_ = false
	) :
		name(name_),
		prim_pass(std::move(prim_pass_)),
		addl_pass(std::move(addl_pass_)),
		auth(auth_),
		def_hg(def_hg_),
		def_db(def_db_),
		rand_pass(rand_pass_)
	{}

	user_def_t(const user_def_t& other) :
		name(other.name),
		auth(other.auth),
		rand_pass(other.rand_pass),
		def_hg(other.def_hg),
		def_db(other.def_db)
	{
		if (other.prim_pass) {
			this->prim_pass = mf_unique_ptr<char>(strdup(other.prim_pass.get()));
		} else {
			this->prim_pass = nullptr;
		}
		if (other.addl_pass) {
			this->addl_pass = mf_unique_ptr<char>(strdup(other.addl_pass.get()));
		} else {
			this->addl_pass = nullptr;
		}
	}

	void operator=(const user_def_t& other) {
		this->name = other.name;
		this->auth = other.auth;
		this->rand_pass = other.rand_pass;
		this->def_hg = other.def_hg;
		this->def_db = other.def_db;

		if (other.prim_pass) {
			this->prim_pass = mf_unique_ptr<char>(strdup(other.prim_pass.get()));
		} else {
			this->prim_pass = nullptr;
		}
		if (other.addl_pass) {
			this->addl_pass = mf_unique_ptr<char>(strdup(other.addl_pass.get()));
		} else {
			this->addl_pass = nullptr;
		}
	}

	user_def_t(user_def_t&& other) :
		name(other.name),
		auth(other.auth),
		rand_pass(other.rand_pass),
		prim_pass(std::move(other.prim_pass)),
		addl_pass(std::move(other.addl_pass)),
		def_hg(other.def_hg),
		def_db(other.def_db)
	{}

	void operator=(user_def_t&& other) {
		this->name = other.name;
		this->auth = other.auth;
		this->rand_pass = other.rand_pass;
		this->prim_pass = std::move(other.prim_pass);
		this->addl_pass = std::move(other.addl_pass);
		this->def_hg = other.def_hg;
		this->def_db = other.def_db;
	}
};

struct user_creds_t {
	user_def_t user_def;
	mf_unique_ptr<char> hashed_prim_pass_bin { nullptr };
	mf_unique_ptr<char> hashed_addl_pass_bin { nullptr };

	user_creds_t(const user_creds_t&) = delete;
	user_creds_t(user_creds_t&&) noexcept(false) = default;

	void operator=(user_creds_t&& other) {
		this->user_def = std::move(other.user_def);
		this->hashed_prim_pass_bin = std::move(other.hashed_prim_pass_bin);
		this->hashed_addl_pass_bin = std::move(other.hashed_addl_pass_bin);
	}
};

bool is_empty_pass(const char* pass) {
	return pass == nullptr || (pass && strlen(pass) == 0);
}

std::string unhex(const std::string& hex) {
	if (hex.size() % 2) { return {}; };

	string result {};

	for (size_t i = 0; i < hex.size() - 1; i += 2) {
		string hex_char { string { hex[i] } + hex[i+1] };
		uint64_t char_val { 0 };

		std::istringstream stream { hex_char };
		stream >> std::hex >> char_val;

		result += string { static_cast<char>(char_val) };
	}

	return result;
}

std::string hex(const std::string& str) {
	std::ostringstream hex_stream;

	 for (unsigned char c : str) {
		hex_stream << std::hex << std::setfill('0') << std::setw(2) <<
			std::uppercase << static_cast<uint64_t>(c);
	}

	return hex_stream.str();
}

/**
 * @brief TODO: Limitation ProxySQL doesn't allow a clear-text pass to start with '*'. See #1762.
 * @param pass Password to check.
 * @return 'true' if password is an invalid clear-text pass for ProxySQL.
 */
bool chk_inv_pass(const char* pass) {
	if (is_empty_pass(pass)) {
		return true;
	} else {
		if (strlen(pass)) {
			return pass[0] == '*';
		} else {
			return false;
		}
	}
}

pair<int,user_def_t> create_mysql_user_exp_creds(MYSQL* mysql, const user_def_t& user_def) {
	const char* addl_pass { user_def.addl_pass.get() };
	const char* prim_pass { user_def.prim_pass.get() };

	if (addl_pass && strlen(addl_pass)) {
		const string CREATE_USER {
			"CREATE USER '" + user_def.name + "'@'%' IDENTIFIED WITH"
				" '" + user_def.auth + "' BY '" + user_def.addl_pass.get() + "'"
		};
		const string GRANT_USER_PRIVS { "GRANT ALL on *.* to '" + user_def.name + "'@'%'" };

		MYSQL_QUERY_T_(mysql, CREATE_USER.c_str());
		MYSQL_QUERY_T_(mysql, GRANT_USER_PRIVS.c_str());

		if (prim_pass && strlen(prim_pass)) {
			const string ALTER_USER_RETAIN {
				"ALTER USER '" + user_def.name + "'@'%' IDENTIFIED BY '" + prim_pass + "'"
					" RETAIN CURRENT PASSWORD"
			};
			MYSQL_QUERY_T_(mysql, ALTER_USER_RETAIN.c_str());
		} else {
			const string ALTER_USER_NO_RETAIN {
				"ALTER USER '" + user_def.name + "'@'%' IDENTIFIED BY ''"
			};
			// When new password is empty; retaining the previous one isn't possible
			MYSQL_QUERY_T_(mysql, ALTER_USER_NO_RETAIN.c_str());
		}
	} else {
		string CREATE_USER { "CREATE USER '" + user_def.name + "'@'%'" };
		string GRANT_USER_PRIVS { "GRANT ALL on *.* to '" + user_def.name + "'@'%'" };

		if (prim_pass) {
			CREATE_USER += " IDENTIFIED WITH '" + user_def.auth + "' BY '" + prim_pass + "'";
		}

		MYSQL_QUERY_T_(mysql, CREATE_USER.c_str());
		MYSQL_QUERY_T_(mysql, GRANT_USER_PRIVS.c_str());
	}

	// If user has a 'default_schema' create the target schema and grant perms
	if (!user_def.def_db.empty()) {
		const string& u_db { user_def.def_db };
		const string& u_name { user_def.name };
		MYSQL_QUERY_T_(mysql, ("CREATE DATABASE IF NOT EXISTS " + u_db).c_str());
		MYSQL_QUERY_T_(mysql, ("GRANT ALL ON " + u_db + ".* TO '" + u_name + "'@'%'").c_str());
	}

	return { EXIT_SUCCESS, user_def };
}


pair<int,user_def_t> create_mysql_user_rnd_creds(MYSQL* mysql, const user_def_t& user_def) {
	const string CREATE_USER {
		"CREATE USER '" + user_def.name + "'@'%' IDENTIFIED WITH"
			" '" + user_def.auth + "' BY RANDOM PASSWORD"
	};
	const string DROP_USER { "DROP USER IF EXISTS '" + user_def.name + "'"};

	mf_unique_ptr<char> addl_text_pass { nullptr };

	{
		// NOTE: Required due to potential pass recreation
		MYSQL_QUERY_T_(mysql, DROP_USER.c_str());
		MYSQL_QUERY_T_(mysql, CREATE_USER.c_str());

		MYSQL_RES* myres = mysql_store_result(mysql);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (myrow && myrow[2]) {
			addl_text_pass = mf_unique_ptr<char>(strdup(myrow[2]));
		}

		mysql_free_result(myres);
	}

	const string ALTER_USER {
		"ALTER USER '" + user_def.name + "'@'%' IDENTIFIED WITH"
			" '" + user_def.auth + "' BY RANDOM PASSWORD RETAIN CURRENT PASSWORD"
	};

	mf_unique_ptr<char> prim_text_pass {};

	{
		MYSQL_QUERY_T_(mysql, ALTER_USER.c_str());

		MYSQL_RES* myres = mysql_store_result(mysql);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (myrow && myrow[2]) {
			prim_text_pass = mf_unique_ptr<char>(strdup(myrow[2]));
		}

		mysql_free_result(myres);
	}

	return {
		EXIT_SUCCESS,
		user_def_t {
			user_def.name,
			std::move(prim_text_pass),
			std::move(addl_text_pass),
			user_def.auth,
			user_def.def_hg,
			user_def.def_db,
			user_def.rand_pass
		}
	};
}


pair<int,user_def_t> create_mysql_user(MYSQL* mysql, const user_def_t& user_def) {
	if (user_def.rand_pass) {
		pair<int,user_def_t> rnd_user_def {};

		while (
			rnd_user_def.first == EXIT_SUCCESS &&
			(chk_inv_pass(rnd_user_def.second.prim_pass.get())
				|| chk_inv_pass(rnd_user_def.second.addl_pass.get()))
		) {
			rnd_user_def = create_mysql_user_rnd_creds(mysql, user_def);
		}

		return rnd_user_def;
	} else {
		return create_mysql_user_exp_creds(mysql, user_def);
	}
}

/**
 * @brief Extract the auth strings (prim/addl) pass from an existing user.
 * @param mysql Opened MySQL conn in which to perform the queries.
 * @param user_def User definition; used to match by username.
 * @return A pair of kind `{err_code, user_creds}`.
 */
pair<int,user_creds_t> ext_user_auth_strs(MYSQL* mysql, const user_def_t& user_def) {
	const char* addl_pass { user_def.addl_pass.get() };
	const char* prim_pass { user_def.prim_pass.get() };

	pair<int,user_creds_t> p_creds_res { EXIT_SUCCESS, user_creds_t {} };

	const string ext_auths_query {
		"SELECT HEX(authentication_string),json_value(user_attributes, '$.additional_password') "
			"FROM mysql.user WHERE user='" + user_def.name + "'"
	};

	if (mysql_query_t(mysql, ext_auths_query.c_str())) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return { EXIT_FAILURE, user_creds_t {} };
	}

	MYSQL_RES* myres = mysql_store_result(mysql);
	MYSQL_ROW myrow = mysql_fetch_row(myres);

	if (myrow && myrow[0]) {
		const char* p_addl_pass { myrow[1] };

		if (p_addl_pass) {
			p_creds_res = {
				EXIT_SUCCESS,
				user_creds_t {
					user_def,
					mf_unique_ptr<char> { strdup(myrow[0]) },
					mf_unique_ptr<char> { strdup(p_addl_pass) }
				}
			};
		} else {
			// MySQL wont allow that 'aditional' pass for a backend user; we don't verify user attributes
			// right now when loading to runtime; but we wont allow user to connect with empty
			// 'additional' passwords either;
			if (addl_pass && strlen(addl_pass) == 0) {
				p_creds_res = {
					EXIT_SUCCESS,
					user_creds_t {
						user_def,
						mf_unique_ptr<char> { strdup(myrow[0]) },
						mf_unique_ptr<char> { strdup("") },
					}
				};
			} else {
				p_creds_res = {
					EXIT_SUCCESS,
					user_creds_t {
						user_def,
						mf_unique_ptr<char> { strdup(myrow[0]) },
						mf_unique_ptr<char> { nullptr },
					}
				};
			}
		}
	} else {
		diag("Empty result; no auth_string found for user   user:'%s'", user_def.name.c_str());
	}

	mysql_free_result(myres);

	return p_creds_res;
}

pair<int,user_creds_t> create_backend_user(MYSQL* mysql, const user_def_t& user_def) {
	const pair<int,user_def_t> c_user_def { create_mysql_user(mysql, user_def) };

	if (c_user_def.first == EXIT_SUCCESS) {
		pair<int,user_creds_t> p_creds_res { ext_user_auth_strs(mysql, c_user_def.second) };

		return p_creds_res;
	} else {
		return { EXIT_FAILURE, user_creds_t {} };
	}
}

/**
 * @brief Configure the backend MySQL 8 users for frontend-backend connection creation.
 * @param mysql Already opened MySQL connection.
 * @param backend_users The users to be created in the MySQL server.
 * @return A pair of kind `{err_code, user_creds}`.
 */
pair<int,vector<user_creds_t>> config_mysql_backend_users(
	MYSQL* mysql, const vector<user_def_t>& users_defs
) {
	for (const auto& u : users_defs) {
		MYSQL_QUERY_T__(mysql, ("DROP USER IF EXISTS '" + u.name + "'").c_str());
	}

	vector<user_creds_t> f_users_creds {};

	for (const auto& user_def : users_defs) {
		pair<int,user_creds_t> creds_res { create_backend_user(mysql, user_def) };

		if (creds_res.first == EXIT_SUCCESS) {
			f_users_creds.push_back(std::move(creds_res.second));
		} else {
			return { EXIT_FAILURE, vector<user_creds_t> {} };
		}
	}

	return { EXIT_SUCCESS, std::move(f_users_creds) };
}

struct test_conf_t {
	/* @brief Default auth method announced by ProxySQL */
	string def_auth;
	/* @brief Auth method requested by client */
	string req_auth;
	/* @brief Wether to use hashed or 'clear_text' passwords. Implies a reload of 'mysql_users'. */
	bool hashed_pass;
	/* @brief Wether to attempt auth under SSL conn or not. */
	bool use_ssl;
	/* @brief Wether to attempt auth with compression enabled or not. */
	bool use_comp;
};

string to_string(const test_conf_t& conf) {
	return "{ "
		"\"req_auth\":'" + conf.req_auth + "', "
		"\"def_auth\":'" + conf.def_auth + "', "
		"\"hashed_pass\":'" + std::to_string(conf.hashed_pass) + "', "
		"\"use_ssl\":'" + std::to_string(conf.use_ssl) + "'"
	" }";
}

/**
 * @brief Gen all combinations of tests configs.
 * @param def_auths Defaults auths to set for ProxySQL.
 * @param req_auths Auth methods for client to request.
 * @param hash_pass If passwords should be hashed or not.
 * @param use_ssl If connection is started with SSL or not.
 * @return Vector with the combinations.
 */
vector<test_conf_t> get_auth_conf_combs(
	const vector<string>& def_auths,
	const vector<string>& req_auths,
	const vector<bool>& hash_pass,
	const vector<bool>& use_ssl,
	const vector<bool>& use_comp
) {
	vector<test_conf_t> confs {};

	for (const auto& def_auth : def_auths) {
		for (const auto& req_auth : req_auths) {
			for (const auto& hashed : hash_pass) {
				for (const auto& ssl : use_ssl) {
					for (const auto& comp : use_comp) {
						confs.push_back({def_auth, req_auth, hashed, ssl, comp});
					}
				}
			}
		}
	}

	return confs;
}

struct PASS_TYPE {
	enum E {
		UNKNOWN = 0,
		PRIMARY,
		ADDITIONAL,
	};
};

string to_string(const PASS_TYPE::E type) {
	if (type == PASS_TYPE::PRIMARY) {
		return "PRIM";
	} else if (type == PASS_TYPE::ADDITIONAL) {
		return "ADDL";
	} else {
		return "UNKN";
	}
}

/**
 * @brief Info from user defs (user_def_t), extracted for building 'test_creds_t'.
 */
struct creds_info_t {
	PASS_TYPE::E type;
	string auth;
};

/**
 * @brief Info about user creds used in a particular test case.
 * @details Multiple 'test_creds_t' are used while testing a single 'test_conf_t'.
 */
struct test_creds_t {
	string name {};
	mf_unique_ptr<char> pass { nullptr };
	creds_info_t info {};

	test_creds_t(const string& name_, mf_unique_ptr<char> pass_) : name(name_), pass(std::move(pass_)) {}
	test_creds_t(const string& name_, mf_unique_ptr<char> pass_, const creds_info_t& info_) :
		name(name_), pass(std::move(pass_)), info(info_) {}
	test_creds_t(const test_creds_t& other) : name(other.name), info(other.info) {
		this->pass = other.pass ? MF_CHAR_(other.pass.get()) : nullptr;
	}
};

string to_string(const test_creds_t& creds) {
	return "{ "
		"\"name\":'" + creds.name + "', "
		"\"pass\":'" + (creds.pass ? creds.pass.get() : "NULL") + "', "
		"\"type\":'" + to_string(creds.info.type) + "'"
	" }";
}

int config_proxysql_users(MYSQL* admin, const test_conf_t& test_conf, const vector<user_creds_t>& users) {
	for (const auto& u : users) {
		MYSQL_QUERY_T(admin, ("DELETE FROM mysql_users WHERE username='" + u.user_def.name + "'").c_str());
	}

	// Ensure cleanup of previously cached clear_text 'caching_sha2' passwords
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

	for (const auto& u : users) {
		const string def_hg { _TO_S(u.user_def.def_hg) };
		string attrs {};

		// A user may not have an additional_password configured
		if (u.user_def.addl_pass) {
			string addl_pass {};

			// NOTE: If the primary pass is empty, addl pass must be empty **by spec**
			if (is_empty_pass(u.user_def.prim_pass.get())) {
				addl_pass = {};
			} else if (test_conf.hashed_pass) {
				const char* c_addl_pass { u.hashed_addl_pass_bin.get() };

				if (c_addl_pass) {
					addl_pass = c_addl_pass;
				}
			} else {
				addl_pass = u.user_def.addl_pass.get();
			}

			const string hex_addl_pass { hex(addl_pass) };
			attrs = "{\"additional_password\": \"" + hex_addl_pass + "\"}";
		}

		string insert_query {};

		if (u.user_def.prim_pass) {
			const string prim_pass {
				test_conf.hashed_pass && strlen(u.hashed_prim_pass_bin.get()) > 0 ?
					"UNHEX('" + string { u.hashed_prim_pass_bin.get() } + "')" :
					"'" + string { u.user_def.prim_pass.get() } + "'"
			};

			if (u.user_def.addl_pass) {
				insert_query = {
					"INSERT INTO mysql_users (username,password,default_hostgroup,attributes) "
						"VALUES ('" + u.user_def.name + "'," + prim_pass + "," + def_hg + ",'" + attrs + "')"
				};
			} else {
				insert_query = {
					"INSERT INTO mysql_users (username,password,default_hostgroup) "
						"VALUES ('" + u.user_def.name + "'," + prim_pass + "," + def_hg + ")"
				};
			}
		} else {
			insert_query = {
				"INSERT INTO mysql_users (username,default_hostgroup,attributes) "
					"VALUES ('" + u.user_def.name + "'," + def_hg + ",'" + attrs + "')"
			};
		}

		MYSQL_QUERY_T(admin, insert_query.c_str());
	}

	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

	return EXIT_SUCCESS;
}

#endif
