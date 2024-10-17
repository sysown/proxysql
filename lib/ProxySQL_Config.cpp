#include "proxysql_config.h"
#include "re2/re2.h"
#include "proxysql.h"
#include "cpp.h"

#include <sstream>

const char* config_header = "########################################################################################\n"
							"# This config file is parsed using libconfig , and its grammar is described in:\n"
							"# http://www.hyperrealm.com/libconfig/libconfig_manual.html#Configuration-File-Grammar\n"
							"# Grammar is also copied at the end of this file\n"
							"########################################################################################\n"
							"\n"
							"########################################################################################\n"
							"# IMPORTANT INFORMATION REGARDING THIS CONFIGURATION FILE:\n"
							"########################################################################################\n"
							"# On startup, ProxySQL reads its config file (if present) to determine its datadir.\n"
							"# What happens next depends on if the database file (disk) is present in the defined\n"
							"# datadir (i.e. \"/var/lib/proxysql/proxysql.db\").\n"
							"#\n"
							"# If the database file is found, ProxySQL initializes its in-memory configuration from\n"
							"# the persisted on-disk database. So, disk configuration gets loaded into memory and\n"
							"# then propagated towards the runtime configuration.\n"
							"#\n"
							"# If the database file is not found and a config file exists, the config file is parsed\n"
							"# and its content is loaded into the in-memory database, to then be both saved on-disk\n"
							"# database and loaded at runtime.\n"
							"#\n"
							"# IMPORTANT: If a database file is found, the config file is NOT parsed. In this case\n"
							"#            ProxySQL initializes its in-memory configuration from the persisted on-disk\n"
							"#            database ONLY. In other words, the configuration found in the proxysql.cnf\n"
							"#            file is only used to initial the on-disk database read on the first startup.\n"
							"#\n"
							"# In order to FORCE a re-initialise of the on-disk database from the configuration file\n"
							"# the ProxySQL service should be started with \"service proxysql initial\".\n"
							"#\n"
							"########################################################################################\n";

ProxySQL_Config::ProxySQL_Config(SQLite3DB* db) {
	assert(db);

	admindb = db;	
}

ProxySQL_Config:: ~ProxySQL_Config() {
}

void ProxySQL_Config::addField(std::string& data, const char* name, const char* value, const char* dq) {
	std::stringstream ss;
	if (!value || !strlen(value)) return;

	// Escape the double quotes in all the fields contents
	std::string esc_value { value };
	RE2::GlobalReplace(&esc_value, "\"", "\\\\\"");

	ss << "\t\t" << name << "=" << dq << esc_value.c_str() << dq << "\n";
	data += ss.str();
}

int ProxySQL_Config::Read_Global_Variables_from_configfile(const char *prefix) {
	const Setting& root = GloVars.confFile->cfg.getRoot();
	char *groupname=(char *)malloc(strlen(prefix)+strlen((char *)"_variables")+1);
	sprintf(groupname,"%s%s",prefix,"_variables");
	if (root.exists(groupname)==false) {
		free(groupname);
	return 0;
	}
	const Setting &group = root[(const char *)groupname];
	int count = group.getLength();
	//fprintf(stderr, "Found %d %s_variables\n",count, prefix);
	int i;
	admindb->execute("PRAGMA foreign_keys = OFF");
	char *q=(char *)"INSERT OR REPLACE INTO global_variables VALUES (\"%s-%s\", \"%s\")";
	for (i=0; i< count; i++) {
		const Setting &sett = group[i];
		const char *n=sett.getName();
		bool value_bool;
		int value_int;
		std::string value_string="";
		if (group.lookupValue(n, value_bool)) {
			value_string = (value_bool ? "true" : "false");
		} else {
			if (group.lookupValue(n, value_int)) {
				value_string = std::to_string(value_int);
			} else {
				group.lookupValue(n, value_string);
			}
		}
		//fprintf(stderr,"%s = %s\n", n, value_string.c_str());
		char *query=(char *)malloc(strlen(q)+strlen(prefix)+strlen(n)+strlen(value_string.c_str()));
		sprintf(query,q, prefix, n, value_string.c_str());
		//fprintf(stderr, "%s\n", query);
  	admindb->execute(query);
		free(query);
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	free(groupname);
	return i;
}

int ProxySQL_Config::Write_MySQL_Users_to_configfile(std::string& data) {
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* sqlite_resultset = NULL;

	char *query=(char *)"SELECT * FROM mysql_users";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from mysql_users: %s\n", error);
		return -1;
	} else {
		if (sqlite_resultset) {
			data += "mysql_users:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "username", r->fields[0]);
				addField(data, "password", r->fields[1]);
				addField(data, "active", r->fields[2], "");
				addField(data, "use_ssl", r->fields[3], "");
				addField(data, "default_hostgroup", r->fields[4], "");
				addField(data, "default_schema", r->fields[5]);
				addField(data, "schema_locked", r->fields[6], "");
				addField(data, "transaction_persistent", r->fields[7], "");
				addField(data, "fast_forward", r->fields[8], "");
				addField(data, "backend", r->fields[9], "");
				addField(data, "frontend", r->fields[10], "");
				addField(data, "max_connections", r->fields[11], "");
				addField(data, "attributes", r->fields[12]);
				addField(data, "comment", r->fields[13]);
				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	return 0;
}

int ProxySQL_Config::Read_MySQL_Users_from_configfile() {
	const Setting& root = GloVars.confFile->cfg.getRoot();
	if (root.exists("mysql_users")==false) return 0;
	const Setting &mysql_users = root["mysql_users"];
	int count = mysql_users.getLength();
	//fprintf(stderr, "Found %d users\n",count);
	int i;
	int rows=0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	char *q=(char *)"INSERT OR REPLACE INTO mysql_users (username, password, active, use_ssl, default_hostgroup, default_schema, schema_locked, transaction_persistent, fast_forward, max_connections, attributes, comment) VALUES ('%s', '%s', %d, %d, %d, '%s', %d, %d, %d, %d, '%s','%s')";
	for (i=0; i< count; i++) {
		const Setting &user = mysql_users[i];
		std::string username;
		std::string password="";
		int active=1;
		int use_ssl=0;
		int default_hostgroup=0;
		std::string default_schema="";
		int schema_locked=0;
		int transaction_persistent=1;
		int fast_forward=0;
		int max_connections=10000;
		std::string comment="";
		std::string attributes="";
		if (user.lookupValue("username", username)==false) {
			proxy_error("Admin: detected a mysql_users in config file without a mandatory username\n");
			continue;
		}
		user.lookupValue("password", password);
		user.lookupValue("default_hostgroup", default_hostgroup);
		user.lookupValue("active", active);
		user.lookupValue("use_ssl", use_ssl);
		//if (user.lookupValue("default_schema", default_schema)==false) default_schema="";
		user.lookupValue("default_schema", default_schema);
		user.lookupValue("schema_locked", schema_locked);
		user.lookupValue("transaction_persistent", transaction_persistent);
		user.lookupValue("fast_forward", fast_forward);
		user.lookupValue("max_connections", max_connections);
		user.lookupValue("attributes", attributes);
		user.lookupValue("comment", comment);
		char *o1=strdup(comment.c_str());
		char *o=escape_string_single_quotes(o1, false);
		char *query=(char *)malloc(strlen(q)+strlen(username.c_str())+strlen(password.c_str())+strlen(o)+strlen(attributes.c_str())+128);
		sprintf(query,q, username.c_str(), password.c_str(), active, use_ssl, default_hostgroup, default_schema.c_str(), schema_locked, transaction_persistent, fast_forward, max_connections, attributes.c_str(), o);
		admindb->execute(query);
		if (o!=o1) free(o);
		free(o1);
		free(query);
		rows++;
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
}

int ProxySQL_Config::Write_Scheduler_to_configfile(std::string& data) {
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* sqlite_resultset = NULL;

	char *query=(char *)"SELECT * FROM scheduler";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from scheduler: %s\n", error);
		return -1;
	} else {
		if (sqlite_resultset) {
			data += "scheduler:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "id", r->fields[0], "");
				addField(data, "active", r->fields[1], "");
				addField(data, "interval_ms", r->fields[2], "");
				addField(data, "filename", r->fields[3]);
				addField(data, "arg1", r->fields[4]);
				addField(data, "arg2", r->fields[5]);
				addField(data, "arg3", r->fields[6]);
				addField(data, "arg4", r->fields[7]);
				addField(data, "arg5", r->fields[8]);
				addField(data, "comment", r->fields[9]);

				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	return 0;
}

int ProxySQL_Config::Read_Scheduler_from_configfile() {
	const Setting& root = GloVars.confFile->cfg.getRoot();
	if (root.exists("scheduler")==false) return 0;
	const Setting &schedulers = root["scheduler"];
	int count = schedulers.getLength();
	//fprintf(stderr, "Found %d users\n",count);
	int i;
	int rows=0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	char *q=(char *)"INSERT OR REPLACE INTO scheduler (id, active, interval_ms, filename, arg1, arg2, arg3, arg4, arg5, comment) VALUES (%d, %d, %d, '%s', %s, %s, %s, %s, %s, '%s')";
	for (i=0; i< count; i++) {
		const Setting &sched = schedulers[i];
		int id;
		int active=1;

		std::string filename;

		bool arg1_exists=false;
		std::string arg1;
		bool arg2_exists=false;
		std::string arg2;
		bool arg3_exists=false;
		std::string arg3;
		bool arg4_exists=false;
		std::string arg4;
		bool arg5_exists=false;
		std::string arg5;

		// variable for parsing interval_ms
		int interval_ms=0;

		std::string comment="";

		// validate arguments
		if (sched.lookupValue("id", id)==false) {
			proxy_error("Admin: detected a scheduler in config file without a mandatory id\n");
			continue;
		}
		sched.lookupValue("active", active);
		sched.lookupValue("interval_ms", interval_ms);
		if (sched.lookupValue("filename", filename)==false) {
			proxy_error("Admin: detected a scheduler in config file without a mandatory filename\n");
			continue;
		}
		if (sched.lookupValue("arg1", arg1)) arg1_exists=true;
		if (sched.lookupValue("arg2", arg2)) arg2_exists=true;
		if (sched.lookupValue("arg3", arg3)) arg3_exists=true;
		if (sched.lookupValue("arg4", arg4)) arg4_exists=true;
		if (sched.lookupValue("arg5", arg5)) arg5_exists=true;
		sched.lookupValue("comment", comment);


		int query_len=0;
		query_len+=strlen(q) +
			strlen(std::to_string(id).c_str()) +
			strlen(std::to_string(active).c_str()) +
			strlen(std::to_string(interval_ms).c_str()) +
			strlen(filename.c_str()) +
			( arg1_exists ? strlen(arg1.c_str()) : 0 ) + 4 +
			( arg2_exists ? strlen(arg2.c_str()) : 0 ) + 4 +
			( arg3_exists ? strlen(arg3.c_str()) : 0 ) + 4 +
			( arg4_exists ? strlen(arg4.c_str()) : 0 ) + 4 +
			( arg5_exists ? strlen(arg5.c_str()) : 0 ) + 4 +
			strlen(comment.c_str()) +
			40;
		char *query=(char *)malloc(query_len);
		if (arg1_exists)
			arg1="\'" + arg1 + "\'";
		else
			arg1 = "NULL";
		if (arg2_exists)
			arg2="\'" + arg2 + "\'";
		else
			arg2 = "NULL";
		if (arg3_exists)
			arg3="\'" + arg3 + "\'";
		else
			arg3 = "NULL";
		if (arg4_exists)
			arg4="\'" + arg4 + "\'";
		else
			arg4 = "NULL";
		if (arg5_exists)
			arg5="\'" + arg5 + "\'";
		else
			arg5 = "NULL";

		sprintf(query, q,
			id, active,
			interval_ms,
			filename.c_str(),
			arg1.c_str(),
			arg2.c_str(),
			arg3.c_str(),
			arg4.c_str(),
			arg5.c_str(),
			comment.c_str()
		);
		admindb->execute(query);
		free(query);
		rows++;
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
}

int ProxySQL_Config::Write_Restapi_to_configfile(std::string& data) {
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* sqlite_resultset = NULL;

	char *query=(char *)"SELECT * FROM restapi_routes";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from restapi_router: %s\n", error);
		return -1;
	} else {
		if (sqlite_resultset) {
			data += "restapi:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "id", r->fields[0], "");
				addField(data, "active", r->fields[1], "");
				addField(data, "timeout_ms", r->fields[2], "");
				addField(data, "method", r->fields[3], "");
				addField(data, "uri", r->fields[4]);
				addField(data, "script", r->fields[5]);
				addField(data, "comment", r->fields[6]);

				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	return 0;
}

int ProxySQL_Config::Read_Restapi_from_configfile() {
	const Setting& root = GloVars.confFile->cfg.getRoot();
	if (root.exists("restapi")==false) return 0;
	const Setting &routes = root["restapi"];
	int count = routes.getLength();
	//fprintf(stderr, "Found %d users\n",count);
	int i;
	int rows=0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	char *q=(char *)"INSERT OR REPLACE INTO restapi_routes VALUES (%d, %d, %d, '%s', '%s', '%s', '%s')";
	for (i=0; i< count; i++) {
		const Setting &route = routes[i];
		int id;
		int active=1;
		// variable for parsing timeout_ms
		int timeout_ms=0;

		std::string method;
		std::string uri;
		std::string script;
		std::string comment="";

		// validate arguments
		if (route.lookupValue("id", id)==false) {
			proxy_error("Admin: detected a restapi route in config file without a mandatory id\n");
			continue;
		}
		route.lookupValue("active", active);
		if (route.lookupValue("interval_ms", timeout_ms) == false) {
			route.lookupValue("timeout_ms", timeout_ms);
		}
		if (route.lookupValue("method", method)==false) {
			proxy_error("Admin: detected a restapi route in config file without a mandatory method\n");
			continue;
		}
		if (route.lookupValue("uri", uri)==false) {
			proxy_error("Admin: detected a restapi route in config file without a mandatory uri\n");
			continue;
		}
		if (route.lookupValue("script", script)==false) {
			proxy_error("Admin: detected a restapi route in config file without a mandatory script\n");
			continue;
		}
		route.lookupValue("comment", comment);

		int query_len=0;
		query_len+=strlen(q) +
			strlen(std::to_string(id).c_str()) +
			strlen(std::to_string(active).c_str()) +
			strlen(std::to_string(timeout_ms).c_str()) +
			strlen(method.c_str()) +
			strlen(uri.c_str()) +
			strlen(script.c_str()) +
			strlen(comment.c_str()) +
			40;
		char *query=(char *)malloc(query_len);
		sprintf(query, q,
			id, active,
			timeout_ms,
			method.c_str(),
			uri.c_str(),
			script.c_str(),
			comment.c_str()
		);
		admindb->execute(query);
		free(query);
		rows++;
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
}

int ProxySQL_Config::Write_MySQL_Query_Rules_to_configfile(std::string& data) {
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* sqlite_resultset = NULL;

	char *query=(char *)"SELECT * FROM mysql_query_rules";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from mysql_query_rules : %s\n", error);
		return -1;
	} else {
		if (sqlite_resultset) {
			std::string prefix;
			data += "mysql_query_rules:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "rule_id", r->fields[0], "");
				addField(data, "active", r->fields[1], "");
				addField(data, "username", r->fields[2]);
				addField(data, "schemaname", r->fields[3]);
				addField(data, "flagIN", r->fields[4], "");
				addField(data, "client_addr", r->fields[5]);
				addField(data, "proxy_addr", r->fields[6]);
				addField(data, "proxy_port", r->fields[7], "");
				addField(data, "digest", r->fields[8]);
				addField(data, "match_digest", r->fields[9]);
				addField(data, "match_pattern", r->fields[10]);
				addField(data, "negate_match_pattern", r->fields[11], "");
				addField(data, "re_modifiers", r->fields[12]);
				addField(data, "flagOUT", r->fields[13], "");
				addField(data, "replace_pattern", r->fields[14]);
				addField(data, "destination_hostgroup", r->fields[15], "");
				addField(data, "cache_ttl", r->fields[16], "");
				addField(data, "cache_empty_result", r->fields[17], "");
				addField(data, "cache_timeout", r->fields[18], "");
				addField(data, "reconnect", r->fields[19], "");
				addField(data, "timeout", r->fields[20], "");
				addField(data, "retries", r->fields[21], "");
				addField(data, "delay", r->fields[22], "");
				addField(data, "next_query_flagIN", r->fields[23], "");
				addField(data, "mirror_flagOUT", r->fields[24], "");
				addField(data, "mirror_hostgroup", r->fields[25], "");
				addField(data, "error_msg", r->fields[26]);
				addField(data, "OK_msg", r->fields[27]);
				addField(data, "sticky_conn", r->fields[28], "");
				addField(data, "multiplex", r->fields[29], "");
				addField(data, "gtid_from_hostgroup", r->fields[30], "");
				addField(data, "log", r->fields[31], "");
				addField(data, "apply", r->fields[32], "");
				addField(data, "attributes", r->fields[33]);
				addField(data, "comment", r->fields[34]);

				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	return 0;
}

int ProxySQL_Config::Read_MySQL_Query_Rules_from_configfile() {
	const Setting& root = GloVars.confFile->cfg.getRoot();
	if (root.exists("mysql_query_rules")==false) return 0;
	const Setting &mysql_query_rules = root["mysql_query_rules"];
	int count = mysql_query_rules.getLength();
	//fprintf(stderr, "Found %d users\n",count);
	int i;
	int rows=0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	char *q=(char *)"INSERT OR REPLACE INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, attributes, comment) VALUES (%d, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %d, %s, %s)";
	for (i=0; i< count; i++) {
		const Setting &rule = mysql_query_rules[i];
		int rule_id;
		int active=1;
		bool username_exists=false;
		std::string username;
		bool schemaname_exists=false;
		std::string schemaname;
		int flagIN=0;

		// variables for parsing client_addr
		bool client_addr_exists=false;
		std::string client_addr;

		// variables for parsing proxy_addr
		bool proxy_addr_exists=false;
		std::string proxy_addr;

		// variable for parsing proxy_port
		int proxy_port=-1;

		// variables for parsing digest
		bool digest_exists=false;
		std::string digest;


		bool match_digest_exists=false;
		std::string match_digest;
		bool match_pattern_exists=false;
		std::string match_pattern;
		int negate_match_pattern=0;

		bool re_modifiers_exists=false;
		std::string re_modifiers;

		int flagOUT=-1;
		bool replace_pattern_exists=false;
		std::string replace_pattern;
		int destination_hostgroup=-1;
		int next_query_flagIN=-1;
		int mirror_flagOUT=-1;
		int mirror_hostgroup=-1;
		int cache_ttl=-1;
		int cache_empty_result=-1;
		int cache_timeout=-1;
		int reconnect=-1;
		int timeout=-1;
		int retries=-1;
		int delay=-1;
		bool error_msg_exists=false;
		std::string error_msg;
		bool OK_msg_exists=false;
		std::string OK_msg;

		int sticky_conn=-1;
		int multiplex=-1;
		int gtid_from_hostgroup = -1;

		// variable for parsing log
		int log=-1;

		int apply=0;

		// attributes
		bool attributes_exists=false;
		std::string attributes {};

		bool comment_exists=false;
		std::string comment;

		// validate arguments
		if (rule.lookupValue("rule_id", rule_id)==false) {
			proxy_error("Admin: detected a mysql_query_rules in config file without a mandatory rule_id\n");
			continue;
		}
		rule.lookupValue("active", active);
		if (rule.lookupValue("username", username)) username_exists=true;
		if (rule.lookupValue("schemaname", schemaname)) schemaname_exists=true;
		rule.lookupValue("flagIN", flagIN);

		if (rule.lookupValue("client_addr", client_addr)) client_addr_exists=true;
		if (rule.lookupValue("proxy_addr", proxy_addr)) proxy_addr_exists=true;
		rule.lookupValue("proxy_port", proxy_port);
		if (rule.lookupValue("digest", digest)) digest_exists=true;

		if (rule.lookupValue("match_digest", match_digest)) match_digest_exists=true;
		if (rule.lookupValue("match_pattern", match_pattern)) match_pattern_exists=true;
		rule.lookupValue("negate_match_pattern", negate_match_pattern);
		if (rule.lookupValue("re_modifiers", re_modifiers)) {
		} else {
			re_modifiers = "CASELESS";
		}
		re_modifiers_exists=true;
		rule.lookupValue("flagOUT", flagOUT);
		if (rule.lookupValue("replace_pattern", replace_pattern)) replace_pattern_exists=true;
		rule.lookupValue("destination_hostgroup", destination_hostgroup);
		rule.lookupValue("next_query_flagIN", next_query_flagIN);
		rule.lookupValue("mirror_flagOUT", mirror_flagOUT);
		rule.lookupValue("mirror_hostgroup", mirror_hostgroup);
		rule.lookupValue("cache_ttl", cache_ttl);
		rule.lookupValue("cache_empty_result", cache_empty_result);
		rule.lookupValue("cache_timeout", cache_timeout);
		rule.lookupValue("reconnect", reconnect);
		rule.lookupValue("timeout", timeout);
		rule.lookupValue("retries", retries);
		rule.lookupValue("delay", delay);

		if (rule.lookupValue("error_msg", error_msg)) error_msg_exists=true;
		if (rule.lookupValue("OK_msg", OK_msg)) OK_msg_exists=true;

		rule.lookupValue("sticky_conn", sticky_conn);
		rule.lookupValue("multiplex", multiplex);
		rule.lookupValue("gtid_from_hostgroup", gtid_from_hostgroup);

		rule.lookupValue("log", log);

		rule.lookupValue("apply", apply);
		if (rule.lookupValue("comment", comment)) comment_exists=true;
		if (rule.lookupValue("attributes", attributes)) attributes_exists=true;


		//if (user.lookupValue("default_schema", default_schema)==false) default_schema="";
		int query_len=0;
		query_len+=strlen(q) +
			strlen(std::to_string(rule_id).c_str()) +
			strlen(std::to_string(active).c_str()) +
			( username_exists ? strlen(username.c_str()) : 0 ) + 4 +
			( schemaname_exists ? strlen(schemaname.c_str()) : 0 ) + 4 +
			strlen(std::to_string(flagIN).c_str()) + 4 +

			( client_addr_exists ? strlen(client_addr.c_str()) : 0 ) + 4 +
			( proxy_addr_exists ? strlen(proxy_addr.c_str()) : 0 ) + 4 +
			strlen(std::to_string(proxy_port).c_str()) + 4 +

			( match_digest_exists ? strlen(match_digest.c_str()) : 0 ) + 4 +
			( match_pattern_exists ? strlen(match_pattern.c_str()) : 0 ) + 4 +
			strlen(std::to_string(negate_match_pattern).c_str()) + 4 +
			( re_modifiers_exists ? strlen(re_modifiers.c_str()) : 0 ) + 4 +
			strlen(std::to_string(flagOUT).c_str()) + 4 +
			( replace_pattern_exists ? strlen(replace_pattern.c_str()) : 0 ) + 4 +
			strlen(std::to_string(destination_hostgroup).c_str()) + 4 +
			strlen(std::to_string(cache_ttl).c_str()) + 4 +
			strlen(std::to_string(cache_empty_result).c_str()) + 4 +
			strlen(std::to_string(cache_timeout).c_str()) + 4 +
			strlen(std::to_string(reconnect).c_str()) + 4 +
			strlen(std::to_string(timeout).c_str()) + 4 +
			strlen(std::to_string(next_query_flagIN).c_str()) + 4 +
			strlen(std::to_string(mirror_flagOUT).c_str()) + 4 +
			strlen(std::to_string(mirror_hostgroup).c_str()) + 4 +
			strlen(std::to_string(retries).c_str()) + 4 +
			strlen(std::to_string(delay).c_str()) + 4 +
			( error_msg_exists ? strlen(error_msg.c_str()) : 0 ) + 4 +
			( OK_msg_exists ? strlen(OK_msg.c_str()) : 0 ) + 4 +
			strlen(std::to_string(sticky_conn).c_str()) + 4 +
			strlen(std::to_string(multiplex).c_str()) + 4 +
			strlen(std::to_string(gtid_from_hostgroup).c_str()) + 4 +
			strlen(std::to_string(log).c_str()) + 4 +
			strlen(std::to_string(apply).c_str()) + 4 +
			( attributes_exists ? strlen(attributes.c_str()) : 0 ) + 4 +
			( comment_exists ? strlen(comment.c_str()) : 0 ) + 4 +
			64;
		char *query=(char *)malloc(query_len);
		if (username_exists)
			username="\"" + username + "\"";
		else
			username = "NULL";
		if (schemaname_exists)
			schemaname="\"" + schemaname + "\"";
		else
			schemaname = "NULL";

		if (client_addr_exists)
			client_addr="\"" + client_addr + "\"";
		else
			client_addr = "NULL";
		if (proxy_addr_exists)
			proxy_addr="\"" + proxy_addr + "\"";
		else
			proxy_addr = "NULL";
		if (digest_exists)
			digest="\"" + digest + "\"";
		else
			digest = "NULL";

		if (match_digest_exists)
			match_digest="\"" + match_digest + "\"";
		else
			match_digest = "NULL";
		if (match_pattern_exists)
			match_pattern="\"" + match_pattern + "\"";
		else
			match_pattern = "NULL";
		if (replace_pattern_exists)
			replace_pattern="\"" + replace_pattern + "\"";
		else
			replace_pattern = "NULL";
		if (error_msg_exists)
			error_msg="\"" + error_msg + "\"";
		else
			error_msg = "NULL";
		if (OK_msg_exists)
			OK_msg="\"" + OK_msg + "\"";
		else
			OK_msg = "NULL";
		if (re_modifiers_exists)
			re_modifiers="\"" + re_modifiers + "\"";
		else
			re_modifiers = "NULL";
		if (attributes_exists)
			attributes="'" + attributes + "'";
		else
			attributes = "NULL";
		if (comment_exists)
			comment="'" + comment + "'";
		else
			comment = "NULL";


		sprintf(query, q,
			rule_id, active,
			username.c_str(),
			schemaname.c_str(),
			( flagIN >= 0 ? std::to_string(flagIN).c_str() : "NULL") ,
			client_addr.c_str(),
			proxy_addr.c_str(),
			( proxy_port >= 0 ? std::to_string(proxy_port).c_str() : "NULL") ,
			digest.c_str(),
			match_digest.c_str(),
			match_pattern.c_str(),
			( negate_match_pattern == 0 ? 0 : 1) ,
			re_modifiers.c_str(),
			( flagOUT >= 0 ? std::to_string(flagOUT).c_str() : "NULL") ,
			replace_pattern.c_str(),
			( destination_hostgroup >= 0 ? std::to_string(destination_hostgroup).c_str() : "NULL") ,
			( cache_ttl >= 0 ? std::to_string(cache_ttl).c_str() : "NULL") ,
			( cache_empty_result >= 0 ? std::to_string(cache_empty_result).c_str() : "NULL") ,
			( cache_timeout >= 0 ? std::to_string(cache_timeout).c_str() : "NULL") ,
			( reconnect >= 0 ? std::to_string(reconnect).c_str() : "NULL") ,
			( timeout >= 0 ? std::to_string(timeout).c_str() : "NULL") ,
			( retries >= 0 ? std::to_string(retries).c_str() : "NULL") ,
			( delay >= 0 ? std::to_string(delay).c_str() : "NULL") ,
			( next_query_flagIN >= 0 ? std::to_string(next_query_flagIN).c_str() : "NULL") ,
			( mirror_flagOUT >= 0 ? std::to_string(mirror_flagOUT).c_str() : "NULL") ,
			( mirror_hostgroup >= 0 ? std::to_string(mirror_hostgroup).c_str() : "NULL") ,
			error_msg.c_str(),
			OK_msg.c_str(),
			( sticky_conn >= 0 ? std::to_string(sticky_conn).c_str() : "NULL") ,
			( multiplex >= 0 ? std::to_string(multiplex).c_str() : "NULL") ,
			( gtid_from_hostgroup >= 0 ? std::to_string(gtid_from_hostgroup).c_str() : "NULL") ,
			( log >= 0 ? std::to_string(log).c_str() : "NULL") ,
			( apply == 0 ? 0 : 1) ,
			attributes.c_str(),
			comment.c_str()
		);
		//fprintf(stderr, "%s\n", query);
		admindb->execute(query);
		free(query);
		rows++;
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
}

int ProxySQL_Config::Write_MySQL_Servers_to_configfile(std::string& data) {
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* sqlite_resultset = NULL;

	char *query=(char *)"SELECT * FROM mysql_servers";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from mysql_query_rules : %s\n", error);
		return -1;
	} else {
		if (sqlite_resultset) {
			data += "mysql_servers:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "hostgroup_id", r->fields[0], "");
				addField(data, "hostname", r->fields[1]);
				addField(data, "port", r->fields[2], "");
				addField(data, "gtid_port", r->fields[3], "");
				addField(data, "status", r->fields[4]);
				addField(data, "weight", r->fields[5], "");
				addField(data, "compression", r->fields[6], "");
				addField(data, "max_connections", r->fields[7], "");
				addField(data, "max_replication_lag", r->fields[8], "");
				addField(data, "use_ssl", r->fields[9], "");
				addField(data, "max_latency_ms", r->fields[10], "");
				addField(data, "comment", r->fields[11]);

				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	query=(char *)"SELECT * FROM mysql_replication_hostgroups";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from mysql_replication_hostgroups : %s\n", error);
		return -1;
	} else {
		if (sqlite_resultset) {
			data += "mysql_replication_hostgroups:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "writer_hostgroup", r->fields[0], "");
				addField(data, "reader_hostgroup", r->fields[1], "");
				addField(data, "check_type", r->fields[2]);
				addField(data, "comment", r->fields[3]);

				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	query=(char *)"SELECT * FROM mysql_group_replication_hostgroups";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from mysql_group_replication_hostgroups : %s\n", error);
		return -1;
	} else {
		if (sqlite_resultset) {
			data += "mysql_group_replication_hostgroups:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "writer_hostgroup", r->fields[0], "");
				addField(data, "backup_writer_hostgroup", r->fields[1], "");
				addField(data, "reader_hostgroup", r->fields[2], "");
				addField(data, "offline_hostgroup", r->fields[3], "");
				addField(data, "active", r->fields[4], "");
				addField(data, "max_writers", r->fields[5], "");
				addField(data, "writer_is_also_reader", r->fields[6], "");
				addField(data, "max_transactions_behind", r->fields[7], "");
				addField(data, "comment", r->fields[8]);

				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	query=(char *)"SELECT * FROM mysql_galera_hostgroups";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from mysql_galera_hostgroups: %s\n", error);
		return -1;
	} else {
		if (sqlite_resultset) {
			data += "mysql_galera_hostgroups:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "writer_hostgroup", r->fields[0], "");
				addField(data, "backup_writer_hostgroup", r->fields[1], "");
				addField(data, "reader_hostgroup", r->fields[2], "");
				addField(data, "offline_hostgroup", r->fields[3], "");
				addField(data, "active", r->fields[4], "");
				addField(data, "max_writers", r->fields[5], "");
				addField(data, "writer_is_also_reader", r->fields[6], "");
				addField(data, "max_transactions_behind", r->fields[7], "");
				addField(data, "comment", r->fields[8]);

				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	query=(char *)"SELECT * FROM mysql_aws_aurora_hostgroups";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from mysql_aws_aurora_hostgroups: %s\n", error);
		return -1;
	} else {
		if (sqlite_resultset) {
			data += "mysql_aws_aurora_hostgroups:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "writer_hostgroup", r->fields[0], "");
				addField(data, "reader_hostgroup", r->fields[1], "");
				addField(data, "active", r->fields[2], "");
				addField(data, "aurora_port", r->fields[3], "");
				addField(data, "domain_name", r->fields[4]);
				addField(data, "max_lag_ms", r->fields[5], "");
				addField(data, "check_interval_ms", r->fields[6], "");
				addField(data, "check_timeout_ms", r->fields[7], "");
				addField(data, "writer_is_also_reader", r->fields[8], "");
				addField(data, "new_reader_weight", r->fields[9], "");
				addField(data, "add_lag_ms", r->fields[10], "");
				addField(data, "min_lag_ms", r->fields[11], "");
				addField(data, "lag_num_checks", r->fields[12], "");
				addField(data, "comment", r->fields[13]);

				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	query = (char *)"SELECT * FROM mysql_hostgroup_attributes";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from mysql_hostgroup_attributes: %s\n", error);
		return -1;
	} else {
		if (sqlite_resultset) {
			data += "mysql_hostgroup_attributes:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "hostgroup_id", r->fields[0], "");
				addField(data, "max_num_online_servers", r->fields[1], "");
				addField(data, "autocommit", r->fields[2], "");
				addField(data, "free_connections_pct", r->fields[3], "");
				addField(data, "init_connect", r->fields[4]);
				addField(data, "multiplex", r->fields[5], "");
				addField(data, "connection_warming", r->fields[6], "");
				addField(data, "throttle_connections_per_sec", r->fields[7], "");
				addField(data, "ignore_session_variables", r->fields[8]);
				addField(data, "hostgroup_settings", r->fields[9]);
				addField(data, "servers_defaults", r->fields[10]);
				addField(data, "comment", r->fields[11]);

				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	return 0;
}

int ProxySQL_Config::Read_MySQL_Servers_from_configfile() {
	const Setting& root = GloVars.confFile->cfg.getRoot();
	int i;
	int rows=0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	if (root.exists("mysql_servers")==true) {
		const Setting &mysql_servers = root["mysql_servers"];
		int count = mysql_servers.getLength();
		//fprintf(stderr, "Found %d servers\n",count);
		char *q=(char *)"INSERT OR REPLACE INTO mysql_servers (hostname, port, gtid_port, hostgroup_id, compression, weight, status, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) VALUES (\"%s\", %d, %d, %d, %d, %d, \"%s\", %d, %d, %d, %d, '%s')";
		for (i=0; i< count; i++) {
			const Setting &server = mysql_servers[i];
			std::string address;
			std::string status="ONLINE";
			int port=3306;
			int gtid_port=0;
			int hostgroup;
			int weight=1;
			int compression=0;
			int max_connections=1000; // default
			int max_replication_lag=0; // default
			int use_ssl=0;
			int max_latency_ms=0;
			std::string comment="";
			if (server.lookupValue("address", address)==false) {
				if (server.lookupValue("hostname", address)==false) {
					proxy_error("Admin: detected a mysql_servers in config file without a mandatory hostname\n");
					continue;
				}
			}
			server.lookupValue("port", port);
			server.lookupValue("gtid_port", gtid_port);
			if (server.lookupValue("hostgroup", hostgroup)==false) {
				if (server.lookupValue("hostgroup_id", hostgroup)==false) {
					proxy_error("Admin: detected a mysql_servers in config file without a mandatory hostgroup_id\n");
					continue;
				}
			}
			server.lookupValue("status", status);
			if (
				(strcasecmp(status.c_str(),(char *)"ONLINE"))
				&& (strcasecmp(status.c_str(),(char *)"SHUNNED"))
				&& (strcasecmp(status.c_str(),(char *)"OFFLINE_SOFT"))
				&& (strcasecmp(status.c_str(),(char *)"OFFLINE_HARD"))
			) {
					status="ONLINE";
			}
			server.lookupValue("compression", compression);
			server.lookupValue("weight", weight);
			server.lookupValue("max_connections", max_connections);
			server.lookupValue("max_replication_lag", max_replication_lag);
			server.lookupValue("use_ssl", use_ssl);
			server.lookupValue("max_latency_ms", max_latency_ms);
			server.lookupValue("comment", comment);
			char *o1=strdup(comment.c_str());
			char *o=escape_string_single_quotes(o1, false);
			char *query=(char *)malloc(strlen(q)+strlen(status.c_str())+strlen(address.c_str())+strlen(o)+128);
			sprintf(query,q, address.c_str(), port, gtid_port, hostgroup, compression, weight, status.c_str(), max_connections, max_replication_lag, use_ssl, max_latency_ms, o);
			//fprintf(stderr, "%s\n", query);
			admindb->execute(query);
			if (o!=o1) free(o);
			free(o1);
			free(query);
			rows++;
		}
	}
	if (root.exists("mysql_replication_hostgroups")==true) {
		const Setting &mysql_replication_hostgroups = root["mysql_replication_hostgroups"];
		int count = mysql_replication_hostgroups.getLength();
		char *q=(char *)"INSERT OR REPLACE INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, comment, check_type) VALUES (%d, %d, '%s', '%s')";
		for (i=0; i< count; i++) {
			const Setting &line = mysql_replication_hostgroups[i];
			int writer_hostgroup;
			int reader_hostgroup;
			std::string comment="";
			std::string check_type="";
			if (line.lookupValue("writer_hostgroup", writer_hostgroup)==false) {
				proxy_error("Admin: detected a mysql_replication_hostgroups in config file without a mandatory writer_hostgroup\n");
				continue;
			}
			if (line.lookupValue("reader_hostgroup", reader_hostgroup)==false) {
				proxy_error("Admin: detected a mysql_replication_hostgroups in config file without a mandatory reader_hostgroup\n");
				continue;
			}
			line.lookupValue("comment", comment);
			char *o1=strdup(comment.c_str());
			char *o=escape_string_single_quotes(o1, false);
			line.lookupValue("check_type", check_type);
			if (
				(strcasecmp(check_type.c_str(),(char *)"read_only"))
				&& (strcasecmp(check_type.c_str(),(char *)"innodb_read_only"))
				&& (strcasecmp(check_type.c_str(),(char *)"super_read_only"))
			) {
				check_type="read_only";
			}
			char *t1=strdup(check_type.c_str());
			char *t=escape_string_single_quotes(t1, false);
			char *query=(char *)malloc(strlen(q)+strlen(o)+strlen(t)+32);
			sprintf(query,q, writer_hostgroup, reader_hostgroup, o, t);
			//fprintf(stderr, "%s\n", query);
			admindb->execute(query);
			if (o!=o1) free(o);
			free(o1);
			if (t!=t1) free(t);
			free(t1);
			free(query);
			rows++;
		}
	}
	if (root.exists("mysql_servers_ssl_params")==true) { // mysql_servers_ssl_params
		const Setting &mysql_servers_ssl_params = root["mysql_servers_ssl_params"];
		int count = mysql_servers_ssl_params.getLength();
		char *q=(char *)"INSERT OR REPLACE INTO mysql_servers_ssl_params (hostname, port, username, ssl_ca, ssl_cert, ssl_key, ssl_capath, ssl_crl, ssl_crlpath, ssl_cipher, tls_version, comment) VALUES ('%s', %d, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')";
		for (i=0; i< count; i++) {
			const Setting &line = mysql_servers_ssl_params[i];
			string hostname = "";
			int port = 3306;
			string username = "";
			string ssl_ca = "";
			string ssl_cert = "";
			string ssl_key = "";
			string ssl_capath = "";
			string ssl_crl = "";
			string ssl_crlpath = "";
			string ssl_cipher = "";
			string tls_version = "";
			std::string comment="";
			if (line.lookupValue("hostname", hostname)==false) {
				proxy_error("Admin: detected a mysql_servers_ssl_params in config file without a mandatory hostname\n");
				continue;
			}
			line.lookupValue("port", port);
			line.lookupValue("username", username);
			line.lookupValue("ssl_ca", ssl_ca);
			line.lookupValue("ssl_cert", ssl_cert);
			line.lookupValue("ssl_key", ssl_key);
			line.lookupValue("ssl_capath", ssl_capath);
			line.lookupValue("ssl_crl", ssl_crl);
			line.lookupValue("ssl_crlpath", ssl_crlpath);
			line.lookupValue("ssl_cipher", ssl_cipher);
			line.lookupValue("tls_version", tls_version);
			line.lookupValue("comment", comment);
			char *o1=strdup(comment.c_str());
			char *o=escape_string_single_quotes(o1, false);
			char *query=(char *)malloc(
				strlen(q)
				+ hostname.length() + username.length()
				+ ssl_ca.length() + ssl_cert.length() + ssl_key.length() + ssl_capath.length()
				+ ssl_crl.length() + ssl_crlpath.length() + ssl_cipher.length() + tls_version.length()
				+ strlen(o) + 32);
			sprintf(query, q,
				hostname.c_str() , port , username.c_str() ,
				ssl_ca.c_str() , ssl_cert.c_str() , ssl_key.c_str() , ssl_capath.c_str() ,
				ssl_crl.c_str() , ssl_crlpath.c_str() , ssl_cipher.c_str() , tls_version.c_str() ,
				o);
			admindb->execute(query);
			if (o!=o1) free(o);
			free(o1);
			free(query);
			rows++;
		}
	}
        if (root.exists("mysql_group_replication_hostgroups")==true) {
                const Setting &mysql_group_replication_hostgroups = root["mysql_group_replication_hostgroups"];
                int count = mysql_group_replication_hostgroups.getLength();
                char *q=(char *)"INSERT OR REPLACE INTO mysql_group_replication_hostgroups (writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, max_writers, writer_is_also_reader, max_transactions_behind, comment) VALUES (%d, %d, %d, %d, %d, %d, %d, %d, '%s')";
                for (i=0; i< count; i++) {
                        const Setting &line = mysql_group_replication_hostgroups[i];
                        int writer_hostgroup;
                        int backup_writer_hostgroup;
                        int reader_hostgroup;
                        int offline_hostgroup;
                        int active=1; // default
                        int max_writers;
                        int writer_is_also_reader;
                        int max_transactions_behind;
                        std::string comment="";
                        if (line.lookupValue("writer_hostgroup", writer_hostgroup)==false) {
                            proxy_error("Admin: detected a mysql_group_replication_hostgroups in config file without a mandatory writer_hostgroup\n");
                            continue;
                        }
                        if (line.lookupValue("backup_writer_hostgroup", backup_writer_hostgroup)==false) {
                            proxy_error("Admin: detected a mysql_group_replication_hostgroups in config file without a mandatory backup_writer_hostgroup\n");
                            continue;
                        }
                        if (line.lookupValue("reader_hostgroup", reader_hostgroup)==false) {
                            proxy_error("Admin: detected a mysql_group_replication_hostgroups in config file without a mandatory reader_hostgroup\n");
                            continue;
                        }
                        if (line.lookupValue("offline_hostgroup", offline_hostgroup)==false) {
                            proxy_error("Admin: detected a mysql_group_replication_hostgroups in config file without a mandatory offline_hostgroup\n");
                            continue;
                        }
			if (line.lookupValue("max_writers", max_writers)==false) max_writers=1;
                        if (line.lookupValue("writer_is_also_reader", writer_is_also_reader)==false) writer_is_also_reader=0;
		        if (line.lookupValue("max_transactions_behind", max_transactions_behind)==false) max_transactions_behind=0;
                        line.lookupValue("comment", comment);
                        char *o1=strdup(comment.c_str());
                        char *o=escape_string_single_quotes(o1, false);
                        char *query=(char *)malloc(strlen(q)+strlen(o)+128); // 128 vs sizeof(int)*8
                        sprintf(query,q, writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, max_writers, writer_is_also_reader, max_transactions_behind, o);
                        //fprintf(stderr, "%s\n", query);
                        admindb->execute(query);
                        if (o!=o1) free(o);
                        free(o1);
                        free(query);
                        rows++;
                }
        }
    if (root.exists("mysql_galera_hostgroups")==true) {
            const Setting &mysql_galera_hostgroups = root["mysql_galera_hostgroups"];
            int count = mysql_galera_hostgroups.getLength();
            char *q=(char *)"INSERT OR REPLACE INTO mysql_galera_hostgroups (writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, max_writers, writer_is_also_reader, max_transactions_behind, comment) VALUES (%d, %d, %d, %d, %d, %d, %d, %d, '%s')";
            for (i=0; i< count; i++) {
                    const Setting &line = mysql_galera_hostgroups[i];
                    int writer_hostgroup;
                    int backup_writer_hostgroup;
                    int reader_hostgroup;
                    int offline_hostgroup;
                    int active=1; // default
                    int max_writers;
                    int writer_is_also_reader;
                    int max_transactions_behind;
                    std::string comment="";
                    if (line.lookupValue("writer_hostgroup", writer_hostgroup)==false) {
                        proxy_error("Admin: detected a mysql_galera_hostgroups in config file without a mandatory writer_hostgroup\n");
                        continue;
                    }
                    if (line.lookupValue("backup_writer_hostgroup", backup_writer_hostgroup)==false) {
                        proxy_error("Admin: detected a mysql_galera_hostgroups in config file without a mandatory backup_writer_hostgroup\n");
                        continue;
                    }
                    if (line.lookupValue("reader_hostgroup", reader_hostgroup)==false) {
                        proxy_error("Admin: detected a mysql_galera_hostgroups in config file without a mandatory reader_hostgroup\n");
                        continue;
                    }
                    if (line.lookupValue("offline_hostgroup", offline_hostgroup)==false) {
                        proxy_error("Admin: detected a mysql_galera_hostgroups in config file without a mandatory offline_hostgroup\n");
                        continue;
                    }
                    if (line.lookupValue("max_writers", max_writers)==false) max_writers=1;
                    if (line.lookupValue("writer_is_also_reader", writer_is_also_reader)==false) writer_is_also_reader=0;
                    if (line.lookupValue("max_transactions_behind", max_transactions_behind)==false) max_transactions_behind=0;
                    line.lookupValue("comment", comment);
                    char *o1=strdup(comment.c_str());
                    char *o=escape_string_single_quotes(o1, false);
                    char *query=(char *)malloc(strlen(q)+strlen(o)+128); // 128 vs sizeof(int)*8
                    sprintf(query,q, writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, max_writers, writer_is_also_reader, max_transactions_behind, o);
                    //fprintf(stderr, "%s\n", query);
                    admindb->execute(query);
                    if (o!=o1) free(o);
                    free(o1);
                    free(query);
                    rows++;
            }
    }
    if (root.exists("mysql_aws_aurora_hostgroups")==true) {
            const Setting &mysql_aws_aurora_hostgroups = root["mysql_aws_aurora_hostgroups"];
            int count = mysql_aws_aurora_hostgroups.getLength();
            char *q=(char *)"INSERT OR REPLACE INTO mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment ) VALUES (%d, %d, %d, %d, '%s', %d, %d, %d, %d, %d, %d, %d, %d, '%s')";
            for (i=0; i< count; i++) {
                    const Setting &line = mysql_aws_aurora_hostgroups[i];
                    int writer_hostgroup;
                    int reader_hostgroup;
                    int active=1; // default
					int aurora_port;
                    int max_lag_ms;
                    int add_lag_ms;
                    int min_lag_ms;
                    int lag_num_checks;
                    int check_interval_ms;
                    int check_timeout_ms;
                    int writer_is_also_reader;
					int new_reader_weight;
                    std::string comment="";
                    std::string domain_name="";
                    if (line.lookupValue("writer_hostgroup", writer_hostgroup)==false) {
                        proxy_error("Admin: detected a mysql_aws_aurora_hostgroups in config file without a mandatory writer_hostgroup\n");
                        continue;
                    }
                    if (line.lookupValue("reader_hostgroup", reader_hostgroup)==false) {
                        proxy_error("Admin: detected a mysql_aws_aurora_hostgroups in config file without a mandatory reader_hostgroup\n");
                        continue;
                    }
                    if (line.lookupValue("aurora_port", aurora_port)==false) aurora_port=3306;
                    if (line.lookupValue("max_lag_ms", max_lag_ms)==false) max_lag_ms=600000;
                    if (line.lookupValue("check_interval_ms", check_interval_ms)==false) check_interval_ms=1000;
                    if (line.lookupValue("check_timeout_ms", check_timeout_ms)==false) check_timeout_ms=1000;
                    if (line.lookupValue("writer_is_also_reader", writer_is_also_reader)==false) writer_is_also_reader=0;
                    if (line.lookupValue("new_reader_weight", new_reader_weight)==false) new_reader_weight=1;
                    if (line.lookupValue("add_lag_ms", add_lag_ms)==false) add_lag_ms=30;
                    if (line.lookupValue("min_lag_ms", min_lag_ms)==false) min_lag_ms=30;
                    if (line.lookupValue("lag_num_checks", lag_num_checks)==false) lag_num_checks=1;
                    line.lookupValue("comment", comment);
                    line.lookupValue("domain_name", domain_name);
                    char *o1=strdup(comment.c_str());
                    char *o=escape_string_single_quotes(o1, false);
                    char *p1=strdup(domain_name.c_str());
                    char *p=escape_string_single_quotes(p1, false);
                    char *query=(char *)malloc(strlen(q)+strlen(o)+strlen(p)+256); // 128 vs sizeof(int)*8
                    sprintf(query,q, writer_hostgroup, reader_hostgroup, active, aurora_port, p, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, o);
                    //fprintf(stderr, "%s\n", query);
                    admindb->execute(query);
                    if (o!=o1) free(o);
                    free(o1);
                    if (p!=p1) free(p);
                    free(p1);
                    free(query);
                    rows++;
            }
    }
	if (root.exists("mysql_hostgroup_attributes") == true) {
		const Setting &mysql_hostgroup_attributes = root["mysql_hostgroup_attributes"];
		int count = mysql_hostgroup_attributes.getLength();

		for (i = 0; i < count; i++) {
			const Setting &hostgroup_attributes = mysql_hostgroup_attributes[i];
			bool is_first_field = true;
			int integer_val = 0;
			std::string string_val = "";
			std::string fields = "";
			std::string values = "";

			auto process_field = [&](const std::string &field_name, const std::string &field_value, int is_int) {
				if (!is_first_field) {
					fields += ", ";
					values += ", ";
				}
				else {
					is_first_field = false;
				}
				fields += field_name;

				if (is_int) {
					values += field_value;
				}
				else {
					char *cs = strdup(field_value.c_str());
					char *ecs = escape_string_single_quotes(cs, false);
					values +=  std::string("'") + ecs + "'";
					if (cs != ecs) free(cs);
					free(ecs);
				}
			};

			// Only inserting/updating fields which are in configuration file.
			// Fields default will be from table schema.

			// Parsing integer field
			if (hostgroup_attributes.lookupValue("hostgroup_id", integer_val) ) {
				process_field("hostgroup_id", to_string(integer_val), true);
			}
			else {
				proxy_error("Admin: detected a mysql_hostgroup_attributes in config file without a mandatory hostgroup_id.\n");
				continue;
			}
			if (hostgroup_attributes.lookupValue("max_num_online_servers", integer_val)) {
				process_field("max_num_online_servers", to_string(integer_val), true);
			}
			if (hostgroup_attributes.lookupValue("autocommit", integer_val)) {
				process_field("autocommit", to_string(integer_val), true);
			}
			if (hostgroup_attributes.lookupValue("free_connections_pct", integer_val)) {
				process_field("free_connections_pct", to_string(integer_val), true);
			}
			if (hostgroup_attributes.lookupValue("multiplex", integer_val)) {
				process_field("multiplex", to_string(integer_val), true);
			}
			if (hostgroup_attributes.lookupValue("connection_warming", integer_val)) {
				process_field("connection_warming", to_string(integer_val), true);
			}
			if (hostgroup_attributes.lookupValue("throttle_connections_per_sec", integer_val)) {
				process_field("throttle_connections_per_sec", to_string(integer_val), true);
			}
			// Parsing string field
			if (hostgroup_attributes.lookupValue("init_connect", string_val)) {
				process_field("init_connect", string_val, false);
			}
			if (hostgroup_attributes.lookupValue("ignore_session_variables", string_val)) {
				process_field("ignore_session_variables", string_val, false);
			}
			if (hostgroup_attributes.lookupValue("hostgroup_settings", string_val)) {
				process_field("hostgroup_settings", string_val, false);
			}
			if (hostgroup_attributes.lookupValue("servers_defaults", string_val)) {
				process_field("servers_defaults", string_val, false);
			}
			if (hostgroup_attributes.lookupValue("comment", string_val)) {
				process_field("comment", string_val, false);
			}

			std::string s_query = "INSERT OR REPLACE INTO mysql_hostgroup_attributes (";
			s_query  += fields + ") VALUES (" + values + ")";

			//fprintf(stderr, "%s\n", s_query.c_str());
			if (admindb->execute(s_query.c_str()) == false) {
				proxy_error("Admin: detected a mysql_hostgroup_attributes invalid value. Failed to insert in the table.\n");
				continue;
			}
			rows++;
		}
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
}

int ProxySQL_Config::Write_ProxySQL_Servers_to_configfile(std::string& data) {
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* sqlite_resultset = NULL;

	char *query=(char *)"SELECT * FROM proxysql_servers";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from proxysql_servers: %s\n", error);
		return -1;
	} else {
		if (sqlite_resultset) {
			data += "proxysql_servers:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "hostname", r->fields[0]);
				addField(data, "port", r->fields[1], "");
				addField(data, "weight", r->fields[2], "");
				addField(data, "comment", r->fields[3]);

				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	return 0;
}

int ProxySQL_Config::Read_ProxySQL_Servers_from_configfile() {
	const Setting& root = GloVars.confFile->cfg.getRoot();
	int i;
	int rows=0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	if (root.exists("proxysql_servers")==true) {
		const Setting & proxysql_servers = root["proxysql_servers"];
		int count = proxysql_servers.getLength();
		//fprintf(stderr, "Found %d servers\n",count);
		char *q=(char *)"INSERT OR REPLACE INTO proxysql_servers (hostname, port, weight, comment) VALUES (\"%s\", %d, %d, '%s')";
		for (i=0; i< count; i++) {
			const Setting &server = proxysql_servers[i];
			std::string address;
			int port;
			int weight=0;
			std::string comment="";
			if (server.lookupValue("address", address)==false) {
				if (server.lookupValue("hostname", address)==false) {
					proxy_error("Admin: detected a proxysql_servers in config file without a mandatory hostname\n");
					continue;
				}
			}
			if (server.lookupValue("port", port)==false) {
				proxy_error("Admin: detected a proxysql_servers in config file without a mandatory port\n");
				continue;
			}
			server.lookupValue("weight", weight);
			server.lookupValue("comment", comment);
			char *o1=strdup(comment.c_str());
			char *o=escape_string_single_quotes(o1, false);
			char *query=(char *)malloc(strlen(q)+strlen(address.c_str())+strlen(o)+128);
			sprintf(query, q, address.c_str(), port, weight, o);
			proxy_info("Cluster: Adding ProxySQL Servers %s:%d from config file\n", address.c_str(), port);
			//fprintf(stderr, "%s\n", query);
			admindb->execute(query);
			if (o!=o1) free(o);
			free(o1);
			free(query);
			rows++;
		}
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
}

int ProxySQL_Config::Write_Global_Variables_to_configfile(std::string& data) {
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* sqlite_resultset = NULL;

	char *query=(char *)"SELECT variable_name, variable_value FROM global_variables ORDER BY variable_name";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from global_variables : %s\n", error);
		return -1;
	} else {
		if (sqlite_resultset) {
			std::string prefix;

			for (auto r : sqlite_resultset->rows) {
				std::string input(r->fields[0]);
				std::string p1 = input.substr(0, input.find("-"));
				if (prefix.empty()) {
					prefix = input.substr(0, input.find("-"));
					data += prefix + "_variables =\n{\n";
				} else {
					if (p1.compare(prefix)) {
						prefix = p1;
						data += "}\n\n" + prefix + "_variables = \n{\n";
					}
				}
				if (r->fields[1] && strlen(r->fields[1])) {
					std::stringstream ss;
					ss << "\t" << r->fields[0] + p1.size() + 1 << "=\"" << r->fields[1] << "\"\n";
					data += ss.str();
				}
			}

			if (!prefix.empty())
				data += "}\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	return 0;
}

int ProxySQL_Config::Write_PgSQL_Servers_to_configfile(std::string& data) {
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* sqlite_resultset = NULL;

	char* query = (char*)"SELECT * FROM pgsql_servers";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from pgsql_servers : %s\n", error);
		return -1;
	}
	else {
		if (sqlite_resultset) {
			data += "pgsql_servers:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "hostgroup_id", r->fields[0], "");
				addField(data, "hostname", r->fields[1]);
				addField(data, "port", r->fields[2], "");
				addField(data, "status", r->fields[3]);
				addField(data, "weight", r->fields[4], "");
				addField(data, "compression", r->fields[5], "");
				addField(data, "max_connections", r->fields[6], "");
				addField(data, "max_replication_lag", r->fields[7], "");
				addField(data, "use_ssl", r->fields[8], "");
				addField(data, "max_latency_ms", r->fields[9], "");
				addField(data, "comment", r->fields[10]);

				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	query = (char*)"SELECT * FROM pgsql_replication_hostgroups";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from pgsql_replication_hostgroups : %s\n", error);
		return -1;
	}
	else {
		if (sqlite_resultset) {
			data += "pgsql_replication_hostgroups:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "writer_hostgroup", r->fields[0], "");
				addField(data, "reader_hostgroup", r->fields[1], "");
				addField(data, "check_type", r->fields[2]);
				addField(data, "comment", r->fields[3]);

				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	return 0;
}

int ProxySQL_Config::Read_PgSQL_Servers_from_configfile() {
	const Setting& root = GloVars.confFile->cfg.getRoot();
	int i;
	int rows = 0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	if (root.exists("pgsql_servers") == true) {
		const Setting& pgsql_servers = root["pgsql_servers"];
		int count = pgsql_servers.getLength();
		//fprintf(stderr, "Found %d servers\n",count);
		char* q = (char*)"INSERT OR REPLACE INTO pgsql_servers (hostname, port, hostgroup_id, compression, weight, status, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) VALUES (\"%s\", %d, %d, %d, %d, \"%s\", %d, %d, %d, %d, '%s')";
		for (i = 0; i < count; i++) {
			const Setting& server = pgsql_servers[i];
			std::string address;
			std::string status = "ONLINE";
			int port = 5432;
			int hostgroup;
			int weight = 1;
			int compression = 0;
			int max_connections = 1000; // default
			int max_replication_lag = 0; // default
			int use_ssl = 0;
			int max_latency_ms = 0;
			std::string comment = "";
			if (server.lookupValue("address", address) == false) {
				if (server.lookupValue("hostname", address) == false) {
					proxy_error("Admin: detected a pgsql_servers in config file without a mandatory hostname\n");
					continue;
				}
			}
			server.lookupValue("port", port);
			if (server.lookupValue("hostgroup", hostgroup) == false) {
				if (server.lookupValue("hostgroup_id", hostgroup) == false) {
					proxy_error("Admin: detected a pgsql_servers in config file without a mandatory hostgroup_id\n");
					continue;
				}
			}
			server.lookupValue("status", status);
			if (
				(strcasecmp(status.c_str(), (char*)"ONLINE"))
				&& (strcasecmp(status.c_str(), (char*)"SHUNNED"))
				&& (strcasecmp(status.c_str(), (char*)"OFFLINE_SOFT"))
				&& (strcasecmp(status.c_str(), (char*)"OFFLINE_HARD"))
				) {
				status = "ONLINE";
			}
			server.lookupValue("compression", compression);
			server.lookupValue("weight", weight);
			server.lookupValue("max_connections", max_connections);
			server.lookupValue("max_replication_lag", max_replication_lag);
			server.lookupValue("use_ssl", use_ssl);
			server.lookupValue("max_latency_ms", max_latency_ms);
			server.lookupValue("comment", comment);
			char* o1 = strdup(comment.c_str());
			char* o = escape_string_single_quotes(o1, false);
			char* query = (char*)malloc(strlen(q) + strlen(status.c_str()) + strlen(address.c_str()) + strlen(o) + 128);
			sprintf(query, q, address.c_str(), port, hostgroup, compression, weight, status.c_str(), max_connections, max_replication_lag, use_ssl, max_latency_ms, o);
			//fprintf(stderr, "%s\n", query);
			admindb->execute(query);
			if (o != o1) free(o);
			free(o1);
			free(query);
			rows++;
		}
	}
	if (root.exists("pgsql_replication_hostgroups") == true) {
		const Setting& pgsql_replication_hostgroups = root["pgsql_replication_hostgroups"];
		int count = pgsql_replication_hostgroups.getLength();
		char* q = (char*)"INSERT OR REPLACE INTO pgsql_replication_hostgroups (writer_hostgroup, reader_hostgroup, comment, check_type) VALUES (%d, %d, '%s', '%s')";
		for (i = 0; i < count; i++) {
			const Setting& line = pgsql_replication_hostgroups[i];
			int writer_hostgroup;
			int reader_hostgroup;
			std::string comment = "";
			std::string check_type = "";
			if (line.lookupValue("writer_hostgroup", writer_hostgroup) == false) {
				proxy_error("Admin: detected a pgsql_replication_hostgroups in config file without a mandatory writer_hostgroup\n");
				continue;
			}
			if (line.lookupValue("reader_hostgroup", reader_hostgroup) == false) {
				proxy_error("Admin: detected a pgsql_replication_hostgroups in config file without a mandatory reader_hostgroup\n");
				continue;
			}
			line.lookupValue("comment", comment);
			char* o1 = strdup(comment.c_str());
			char* o = escape_string_single_quotes(o1, false);
			line.lookupValue("check_type", check_type);
			if (
				(strcasecmp(check_type.c_str(), (char*)"read_only"))
				&& (strcasecmp(check_type.c_str(), (char*)"innodb_read_only"))
				&& (strcasecmp(check_type.c_str(), (char*)"super_read_only"))
				) {
				check_type = "read_only";
			}
			char* t1 = strdup(check_type.c_str());
			char* t = escape_string_single_quotes(t1, false);
			char* query = (char*)malloc(strlen(q) + strlen(o) + strlen(t) + 32);
			sprintf(query, q, writer_hostgroup, reader_hostgroup, o, t);
			//fprintf(stderr, "%s\n", query);
			admindb->execute(query);
			if (o != o1) free(o);
			free(o1);
			if (t != t1) free(t);
			free(t1);
			free(query);
			rows++;
		}
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
}

int ProxySQL_Config::Write_PgSQL_Users_to_configfile(std::string& data) {
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* sqlite_resultset = NULL;

	char* query = (char*)"SELECT * FROM pgsql_users";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from pgsql_users: %s\n", error);
		return -1;
	}
	else {
		if (sqlite_resultset) {
			data += "pgsql_users:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "username", r->fields[0]);
				addField(data, "password", r->fields[1]);
				addField(data, "active", r->fields[2], "");
				addField(data, "use_ssl", r->fields[3], "");
				addField(data, "default_hostgroup", r->fields[4], "");
				addField(data, "transaction_persistent", r->fields[5], "");
				addField(data, "fast_forward", r->fields[6], "");
				addField(data, "backend", r->fields[7], "");
				addField(data, "frontend", r->fields[8], "");
				addField(data, "max_connections", r->fields[9], "");
				addField(data, "attributes", r->fields[10]);
				addField(data, "comment", r->fields[11]);
				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	return 0;
}

int ProxySQL_Config::Read_PgSQL_Users_from_configfile() {
	const Setting& root = GloVars.confFile->cfg.getRoot();
	if (root.exists("pgsql_users") == false) return 0;
	const Setting& pgsql_users = root["pgsql_users"];
	int count = pgsql_users.getLength();
	//fprintf(stderr, "Found %d users\n",count);
	int i;
	int rows = 0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	char* q = (char*)"INSERT OR REPLACE INTO pgsql_users (username, password, active, use_ssl, default_hostgroup, transaction_persistent, fast_forward, max_connections, attributes, comment) VALUES ('%s', '%s', %d, %d, %d, %d, %d, %d, '%s','%s')";
	for (i = 0; i < count; i++) {
		const Setting& user = pgsql_users[i];
		std::string username;
		std::string password = "";
		int active = 1;
		int use_ssl = 0;
		int default_hostgroup = 0;
		int transaction_persistent = 1;
		int fast_forward = 0;
		int max_connections = 10000;
		std::string comment = "";
		std::string attributes = "";
		if (user.lookupValue("username", username) == false) {
			proxy_error("Admin: detected a pgsql_users in config file without a mandatory username\n");
			continue;
		}
		user.lookupValue("password", password);
		user.lookupValue("default_hostgroup", default_hostgroup);
		user.lookupValue("active", active);
		user.lookupValue("use_ssl", use_ssl);
		//if (user.lookupValue("default_schema", default_schema)==false) default_schema="";
		user.lookupValue("transaction_persistent", transaction_persistent);
		user.lookupValue("fast_forward", fast_forward);
		user.lookupValue("max_connections", max_connections);
		user.lookupValue("attributes", attributes);
		user.lookupValue("comment", comment);
		char* o1 = strdup(comment.c_str());
		char* o = escape_string_single_quotes(o1, false);
		char* query = (char*)malloc(strlen(q) + strlen(username.c_str()) + strlen(password.c_str()) + strlen(o) + strlen(attributes.c_str()) + 128);
		sprintf(query, q, username.c_str(), password.c_str(), active, use_ssl, default_hostgroup, transaction_persistent, fast_forward, max_connections, attributes.c_str(), o);
		admindb->execute(query);
		if (o != o1) free(o);
		free(o1);
		free(query);
		rows++;
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
}

int ProxySQL_Config::Write_PgSQL_Query_Rules_to_configfile(std::string& data) {
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* sqlite_resultset = NULL;

	char* query = (char*)"SELECT * FROM pgsql_query_rules";
	admindb->execute_statement(query, &error, &cols, &affected_rows, &sqlite_resultset);
	if (error) {
		proxy_error("Error on read from pgsql_query_rules : %s\n", error);
		return -1;
	}
	else {
		if (sqlite_resultset) {
			std::string prefix;
			data += "pgsql_query_rules:\n(\n";
			bool isNext = false;
			for (auto r : sqlite_resultset->rows) {
				if (isNext)
					data += ",\n";
				data += "\t{\n";
				addField(data, "rule_id", r->fields[0], "");
				addField(data, "active", r->fields[1], "");
				addField(data, "username", r->fields[2]);
				addField(data, "database", r->fields[3]);
				addField(data, "flagIN", r->fields[4], "");
				addField(data, "client_addr", r->fields[5]);
				addField(data, "proxy_addr", r->fields[6]);
				addField(data, "proxy_port", r->fields[7], "");
				addField(data, "digest", r->fields[8]);
				addField(data, "match_digest", r->fields[9]);
				addField(data, "match_pattern", r->fields[10]);
				addField(data, "negate_match_pattern", r->fields[11], "");
				addField(data, "re_modifiers", r->fields[12]);
				addField(data, "flagOUT", r->fields[13], "");
				addField(data, "replace_pattern", r->fields[14]);
				addField(data, "destination_hostgroup", r->fields[15], "");
				addField(data, "cache_ttl", r->fields[16], "");
				addField(data, "cache_empty_result", r->fields[17], "");
				addField(data, "cache_timeout", r->fields[18], "");
				addField(data, "reconnect", r->fields[19], "");
				addField(data, "timeout", r->fields[20], "");
				addField(data, "retries", r->fields[21], "");
				addField(data, "delay", r->fields[22], "");
				addField(data, "next_query_flagIN", r->fields[23], "");
				addField(data, "mirror_flagOUT", r->fields[24], "");
				addField(data, "mirror_hostgroup", r->fields[25], "");
				addField(data, "error_msg", r->fields[26]);
				addField(data, "OK_msg", r->fields[27]);
				addField(data, "sticky_conn", r->fields[28], "");
				addField(data, "multiplex", r->fields[29], "");
				addField(data, "log", r->fields[30], "");
				addField(data, "apply", r->fields[31], "");
				addField(data, "attributes", r->fields[32]);
				addField(data, "comment", r->fields[33]);

				data += "\t}";
				isNext = true;
			}
			data += "\n)\n";
		}
	}

	if (sqlite_resultset)
		delete sqlite_resultset;

	return 0;
}


int ProxySQL_Config::Read_PgSQL_Query_Rules_from_configfile() {
	const Setting& root = GloVars.confFile->cfg.getRoot();
	if (root.exists("pgsql_query_rules") == false) return 0;
	const Setting& pgsql_query_rules = root["pgsql_query_rules"];
	int count = pgsql_query_rules.getLength();
	//fprintf(stderr, "Found %d users\n",count);
	int i;
	int rows = 0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	char* q = (char*)"INSERT OR REPLACE INTO pgsql_query_rules (rule_id, active, username, database, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, log, apply, attributes, comment) VALUES (%d, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %d, %s, %s)";
	for (i = 0; i < count; i++) {
		const Setting& rule = pgsql_query_rules[i];
		int rule_id;
		int active = 1;
		bool username_exists = false;
		std::string username;
		bool database_exists = false;
		std::string database;
		int flagIN = 0;

		// variables for parsing client_addr
		bool client_addr_exists = false;
		std::string client_addr;

		// variables for parsing proxy_addr
		bool proxy_addr_exists = false;
		std::string proxy_addr;

		// variable for parsing proxy_port
		int proxy_port = -1;

		// variables for parsing digest
		bool digest_exists = false;
		std::string digest;


		bool match_digest_exists = false;
		std::string match_digest;
		bool match_pattern_exists = false;
		std::string match_pattern;
		int negate_match_pattern = 0;

		bool re_modifiers_exists = false;
		std::string re_modifiers;

		int flagOUT = -1;
		bool replace_pattern_exists = false;
		std::string replace_pattern;
		int destination_hostgroup = -1;
		int next_query_flagIN = -1;
		int mirror_flagOUT = -1;
		int mirror_hostgroup = -1;
		int cache_ttl = -1;
		int cache_empty_result = -1;
		int cache_timeout = -1;
		int reconnect = -1;
		int timeout = -1;
		int retries = -1;
		int delay = -1;
		bool error_msg_exists = false;
		std::string error_msg;
		bool OK_msg_exists = false;
		std::string OK_msg;

		int sticky_conn = -1;
		int multiplex = -1;

		// variable for parsing log
		int log = -1;

		int apply = 0;

		// attributes
		bool attributes_exists = false;
		std::string attributes{};

		bool comment_exists = false;
		std::string comment;

		// validate arguments
		if (rule.lookupValue("rule_id", rule_id) == false) {
			proxy_error("Admin: detected a pgsql_query_rules in config file without a mandatory rule_id\n");
			continue;
		}
		rule.lookupValue("active", active);
		if (rule.lookupValue("username", username)) username_exists = true;
		if (rule.lookupValue("database", database)) database_exists = true;
		rule.lookupValue("flagIN", flagIN);

		if (rule.lookupValue("client_addr", client_addr)) client_addr_exists = true;
		if (rule.lookupValue("proxy_addr", proxy_addr)) proxy_addr_exists = true;
		rule.lookupValue("proxy_port", proxy_port);
		if (rule.lookupValue("digest", digest)) digest_exists = true;

		if (rule.lookupValue("match_digest", match_digest)) match_digest_exists = true;
		if (rule.lookupValue("match_pattern", match_pattern)) match_pattern_exists = true;
		rule.lookupValue("negate_match_pattern", negate_match_pattern);
		if (rule.lookupValue("re_modifiers", re_modifiers)) {
		}
		else {
			re_modifiers = "CASELESS";
		}
		re_modifiers_exists = true;
		rule.lookupValue("flagOUT", flagOUT);
		if (rule.lookupValue("replace_pattern", replace_pattern)) replace_pattern_exists = true;
		rule.lookupValue("destination_hostgroup", destination_hostgroup);
		rule.lookupValue("next_query_flagIN", next_query_flagIN);
		rule.lookupValue("mirror_flagOUT", mirror_flagOUT);
		rule.lookupValue("mirror_hostgroup", mirror_hostgroup);
		rule.lookupValue("cache_ttl", cache_ttl);
		rule.lookupValue("cache_empty_result", cache_empty_result);
		rule.lookupValue("cache_timeout", cache_timeout);
		rule.lookupValue("reconnect", reconnect);
		rule.lookupValue("timeout", timeout);
		rule.lookupValue("retries", retries);
		rule.lookupValue("delay", delay);

		if (rule.lookupValue("error_msg", error_msg)) error_msg_exists = true;
		if (rule.lookupValue("OK_msg", OK_msg)) OK_msg_exists = true;

		rule.lookupValue("sticky_conn", sticky_conn);
		rule.lookupValue("multiplex", multiplex);

		rule.lookupValue("log", log);

		rule.lookupValue("apply", apply);
		if (rule.lookupValue("comment", comment)) comment_exists = true;
		if (rule.lookupValue("attributes", attributes)) attributes_exists = true;


		//if (user.lookupValue("default_schema", default_schema)==false) default_schema="";
		int query_len = 0;
		query_len += strlen(q) +
			strlen(std::to_string(rule_id).c_str()) +
			strlen(std::to_string(active).c_str()) +
			(username_exists ? strlen(username.c_str()) : 0) + 4 +
			(database_exists ? strlen(database.c_str()) : 0) + 4 +
			strlen(std::to_string(flagIN).c_str()) + 4 +

			(client_addr_exists ? strlen(client_addr.c_str()) : 0) + 4 +
			(proxy_addr_exists ? strlen(proxy_addr.c_str()) : 0) + 4 +
			strlen(std::to_string(proxy_port).c_str()) + 4 +

			(match_digest_exists ? strlen(match_digest.c_str()) : 0) + 4 +
			(match_pattern_exists ? strlen(match_pattern.c_str()) : 0) + 4 +
			strlen(std::to_string(negate_match_pattern).c_str()) + 4 +
			(re_modifiers_exists ? strlen(re_modifiers.c_str()) : 0) + 4 +
			strlen(std::to_string(flagOUT).c_str()) + 4 +
			(replace_pattern_exists ? strlen(replace_pattern.c_str()) : 0) + 4 +
			strlen(std::to_string(destination_hostgroup).c_str()) + 4 +
			strlen(std::to_string(cache_ttl).c_str()) + 4 +
			strlen(std::to_string(cache_empty_result).c_str()) + 4 +
			strlen(std::to_string(cache_timeout).c_str()) + 4 +
			strlen(std::to_string(reconnect).c_str()) + 4 +
			strlen(std::to_string(timeout).c_str()) + 4 +
			strlen(std::to_string(next_query_flagIN).c_str()) + 4 +
			strlen(std::to_string(mirror_flagOUT).c_str()) + 4 +
			strlen(std::to_string(mirror_hostgroup).c_str()) + 4 +
			strlen(std::to_string(retries).c_str()) + 4 +
			strlen(std::to_string(delay).c_str()) + 4 +
			(error_msg_exists ? strlen(error_msg.c_str()) : 0) + 4 +
			(OK_msg_exists ? strlen(OK_msg.c_str()) : 0) + 4 +
			strlen(std::to_string(sticky_conn).c_str()) + 4 +
			strlen(std::to_string(multiplex).c_str()) + 4 +
			strlen(std::to_string(log).c_str()) + 4 +
			strlen(std::to_string(apply).c_str()) + 4 +
			(attributes_exists ? strlen(attributes.c_str()) : 0) + 4 +
			(comment_exists ? strlen(comment.c_str()) : 0) + 4 +
			64;
		char* query = (char*)malloc(query_len);
		if (username_exists)
			username = "\"" + username + "\"";
		else
			username = "NULL";
		if (database_exists)
			database = "\"" + database + "\"";
		else
			database = "NULL";

		if (client_addr_exists)
			client_addr = "\"" + client_addr + "\"";
		else
			client_addr = "NULL";
		if (proxy_addr_exists)
			proxy_addr = "\"" + proxy_addr + "\"";
		else
			proxy_addr = "NULL";
		if (digest_exists)
			digest = "\"" + digest + "\"";
		else
			digest = "NULL";

		if (match_digest_exists)
			match_digest = "\"" + match_digest + "\"";
		else
			match_digest = "NULL";
		if (match_pattern_exists)
			match_pattern = "\"" + match_pattern + "\"";
		else
			match_pattern = "NULL";
		if (replace_pattern_exists)
			replace_pattern = "\"" + replace_pattern + "\"";
		else
			replace_pattern = "NULL";
		if (error_msg_exists)
			error_msg = "\"" + error_msg + "\"";
		else
			error_msg = "NULL";
		if (OK_msg_exists)
			OK_msg = "\"" + OK_msg + "\"";
		else
			OK_msg = "NULL";
		if (re_modifiers_exists)
			re_modifiers = "\"" + re_modifiers + "\"";
		else
			re_modifiers = "NULL";
		if (attributes_exists)
			attributes = "'" + attributes + "'";
		else
			attributes = "NULL";
		if (comment_exists)
			comment = "'" + comment + "'";
		else
			comment = "NULL";


		sprintf(query, q,
			rule_id, active,
			username.c_str(),
			database.c_str(),
			(flagIN >= 0 ? std::to_string(flagIN).c_str() : "NULL"),
			client_addr.c_str(),
			proxy_addr.c_str(),
			(proxy_port >= 0 ? std::to_string(proxy_port).c_str() : "NULL"),
			digest.c_str(),
			match_digest.c_str(),
			match_pattern.c_str(),
			(negate_match_pattern == 0 ? 0 : 1),
			re_modifiers.c_str(),
			(flagOUT >= 0 ? std::to_string(flagOUT).c_str() : "NULL"),
			replace_pattern.c_str(),
			(destination_hostgroup >= 0 ? std::to_string(destination_hostgroup).c_str() : "NULL"),
			(cache_ttl >= 0 ? std::to_string(cache_ttl).c_str() : "NULL"),
			(cache_empty_result >= 0 ? std::to_string(cache_empty_result).c_str() : "NULL"),
			(cache_timeout >= 0 ? std::to_string(cache_timeout).c_str() : "NULL"),
			(reconnect >= 0 ? std::to_string(reconnect).c_str() : "NULL"),
			(timeout >= 0 ? std::to_string(timeout).c_str() : "NULL"),
			(retries >= 0 ? std::to_string(retries).c_str() : "NULL"),
			(delay >= 0 ? std::to_string(delay).c_str() : "NULL"),
			(next_query_flagIN >= 0 ? std::to_string(next_query_flagIN).c_str() : "NULL"),
			(mirror_flagOUT >= 0 ? std::to_string(mirror_flagOUT).c_str() : "NULL"),
			(mirror_hostgroup >= 0 ? std::to_string(mirror_hostgroup).c_str() : "NULL"),
			error_msg.c_str(),
			OK_msg.c_str(),
			(sticky_conn >= 0 ? std::to_string(sticky_conn).c_str() : "NULL"),
			(multiplex >= 0 ? std::to_string(multiplex).c_str() : "NULL"),
			(log >= 0 ? std::to_string(log).c_str() : "NULL"),
			(apply == 0 ? 0 : 1),
			attributes.c_str(),
			comment.c_str()
		);
		//fprintf(stderr, "%s\n", query);
		admindb->execute(query);
		free(query);
		rows++;
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
}
