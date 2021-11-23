#include <vector>
#include <iostream>
#include <string>
#include <unordered_map>
#include <stdlib.h>
#include <string.h>

std::vector<std::string> bool_values = {
	"0", "1",
	"ON", "OFF",
	"oN", "Off",
	"`ON`", "`OFF`",
	"\"ON\"", "\"OFF\"",
};

std::vector<int> int_values = {
	10, 20, 100, 1010, 1234, 3456, 7890, 34564, 68100, 123456, 456123
};

std::vector<int> int_values_small = {
	13, 32, 110, 310, 434, 558, 789
};

std::unordered_map<std::string, std::string> fixed_sets = {
	{ "SET session transaction read only", "{'transaction_read_only':'ON'}" },
	{ "SET session transaction read write", "{'transaction_read_only':'OFF'}" },
	{ "SET session transaction isolation level READ COMMITTED", "{'transaction_isolation':'READ-COMMITTED'}" },
	{ "SET session transaction isolation level READ UNCOMMITTED", "{'transaction_isolation':'READ-UNCOMMITTED'}" },
	{ "SET session transaction isolation level REPEATABLE READ", "{'transaction_isolation':'REPEATABLE-READ'}" },
	{ "SET session transaction isolation level SERIALIZABLE", "{'transaction_isolation':'SERIALIZABLE'}" }
};

class variable {
	public:
	std::string name;
	int uses_quotes = 0;
	bool mix = false; // the variable can be set together with other variables
	bool number = false;
	bool is_bool = false;
	std::vector<std::string> values;
	variable(const std::string& n, bool m, bool is_n, bool is_b) {
		name = n;
		mix = m;
		number = is_n;
		is_bool = is_b;
	}
	void add(const std::string& v) {
		values.push_back(v);
	}
	void add(const std::vector<std::string>& v) {
		for (std::vector<std::string>::const_iterator it = v.begin() ; it != v.end() ; it++) {
			values.push_back(*it);
		}
	}
	void add(const std::vector<int>& v, int inc) {
		for (std::vector<int>::const_iterator it = v.begin() ; it != v.end() ; it++) {
			int a = *it;
			a += inc; // "inc" is a random number passed as argument different for each variable
					  // to try to avoid that two variables get identical values
			values.push_back(std::to_string(a));
		}
	}
};


std::unordered_map<std::string, variable *> vars;


void add_value_j(std::string& j, std::string& s, variable *v) {
	if (v->is_bool == true) {
		if (
			(strcasestr(s.c_str(), "OFF") != NULL)
			||
			(strcasestr(s.c_str(), "0") != NULL)
		) {
			j+= "OFF";
		} else {
			if (
				(strcasestr(s.c_str(), "ON") != NULL)
				||
				(strcasestr(s.c_str(), "1") != NULL)
			) {
				j+= "ON";
			} else {
				j+= "";
			}
		}
		return;
	}
	for (int i=0; i<s.length(); i++) {
		if (i==0 || i==(s.length() - 1)) {
			if (s[i] == '`' || s[i] == '\'' || s[i]== '"')
				continue;
		}
		if (v->name == "time_zone") {
			if (s[i] == '+' || s[i] == '-') {
				if (s[i+2] == ':') {
					j += s[i];
					j += '0';
					i++;
				}
			}
		}
		if (s[i] == '"')
			j+= "\\";
		j+= s[i];
	}
}


int main() {

	srand(1);
	vars["sql_log_bin"] = new variable("sql_log_bin", false, false, true);
	vars["sql_log_bin"]->add(bool_values);
	vars["sql_safe_updates"] = new variable("sql_safe_updates", true, false, true);
	vars["sql_safe_updates"]->add(bool_values);
//	vars["wsrep_sync_wait"] = new variable("wsrep_sync_wait", true, false);
//	vars["wsrep_sync_wait"]->add(bool_values);
	vars["sql_auto_is_null"] = new variable("sql_auto_is_null", true, false, true);
	vars["sql_auto_is_null"]->add(bool_values);
	vars["foreign_key_checks"] = new variable("foreign_key_checks", true, false, true);
	vars["foreign_key_checks"]->add(bool_values);
	vars["unique_checks"] = new variable("unique_checks", true, false, true);
	vars["unique_checks"]->add(bool_values);
	vars["innodb_lock_wait_timeout"] = new variable("innodb_lock_wait_timeout", true, true, false);
	vars["innodb_lock_wait_timeout"]->add(int_values_small, 34);
	vars["innodb_lock_wait_timeout"]->add(int_values, 117);
	vars["innodb_strict_mode"] = new variable("innodb_strict_mode", true, false, true);
	vars["innodb_strict_mode"]->add(bool_values);
	vars["innodb_table_locks"] = new variable("innodb_table_locks", true, false, true);
	vars["innodb_table_locks"]->add(bool_values);

	//vars[""] = new variable("");
	//vars[""]->add(bool_values);

	vars["auto_increment_increment"] = new variable("auto_increment_increment", true, true, false);
	vars["auto_increment_increment"]->add(int_values_small, 10);
	vars["auto_increment_offset"] = new variable("auto_increment_offset", true, true, false);
	vars["auto_increment_offset"]->add(int_values_small, 20);
	vars["sql_select_limit"] = new variable("sql_select_limit", true, true, false);
	vars["sql_select_limit"]->add(int_values_small, 50);
	vars["sql_select_limit"]->add(int_values, 50);
	vars["group_concat_max_len"] = new variable("group_concat_max_len", true, true, false);
	vars["group_concat_max_len"]->add(int_values_small, 123);
	vars["group_concat_max_len"]->add(int_values, 123);
	vars["join_buffer_size"] = new variable("join_buffer_size", true, true, false);
	vars["join_buffer_size"]->add(int_values, 1028);
	{
		// join_buffer_size uses blocks of 128 , so we need to round it
		std::vector<std::string>& vals = vars["join_buffer_size"]->values;
		for (std::vector<std::string>::iterator it = vals.begin(); it != vals.end(); it++) {
			int a = std::stoi(*it);
			a = a/128;
			a *= 128;
			*it = std::to_string(a);
		}
	}
	vars["lock_wait_timeout"] = new variable("lock_wait_timeout", true, true, false);
	vars["lock_wait_timeout"]->add(int_values_small, 321);
	vars["max_join_size"] = new variable("max_join_size", true, true, false);
	vars["max_join_size"]->add(int_values, 1000);
	vars["max_join_size"]->add("18446744073709551615");
	
	vars["session_track_gtids"] = new variable("session_track_gtids", true, true, false);
	vars["session_track_gtids"]->add("OWN_GTID");
//	vars["session_track_gtids"]->add("OFF");
//	vars["session_track_gtids"]->add("ALL_GTID");
	
	
	vars["time_zone"] = new variable("time_zone", true, false, false);
	vars["time_zone"]->add(std::vector<std::string> {"'+01:00'", "`+02:15`", "\"+03:30\""});
	vars["time_zone"]->add(std::vector<std::string> {"'+04:45'", "`+05:00`", "\"+06:10\""});
	vars["time_zone"]->add(std::vector<std::string> {"'-1:10'", "`-03:33`", "\"-04:56\""});
	vars["time_zone"]->add(std::vector<std::string> {"'+02:45'", "`+7:00`", "\"+06:10\""});
	vars["time_zone"]->add(std::vector<std::string> {"'-11:10'", "`-11:33`", "\"-04:56\""});
	vars["sql_mode"] = new variable("sql_mode", true, false, false);
	vars["sql_mode"]->add(std::vector<std::string> {"'traditional'", "TRADITIONAL", "''"});
	vars["sql_mode"]->add(std::vector<std::string> {"'PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'", "\"PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION\""});
	vars["sql_mode"]->add(std::vector<std::string> {"ALLOW_INVALID_DATES", "'ALLOW_INVALID_DATES'", "\"ALLOW_INVALID_DATES\""});
	vars["sql_mode"]->add(std::vector<std::string> {"NO_ENGINE_SUBSTITUTION", "'NO_ENGINE_SUBSTITUTION'", "\"NO_ENGINE_SUBSTITUTION\""});
	vars["sql_mode"]->add(std::vector<std::string> {"concat(@@sql_mode,',STRICT_TRANS_TABLES')"});
	vars["sql_mode"]->add(std::vector<std::string> {"CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO')"});


	vars["default_storage_engine"] = new variable("default_storage_engine", true, false, false);
	{
		std::vector<std::string> engines = {"InnoDB", "MEMORY", "MyISAM", "BLACKHOLE"};
		for (std::vector<std::string>::iterator it = engines.begin(); it != engines.end(); it++) {
			vars["default_storage_engine"]->add(*it);
			std::string s;
			s = "\"" + *it + "\"";
			vars["default_storage_engine"]->add(s);
			s = "'" + *it + "'";
			vars["default_storage_engine"]->add(s);
			s = "`" + *it + "`";
			vars["default_storage_engine"]->add(s);
		}
	}
	vars["default_tmp_storage_engine"] = new variable("default_tmp_storage_engine", true, false, false);
	vars["default_tmp_storage_engine"]->add(vars["default_storage_engine"]->values);

/*
example:
"SET sql_mode='NO_ENGINE_SUBSTITUTION', sql_select_limit=3030, session_track_gtids=OWN_GTID; SET max_join_size=10000; ", "{'sql_mode':'NO_ENGINE_SUBSTITUTION','sql_select_limit':'3030', 'max_join_size':'10000', 'session_track_gtids':'OWN_GTID'}"
*/

	variable * vararray[vars.size()];
	{
		unsigned int i = 0;
		for (std::unordered_map<std::string, variable *>::iterator it = vars.begin() ; it != vars.end() ; it++) {
			vararray[i] = it->second;
			i++;
		}
	}
	for (int i=0; i<10000; i++) {
		int ne = rand()%4+1;
		variable * va[ne];
		for (int ine = 0; ine < ne; ) {
			int r1 = rand()%vars.size();
			variable *v = vararray[r1];
			bool there = false;
			for (unsigned int tl = 0; tl < ine && there == false; tl++) {
				if (va[tl] == v) there = true;
			}
			if (there == false) {
				if (v->mix == false) {
					if (ne == 1) {
						va[ine++] = v;
					}
				} else {
					va[ine++] = v;
				}
			}
		}
		std::string query = "SET ";
		std::string j = "{";
		//std::cout << "\"SET ";
		for (int ine = 0; ine < ne; ine++) {
			variable *v = va[ine];
			int r = rand()%(v->values.size());
			std::string s = v->values[r];
			//std::cout << v->name << "=";
			query += v->name + "=";
			if (s[0] == '"') {
				std::string s1 = std::string(s,0,s.length()-1);
				//std::cout << "\\" << s1 << "\\\"";
				query+= "\\" + s1 + "\\\"";
			} else {
				query += s;
			}
			j += "\"" + v->name + "\":\"";
			add_value_j(j,s,v);
			if (ine != ne -1) {
				query+= ", ";
				j+= "\", ";
			} else {
				query+= ";";
				j+= "\"}";
			}
		}
		std::cout << "{\"query\":\"" << query << "\", \"expected\":" << j << ", \"reset\":{}}" << std::endl;
	}

	return 0;
}