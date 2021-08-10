#include <vector>
#include <string>
#include <unordered_map>
#include <stdlib.h>


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
	bool mix = false;
	bool number = false;
	std::vector<std::string> values;
	variable(const std::string& n, bool m, bool is_n) {
		name = n;
		mix = m;
		number = is_n;
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
			a += inc;
			values.push_back(std::to_string(a));
		}
	}
};


std::unordered_map<std::string, variable *> vars;

int main() {

	srand(1);
	vars["sql_log_bin"] = new variable("sql_log_bin", false, false);
	vars["sql_log_bin"]->add(bool_values);
	vars["sql_safe_updates"] = new variable("sql_safe_updates", true, false);
	vars["sql_safe_updates"]->add(bool_values);
	vars["sql_auto_is_null"] = new variable("sql_auto_is_null", true, false);
	vars["sql_auto_is_null"]->add(bool_values);
	vars["foreign_key_checks"] = new variable("foreign_key_checks", true, false);
	vars["foreign_key_checks"]->add(bool_values);
	vars["unique_checks"] = new variable("unique_checks", true, false);
	vars["unique_checks"]->add(bool_values);
	//vars[""] = new variable("");
	//vars[""]->add(bool_values);
	vars["sql_select_limit"] = new variable("sql_select_limit", true, true);
	vars["sql_select_limit"]->add(int_values, 5);
	vars["group_concat_max_len"] = new variable("group_concat_max_len", true, true);
	vars["group_concat_max_len"]->add(int_values, 123);
	vars["max_join_size"] = new variable("max_join_size", true, true);
	vars["max_join_size"]->add(int_values, 1000);
	vars["max_join_size"]->add("18446744073709551615");
	
	
	
	vars["time_zone"] = new variable("time_zone", true, false);
	vars["time_zone"]->add(std::vector<std::string> {"+01:00", "`+02:15`", "\"+03:30\""});
	vars["time_zone"]->add(std::vector<std::string> {"+04:45", "`+05:00`", "\"+06:10\""});
	vars["time_zone"]->add(std::vector<std::string> {"-1:10", "-03:33", "\"-04:56\""});
	vars["sql_mode"] = new variable("sql_mode", true, false);

	for (int i=0; i<1000; i++) {
		int ne = rand()%4+1;
		int r1 = rand()%vars.size();
	}

	return 0;
}
