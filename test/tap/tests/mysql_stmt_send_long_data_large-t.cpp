#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

/*
mysql_stmt_send_long_data_large-t.cpp is almost identical to mysql_stmt_send_long_data-t.cpp
but it uses very large buffers.
We run:
ALTER TABLE sbtest1 MODIFY c LONGTEXT NOT NULL;

Because "c" cannot be empty, we always specify it.


FIXME:
Large packets require the use of a large max_allowed_packet on backend.
This test needs to be extended to send packets smaller than 4MB, but also 16MB or larger.
ProxySQL needs proper error handling

*/

const int NUM_EXECUTIONS = 10;

std::string select_query = "SELECT /* hostgroup=0 */ * FROM test.sbtest1 WHERE id = ?";

std::string insert_query[2] = {
	"INSERT INTO test.sbtest1 (id, k, c) VALUES (?,?,?)",
	"INSERT INTO test.sbtest1 (id, k, c, pad) VALUES (?,?,?,?)"
};

int idx = 0;
int idx2 = 0;
int k = 0;

int main(int argc, char** argv) {
	CommandLine cl;

	int plans = 2 * 3; // 4 INSERT queries each of them triggers a SELECT and a data comparison
	plans *= NUM_EXECUTIONS;
	plans += 3; // prepares
	plans += (2 * NUM_EXECUTIONS / 5); //mysql_stmt_reset()

	plan(plans);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	idx = 1000;
	if (create_table_test_sbtest1(idx,mysql)) {
		fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
		return exit_status();
	}
	idx++;

	MYSQL_QUERY(mysql,"ALTER TABLE test.sbtest1 MODIFY c LONGTEXT NOT NULL");

	MYSQL_STMT* stmt[2];
	MYSQL_STMT* select_stmt;
	for (int i=0; i<2; i++) {
		// Initialize and prepare the statement
		stmt[i]= mysql_stmt_init(mysql);
		if (!stmt[i]) {
			diag("mysql_stmt_init(), out of memory\n");
			return exit_status();
		}
		if (mysql_stmt_prepare(stmt[i], insert_query[i].c_str(), strlen(insert_query[i].c_str()))) {
			diag("insert_query: %s", insert_query[i].c_str());
			ok(false, "mysql_stmt_prepare at line %d failed: %s", __LINE__ , mysql_error(mysql));
			mysql_close(mysql);
			mysql_library_end();
			return exit_status();
		} else {
			ok(true, "Prepare succeeded: %s", insert_query[i].c_str());
		}
	}

	select_stmt = mysql_stmt_init(mysql);
	if (!select_stmt) {
		diag("mysql_stmt_init(), out of memory\n");
		return exit_status();
	}
	if (mysql_stmt_prepare(select_stmt, select_query.c_str(), strlen(select_query.c_str()))) {
		diag("select_query: %s", select_query.c_str());
		ok(false, "mysql_stmt_prepare at line %d failed: %s", __LINE__ , mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		return exit_status();
	} else {
		ok(true, "Prepare succeeded: %s", select_query.c_str());
	}

	int rc = 0;

	for (int n = 0; n < NUM_EXECUTIONS; n++) {
		MYSQL_BIND    bind[4];
		for (int i=0; i<2; i++) {
			if ((n*2+i)%5==0) {
				// sometime we also run mysql_stmt_reset() to test the code
				rc = mysql_stmt_reset(stmt[i]);
				ok(rc==0, "mysql_stmt_reset() for stmt %d returned: %s" , i , (rc == 0 ? "" : mysql_stmt_error(stmt[i])));
				if (rc)
					return exit_status();
			}
			if (i==0)
				k=0;
			else {
				k=n+7+i;
			}
			long unsigned c_length;
			long unsigned pad_length;
			diag("Executing: %s", insert_query[i].c_str());
			memset(bind, 0, sizeof(bind));
			bind[0].buffer_type= MYSQL_TYPE_LONG;
			bind[0].buffer= (char *)&idx;
			bind[0].is_null= 0;
			bind[0].length= 0;
			bind[1].buffer_type= MYSQL_TYPE_LONG;
			bind[1].buffer= (char *)&k;
			bind[1].is_null= 0;
			bind[1].length= 0;
			bind[2].buffer_type= MYSQL_TYPE_STRING;
			bind[2].length= &c_length;
			bind[2].is_null= 0;
			bind[3].buffer_type= MYSQL_TYPE_STRING;
			bind[3].length= &pad_length;
			bind[3].is_null= 0;
			if (mysql_stmt_bind_param(stmt[i], bind)) {
				diag("mysql_stmt_bind_param() for stmt %d failed: %s", i, mysql_stmt_error(stmt[i]));
				return exit_status();
			}
			// here we keep record of what we wrote
			std::string p2 = "";
			std::string p3 = "";
			for (int j=2; j<4; j++) {
				if (j<=i+2) {
					for (int k=0; k<1 + rand()%3 + (j==2 ? 3 : 0) ; k++) { // we send multiple chunks
						std::string s = "HelloWorld" + std::to_string(idx2++);
						if (j==2) {
							p2 += s;
						} else {
							p3 += s;
						}
						if (mysql_stmt_send_long_data(stmt[i], j, s.c_str(), s.length())) {
							diag("mysql_stmt_send_long_data() for stmt %d and param %d failed: %s", i, j, mysql_stmt_error(stmt[i]));
							return exit_status();
						}
					}
				}
			}
			// send a large packet
			if (i==1) {
				std::string s = "";
				while (s.length() < 3*1024*1024) {
					s += "blahblahblah1234567890blahblahblah1234567890blahblahblah1234567890blahblahblah1234567890" + std::to_string(rand()%100);
				}
				p2 += s;
				if (mysql_stmt_send_long_data(stmt[i], 2, s.c_str(), s.length())) {
					diag("mysql_stmt_send_long_data() for stmt %d and param %d failed: %s", i, 2, mysql_stmt_error(stmt[i]));
					return exit_status();
				}
			}
			rc = mysql_stmt_execute(stmt[i]);
			if (rc!=0) {
				diag("mysql_stmt_execute() for stmt %d failed: %s", i, mysql_stmt_error(stmt[i]));
			}
			ok(rc==0, "mysql_stmt_execute for stmt %d", i);
			if (rc==0) {
				MYSQL_BIND    bind[4];
				unsigned long length[4];
				memset(bind, 0, sizeof(bind));
				bind[0].buffer_type= MYSQL_TYPE_LONG;
				bind[0].buffer= (char *)&idx;
				bind[0].is_null= 0;
				bind[0].length= 0;
				if (mysql_stmt_bind_param(select_stmt, bind)) {
					diag("mysql_stmt_bind_param() on SELECT for stmt %d failed: %s", i, mysql_stmt_error(select_stmt));
					return exit_status();
				}
				rc = mysql_stmt_execute(select_stmt);
				ok(rc==0, "mysql_stmt_execute on SELECT for stmt %d", i);
				if (rc!=0) {
					diag("mysql_stmt_execute() on SELECT for stmt %d failed: %s", i, mysql_stmt_error(select_stmt));
				} else {
					MYSQL_RES     *prepare_meta_result;
					prepare_meta_result = mysql_stmt_result_metadata(select_stmt);
					memset(bind, 0, sizeof(bind));
					int id, k_i;

					char          is_null[4];
					char           error[4];

					int buff_len_str_data_c=30*1024*1024;
					char * str_data_c = (char *)malloc(buff_len_str_data_c);
					if (str_data_c == NULL) {
						fprintf(stderr,"Out of memory\n");
						diag("Out of memory");
						return exit_status();
					}
					char str_data_pad[256];
					bind[0].buffer_type= MYSQL_TYPE_LONG;
					bind[0].buffer= (char *)&id;
					bind[0].is_null= &is_null[0];
					bind[0].length= &length[0];
					bind[0].error= &error[0];
					bind[1].buffer_type= MYSQL_TYPE_LONG;
					bind[1].buffer= (char *)&k_i;
					bind[1].is_null= &is_null[1];
					bind[1].length= &length[1];
					bind[1].error= &error[1];
					bind[2].buffer_type= MYSQL_TYPE_STRING;
					bind[2].buffer= str_data_c;
					bind[2].buffer_length=buff_len_str_data_c;
					bind[2].is_null= &is_null[2];
					bind[2].length= &length[2];
					bind[2].error= &error[2];
					bind[3].buffer_type= MYSQL_TYPE_STRING;
					bind[3].buffer= (char *)str_data_pad;
					bind[3].buffer_length= 256;
					bind[3].is_null= &is_null[3];
					bind[3].length= &length[3];
					bind[3].error= &error[3];

					if (mysql_stmt_bind_result(select_stmt, bind)) {
						diag("mysql_stmt_bind_result() on SELECT for stmt %d failed: %s", i, mysql_stmt_error(select_stmt));
						return exit_status();
					}
					if (mysql_stmt_store_result(select_stmt)) {
						diag("mysql_stmt_store_result() on SELECT for stmt %d failed: %s", i, mysql_stmt_error(select_stmt));
						return exit_status();
					}
					//sleep(1);
					if (mysql_stmt_fetch(select_stmt)) {
						diag("mysql_stmt_fetch() on SELECT for stmt %d failed: %s", i, mysql_stmt_error(select_stmt));
						return exit_status();
					}
					if (p2.length() < 1000) {
						diag("Expected:  id=%d, k=%d, c=%s, pad=%s", idx, k, p2.c_str(), p3.c_str());
						diag("Retrieved: id=%d, k=%d, c=%s, pad=%s", id, k_i, str_data_c, str_data_pad);
					} else {
						diag("Expected:  id=%d, k=%d, c=<OMITTED,length=%llu>, pad=%s", idx, k, p2.length(), p3.c_str());
						diag("Retrieved: id=%d, k=%d, c=<OMITTED,length=%llu>, pad=%s", id, k_i, strlen(str_data_c), str_data_pad);
					}
					int dm = 0;
					if (idx==id && k == k_i && strcmp(p2.c_str(),str_data_c)==0 && strcmp(p3.c_str(),str_data_pad)==0) {
						dm=1;
					}
					ok(dm==1, "Data match: %s", (dm == 1 ? "YES" : "NO . See output above")); 
					mysql_free_result(prepare_meta_result);
					mysql_stmt_free_result(select_stmt);
					free(str_data_c);
				}
			}
//			}
			//rc = mysql_stmt_store_result(stmt[i]);
			//mysql_stmt_free_result(stmt[i]);
			idx++;
		}
	}
	for (int i=0; i<2; i++) {
		if (mysql_stmt_close(stmt[i])) {
			ok(false, "mysql_stmt_close at line %d failed: %s\n", __LINE__ , mysql_error(mysql));
		}
	}
	mysql_close(mysql);

	return exit_status();
}
