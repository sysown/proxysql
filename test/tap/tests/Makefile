DEPS_PATH=../../../deps

MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include
MARIADB_LDIR=$(MARIADB_PATH)/libmariadb

JEMALLOC_PATH=$(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR=$(JEMALLOC_PATH)/include/jemalloc
JEMALLOC_LDIR=$(JEMALLOC_PATH)/lib

PROXYSQL_PATH=../../..
PROXYSQL_IDIR=$(PROXYSQL_PATH)/include

SQLITE3_DIR=$(DEPS_PATH)/sqlite3/sqlite3
JSON_IDIR=$(DEPS_PATH)/json

RE2_PATH=$(DEPS_PATH)/re2/re2
RE2_IDIR=$(RE2_PATH)

SQLITE3_DIR=$(DEPS_PATH)/sqlite3/sqlite3

LIBHTTPSERVER_DIR=$(DEPS_PATH)/libhttpserver/libhttpserver
LIBHTTPSERVER_IDIR=$(LIBHTTPSERVER_DIR)/src
LIBHTTPSERVER_LDIR=$(LIBHTTPSERVER_DIR)/build/src/.libs/

LIBCONFIG_PATH=$(DEPS_PATH)/libconfig/libconfig
LIBCONFIG_IDIR=$(LIBCONFIG_PATH)/lib
LIBCONFIG_LDIR=-L$(LIBCONFIG_PATH)/lib/.libs

CURL_DIR=$(DEPS_PATH)/curl/curl
CURL_IDIR=$(CURL_DIR)/include
CURL_LDIR=$(CURL_DIR)/lib/.libs

DAEMONPATH=$(DEPS_PATH)/libdaemon/libdaemon
DAEMONPATH_IDIR=$(DAEMONPATH)
DAEMONPATH_LDIR=$(DAEMONPATH)/libdaemon/.libs

PCRE_PATH=$(DEPS_PATH)/pcre/pcre
PCRE_LDIR=$(PCRE_PATH)/.libs

MICROHTTPD_DIR=$(DEPS_PATH)/libmicrohttpd/libmicrohttpd/src
MICROHTTPD_IDIR=$(MICROHTTPD_DIR)/include
MICROHTTPD_LDIR=$(MICROHTTPD_DIR)/microhttpd/.libs

LIBINJECTION_DIR=$(DEPS_PATH)/libinjection/libinjection
LIBINJECTION_IDIR=$(LIBINJECTION_DIR)/src
LIBINJECTION_LDIR=$(LIBINJECTION_DIR)/src

SSL_DIR=$(DEPS_PATH)/libssl/openssl/
SSL_IDIR=$(SSL_DIR)/include
SSL_LDIR=$(SSL_DIR)

EV_DIR=$(DEPS_PATH)/libev/libev/
EV_IDIR=$(EV_DIR)
EV_LDIR=$(EV_DIR)/.libs

PROMETHEUS_PATH=$(DEPS_PATH)/prometheus-cpp/prometheus-cpp
PROMETHEUS_IDIR=$(PROMETHEUS_PATH)/pull/include -I$(PROMETHEUS_PATH)/core/include
PROMETHEUS_LDIR=$(PROMETHEUS_PATH)/lib

CITYHASH_DIR=$(DEPS_PATH)/cityhash/cityhash/
CITYHASH_IDIR=$(CITYHASH_DIR)
CITYHASH_LDIR=$(CITYHASH_DIR)/src/.libs

IDIR=../../../include
LDIR=../../../lib
TAP_LIBDIR=../tap

LIBPROXYSQLAR=$(LDIR)/libproxysql.a

ODIR=../../../obj

EXECUTABLE=proxysql

OBJ=../../../src/obj/proxysql_global.o ../../../src/obj/main.o ../../../src/obj/proxy_tls.o

INCLUDEDIRS=-I../tap -I$(RE2_PATH) -I$(IDIR) -I$(JEMALLOC_IDIR) -I$(SQLITE3_DIR) -I$(MICROHTTPD_IDIR) -I$(LIBHTTPSERVER_IDIR) -I$(CURL_IDIR) -I$(DAEMONPATH_IDIR) -I$(MARIADB_IDIR) -I$(SSL_IDIR) -I$(JSON_IDIR) -I$(LIBCONFIG_IDIR) -I$(PROMETHEUS_IDIR) -I$(EV_IDIR)
LDIRS=-L$(TAP_LIBDIR) -L$(LDIR) -L$(JEMALLOC_LDIR) $(LIBCONFIG_LDIR) -L$(RE2_PATH)/obj -L$(MARIADB_LDIR) -L$(DAEMONPATH_LDIR) -L$(PCRE_LDIR) -L$(MICROHTTPD_LDIR) -L$(LIBHTTPSERVER_LDIR) -L$(LIBINJECTION_LDIR) -L$(CURL_LDIR) -L$(EV_LDIR) -L$(SSL_LDIR) -L$(PROMETHEUS_LDIR)

MYLIBS=-Wl,--export-dynamic -Wl,-Bstatic -lconfig -lproxysql -ldaemon -ljemalloc -lconfig++ -lre2 -lpcrecpp -lpcre -lmariadbclient -lhttpserver -lmicrohttpd -linjection -lcurl -lssl -lcrypto -lev -Wl,-Bdynamic -lgnutls -lpthread -lm -lz -lrt $(EXTRALINK) -lprometheus-cpp-pull -lprometheus-cpp-core -luuid
STATIC_LIBS= $(SSL_LDIR)/libssl.a $(SSL_LDIR)/libcrypto.a $(CITYHASH_LDIR)/libcityhash.a

.PHONY: all
all: tests

.PHONY: clean
clean:
	rm -f *-t galera_1_timeout_count galera_2_timeout_no_count aurora generate_set_session_csv set_testing-240.csv clickhouse_php_conn-t reg_test_3992_fast_forward_malformed_packet-pymysql-t || true

WITHGCOVVAR := $(shell echo $(WITHGCOV))
ifeq ($(WITHGCOVVAR),1)
WGCOV=-DWITHGCOV --coverage -lgcov
else
WGCOV=
endif

WITHASANVAR := $(shell echo $(WITHASAN))
ifeq ($(WITHASANVAR),1)
WASAN=-fsanitize=address -DTEST_WITHASAN
else
WASAN=
endif

OPT=-O2 $(WGCOV) -Wl,--no-as-needed
debug: OPT=-O0 -DDEBUG -ggdb -Wl,--no-as-needed $(WGCOV) $(WASAN)
debug: tests

tests: tests-cpp tests-php tests-py \
	setparser_test reg_test_3504-change_user_libmariadb_helper reg_test_3504-change_user_libmysql_helper \
	set_testing-240.csv test_clickhouse_server_libmysql-t reg_test_stmt_resultset_err_no_rows_libmysql-t \
	prepare_statement_err3024_libmysql-t prepare_statement_err3024_async-t reg_test_mariadb_stmt_store_result_libmysql-t \
	reg_test_mariadb_stmt_store_result_async-t
tests-cpp: $(patsubst %.cpp,%,$(wildcard *-t.cpp))
tests-php: $(patsubst %,php-%,$(wildcard *-t.php))
tests-py: $(patsubst %,py-%,$(wildcard *-t.py))
testgalera: galera_1_timeout_count galera_2_timeout_no_count
testaurora: aurora

set_testing-240.csv: generate_set_session_csv
	./generate_set_session_csv > set_testing-240.csv

php-%:
	cp $(patsubst php-%,%,$@) $(patsubst php-%.php,%,$@)
	chmod +x $(patsubst php-%.php,%,$@)

py-%:
	cp $(patsubst py-%,%,$@) $(patsubst py-%.py,%,$@)
	chmod +x $(patsubst py-%.py,%,$@)

%-t: %-t.cpp $(TAP_LIBDIR)/libtap.a
	$(CXX) $^ $(INCLUDEDIRS) $(LDIRS) $(OPT) $(MYLIBS) -lpthread -ldl -std=c++11 -ltap $(STATIC_LIBS) -o $@

galera_1_timeout_count: galera_1_timeout_count.cpp $(TAP_LIBDIR)/libtap.a
	g++ -DTEST_GALERA -DDEBUG galera_1_timeout_count.cpp ../tap/SQLite3_Server.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(OBJ) -lproxysql $(MYLIBS) -ltap -ldl $(STATIC_LIBS) -o galera_1_timeout_count -DGITVERSION=\"$(GIT_VERSION)\"

galera_2_timeout_no_count: galera_2_timeout_no_count.cpp $(TAP_LIBDIR)/libtap.a
	g++ -DTEST_GALERA -DDEBUG galera_2_timeout_no_count.cpp ../tap/SQLite3_Server.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(OBJ) -lproxysql $(MYLIBS) -ltap -ldl $(STATIC_LIBS) -o galera_2_timeout_no_count -DGITVERSION=\"$(GIT_VERSION)\"

generate_set_session_csv: generate_set_session_csv.cpp
	g++ -o generate_set_session_csv generate_set_session_csv.cpp -O0 -ggdb

aurora: aurora.cpp $(TAP_LIBDIR)/libtap.a
	g++ -DTEST_AURORA -DDEBUG aurora.cpp ../tap/SQLite3_Server.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(OBJ) -lproxysql $(MYLIBS) -ltap -ldl $(STATIC_LIBS) -o aurora -DGITVERSION=\"$(GIT_VERSION)\"

test_tokenizer-t: test_tokenizer-t.cpp $(TAP_LIBDIR)/libtap.a
	g++ test_tokenizer-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(MYLIBS) -lproxysql -ltap -Wl,--no-as-needed -ldl -lpthread -o test_tokenizer-t -DGITVERSION=\"$(GIT_VERSION)\"

test_mysql_query_digests_stages-t: test_mysql_query_digests_stages-t.cpp $(TAP_LIBDIR)/libtap.a
	g++ test_mysql_query_digests_stages-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(MYLIBS) -lproxysql -ltap -Wl,--no-as-needed -ldl -lpthread -o test_mysql_query_digests_stages-t -DGITVERSION=\"$(GIT_VERSION)\"

sqlite3-t: sqlite3-t.cpp $(TAP_LIBDIR)/libtap.a
	g++ sqlite3-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 -lproxysql $(MYLIBS) -ltap -Wl,--no-as-needed -ldl -lpthread -o sqlite3-t -DGITVERSION=\"$(GIT_VERSION)\"

test_gtid_forwarding-t: test_gtid_forwarding-t.cpp $(TAP_LIBDIR)/libtap.a
	g++ test_gtid_forwarding-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(MYLIBS) -ltap -Wl,--no-as-needed -ldl -lpthread -o test_gtid_forwarding-t -DGITVERSION=\"$(GIT_VERSION)\"

test_admin_prometheus_metrics_dump-t: test_admin_prometheus_metrics_dump-t.cpp $(TAP_LIBDIR)/libtap.a
	g++ test_admin_prometheus_metrics_dump-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(MYLIBS) -ltap -Wl,--no-as-needed -ldl -lpthread -o test_admin_prometheus_metrics_dump-t -DGITVERSION=\"$(GIT_VERSION)\"

create_connection_annotation: test_connection_annotation-t.cpp
	g++ -DTEST_AURORA -DDEBUG test_connection_annotation-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(OBJ) $(MYLIBS) -ltap -ldl $(STATIC_LIBS) -o test_connection_annotation-t -DGITVERSION=\"$(GIT_VERSION)\"

setparser_test: setparser_test.cpp $(TAP_LIBDIR)/libtap.a $(RE2_PATH)/util/test.cc $(LDIR)/set_parser.cpp $(LIBPROXYSQLAR)
	g++ -DDEBUG setparser_test.cpp $(RE2_PATH)/util/test.cc $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 -lproxysql $(MYLIBS) -ltap -ldl -lpthread $(WASAN) -o setparser_test -DGITVERSION=\"$(GIT_VERSION)\"

reg_test_3504-change_user_libmariadb_helper: reg_test_3504-change_user_helper.cpp
	$(CXX) -DDEBUG reg_test_3504-change_user_helper.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) $(MYLIBS) -lpthread -ldl -std=c++11 -ltap $(STATIC_LIBS) -o reg_test_3504-change_user_libmariadb_helper -DGITVERSION=\"$(GIT_VERSION)\"

reg_test_3504-change_user_libmysql_helper: reg_test_3504-change_user_helper.cpp
	$(CXX) -DLIBMYSQL_HELPER -DDEBUG reg_test_3504-change_user_helper.cpp -I/usr/include/mysql -I$(IDIR) -I$(JSON_IDIR) -I../tap -L$(TAP_LIBDIR) -lpthread -ldl -std=c++11 -ltap -lmysqlclient -o reg_test_3504-change_user_libmysql_helper -DGITVERSION=\"$(GIT_VERSION)\"

test_clickhouse_server_libmysql-t: test_clickhouse_server-t.cpp
	$(CXX) -DLIBMYSQL_HELPER -DDEBUG test_clickhouse_server-t.cpp -I/usr/include/mysql -I$(IDIR) -I$(JSON_IDIR) -I../tap -L$(TAP_LIBDIR) -lpthread -ldl -std=c++11 -ltap -lmysqlclient -o test_clickhouse_server_libmysql-t -DGITVERSION=\"$(GIT_VERSION)\"

reg_test_stmt_resultset_err_no_rows_libmysql-t: reg_test_stmt_resultset_err_no_rows-t.cpp
	$(CXX) -DLIBMYSQL_HELPER reg_test_stmt_resultset_err_no_rows-t.cpp -I/usr/include/mysql -I$(IDIR) -I$(JSON_IDIR) -I../tap $(OPT) -L$(TAP_LIBDIR) -lpthread -ldl -std=c++11 -ltap -lmysqlclient -o reg_test_stmt_resultset_err_no_rows_libmysql-t -DGITVERSION=\"$(GIT_VERSION)\"

reg_test_mariadb_stmt_store_result_libmysql-t: reg_test_mariadb_stmt_store_result-t.cpp $(TAP_LIBDIR)/libtap.a
	$(CXX) -DLIBMYSQL_HELPER reg_test_mariadb_stmt_store_result-t.cpp -I/usr/include/mysql -I$(IDIR) -I$(JSON_IDIR) -I../tap $(OPT) -L$(TAP_LIBDIR) -lpthread -ldl -std=c++11 -ltap -lmysqlclient -o reg_test_mariadb_stmt_store_result_libmysql-t -DGITVERSION=\"$(GIT_VERSION)\"

reg_test_mariadb_stmt_store_result_async-t: reg_test_mariadb_stmt_store_result-t.cpp $(TAP_LIBDIR)/libtap.a
	$(CXX) -DASYNC_API reg_test_mariadb_stmt_store_result-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) $(MYLIBS) -lpthread -ldl -std=c++11 -ltap $(STATIC_LIBS) -o reg_test_mariadb_stmt_store_result_async-t -DGITVERSION=\"$(GIT_VERSION)\"

prepare_statement_err3024_libmysql-t: prepare_statement_err3024-t.cpp $(TAP_LIBDIR)/libtap.a
	$(CXX) -DLIBMYSQL_HELPER prepare_statement_err3024-t.cpp -I/usr/include/mysql -I$(IDIR) -I$(JSON_IDIR) -I../tap $(OPT) -L$(TAP_LIBDIR) -lpthread -ldl -std=c++11 -ltap -lmysqlclient -o prepare_statement_err3024_libmysql-t -DGITVERSION=\"$(GIT_VERSION)\"

prepare_statement_err3024_async-t: prepare_statement_err3024-t.cpp $(TAP_LIBDIR)/libtap.a
	$(CXX) -DASYNC_API prepare_statement_err3024-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) $(MYLIBS) -lpthread -ldl -std=c++11 -ltap $(STATIC_LIBS) -o prepare_statement_err3024_async-t -DGITVERSION=\"$(GIT_VERSION)\"

test_wexecvp_syscall_failures-t: test_wexecvp_syscall_failures-t.cpp $(TAP_LIBDIR)/libtap.a
	$(CXX) $^ $(INCLUDEDIRS) $(LDIRS) $(OPT) $(MYLIBS) -std=c++11 -Wl,--wrap=pipe,--wrap=fcntl,--wrap=read,--wrap=poll -lpthread -ldl -ltap $(STATIC_LIBS) -o $@
