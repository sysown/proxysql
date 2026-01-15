#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk


IDIRS :=	-I$(TAP_IDIR) \
			-I$(RE2_IDIR) \
			-I$(PROXYSQL_IDIR) \
			-I$(JEMALLOC_IDIR) \
			-I$(LIBCONFIG_IDIR) \
			-I$(MARIADB_IDIR) \
			-I$(LIBDAEMON_IDIR) \
			-I$(MICROHTTPD_IDIR) \
			-I$(LIBHTTPSERVER_IDIR) \
			-I$(CURL_IDIR) -I$(EV_IDIR)\
			-I$(PROMETHEUS_IDIR) \
			-I$(DOTENV_DYN_IDIR) \
			-I$(SQLITE3_IDIR) \
			-I$(JSON_IDIR) \
			-I$(POSTGRESQL_IDIR)\
			-I$(LIBSCRAM_IDIR) \
			-I$(LIBUSUAL_IDIR) \
			-I$(SSL_IDIR)

LDIRS :=	-L$(TAP_LDIR) \
			-L$(RE2_LDIR) \
			-L$(PROXYSQL_LDIR) \
			-L$(JEMALLOC_LDIR) \
			-L$(LIBCONFIG_LDIR) \
			-L$(MARIADB_LDIR) \
			-L$(LIBDAEMON_LDIR) \
			-L$(MICROHTTPD_LDIR) \
			-L$(LIBHTTPSERVER_LDIR) \
			-L$(CURL_LDIR) -L$(EV_LDIR) \
			-L$(PROMETHEUS_LDIR) \
			-L$(DOTENV_DYN_LDIR) \
			-L$(PCRE_LDIR) \
			-L$(LIBINJECTION_LDIR) \
			-L$(POSTGRESQL_LDIR)\
			-L$(LIBSCRAM_LDIR) \
			-L$(LIBUSUAL_LDIR) \
			-L$(SSL_LDIR)

ifeq ($(UNAME_S),Linux)
	LDIRS += -L$(COREDUMPER_LDIR)
endif


LIBPROXYSQLAR := $(PROXYSQL_LDIR)/libproxysql.a

ODIR := $(PROXYSQL_PATH)/obj

EXECUTABLE := proxysql

OBJ := $(PROXYSQL_PATH)/src/obj/proxysql_global.o $(PROXYSQL_PATH)/src/obj/main.o $(PROXYSQL_PATH)/src/obj/proxy_tls.o

#SOURCES := ../tap/utils.cpp

MYLIBS_DYNAMIC_PART := -Wl,--export-dynamic -Wl,-Bdynamic -lgnutls -ltap -lcpp_dotenv -lcurl -lssl -lcrypto -luuid
MYLIBS_STATIC_PART := -Wl,-Bstatic -lconfig -lproxysql -ldaemon -lconfig++ -lre2 -lpcrecpp -lpcre -lmariadbclient -lhttpserver -lmicrohttpd -linjection -lev -lprometheus-cpp-pull -lprometheus-cpp-core
MYLIBS_PG_PART := -Wl,-Bstatic -lpq -lpgcommon -lpgport
MYLIBS_LAST_PART := -Wl,-Bdynamic -lpthread -lm -lz -lrt -ldl $(EXTRALINK)
MYLIBS := $(MYLIBS_DYNAMIC_PART) $(MYLIBS_STATIC_PART) $(MYLIBS_PG_PART) $(MYLIBS_LAST_PART)
#MYLIBS_PG := $(MYLIBS_DYNAMIC_PART) $(MYLIBS_STATIC_PART) $(MYLIBS_PG_PART) $(MYLIBS_LAST_PART)
#MYLIBS := -Wl,--export-dynamic -Wl,-Bdynamic -lssl -lcrypto -lgnutls -ltap -lcpp_dotenv -Wl,-Bstatic -lconfig -lproxysql -ldaemon -lconfig++ -lre2 -lpcrecpp -lpcre -lmariadbclient -lhttpserver -lmicrohttpd -linjection -lev -lprometheus-cpp-pull -lprometheus-cpp-core -luuid -Wl,-Bdynamic -lpthread -lm -lz -lrt -ldl $(EXTRALINK)

MYLIBSJEMALLOC := -Wl,-Bstatic -ljemalloc
STATIC_LIBS := $(CITYHASH_LDIR)/libcityhash.a

LIBCOREDUMPERAR :=
ifeq ($(UNAME_S),Linux)
	LIBCOREDUMPERAR := $(COREDUMPER_LDIR)/libcoredumper.a
	STATIC_LIBS += $(LIBCOREDUMPERAR)
endif


OPT := $(STDCPP) -O2 -ggdb -Wl,--no-as-needed -Wl,-rpath,$(TAP_LDIR) $(WGCOV) $(WASAN) -DGITVERSION=\"$(GIT_VERSION)\"

### main targets

.DEFAULT: default
.PHONY: default
default: all

CUSTOMARGS := -I$(TAP_IDIR) -I$(CURL_IDIR) -I$(SQLITE3_IDIR) -I$(PROXYSQL_IDIR) -I$(JSON_IDIR) -I$(RE2_IDIR) -I$(SSL_IDIR)
CUSTOMARGS += -L$(TAP_LDIR) -L$(CURL_LDIR) -L$(RE2_LDIR) -L$(SSL_LDIR)
CUSTOMARGS += -Wl,-Bdynamic -lcpp_dotenv -lcurl -lssl -lcrypto -lre2 -lpthread -lz -ldl

.PHONY: all
all: tests

debug: OPT := $(STDCPP) -O0 -DDEBUG -ggdb -Wl,--no-as-needed -Wl,-rpath,$(TAP_LDIR) $(WGCOV) $(WASAN) -DGITVERSION=\"$(GIT_VERSION)\"
debug: tests

tests: CUSTOMARGS += $(OPT)
tests: tests-cpp \
	tests-php \
	tests-py \
	tests-sh \
	setparser_test \
	reg_test_3504-change_user_libmariadb_helper \
	reg_test_3504-change_user_libmysql_helper \
	mysql_reconnect_libmariadb-t \
	mysql_reconnect_libmysql-t \
	test_match_eof_conn_cap_libmysql-t \
	test_match_eof_conn_cap_libmariadb-t \
	test_sqlite3_special_queries_libmariadb-t \
	test_sqlite3_special_queries_libmysql-t \
	test_ssl_fast_forward-2_libmariadb-t \
	test_ssl_fast_forward-2_libmysql-t \
	test_ssl_fast_forward-3_libmariadb-t \
	test_ssl_fast_forward-3_libmysql-t \
	setparser_test2 setparser_test2-t \
	setparser_test3 setparser_test3-t \
	set_testing-240.csv \
	test_clickhouse_server_libmysql-t \
	reg_test_stmt_resultset_err_no_rows_libmysql-t \
	prepare_statement_err3024_libmysql-t \
	prepare_statement_err3024_async-t \
	fast_forward_grace_close_libmysql-t \
	fast_forward_switch_replication_deprecate_eof_libmysql-t \
	reg_test_mariadb_stmt_store_result_libmysql-t \
	reg_test_mariadb_stmt_store_result_async-t
tests:
	@echo "Removing empty .gcno files ..."
	find -L . -type f -name '*.gcno' -empty -ls -delete

tests-cpp: $(patsubst %.cpp,%,$(wildcard *-t.cpp))
tests-php: $(patsubst %,php-%,$(wildcard *-t.php))
tests-py: $(patsubst %,py-%,$(wildcard *-t.py))
tests-sh: $(patsubst %,sh-%,$(wildcard *-t.sh))
testgalera: galera_1_timeout_count galera_2_timeout_no_count
testaurora: aurora


### test deps targets

#build_test_deps: $(TAP_LDIR)/libtap.so $(TEST_MARIADB_LDIR)/libmariadbclient.a $(TEST_MYSQL_LDIR)/libmysqlclient.a

$(TAP_LDIR)/libtap.so:
	cd $(TAP_PATH) && CC=${CC} CXX=${CXX} ${MAKE} 

$(TEST_MARIADB_LDIR)/libmariadbclient.a:
	cd $(TEST_DEPS_PATH) && CC=${CC} CXX=${CXX} ${MAKE} mariadb_client

$(TEST_MYSQL_LDIR)/libmysqlclient.a:
	cd $(TEST_DEPS_PATH) && CC=${CC} CXX=${CXX} ${MAKE} mysql_client


### helper targets

set_testing-240.csv: generate_set_session_csv
	./generate_set_session_csv > set_testing-240.csv

php-%:
	cp $(patsubst php-%,%,$@) $(patsubst php-%.php,%,$@)
	chmod +x $(patsubst php-%.php,%,$@)

py-%:
	cp $(patsubst py-%,%,$@) $(patsubst py-%.py,%,$@)
	chmod +x $(patsubst py-%.py,%,$@)

sh-%:
	cp $(patsubst sh-%,%,$@) $(patsubst sh-%.sh,%,$@)
	chmod +x $(patsubst sh-%.sh,%,$@)

%-t: %-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

galera_1_timeout_count: galera_1_timeout_count.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DTEST_GALERA $< ../tap/SQLite3_Server.cpp $(IDIRS) $(LDIRS) $(OPT) $(OBJ) $(MYLIBSJEMALLOC) $(MYLIBS) $(STATIC_LIBS) -lscram -lusual -o $@

galera_2_timeout_no_count: galera_2_timeout_no_count.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DTEST_GALERA $< ../tap/SQLite3_Server.cpp $(IDIRS) $(LDIRS) $(OPT) $(OBJ) $(MYLIBSJEMALLOC) $(MYLIBS) $(STATIC_LIBS) -lscram -lusual -o $@

generate_set_session_csv: generate_set_session_csv.cpp
	$(CXX) $< $(OPT) -o $@

aurora: aurora.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DTEST_AURORA $< ../tap/SQLite3_Server.cpp $(IDIRS) $(LDIRS) $(OPT) $(OBJ) $(MYLIBSJEMALLOC) $(MYLIBS) $(STATIC_LIBS) -o $@

test_tokenizer-t: test_tokenizer-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

test_mysql_query_digests_stages-t: test_mysql_query_digests_stages-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

sqlite3-t: sqlite3-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< -DEXCLUDE_TRACKING_VARIABLES $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) -o $@

test_gtid_forwarding-t: test_gtid_forwarding-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

test_ignore_min_gtid-t: test_ignore_min_gtid-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

test_admin_prometheus_metrics_dump-t: test_admin_prometheus_metrics_dump-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

create_connection_annotation: test_connection_annotation-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DTEST_AURORA $< $(IDIRS) $(LDIRS) $(OPT) $(OBJ) $(MYLIBS) $(STATIC_LIBS) -o $@

setparser_test: setparser_test.cpp $(TAP_LDIR)/libtap.so $(RE2_PATH)/util/test.cc $(PROXYSQL_LDIR)/MySQL_Set_Stmt_Parser.cpp $(LIBPROXYSQLAR) $(LIBCOREDUMPERAR)
	$(CXX) $< -DEXCLUDE_TRACKING_VARIABLES $(RE2_PATH)/util/test.cc $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) -o $@

setparser_test2-t: setparser_test2
	ln -fs setparser_test2 setparser_test2-t

setparser_test2: setparser_test2.cpp $(TAP_LDIR)/libtap.so $(PROXYSQL_LDIR)/MySQL_Set_Stmt_Parser.cpp setparser_test_common.h $(LIBPROXYSQLAR) $(LIBCOREDUMPERAR)
	$(CXX) $<  -DEXCLUDE_TRACKING_VARIABLES $(PROXYSQL_LDIR)/MySQL_Set_Stmt_Parser.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) -o $@

setparser_test3-t: setparser_test3
	ln -fs setparser_test3 setparser_test3-t

setparser_test3: setparser_test3.cpp $(TAP_LDIR)/libtap.so $(PROXYSQL_LDIR)/MySQL_Set_Stmt_Parser.cpp setparser_test_common.h $(LIBPROXYSQLAR) $(LIBCOREDUMPERAR)
	$(CXX) $< -DEXCLUDE_TRACKING_VARIABLES -DPARSERDEBUG $(PROXYSQL_LDIR)/MySQL_Set_Stmt_Parser.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) -o $@

reg_test_3504-change_user_libmariadb_helper: reg_test_3504-change_user_helper.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

reg_test_3504-change_user_libmysql_helper: reg_test_3504-change_user_helper.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DLIBMYSQL_HELPER -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -Wl,-Bstatic -lmysqlclient -ltap_mysql57 $(CUSTOMARGS) -o $@

mysql_reconnect_libmariadb-t: mysql_reconnect.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

mysql_reconnect_libmysql-t: mysql_reconnect.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 -lresolv $(CUSTOMARGS) -o $@

fast_forward_grace_close_libmysql-t: fast_forward_grace_close.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 -lresolv $(CUSTOMARGS) -o $@

test_match_eof_conn_cap_libmysql-t: test_match_eof_conn_cap.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 -lresolv $(CUSTOMARGS) -o $@

test_match_eof_conn_cap_libmariadb-t: test_match_eof_conn_cap.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

test_sqlite3_special_queries_libmariadb-t: test_sqlite3_special_queries.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

test_sqlite3_special_queries_libmysql-t: test_sqlite3_special_queries.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 -lresolv $(CUSTOMARGS) -o $@

test_ssl_fast_forward-2_libmariadb-t: test_ssl_fast_forward-2.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

test_ssl_fast_forward-2_libmysql-t: test_ssl_fast_forward-2.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 -lresolv $(CUSTOMARGS) -o $@

test_ssl_fast_forward-3_libmariadb-t: test_ssl_fast_forward-3.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

test_ssl_fast_forward-3_libmysql-t: test_ssl_fast_forward-3.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 -lresolv $(CUSTOMARGS) -o $@

fast_forward_switch_replication_deprecate_eof_libmysql-t: fast_forward_switch_replication_deprecate_eof.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 -lresolv $(CUSTOMARGS) -o $@

test_clickhouse_server_libmysql-t: test_clickhouse_server-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DLIBMYSQL_HELPER -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -lmysqlclient -ltap_mysql57 $(CUSTOMARGS) -o $@

reg_test_stmt_resultset_err_no_rows_libmysql-t: reg_test_stmt_resultset_err_no_rows-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DLIBMYSQL_HELPER -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -lmysqlclient -ltap_mysql57 $(CUSTOMARGS) -o $@

reg_test_mariadb_stmt_store_result_libmysql-t: reg_test_mariadb_stmt_store_result-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DLIBMYSQL_HELPER -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -lmysqlclient -ltap_mysql57 $(CUSTOMARGS) -o $@

reg_test_mariadb_stmt_store_result_async-t: reg_test_mariadb_stmt_store_result-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DASYNC_API $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

prepare_statement_err3024_libmysql-t: prepare_statement_err3024-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DLIBMYSQL_HELPER -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -lmysqlclient -ltap_mysql57 $(CUSTOMARGS) -o $@

prepare_statement_err3024_async-t: prepare_statement_err3024-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DASYNC_API $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

test_wexecvp_syscall_failures-t: test_wexecvp_syscall_failures-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -Wl,--wrap=pipe,--wrap=fcntl,--wrap=read,--wrap=poll $(STATIC_LIBS) -o $@

pgsql-extended_query_protocol_test-t: pgsql-extended_query_protocol_test-t.cpp pg_lite_client.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< pg_lite_client.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

pgsql-reg_test_5273_bind_parameter_format-t: pgsql-reg_test_5273_bind_parameter_format-t.cpp pg_lite_client.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< pg_lite_client.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

pgsql-reg_test_5300_threshold_resultset_deadlock-t: pgsql-reg_test_5300_threshold_resultset_deadlock-t.cpp pg_lite_client.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< pg_lite_client.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@


### clean targets

.SILENT: clean
.PHONY: clean
clean:
	rm -f *-t || true
	rm -f galera_1_timeout_count galera_2_timeout_no_count aurora || true
	rm -f generate_set_session_csv set_testing-240.csv || true
	rm -f setparser_test setparser_test2 setparser_test3  || true
	rm -f reg_test_3504-change_user_libmariadb_helper reg_test_3504-change_user_libmysql_helper || true
	rm -f *.gcda *.gcno || true
