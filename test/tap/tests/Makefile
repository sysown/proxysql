#!/bin/make -f


GIT_VERSION ?= $(shell git describe --long --abbrev=7)
ifndef GIT_VERSION
    $(error GIT_VERSION is not set)
endif


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)
PROXYSQL_IDIR := $(PROXYSQL_PATH)/include
PROXYSQL_LDIR := $(PROXYSQL_PATH)/lib

DEPS_PATH := $(PROXYSQL_PATH)/deps

MARIADB_PATH := $(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR := $(MARIADB_PATH)/include
MARIADB_LDIR := $(MARIADB_PATH)/libmariadb

JEMALLOC_PATH := $(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR := $(JEMALLOC_PATH)/include/jemalloc
JEMALLOC_LDIR := $(JEMALLOC_PATH)/lib

JSON_IDIR := $(DEPS_PATH)/json

RE2_PATH := $(DEPS_PATH)/re2/re2
RE2_IDIR := $(RE2_PATH)
RE2_LDIR := $(RE2_PATH)/obj

SQLITE3_PATH := $(DEPS_PATH)/sqlite3/sqlite3
SQLITE3_IDIR := $(SQLITE3_PATH)
SQLITE3_LDIR := $(SQLITE3_PATH)

LIBHTTPSERVER_DIR := $(DEPS_PATH)/libhttpserver/libhttpserver
LIBHTTPSERVER_IDIR := $(LIBHTTPSERVER_DIR)/src
LIBHTTPSERVER_LDIR := $(LIBHTTPSERVER_DIR)/build/src/.libs/

LIBCONFIG_PATH := $(DEPS_PATH)/libconfig/libconfig
LIBCONFIG_IDIR := $(LIBCONFIG_PATH)/lib
LIBCONFIG_LDIR := $(LIBCONFIG_PATH)/lib/.libs

CURL_DIR := $(DEPS_PATH)/curl/curl
CURL_IDIR := $(CURL_DIR)/include
CURL_LDIR := $(CURL_DIR)/lib/.libs

DAEMONPATH := $(DEPS_PATH)/libdaemon/libdaemon
DAEMONPATH_IDIR := $(DAEMONPATH)
DAEMONPATH_LDIR := $(DAEMONPATH)/libdaemon/.libs

PCRE_PATH := $(DEPS_PATH)/pcre/pcre
PCRE_LDIR := $(PCRE_PATH)/.libs

MICROHTTPD_DIR := $(DEPS_PATH)/libmicrohttpd/libmicrohttpd/src
MICROHTTPD_IDIR := $(MICROHTTPD_DIR)/include
MICROHTTPD_LDIR := $(MICROHTTPD_DIR)/microhttpd/.libs

LIBINJECTION_DIR := $(DEPS_PATH)/libinjection/libinjection
LIBINJECTION_IDIR := $(LIBINJECTION_DIR)/src
LIBINJECTION_LDIR := $(LIBINJECTION_DIR)/src

SSL_DIR := $(DEPS_PATH)/libssl/openssl/
SSL_IDIR := $(SSL_DIR)/include
SSL_LDIR := $(SSL_DIR)

EV_DIR := $(DEPS_PATH)/libev/libev/
EV_IDIR := $(EV_DIR)
EV_LDIR := $(EV_DIR)/.libs

PROMETHEUS_PATH := $(DEPS_PATH)/prometheus-cpp/prometheus-cpp
PROMETHEUS_IDIR := $(PROMETHEUS_PATH)/pull/include -I$(PROMETHEUS_PATH)/core/include
PROMETHEUS_LDIR := $(PROMETHEUS_PATH)/lib

CITYHASH_DIR := $(DEPS_PATH)/cityhash/cityhash/
CITYHASH_IDIR := $(CITYHASH_DIR)
CITYHASH_LDIR := $(CITYHASH_DIR)/src/.libs

COREDUMPER_DIR := $(DEPS_PATH)/coredumper/coredumper
COREDUMPER_IDIR := $(COREDUMPER_DIR)/include
COREDUMPER_LDIR := $(COREDUMPER_DIR)/src

TAP_PATH := ../tap
TAP_IDIR := ../tap
TAP_LDIR := ../tap

DOTENV_DYN_PATH := $(TAP_LDIR)/cpp-dotenv/dynamic/cpp-dotenv
DOTENV_DYN_IDIR := $(DOTENV_DYN_PATH)/include
DOTENV_DYN_LDIR := $(TAP_LDIR)

TEST_DEPS_PATH := $(PROXYSQL_PATH)/test/deps

TEST_MARIADB_PATH := $(TEST_DEPS_PATH)/mariadb-connector-c/mariadb-connector-c
TEST_MARIADB_IDIR := $(TEST_MARIADB_PATH)/include
TEST_MARIADB_LDIR := $(TEST_MARIADB_PATH)/libmariadb

TEST_MYSQL_PATH := $(TEST_DEPS_PATH)/mysql-connector-c/mysql-connector-c
TEST_MYSQL_IDIR := $(TEST_MYSQL_PATH)/include
TEST_MYSQL_EDIR := $(TEST_MYSQL_PATH)/libbinlogevents/export/
TEST_MYSQL_LDIR := $(TEST_MYSQL_PATH)/libmysql

TEST_MYSQL8_PATH := $(TEST_DEPS_PATH)/mysql-connector-c-8.4.0/mysql-connector-c
TEST_MYSQL8_IDIR := $(TEST_MYSQL8_PATH)/include
TEST_MYSQL8_EDIR := $(TEST_MYSQL8_PATH)/libbinlogevents/export/
TEST_MYSQL8_LDIR := $(TEST_MYSQL8_PATH)/libmysql

LIBPROXYSQLAR := $(PROXYSQL_LDIR)/libproxysql.a

ODIR := $(PROXYSQL_PATH)/obj

EXECUTABLE := proxysql

OBJ := $(PROXYSQL_PATH)/src/obj/proxysql_global.o $(PROXYSQL_PATH)/src/obj/main.o $(PROXYSQL_PATH)/src/obj/proxy_tls.o

SOURCES := ../tap/utils.cpp

IDIRS := -I$(TAP_IDIR) -I$(RE2_IDIR) -I$(PROXYSQL_IDIR) -I$(JEMALLOC_IDIR) -I$(LIBCONFIG_IDIR) -I$(MARIADB_IDIR)\
		 -I$(DAEMONPATH_IDIR) -I$(MICROHTTPD_IDIR) -I$(LIBHTTPSERVER_IDIR) -I$(CURL_IDIR) -I$(EV_IDIR)\
		 -I$(PROMETHEUS_IDIR) -I$(DOTENV_DYN_IDIR) -I$(SSL_IDIR) -I$(SQLITE3_IDIR) -I$(JSON_IDIR)
LDIRS := -L$(TAP_LDIR) -L$(RE2_LDIR) -L$(PROXYSQL_LDIR) -L$(JEMALLOC_LDIR) -L$(LIBCONFIG_LDIR) -L$(MARIADB_LDIR)\
		 -L$(DAEMONPATH_LDIR) -L$(MICROHTTPD_LDIR) -L$(LIBHTTPSERVER_LDIR) -L$(CURL_LDIR) -L$(EV_LDIR)\
		 -L$(PROMETHEUS_LDIR) -L$(DOTENV_DYN_LDIR) -L$(SSL_LDIR) -L$(PCRE_LDIR) -L$(LIBINJECTION_LDIR)

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
	LDIRS += -L$(COREDUMPER_LDIR)
endif

MYLIBS := -Wl,--export-dynamic
MYLIBS += -Wl,-Bdynamic -lgnutls -ltap -lcpp_dotenv -lcurl -lssl -lcrypto -lre2 -luuid
MYLIBS += -Wl,-Bstatic -lconfig -lproxysql -ldaemon -lconfig++ -lpcrecpp -lpcre -lmariadbclient -lhttpserver\
		  -lmicrohttpd -linjection -lev -lprometheus-cpp-pull -lprometheus-cpp-core
MYLIBS += -Wl,-Bdynamic -lpthread -lm -lz -lrt -ldl $(EXTRALINK)

MYLIBSJEMALLOC := -Wl,-Bstatic -ljemalloc
STATIC_LIBS := $(CITYHASH_LDIR)/libcityhash.a

LIBCOREDUMPERAR :=
ifeq ($(UNAME_S),Linux)
	LIBCOREDUMPERAR := $(COREDUMPER_LDIR)/libcoredumper.a
	STATIC_LIBS += $(LIBCOREDUMPERAR)
endif

### detect compiler support for c++11/17
CPLUSPLUS := $(shell ${CC} -std=c++17 -dM -E -x c++ /dev/null 2>/dev/null | grep -F __cplusplus | egrep -o '[0-9]{6}L')
ifneq ($(CPLUSPLUS),201703L)
	CPLUSPLUS := $(shell ${CC} -std=c++11 -dM -E -x c++ /dev/null 2>/dev/null| grep -F __cplusplus | egrep -o '[0-9]{6}L')
ifneq ($(CPLUSPLUS),201103L)
    $(error Compiler must support at least c++11)
endif
endif
STDCPP := -std=c++$(shell echo $(CPLUSPLUS) | cut -c3-4) -DCXX$(shell echo $(CPLUSPLUS) | cut -c3-4)

WGCOV :=
ifeq ($(WITHGCOV),1)
	WGCOV := -DWITHGCOV --coverage -lgcov
endif

WASAN :=
ifeq ($(WITHASAN),1)
	WASAN := -fsanitize=address -DTEST_WITHASAN
	# Force the disable of JEMALLOC, since ASAN isn't compatible.
	export NOJEMALLOC=1
	# workaroud ASAN limitation ASLR > 28bits
	# https://github.com/google/sanitizers/issues/1716
	# sudo sysctl vm.mmap_rnd_bits=28
    $(warning ASAN needs ASLR =< 28bits, make sure 'sysctl vm.mmap_rnd_bits=28' is set.)
endif

OPT := $(STDCPP) -O2 -ggdb -Wl,--no-as-needed -Wl,-rpath,$(TAP_LDIR) $(WGCOV) $(WASAN) -DGITVERSION=\"$(GIT_VERSION)\"

### main targets

.DEFAULT: default
.PHONY: default
default: all

CUSTOMARGS := -I$(TAP_IDIR) -I$(CURL_IDIR) -I$(SQLITE3_IDIR) -I$(PROXYSQL_IDIR) -I$(JSON_IDIR) -I$(SSL_IDIR) -I$(RE2_IDIR)
CUSTOMARGS += -L$(TAP_LDIR) -L$(CURL_LDIR) -L$(SSL_LDIR) -L$(RE2_LDIR)
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
	setparser_test2 setparser_test2-t \
	setparser_test3 setparser_test3-t \
	set_testing-240.csv \
	test_clickhouse_server_libmysql-t \
	reg_test_stmt_resultset_err_no_rows_libmysql-t \
	prepare_statement_err3024_libmysql-t \
	prepare_statement_err3024_async-t \
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
	$(CXX) -DTEST_GALERA $< ../tap/SQLite3_Server.cpp $(IDIRS) $(LDIRS) $(OPT) $(OBJ) $(MYLIBSJEMALLOC) $(MYLIBS) $(STATIC_LIBS) -o $@

galera_2_timeout_no_count: galera_2_timeout_no_count.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DTEST_GALERA $< ../tap/SQLite3_Server.cpp $(IDIRS) $(LDIRS) $(OPT) $(OBJ) $(MYLIBSJEMALLOC) $(MYLIBS) $(STATIC_LIBS) -o $@

generate_set_session_csv: generate_set_session_csv.cpp
	$(CXX) $< $(OPT) -o $@

aurora: aurora.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DTEST_AURORA $< ../tap/SQLite3_Server.cpp $(IDIRS) $(LDIRS) $(OPT) $(OBJ) $(MYLIBSJEMALLOC) $(MYLIBS) $(STATIC_LIBS) -o $@

test_tokenizer-t: test_tokenizer-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

test_mysql_query_digests_stages-t: test_mysql_query_digests_stages-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

sqlite3-t: sqlite3-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) -o $@

test_gtid_forwarding-t: test_gtid_forwarding-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

test_admin_prometheus_metrics_dump-t: test_admin_prometheus_metrics_dump-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

create_connection_annotation: test_connection_annotation-t.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DTEST_AURORA $< $(IDIRS) $(LDIRS) $(OPT) $(OBJ) $(MYLIBS) $(STATIC_LIBS) -o $@

setparser_test: setparser_test.cpp $(TAP_LDIR)/libtap.so $(RE2_PATH)/util/test.cc $(PROXYSQL_LDIR)/set_parser.cpp $(LIBPROXYSQLAR) $(LIBCOREDUMPERAR)
	$(CXX) $< $(RE2_PATH)/util/test.cc $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) -o $@

setparser_test2-t: setparser_test2
	ln -fs setparser_test2 setparser_test2-t

setparser_test2: setparser_test2.cpp $(TAP_LDIR)/libtap.so $(PROXYSQL_LDIR)/set_parser.cpp setparser_test_common.h $(LIBPROXYSQLAR) $(LIBCOREDUMPERAR)
	$(CXX) $< $(PROXYSQL_LDIR)/set_parser.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) -o $@

setparser_test3-t: setparser_test3
	ln -fs setparser_test3 setparser_test3-t

setparser_test3: setparser_test3.cpp $(TAP_LDIR)/libtap.so $(PROXYSQL_LDIR)/set_parser.cpp setparser_test_common.h $(LIBPROXYSQLAR) $(LIBCOREDUMPERAR)
	$(CXX) -DPARSERDEBUG $< $(PROXYSQL_LDIR)/set_parser.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) -o $@

reg_test_3504-change_user_libmariadb_helper: reg_test_3504-change_user_helper.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

reg_test_3504-change_user_libmysql_helper: reg_test_3504-change_user_helper.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DLIBMYSQL_HELPER -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -Wl,-Bstatic -lmysqlclient -ltap_mysql57 $(CUSTOMARGS) -o $@

mysql_reconnect_libmariadb-t: mysql_reconnect.cpp $(TAP_LDIR)/libtap.so
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

mysql_reconnect_libmysql-t: mysql_reconnect.cpp $(TAP_LDIR)/libtap_mysql8.a
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
