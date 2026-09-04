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
			-I$(SSL_IDIR) \
			-I$(PROXYSQL_PATH)/include

LDIRS :=	-L$(TAP_LDIR) \
			-L$(RE2_LDIR) \
			-L$(ABSL_LDIR) \
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
			-L$(PCRE2_LDIR) \
			-L$(LIBINJECTION_LDIR) \
			-L$(POSTGRESQL_LDIR) \
			-L$(LIBSCRAM_LDIR) \
			-L$(LIBUSUAL_LDIR) \
			-L$(SSL_LDIR) \
			-L$(PARSERSQL_LDIR)

ifeq ($(UNAME_S),Linux)
	LDIRS += -L$(COREDUMPER_LDIR)
endif

# Vendored protobuf 3.21.12 -- mirrors the definitions/usage in
# test/tap/tests/unit/Makefile. ProxySQL builds protobuf locally under
# deps/protobuf/ when PROXYSQL40=1 and the committed plugins/mysqlx/proto
# /*.pb.h files require headers (e.g. <google/protobuf/generated_message
# _bases.h>) that only exist in 3.16+. The vendored install path must be
# on IDIRS/LDIRS so every test_mysqlx_e2e_*-t rule below resolves the
# right headers and the link rules below reference the vendored
# libprotobuf.a explicitly via $(PROTOBUF_LIB) (full path) instead of
# `-lprotobuf`. Going through -lprotobuf races the system v3.12 .so
# that the deb-compliant entrypoint apt-installs for PROXYSQL40 builds
# -- `-Bdynamic -lprotobuf` resolves to the system .so first and the
# .pb.o (built against vendored 3.21 headers) fails to link. Same fix
# as test/tap/tests/unit/Makefile.
ifeq ($(PROXYSQL40),1)
PROTOBUF_VERSION := 3.21.12
PROTOBUF_INSTALL_DIR := $(PROXYSQL_PATH)/deps/protobuf/protobuf-$(PROTOBUF_VERSION)/install
PROTOBUF_INCLUDE_DIR := $(PROTOBUF_INSTALL_DIR)/include
PROTOBUF_LDIR := $(PROTOBUF_INSTALL_DIR)/lib
PROTOBUF_LIB := $(PROTOBUF_LDIR)/libprotobuf.a
IDIRS += -I$(PROTOBUF_INCLUDE_DIR)
LDIRS += -L$(PROTOBUF_LDIR)
endif


LIBPROXYSQLAR := $(PROXYSQL_LDIR)/libproxysql.a

ODIR := $(PROXYSQL_PATH)/obj

EXECUTABLE := proxysql

OBJ := $(PROXYSQL_PATH)/src/obj/proxysql_global.o $(PROXYSQL_PATH)/src/obj/main.o $(PROXYSQL_PATH)/src/obj/proxy_tls.o

#SOURCES := ../tap/utils.cpp

CURL_STATIC_LIB := $(CURL_LDIR)/libcurl.a
POSTGRESQL_STATIC_LIBS := $(POSTGRESQL_PATH)/interfaces/libpq/libpq.a \
	$(POSTGRESQL_PATH)/common/libpgcommon.a \
	$(POSTGRESQL_PATH)/port/libpgport.a

ifeq ($(UNAME_S),Darwin)
MYLIBS_DYNAMIC_PART := -lgnutls -lcpp_dotenv -luuid
MYLIBS_STATIC_PART := -lconfig -lproxysql -lsqlparser -ldaemon -lconfig++ $(RE2_STATIC_LIBS) $(PCRE2_LIBS) -lmariadbclient -lhttpserver -lmicrohttpd -linjection -lev -lprometheus-cpp-pull -lprometheus-cpp-core
MYLIBS_LAST_PART := -lpthread -lm -lz -lzstd -liconv -ldl $(EXTRALINK)
MYLIBS := -ltap $(MYLIBS_DYNAMIC_PART) $(MYLIBS_STATIC_PART) \
	$(POSTGRESQL_STATIC_LIBS) $(CURL_STATIC_LIB) $(OPENSSL_STATIC_LIBS) \
	$(MYLIBS_LAST_PART)
else
MYLIBS_DYNAMIC_PART := -Wl,--export-dynamic -Wl,-Bdynamic -lgnutls -lcpp_dotenv -luuid
MYLIBS_STATIC_PART := -Wl,-Bstatic -lconfig -lproxysql -lsqlparser -ldaemon -lconfig++ $(RE2_STATIC_LIBS) $(PCRE2_LIBS) -lmariadbclient -lhttpserver -lmicrohttpd -linjection -lev -lprometheus-cpp-pull -lprometheus-cpp-core
MYLIBS_LAST_PART := -Wl,-Bdynamic -lpthread -lm -lz -lzstd -lrt -ldl $(EXTRALINK)
MYLIBS := -Wl,-Bdynamic -ltap $(MYLIBS_DYNAMIC_PART) $(MYLIBS_STATIC_PART) \
	$(POSTGRESQL_STATIC_LIBS) $(CURL_STATIC_LIB) $(OPENSSL_STATIC_LIBS) \
	$(MYLIBS_LAST_PART)
endif

MYLIBSJEMALLOC :=
ifneq ($(NOJEMALLOC),1)
ifeq ($(UNAME_S),Linux)
MYLIBSJEMALLOC := -Wl,-Bstatic -ljemalloc
endif
endif
STATIC_LIBS := $(CITYHASH_LDIR)/libcityhash.a

ALLOW_MULTI_DEF :=
ifneq ($(UNAME_S),Darwin)
	ALLOW_MULTI_DEF := -Wl,--allow-multiple-definition
endif

RESOLV_LIB :=
ifeq ($(UNAME_S),Linux)
	RESOLV_LIB := -lresolv
endif

LIBCOREDUMPERAR :=
ifeq ($(UNAME_S),Linux)
	LIBCOREDUMPERAR := $(COREDUMPER_LDIR)/libcoredumper.a
	STATIC_LIBS += $(LIBCOREDUMPERAR)
endif

ifneq ($(PROXYSQL40),)
ifneq ($(wildcard $(SQLITE3_LDIR)/vec.o),)
	STATIC_LIBS += $(SQLITE3_LDIR)/vec.o
endif
endif

# Keep public class layouts identical to libproxysql.a. In particular,
# PROXYSQL40 adds members to ProxySQL_GlobalVariables; omitting the define in
# TAP translation units makes their GloVars allocation smaller than the
# constructor linked from the archive.
PSQL40 :=
ifeq ($(PROXYSQL40),1)
	PSQL40 := -DPROXYSQL40
endif

OPT := $(STDCPP) -O2 -ggdb $(PSQL40) $(WGCOV) $(WASAN) -DGITVERSION=\"$(GIT_VERSION)\"
ifneq ($(UNAME_S),Darwin)
OPT += -Wl,--no-as-needed
endif
OPT += -Wl,-rpath,$(TAP_LDIR) -Wl,-rpath,$(POSTGRESQL_PATH)/interfaces/libpq -Wl,-rpath,$(RE2_LDIR)

### main targets

.DEFAULT: default
.PHONY: default debug
default: all

CUSTOMARGS := -I$(TAP_IDIR) -I$(CURL_IDIR) -I$(SQLITE3_IDIR) -I$(PROXYSQL_IDIR) -I$(JSON_IDIR) -I$(RE2_IDIR) -I$(SSL_IDIR)
CUSTOMARGS += -L$(TAP_LDIR) -L$(CURL_LDIR) -L$(RE2_LDIR) -L$(ABSL_LDIR) -L$(SSL_LDIR) -L$(POSTGRESQL_LDIR)
ifeq ($(UNAME_S),Darwin)
CUSTOMARGS += -ltap -lcpp_dotenv $(RE2_STATIC_LIBS) $(POSTGRESQL_STATIC_LIBS) \
	$(CURL_STATIC_LIB) $(OPENSSL_STATIC_LIBS) -lpthread -lz -lzstd -ldl $(LWGCOV)
else
CUSTOMARGS += -Wl,--export-dynamic -Wl,-Bdynamic -ltap -lcpp_dotenv $(RE2_STATIC_LIBS) \
	$(POSTGRESQL_STATIC_LIBS) $(CURL_STATIC_LIB) $(OPENSSL_STATIC_LIBS) \
	-lpthread -lz -lzstd -ldl $(LWGCOV)
endif

.PHONY: all
all: tests

.PHONY: tests_no_infra
tests_no_infra: admin_set_credentials_logging-t listener_conflicts_validation-t
	./admin_set_credentials_logging-t
	./listener_conflicts_validation-t

DEBUG_OPT := $(STDCPP) -O0 -DDEBUG -ggdb $(PSQL40) $(WGCOV) $(WASAN) -DGITVERSION=\"$(GIT_VERSION)\"
ifneq ($(UNAME_S),Darwin)
DEBUG_OPT += -Wl,--no-as-needed
endif
DEBUG_OPT += -Wl,-rpath,$(TAP_LDIR) -Wl,-rpath,$(POSTGRESQL_PATH)/interfaces/libpq -Wl,-rpath,$(RE2_LDIR)
debug: OPT := $(DEBUG_OPT)
debug: tests

test_cacert_load_and_verify_duration-t: private OPT += -DPROXYSQL_VENDORED_OPENSSL_VERSION=\"$(OPENSSL_VERSION)\"

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
	setparser_parsersql_test setparser_parsersql_test-t \
	parsersql_digest_test parsersql_digest_test-t \
	setparser_test2 setparser_test2-t \
	setparser_test3 setparser_test3-t \
	set_testing-240.csv \
	test_clickhouse_server_libmysql-t \
	reg_test_stmt_resultset_err_no_rows_libmysql-t \
	prepare_statement_err3024_libmysql-t \
	prepare_statement_err3024_async-t \
	fast_forward_grace_close_libmysql-t \
	mysql-zstd_compression_level_libmysql-t \
	fast_forward_switch_replication_deprecate_eof_libmysql-t \
	reg_test_mariadb_stmt_store_result_libmysql-t \
	reg_test_mariadb_stmt_store_result_async-t
tests:
	@echo "Removing empty .gcno files ..."
	find -L . -type f -name '*.gcno' -empty -ls -delete

# test_mysqlx_*-t.cpp reference chassis/plugin types (ProxySQL_PluginServices,
# mysqlx_config_store.h from plugins/mysqlx/include) that only exist when
# libproxysql.a was built with -DPROXYSQL40.  Autodetect the flag via a
# chassis-exclusive symbol in the static lib; under !PROXYSQL40 filter
# these tests out of the wildcard glob so plain v3.0/v3.1 `make debug`
# doesn't try to compile them.
LIBPROXYSQLAR := $(PROXYSQL_LDIR)/libproxysql.a
PROXYSQL40_DETECTED := $(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -c invoke_register_schemas_phase)

# Tests that use GNU ld --wrap (unsupported on macOS)
TESTS_FILTER_DARWIN := test_wexecvp_syscall_failures-t
TESTS_CPP_FILTER := $(if $(filter Darwin,$(UNAME_S)),$(TESTS_FILTER_DARWIN),)

ifeq ($(PROXYSQL40_DETECTED),0)
TESTS_CPP := $(filter-out test_mysqlx_% $(TESTS_CPP_FILTER),$(patsubst %.cpp,%,$(wildcard *-t.cpp)))
else
TESTS_CPP := $(filter-out $(TESTS_CPP_FILTER),$(patsubst %.cpp,%,$(wildcard *-t.cpp)))
endif

tests-cpp: $(TESTS_CPP)
tests-php: $(patsubst %,php-%,$(wildcard *-t.php))
tests-py: $(patsubst %,py-%,$(wildcard *-t.py))
tests-sh: $(patsubst %,sh-%,$(wildcard *-t.sh))
testgalera: galera_1_timeout_count galera_2_timeout_no_count
testaurora: aurora


### test deps targets

#build_test_deps: $(TAP_LDIR)/libtap$(SHLIB_EXT) $(TEST_MARIADB_LDIR)/libmariadbclient.a $(TEST_MYSQL_LDIR)/libmysqlclient.a

$(TAP_LDIR)/libtap$(SHLIB_EXT):
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

 test_com_register_slave_enables_fast_forward-t: binlog_rpl.h

%-t: %-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT) $(POSTGRESQL_STATIC_LIBS)
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

galera_1_timeout_count: galera_1_timeout_count.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DTEST_GALERA $< ../../../src/SQLite3_Server.cpp ../../../lib/ProxySQL_Admin.cpp -I$(COREDUMPER_IDIR) $(IDIRS) $(LDIRS) -L$(CLICKHOUSE_CPP_LDIR) -L$(LZ4_LDIR) $(OPT) $(OBJ) $(MYLIBSJEMALLOC) $(MYLIBS) $(STATIC_LIBS) $(CLICKHOUSE_CPP_LDIR)/libclickhouse-cpp-lib.a $(CLICKHOUSE_CPP_PATH)/contrib/zstd/zstd/libzstdstatic.a $(LZ4_LDIR)/liblz4.a -lscram -lusual $(ALLOW_MULTI_DEF) -o $@

galera_2_timeout_no_count: galera_2_timeout_no_count.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DTEST_GALERA $< ../../../src/SQLite3_Server.cpp ../../../lib/ProxySQL_Admin.cpp -I$(COREDUMPER_IDIR) $(IDIRS) $(LDIRS) -L$(CLICKHOUSE_CPP_LDIR) -L$(LZ4_LDIR) $(OPT) $(OBJ) $(MYLIBSJEMALLOC) $(MYLIBS) $(STATIC_LIBS) $(CLICKHOUSE_CPP_LDIR)/libclickhouse-cpp-lib.a $(CLICKHOUSE_CPP_PATH)/contrib/zstd/zstd/libzstdstatic.a $(LZ4_LDIR)/liblz4.a -lscram -lusual $(ALLOW_MULTI_DEF) -o $@

generate_set_session_csv: generate_set_session_csv.cpp
	$(CXX) $< $(OPT) -o $@

aurora: aurora.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DTEST_AURORA $< ../tap/SQLite3_Server.cpp $(IDIRS) $(LDIRS) $(OPT) $(OBJ) $(MYLIBSJEMALLOC) $(MYLIBS) $(STATIC_LIBS) -o $@

test_tokenizer-t: test_tokenizer-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

test_mysql_query_digests_stages-t: test_mysql_query_digests_stages-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

MYSQLX_BRIDGE_TESTS := test_mysqlx_plugin_load-t test_mysqlx_admin_tables-t

# Build both bridge tests in one unit submake. Separate recursive makes do not
# share a dependency graph and can otherwise rebuild common objects such as
# unit/obj/test_init.o concurrently.
.PHONY: mysqlx-bridge-tests $(MYSQLX_BRIDGE_TESTS)
mysqlx-bridge-tests:
	$(MAKE) -C unit $(MYSQLX_BRIDGE_TESTS)

$(MYSQLX_BRIDGE_TESTS): mysqlx-bridge-tests
	ln -fs unit/$@ $@

# test_mysqlx_listener_smoke-t was retired with the dormant MysqlxWorker
# path in 98aee7db2. Listener-lifecycle coverage now lives in
# mysqlx_thread_unit-t and mysqlx_robustness_unit-t under unit/.

sqlite3-t: sqlite3-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
ifneq ($(PROXYSQL40),)
	$(CXX) $< -DEXCLUDE_TRACKING_VARIABLES $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) $(SQLITE3_LDIR)/vec.o -o $@
else
	$(CXX) $< -DEXCLUDE_TRACKING_VARIABLES $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) -o $@
endif

test_gtid_forwarding-t: test_gtid_forwarding-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

test_gtid_from_ok-t: test_gtid_from_ok-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

test_ignore_min_gtid-t: test_ignore_min_gtid-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

test_admin_prometheus_metrics_dump-t: test_admin_prometheus_metrics_dump-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -o $@

create_connection_annotation: test_connection_annotation-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DTEST_AURORA $< $(IDIRS) $(LDIRS) $(OPT) $(OBJ) $(MYLIBS) $(STATIC_LIBS) -o $@

setparser_test: setparser_test.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT) $(PROXYSQL_LDIR)/MySQL_Set_Stmt_Parser.cpp $(LIBPROXYSQLAR) $(LIBCOREDUMPERAR)
ifneq ($(PROXYSQL40),)
	$(CXX) $< -DEXCLUDE_TRACKING_VARIABLES $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) $(SQLITE3_LDIR)/vec.o -o $@
else
	$(CXX) $< -DEXCLUDE_TRACKING_VARIABLES $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) -o $@
endif

setparser_test2-t: setparser_test2
	ln -fs setparser_test2 setparser_test2-t

setparser_test2: setparser_test2.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT) $(PROXYSQL_LDIR)/MySQL_Set_Stmt_Parser.cpp setparser_test_common.h $(LIBPROXYSQLAR) $(LIBCOREDUMPERAR)
ifneq ($(PROXYSQL40),)
	$(CXX) $<  -DEXCLUDE_TRACKING_VARIABLES $(PROXYSQL_LDIR)/MySQL_Set_Stmt_Parser.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) $(SQLITE3_LDIR)/vec.o -o $@
else
	$(CXX) $<  -DEXCLUDE_TRACKING_VARIABLES $(PROXYSQL_LDIR)/MySQL_Set_Stmt_Parser.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) -o $@
endif

setparser_test3-t: setparser_test3
	ln -fs setparser_test3 setparser_test3-t

setparser_test3: setparser_test3.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT) $(PROXYSQL_LDIR)/MySQL_Set_Stmt_Parser.cpp setparser_test_common.h $(LIBPROXYSQLAR) $(LIBCOREDUMPERAR)
ifneq ($(PROXYSQL40),)
	$(CXX) $< -DEXCLUDE_TRACKING_VARIABLES -DPARSERDEBUG $(PROXYSQL_LDIR)/MySQL_Set_Stmt_Parser.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) $(SQLITE3_LDIR)/vec.o -o $@
else
	$(CXX) $< -DEXCLUDE_TRACKING_VARIABLES -DPARSERDEBUG $(PROXYSQL_LDIR)/MySQL_Set_Stmt_Parser.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) -o $@
endif

reg_test_3504-change_user_libmariadb_helper: reg_test_3504-change_user_helper.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

reg_test_3504-change_user_libmysql_helper: reg_test_3504-change_user_helper.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
ifneq ($(UNAME_S),Darwin)
	$(CXX) -DLIBMYSQL_HELPER -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -Wl,-Bstatic -lmysqlclient -ltap_mysql57 $(CUSTOMARGS) -o $@
else
	$(CXX) -DLIBMYSQL_HELPER -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -lmysqlclient -ltap_mysql57 $(CUSTOMARGS) -o $@
endif

mysql_reconnect_libmariadb-t: mysql_reconnect.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

mysql_reconnect_libmysql-t: mysql_reconnect.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 $(RESOLV_LIB) $(CUSTOMARGS) -o $@

mysql-zstd_compression_level_libmysql-t: mysql-zstd_compression_level-t.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 $(RESOLV_LIB) $(CUSTOMARGS) -o $@

fast_forward_grace_close_libmysql-t: fast_forward_grace_close.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 $(RESOLV_LIB) $(CUSTOMARGS) -o $@

test_match_eof_conn_cap_libmysql-t: test_match_eof_conn_cap.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 $(RESOLV_LIB) $(CUSTOMARGS) -o $@

test_match_eof_conn_cap_libmariadb-t: test_match_eof_conn_cap.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

test_sqlite3_special_queries_libmariadb-t: test_sqlite3_special_queries.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

test_sqlite3_special_queries_libmysql-t: test_sqlite3_special_queries.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 $(RESOLV_LIB) $(CUSTOMARGS) -o $@

test_ssl_fast_forward-2_libmariadb-t: test_ssl_fast_forward-2.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

test_ssl_fast_forward-2_libmysql-t: test_ssl_fast_forward-2.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 $(RESOLV_LIB) $(CUSTOMARGS) -o $@

test_ssl_fast_forward-3_libmariadb-t: test_ssl_fast_forward-3.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

test_ssl_fast_forward-3_libmysql-t: test_ssl_fast_forward-3.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 $(RESOLV_LIB) $(CUSTOMARGS) -o $@

fast_forward_switch_replication_deprecate_eof_libmysql-t: fast_forward_switch_replication_deprecate_eof.cpp $(TAP_LDIR)/libtap_mysql8.a
	$(CXX) -DLIBMYSQL_HELPER8 -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL8_EDIR) -L$(TEST_MYSQL8_LDIR) -lmysqlclient -ltap_mysql8 $(RESOLV_LIB) $(CUSTOMARGS) -o $@

test_clickhouse_server_libmysql-t: test_clickhouse_server-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DLIBMYSQL_HELPER -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -lmysqlclient -ltap_mysql57 $(CUSTOMARGS) -o $@

reg_test_stmt_resultset_err_no_rows_libmysql-t: reg_test_stmt_resultset_err_no_rows-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DLIBMYSQL_HELPER -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -lmysqlclient -ltap_mysql57 $(CUSTOMARGS) -o $@

reg_test_mariadb_stmt_store_result_libmysql-t: reg_test_mariadb_stmt_store_result-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DLIBMYSQL_HELPER -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -lmysqlclient -ltap_mysql57 $(CUSTOMARGS) -o $@

reg_test_mariadb_stmt_store_result_async-t: reg_test_mariadb_stmt_store_result-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DASYNC_API $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

prepare_statement_err3024_libmysql-t: prepare_statement_err3024-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DLIBMYSQL_HELPER -DDISABLE_WARNING_COUNT_LOGGING $< -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -lmysqlclient -ltap_mysql57 $(CUSTOMARGS) -o $@

prepare_statement_err3024_async-t: prepare_statement_err3024-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) -DASYNC_API $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

ifneq ($(UNAME_S),Darwin)
test_wexecvp_syscall_failures-t: test_wexecvp_syscall_failures-t.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) $< $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) -Wl,--wrap=pipe,--wrap=fcntl,--wrap=read,--wrap=poll,--wrap=fork,--wrap=_Znwm,--wrap=opendir $(STATIC_LIBS) -o $@
endif

# Every test that links pg_lite_client.cpp shares one link line. pg_lite_client
# implements PostgreSQL MD5 and SCRAM-SHA-256 client authentication (including the
# stepwise saslBegin/saslFinish pair the mid-handshake reload test drives), so it
# needs -lscram/-lusual; $(ALLOW_MULTI_DEF) resolves the duplicate symbols between
# libscram/libusual and the other vendored static libs (test binaries only, and
# it is empty on Darwin where the linker has no such flag).
PG_LITE_CLIENT_TESTS := \
	pgsql-extended_query_protocol_test-t \
	pgsql-reg_test_5273_bind_parameter_format-t \
	pgsql-reg_test_5899_bind_zero_param_formats-t \
	pgsql-reg_test_5300_threshold_resultset_deadlock-t \
	pgsql-reg_test_5866_result_format-t \
	pgsql-auth_method_matrix-t \
	pgsql-datatype_matrix-t \
	pgsql-server_side_cursors-t \
	pgsql-scram_reload_midhandshake-t \
	pgsql-scram_user_removed_midhandshake-t \
	pgsql-scram_rotate_midhandshake_backend-t \
	pgsql-native_portals-t \
	test_ffto_pgsql_pipeline-t \
	test_ffto_pgsql_stmt_portal-t

$(PG_LITE_CLIENT_TESTS): %: %.cpp pg_lite_client.cpp pg_lite_client.h $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) $< pg_lite_client.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -lscram -lusual $(ALLOW_MULTI_DEF) -o $@

# pgsql_mock_backend.cpp is a scriptable fake PostgreSQL server. It exists to
# reach backend behaviour a real PostgreSQL never produces -- a server that
# vanishes mid-result, or replies in an invalid sequence. These rules differ from
# the generic %-t rule ONLY by compiling pgsql_mock_backend.cpp in alongside the
# test; the generic rule builds $< alone, so the harness would not be linked.
# Nothing else is needed: -lpthread for its listener/worker threads already comes
# from MYLIBS, and unlike the pg_lite_client rules above there is no -lscram or
# -lusual to create duplicate symbols, so $(ALLOW_MULTI_DEF) does not apply.
PGSQL_MOCK_BACKEND_TESTS := \
	pgsql-reg_test_6109_midresult_disconnect-t \
	pgsql-reg_test_6110_invalid_reply_sequence-t \
	pgsql-native_hostile_backend-t

$(PGSQL_MOCK_BACKEND_TESTS): %: %.cpp pgsql_mock_backend.cpp pgsql_mock_backend.h $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) $< pgsql_mock_backend.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@

MYSQLX_PROTO_DIR := $(PROXYSQL_PATH)/plugins/mysqlx/proto
MYSQLX_PROTO_SRCS := $(wildcard $(MYSQLX_PROTO_DIR)/*.pb.cc)
MYSQLX_PROTO_OBJS := $(patsubst $(MYSQLX_PROTO_DIR)/%.pb.cc,$(ODIR)/mysqlx_proto_%.pb.o,$(MYSQLX_PROTO_SRCS))

$(ODIR):
	@mkdir -p $(ODIR)

# PROTOBUF_INCLUDE_DIR comes through $(IDIRS) -- added above under the
# ifeq ($(PROXYSQL40),1) block. PROTOBUF_LIB as a prerequisite chains
# the deps protobuf build for anyone running this target standalone.
$(ODIR)/mysqlx_proto_%.pb.o: $(MYSQLX_PROTO_DIR)/%.pb.cc $(PROTOBUF_LIB) | $(ODIR)
	$(CXX) -c -o $@ $< $(STDCPP) -O2 -ggdb \
		-I$(MYSQLX_PROTO_DIR) $(IDIRS) -w

test_mysqlx_e2e_handshake-t: test_mysqlx_e2e_handshake-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(PROTOBUF_LIB) -ltap -lcpp_dotenv -lmariadbclient \
		$(POSTGRESQL_STATIC_LIBS) $(CURL_STATIC_LIB) $(OPENSSL_STATIC_LIBS) \
		-lpthread -lz -ldl -o $@

test_mysqlx_e2e_routing-t: test_mysqlx_e2e_routing-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(PROTOBUF_LIB) -ltap -lcpp_dotenv -lmariadbclient \
		$(POSTGRESQL_STATIC_LIBS) $(CURL_STATIC_LIB) $(OPENSSL_STATIC_LIBS) \
		-lpthread -lz -ldl -o $@

# Behavioural validation TAP test for issue #5678 part (b): the X-Protocol
# clients are driven directly via the protocol helpers (same set used by
# test_mysqlx_e2e_*-t), and the admin DELETE+LOAD is issued through
# libmariadbclient (classic protocol on port 6032). Same link-line as the
# e2e routing test.
test_mysqlx_route_drop_inflight-t: test_mysqlx_route_drop_inflight-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TAP_LDIR)/libtap$(SHLIB_EXT)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(PROTOBUF_LIB) -ltap -lcpp_dotenv -lmariadbclient \
		$(POSTGRESQL_STATIC_LIBS) $(CURL_STATIC_LIB) $(OPENSSL_STATIC_LIBS) \
		-lpthread -lz -ldl -o $@

# The historical inflight stub binary was deleted in the same PR that
# removed skip_all() from the framework. The stub had never been more
# than a skip_all() guard pointing operators at the real implementation,
# which lives in test/scripts/mysqlx/behavioral_validation.py
# --scenario shutdown. Once skip_all was removed, the stub had no
# purpose other than to BAIL_OUT on invocation, so the source and this
# Makefile target were removed together. The python scenario is the
# canonical shutdown-inflight test.


### clean targets

.SILENT: clean
.PHONY: clean
clean:
	rm -f *-t || true
	rm -f galera_1_timeout_count galera_2_timeout_no_count aurora || true
	rm -f generate_set_session_csv set_testing-240.csv || true
	rm -f setparser_test setparser_test2 setparser_test3 setparser_parsersql_test parsersql_digest_test || true
	rm -f reg_test_3504-change_user_libmariadb_helper reg_test_3504-change_user_libmysql_helper || true

setparser_parsersql_test-t: setparser_parsersql_test
	ln -fs setparser_parsersql_test setparser_parsersql_test-t

setparser_parsersql_test: setparser_parsersql_test.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT) setparser_test_common.h $(LIBPROXYSQLAR) $(LIBCOREDUMPERAR) $(PARSERSQL_LDIR)/libsqlparser.a
ifeq ($(PROXYSQL40),1)
	$(CXX) $< -DEXCLUDE_TRACKING_VARIABLES $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) $(SQLITE3_LDIR)/vec.o $(PARSERSQL_LDIR)/libsqlparser.a -o $@
else
	$(CXX) $< -DEXCLUDE_TRACKING_VARIABLES $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) $(PARSERSQL_LDIR)/libsqlparser.a -o $@
endif

parsersql_digest_test: parsersql_digest_test.cpp $(TAP_LDIR)/libtap$(SHLIB_EXT) $(LIBPROXYSQLAR) $(LIBCOREDUMPERAR) $(PARSERSQL_LDIR)/libsqlparser.a
ifeq ($(PROXYSQL40),1)
	$(CXX) $< -DEXCLUDE_TRACKING_VARIABLES $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) $(SQLITE3_LDIR)/vec.o $(PARSERSQL_LDIR)/libsqlparser.a -o $@
else
	$(CXX) $< -DEXCLUDE_TRACKING_VARIABLES $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(LIBCOREDUMPERAR) $(PARSERSQL_LDIR)/libsqlparser.a -o $@
endif

parsersql_digest_test-t: parsersql_digest_test
	ln -fs parsersql_digest_test parsersql_digest_test-t
