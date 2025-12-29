#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk


IDIRS :=	-I$(TAP_IDIR) \
			-I$(RE2_IDIR) \
			-I$(PROXYSQL_IDIR) \
			-I$(JEMALLOC_IDIR) \
			-I$(LIBCONFIG_IDIR) \
			-I$(MICROHTTPD_IDIR) \
			-I$(LIBHTTPSERVER_IDIR) \
			-I$(CURL_IDIR) \
			-I$(EV_IDIR) \
			-I$(PROMETHEUS_IDIR) \
			-I$(SQLITE3_IDIR) \
			-I$(JSON_IDIR) \
			-I$(POSTGRESQL_IDIR) \
			-I$(SSL_IDIR)

LDIRS :=	-L$(TAP_LDIR) \
			-L$(RE2_LDIR) \
			-L$(PROXYSQL_LDIR) \
			-L$(JEMALLOC_LDIR) \
			-L$(LIBCONFIG_LDIR) \
			-L$(MICROHTTPD_LDIR) \
			-L$(LIBHTTPSERVER_LDIR) \
			-L$(CURL_LDIR) \
			-L$(EV_LDIR) \
			-L$(PROMETHEUS_LDIR) \
			-L$(SQLITE3_LDIR) \
			-L$(PCRE_LDIR) \
			-L$(POSTGRESQL_LDIR) \
			-L$(SSL_LDIR) 

OPT := $(STDCPP) -O2 -ggdb -Wl,--no-as-needed -Wl,-rpath,"../../tap" $(WGCOV) $(WASAN)


### main targets

.DEFAULT: default
.PHONY: default
default: all

.PHONY: all
all: tests

.PHONY: debug
debug: DEBUG := -DDEBUG
debug: OPT := $(STDCPP) -O0 -DDEBUG -ggdb -Wl,--no-as-needed -Wl,-rpath,"../../tap" $(WGCOV) $(WASAN)
debug: tests


### test deps targets

#.PHONY: build_test_deps
#build_test_deps: $(TAP_LDIR)/libtap.so $(TEST_MARIADB_LDIR)/libmariadbclient.a $(TEST_MYSQL_LDIR)/libmysqlclient.a

$(TAP_LDIR)/libtap.so:
	cd $(TAP_PATH) && CC=${CC} CXX=${CXX} ${MAKE} 

$(TEST_MARIADB_LDIR)/libmariadbclient.a:
	cd $(TEST_DEPS_PATH) && CC=${CC} CXX=${CXX} ${MAKE} mariadb_client

$(TEST_MYSQL_LDIR)/libmysqlclient.a:
	cd $(TEST_DEPS_PATH) && CC=${CC} CXX=${CXX} ${MAKE} mysql_client


### test and helper targets

#tests: build_test_deps
tests: $(patsubst %.cpp,%,$(wildcard *-t.cpp)) ok_packet_mixed_queries-t fwd_eof_query fwd_eof_ok_query
tests:
	@echo "Removing empty .gcno files ..."
	find -L . -type f -name '*.gcno' -empty -ls -delete

COMMONARGS = $(OPT) -Wl,-Bdynamic -ltap -lcpp_dotenv -lcurl -lre2 -lssl -lcrypto -lz -ldl -lpthread -DGITVERSION=\"$(GIT_VERSION)\"

ok_packet_mixed_queries-t: eof_packet_mixed_queries-t.cpp
	$(CXX) $< -I$(MARIADB_IDIR) $(IDIRS) -L$(MARIADB_LDIR) $(LDIRS) -lmariadbclient $(COMMONARGS) -o $@

eof_packet_mixed_queries-t: eof_packet_mixed_queries-t.cpp
	$(CXX) -DNON_EOF_SUPPORT $< -I$(TEST_MARIADB_IDIR) $(IDIRS) -L$(TEST_MARIADB_LDIR) $(LDIRS) -lmariadbclient $(COMMONARGS) -o $@

fwd_eof_query: fwd_eof_query.cpp
	$(CXX) -DNON_EOF_SUPPORT $< -I$(TEST_MARIADB_IDIR) $(IDIRS) -L$(TEST_MARIADB_LDIR) $(LDIRS) -lmariadbclient $(COMMONARGS) -o $@

# NOTE: Compilation with 'libmysql' instead of 'libmariadb' client to confirm packet sequence id isn't check by 'libmariadb'
fwd_eof_ok_query: fwd_eof_query.cpp
	$(CXX) $< -I$(TEST_MARIADB_IDIR) -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) $(IDIRS) -L$(TEST_MYSQL_LDIR) $(LDIRS) -lmysqlclient $(COMMONARGS) -o $@
# NOTE end

deprecate_eof_cache-t: deprecate_eof_cache-t.cpp
	$(CXX) $< -I$(TEST_MARIADB_IDIR) $(IDIRS) -L$(TEST_MARIADB_LDIR) $(LDIRS) $(PROXYSQL_LDIR)/proxysql_utils.cpp -lmariadbclient $(COMMONARGS) -o $@

eof_cache_mixed_flags-t: eof_cache_mixed_flags-t.cpp
	$(CXX) $< -I$(TEST_MARIADB_IDIR) $(IDIRS) -L$(TEST_MARIADB_LDIR) $(LDIRS) -lmariadbclient $(COMMONARGS) -o $@

eof_mixed_flags_queries-t: eof_mixed_flags_queries-t.cpp
	$(CXX) $< -I$(TEST_MARIADB_IDIR) $(IDIRS) -L$(TEST_MARIADB_LDIR) $(LDIRS) -lmariadbclient $(COMMONARGS) -o $@

eof_conn_options_check-t: eof_conn_options_check-t.cpp
	$(CXX) $< -I$(MARIADB_IDIR) $(IDIRS) -L$(MARIADB_LDIR) $(LDIRS) -lmariadbclient $(COMMONARGS) -o $@

eof_fast_forward-t: eof_fast_forward-t.cpp
	$(CXX) $< -I$(MARIADB_IDIR) $(IDIRS) -L$(MARIADB_LDIR) $(LDIRS) -lmariadbclient $(COMMONARGS) -o $@


### clean targets

.SILENT: cleanall
.PHONY: cleanall
cleanall: clean
	cd $(TEST_DEPS_PATH) && ${MAKE} cleanall

.SILENT: clean
.PHONY: clean
clean:
	rm -f *-t || true
	rm -f fwd_eof_query || true
	rm -f fwd_eof_ok_query || true
	rm -f *.a *.o || true
	rm -f *.gcda *.gcno || true
