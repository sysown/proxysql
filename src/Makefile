#!/bin/make -f


GIT_VERSION ?= $(shell git describe --long --abbrev=7)
ifndef GIT_VERSION
    $(error GIT_VERSION is not set)
endif

CENTOSVER := Unknown
ifneq (,$(wildcard /etc/system-release))
	CENTOSVER := $(shell rpm --eval %rhel)
endif


PROXYSQL_PATH := ..
PROXYSQL_IDIR := $(PROXYSQL_PATH)/include
PROXYSQL_LDIR := $(PROXYSQL_PATH)/lib

DEPS_PATH := $(PROXYSQL_PATH)/deps

MARIADB_PATH := $(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR := $(MARIADB_PATH)/include
MARIADB_LDIR := $(MARIADB_PATH)/libmariadb

LIBDAEMON_PATH := $(DEPS_PATH)/libdaemon/libdaemon
LIBDAEMON_IDIR := $(LIBDAEMON_PATH)
LIBDAEMON_LDIR := $(LIBDAEMON_PATH)/libdaemon/.libs

JEMALLOC_PATH := $(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR := $(JEMALLOC_PATH)/include/jemalloc
JEMALLOC_LDIR := $(JEMALLOC_PATH)/lib

LIBCONFIG_PATH := $(DEPS_PATH)/libconfig/libconfig
LIBCONFIG_IDIR := $(LIBCONFIG_PATH)/lib
LIBCONFIG_LDIR := $(LIBCONFIG_PATH)/lib/.libs

PROMETHEUS_PATH := $(DEPS_PATH)/prometheus-cpp/prometheus-cpp
PROMETHEUS_IDIR := $(PROMETHEUS_PATH)/pull/include -I$(PROMETHEUS_PATH)/core/include
PROMETHEUS_LDIR := $(PROMETHEUS_PATH)/lib

RE2_PATH := $(DEPS_PATH)/re2/re2
RE2_IDIR := $(RE2_PATH)
RE2_LDIR := $(RE2_PATH)/obj

PCRE_PATH := $(DEPS_PATH)/pcre/pcre
PCRE_IDIR := $(PCRE_PATH)
PCRE_LDIR := $(PCRE_PATH)/.libs

SQLITE3_PATH := $(DEPS_PATH)/sqlite3/sqlite3
SQLITE3_IDIR := $(SQLITE3_PATH)
SQLITE3_LDIR := $(SQLITE3_PATH)

CITYHASH_PATH := $(DEPS_PATH)/cityhash/cityhash
CITYHASH_LDIR := $(CITYHASH_PATH)/src/.libs

LZ4_PATH := $(DEPS_PATH)/lz4/lz4
LZ4_LDIR := $(LZ4_PATH)/lib

CLICKHOUSE_CPP_PATH := $(DEPS_PATH)/clickhouse-cpp/clickhouse-cpp
CLICKHOUSE_CPP_CDIR := $(CLICKHOUSE_CPP_PATH)/contrib
CLICKHOUSE_CPP_IDIR := $(CLICKHOUSE_CPP_PATH)
CLICKHOUSE_CPP_LDIR := $(CLICKHOUSE_CPP_PATH)/clickhouse

LIBINJECTION_PATH := $(DEPS_PATH)/libinjection/libinjection
LIBINJECTION_IDIR := $(LIBINJECTION_PATH)/src
LIBINJECTION_LDIR := $(LIBINJECTION_PATH)/src

LIBHTTPSERVER_PATH := $(DEPS_PATH)/libhttpserver/libhttpserver
LIBHTTPSERVER_IDIR := $(LIBHTTPSERVER_PATH)/src
LIBHTTPSERVER_LDIR := $(LIBHTTPSERVER_PATH)/build/src/.libs/

MICROHTTPD_PATH := $(DEPS_PATH)/libmicrohttpd/libmicrohttpd/src
MICROHTTPD_IDIR := $(MICROHTTPD_PATH)/include
MICROHTTPD_LDIR := $(MICROHTTPD_PATH)/microhttpd/.libs

COREDUMPER_PATH := $(DEPS_PATH)/coredumper/coredumper
COREDUMPER_IDIR := $(COREDUMPER_PATH)/include
COREDUMPER_LDIR := $(COREDUMPER_PATH)/src

CURL_PATH := $(DEPS_PATH)/curl/curl
CURL_IDIR := $(CURL_PATH)/include
CURL_LDIR := $(CURL_PATH)/lib/.libs

SSL_PATH := $(DEPS_PATH)/libssl/openssl/
SSL_IDIR := $(SSL_PATH)/include
SSL_LDIR := $(SSL_PATH)

EV_PATH := $(DEPS_PATH)/libev/libev/
EV_IDIR := $(EV_PATH)
EV_LDIR := $(EV_PATH)/.libs


IDIRS := -I$(PROXYSQL_IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) -I$(LIBCONFIG_IDIR) -I$(LIBDAEMON_IDIR) -I$(RE2_IDIR) -L$(PCRE_IDIR) -I$(MICROHTTPD_IDIR) -I$(LIBHTTPSERVER_IDIR) -I$(LIBINJECTION_IDIR) -I$(CURL_IDIR) -I$(EV_IDIR) -I$(SSL_IDIR) -I$(PROMETHEUS_IDIR)  -I$(SQLITE3_IDIR) -I$(CLICKHOUSE_CPP_IDIR) -I$(CLICKHOUSE_CPP_CDIR) -I$(0)
LDIRS := -L$(PROXYSQL_LDIR) -L$(JEMALLOC_LDIR) -L$(MARIADB_LDIR) -L$(LIBCONFIG_LDIR) -L$(LIBDAEMON_LDIR) -L$(RE2_LDIR) -L$(PCRE_LDIR) -L$(MICROHTTPD_LDIR) -L$(LIBHTTPSERVER_LDIR) -L$(LIBINJECTION_LDIR) -L$(CURL_LDIR) -L$(EV_LDIR) -L$(SSL_LDIR) -L$(PROMETHEUS_LDIR)


UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LDIRS += -L$(COREDUMPER_LDIR)
endif
ifeq ($(UNAME_S),Darwin)
	IDIRS += -I/usr/local/include
	LDIRS += -L/usr/local/lib -L/opt/homebrew/lib
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


### handle clang issue https://bugs.llvm.org/show_bug.cgi?id=16404
CLANGFIX :=
ifeq ($(CXX),clang++)
#    CLANG_VERSION := $(shell clang -dumpversion | tr '.' ' ' | awk '{ printf("%04d.%04d.%04d", $$1, $$2, $$3) }')
#    CLANG_MIN_VER := $(shell echo 14.0 | tr '.' ' ' | awk '{ printf("%04d.%04d.%04d", $$1, $$2, $$3) }')
#ifneq ($(CLANG_MIN_VER),$(firstword $(sort $(CLANG_VERSION) $(CLANG_MIN_VER))))
    CLANGFIX := --rtlib=compiler-rt --unwindlib=libgcc
#endif
endif

PSQLCH :=
ifeq ($(PROXYSQLCLICKHOUSE),1)
	PSQLCH := -DPROXYSQLCLICKHOUSE
endif

WGCOV :=
ifeq ($(WITHGCOV),1)
	WGCOV := -DWITHGCOV -lgcov --coverage
endif

WASAN :=
ifeq ($(WITHASAN),1)
	WASAN := -fsanitize=address
	# Force the disable of JEMALLOC, since ASAN isn't compatible.
	export NOJEMALLOC=1
	# workaroud ASAN limitation ASLR > 28bits
	# https://github.com/google/sanitizers/issues/1716
	# sudo sysctl vm.mmap_rnd_bits=28
    $(warning ASAN needs ASLR =< 28bits, make sure 'sysctl vm.mmap_rnd_bits=28' is set.)
endif
ifeq ($(TEST_WITHASAN),1)
	WASAN += -DTEST_WITHASAN
endif

NOJEMALLOC := $(shell echo $(NOJEMALLOC))
ifeq ($(NOJEMALLOC),1)
NOJEM=-DNOJEM
else
NOJEM=
endif

MYCXXFLAGS := $(STDCPP)
ifeq ($(CXX),clang++)
	MYCXXFLAGS += -fuse-ld=lld
endif
MYCXXFLAGS += $(IDIRS) $(OPTZ) $(DEBUG) $(PSQLCH) -DGITVERSION=\"$(GIT_VERSION)\" $(NOJEM) $(WGCOV) $(WASAN)


STATICMYLIBS := -Wl,-Bstatic -lconfig -lproxysql -ldaemon -lconfig++ -lre2 -lpcrecpp -lpcre -lmariadbclient -lhttpserver -lmicrohttpd -linjection -lcurl -lssl -lcrypto -lev
ifneq ($(NOJEMALLOC),1)
	STATICMYLIBS += -ljemalloc
endif
ifeq ($(UNAME_S),Linux)
	STATICMYLIBS += -lcoredumper
endif

MYLIBS := -Wl,--export-dynamic $(STATICMYLIBS) -Wl,-Bdynamic -lgnutls -lpthread -lm -lz -lrt -lprometheus-cpp-pull -lprometheus-cpp-core -luuid $(EXTRALINK)
ifeq ($(UNAME_S),Darwin)
	MYLIBS :=-lre2 -lmariadbclient -lpthread -lm -lz -liconv -lgnutls -lprometheus-cpp-pull -lprometheus-cpp-core -luuid
else
	CURL_DIR := $(DEPS_PATH)/curl/curl
	IDIRS += -L$(CURL_DIR)/include
	LDIRS += -L$(CURL_DIR)/lib/.libs
endif
ifeq ($(UNAME_S),Linux)
	MYLIBS += -ldl
endif
ifeq ($(UNAME_S),FreeBSD)
	MYLIBS += -lexecinfo
endif
ifeq ($(CENTOSVER),6)
	MYLIBS += -lgcrypt
endif

LIBPROXYSQLAR := $(PROXYSQL_LDIR)/libproxysql.a
ifeq ($(UNAME_S),Darwin)
	LIBPROXYSQLAR += $(JEMALLOC_LDIR)/libjemalloc.a
	LIBPROXYSQLAR += $(MICROHTTPD_LDIR)/libmicrohttpd.a
	LIBPROXYSQLAR += $(LIBHTTPSERVER_LDIR)/libhttpserver.a
	LIBPROXYSQLAR += $(PCRE_LDIR)/libpcre.a
	LIBPROXYSQLAR += $(PCRE_LDIR)/libpcrecpp.a
	LIBPROXYSQLAR += $(LIBDAEMON_LDIR)/libdaemon.a
	LIBPROXYSQLAR += $(LIBCONFIG_LDIR)/libconfig++.a
	LIBPROXYSQLAR += $(LIBCONFIG_LDIR)/libconfig.a
	LIBPROXYSQLAR += $(CURL_LDIR)/libcurl.a
	LIBPROXYSQLAR += $(SQLITE3_LDIR)/sqlite3.o
	LIBPROXYSQLAR += $(LIBINJECTION_LDIR)/libinjection.a
	LIBPROXYSQLAR += $(EV_LDIR)/libev.a
endif
LIBPROXYSQLAR += $(SSL_LDIR)/libssl.a
LIBPROXYSQLAR += $(SSL_LDIR)/libcrypto.a
LIBPROXYSQLAR += $(CITYHASH_LDIR)/libcityhash.a

ODIR := obj

EXECUTABLE := proxysql

_OBJ := main.o proxysql_global.o SQLite3_Server.o proxy_tls.o
OBJ := $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.cpp
	$(CXX) -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS) -Wall

$(EXECUTABLE): $(ODIR) $(OBJ) $(LIBPROXYSQLAR)
ifeq ($(PROXYSQLCLICKHOUSE),1)
	$(CXX) -o $@ $(OBJ) $(CLANGFIX) $(LIBPROXYSQLAR) $(CLICKHOUSE_CPP_LDIR)/libclickhouse-cpp-lib-static.a $(LZ4_LDIR)/liblz4.a $(MYCXXFLAGS) $(CXXFLAGS) $(LDIRS) $(LIBS) $(MYLIBS)
else
	$(CXX) -o $@ $(OBJ) $(CLANGFIX) $(LIBPROXYSQLAR) $(MYCXXFLAGS) $(CXXFLAGS) $(LDIRS) $(LIBS) $(MYLIBS)
endif
ifeq ($(UNAME_S),Darwin)
	shasum $(EXECUTABLE) > $(EXECUTABLE).sha1
else
	sha1sum $(EXECUTABLE) > $(EXECUTABLE).sha1
endif

$(ODIR):
	mkdir $(ODIR)

$(LIBPROXYSQLAR):
	cd $(PROXYSQL_LDIR) && ${MAKE}


### main targets

default: $(EXECUTABLE)

clean:
	rm -rf *.pid $(ODIR)/*.o $(ODIR)/*.gcno $(ODIR)/*.gcda *~ core perf.data* heaptrack.proxysql.* $(EXECUTABLE) $(EXECUTABLE).sha1 $(ODIR)

