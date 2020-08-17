ifndef GIT_VERSION
GIT_VERSION := $(shell git describe --long)
ifndef GIT_VERSION
$(error GIT_VERSION is not set)
endif
endif

DEPS_PATH=../deps

ifneq (,$(wildcard /etc/system-release))
	CENTOSVER := $(shell rpm --eval %rhel)
else
	CENTOSVER := Unknown
endif

MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include
MARIADB_LDIR=$(MARIADB_PATH)/libmariadb


DAEMONPATH=$(DEPS_PATH)/libdaemon/libdaemon
DAEMONPATH_IDIR=$(DAEMONPATH)
DAEMONPATH_LDIR=$(DAEMONPATH)/libdaemon/.libs

JEMALLOC_PATH=$(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR=$(JEMALLOC_PATH)/include/jemalloc
JEMALLOC_LDIR=$(JEMALLOC_PATH)/lib

LIBCONFIG_PATH=$(DEPS_PATH)/libconfig/libconfig
LIBCONFIG_IDIR=-I$(LIBCONFIG_PATH)/lib
LIBCONFIG_LDIR=-L$(LIBCONFIG_PATH)/lib/.libs

RE2_PATH=$(DEPS_PATH)/re2/re2
RE2_IDIR=$(RE2_PATH)

PCRE_PATH=$(DEPS_PATH)/pcre/pcre
PCRE_LDIR=$(PCRE_PATH)/.libs

SQLITE3_DIR=$(DEPS_PATH)/sqlite3/sqlite3


CLICKHOUSE_CPP_DIR=$(DEPS_PATH)/clickhouse-cpp/clickhouse-cpp
CITYHASH_DIR=$(DEPS_PATH)/cityhash/cityhash/src/.libs
LZ4_DIR=$(DEPS_PATH)/lz4/lz4

CLICKHOUSE_CPP_DIR=$(DEPS_PATH)/clickhouse-cpp/clickhouse-cpp

LIBINJECTION_DIR=$(DEPS_PATH)/libinjection/libinjection
LIBINJECTION_IDIR=$(LIBINJECTION_DIR)/src
LIBINJECTION_LDIR=$(LIBINJECTION_DIR)/src

LIBHTTPSERVER_DIR=$(DEPS_PATH)/libhttpserver/libhttpserver
LIBHTTPSERVER_IDIR=$(LIBHTTPSERVER_DIR)/src
LIBHTTPSERVER_LDIR=$(LIBHTTPSERVER_DIR)/build/src/.libs/

MICROHTTPD_DIR=$(DEPS_PATH)/libmicrohttpd/libmicrohttpd/src
MICROHTTPD_IDIR=$(MICROHTTPD_DIR)/include
MICROHTTPD_LDIR=$(MICROHTTPD_DIR)/microhttpd/.libs

CURL_DIR=$(DEPS_PATH)/curl/curl
CURL_IDIR=$(CURL_DIR)/include
CURL_LDIR=$(CURL_DIR)/lib/.libs

SSL_DIR=$(DEPS_PATH)/libssl/openssl/
SSL_IDIR=$(SSL_DIR)/include
SSL_LDIR=$(SSL_DIR)


EV_DIR=$(DEPS_PATH)/libev/libev/
EV_IDIR=$(EV_DIR)
EV_LDIR=$(EV_DIR)/.libs

IDIR=../include
LDIR=../lib
IDIRS=-I$(IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) $(LIBCONFIG_IDIR) -I$(DAEMONPATH_IDIR) -I$(SQLITE3_DIR) -I$(CLICKHOUSE_CPP_DIR) -I$(MICROHTTPD_IDIR) -I$(LIBHTTPSERVER_IDIR) -I$(LIBINJECTION_IDIR) -I$(CURL_IDIR) -I$(EV_IDIR) -I$(SSL_IDIR) -I$(RE2_IDIR)
LDIRS=-L$(LDIR) -L$(JEMALLOC_LDIR) $(LIBCONFIG_LDIR) -L$(RE2_PATH)/obj -L$(MARIADB_LDIR) -L$(DAEMONPATH_LDIR) -L$(PCRE_LDIR) -L$(MICROHTTPD_LDIR) -L$(LIBHTTPSERVER_LDIR) -L$(LIBINJECTION_LDIR) -L$(CURL_LDIR) -L$(EV_LDIR) -L$(SSL_LDIR)

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
	IDIRS+= -I/usr/local/include -I/usr/local/opt/openssl/include
	LDIRS+= -L/usr/local/lib
endif

PROXYSQLCLICKHOUSE := $(shell echo $(PROXYSQLCLICKHOUSE))
ifeq ($(PROXYSQLCLICKHOUSE),1)
PSQLCH=-DPROXYSQLCLICKHOUSE
else
PSQLCH=
endif

MYCXXFLAGS=-std=c++11 $(IDIRS) $(OPTZ) $(DEBUG) $(PSQLCH) -DGITVERSION=\"$(GIT_VERSION)\"

LDFLAGS+=
NOJEMALLOC := $(shell echo $(NOJEMALLOC))
ifeq ($(NOJEMALLOC),1)
MYLIBS=-Wl,--export-dynamic -Wl,-Bstatic -lconfig -lproxysql -ldaemon -lconfig++ -lre2 -lpcrecpp -lpcre -lmariadbclient -lmicrohttpd -lhttpserver -linjection -lcurl -lssl -lcrypto -lev -Wl,-Bdynamic -lgnutls -lpthread -lm -lz -lrt $(EXTRALINK)
else
MYLIBS=-Wl,--export-dynamic -Wl,-Bstatic -lconfig -lproxysql -ldaemon -ljemalloc -lconfig++ -lre2 -lpcrecpp -lpcre -lmariadbclient -lhttpserver -lmicrohttpd -linjection -lcurl -lssl -lcrypto -lev -Wl,-Bdynamic -lgnutls -lpthread -lm -lz -lrt $(EXTRALINK)
endif

ifeq ($(UNAME_S),Darwin)
	MYLIBS=-lssl -lre2 -lmariadbclient -lpthread -lm -lz -liconv -lcrypto -lcurl -lgnutls
else
	CURL_DIR=$(DEPS_PATH)/curl/curl
	IDIRS+= -L$(CURL_DIR)/include
	LDIRS+= -L$(CURL_DIR)/lib/.libs
endif
ifeq ($(UNAME_S),Linux)
	MYLIBS+= -ldl
endif
ifeq ($(UNAME_S),FreeBSD)
	MYLIBS+= -lexecinfo
endif
ifeq ($(CENTOSVER),6)
	MYLIBS+= -lgcrypt
endif

LIBPROXYSQLAR=$(LDIR)/libproxysql.a
ifeq ($(UNAME_S),Darwin)
	LIBPROXYSQLAR=$(LDIR)/libproxysql.a ../deps/libmicrohttpd/libmicrohttpd/src/microhttpd/.libs/libmicrohttpd.a ../deps/libhttpserver/libhttpserver/build/src/.libs/libhttpserver.a ../deps/pcre/pcre/.libs/libpcre.a ../deps/pcre/pcre/.libs/libpcrecpp.a  ../deps/libdaemon/libdaemon/libdaemon/.libs/libdaemon.a  ../deps/libconfig/libconfig/lib/.libs/libconfig++.a ../deps/libconfig/libconfig/lib/.libs/libconfig.a ../deps/curl/curl/lib/.libs/libcurl.a ../deps/sqlite3/sqlite3/sqlite3.o ../deps/libinjection/libinjection/src/libinjection.a  ../deps/libhttpserver/libhttpserver/build/src/.libs/libhttpserver.a ../deps/libev/libev-4.24/.libs/libev.a
endif

LIBPROXYSQLAR+= $(SSL_LDIR)/libssl.a $(SSL_LDIR)/libcrypto.a
ODIR= obj

EXECUTABLE=proxysql

_OBJ = main.o proxysql_global.o SQLite3_Server.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.cpp
	$(CXX) -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS) -Wall

proxysql: $(ODIR) $(OBJ) $(LIBPROXYSQLAR)
ifeq ($(PROXYSQLCLICKHOUSE),1)
	$(CXX) -o $@ $(OBJ) $(LIBPROXYSQLAR) $(CLICKHOUSE_CPP_DIR)/clickhouse/libclickhouse-cpp-lib.a $(CITYHASH_DIR)/libcityhash.a $(LZ4_DIR)/liblz4.a $(MYCXXFLAGS) $(CXXFLAGS) $(LDIRS) $(LIBS) $(LDFLAGS) $(MYLIBS)
else
	$(CXX) -o $@ $(OBJ) $(LIBPROXYSQLAR) $(MYCXXFLAGS) $(CXXFLAGS) $(LDIRS) $(LIBS) $(LDFLAGS) $(MYLIBS)
endif

$(ODIR):
	mkdir $(ODIR)

$(LIBPROXYSQLAR):
	cd $(LDIR) && ${MAKE}

default: $(EXECUTABLE)

clean:
	rm -f *.pid $(ODIR)/*.o *~ core perf.data* heaptrack.proxysql.* $(EXECUTABLE)

