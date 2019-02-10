



DEPS_PATH=../../deps

RE2_PATH=$(DEPS_PATH)/re2/re2
RE2_IDIR=$(RE2_PATH)

MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include
MARIADB_LDIR=$(MARIADB_PATH)/libmariadb

DAEMONPATH=$(DEPS_PATH)/libdaemon/libdaemon
DAEMONPATH_IDIR=$(DAEMONPATH)
DAEMONPATH_LDIR=$(DAEMONPATH)/libdaemon/.libs

JEMALLOC_PATH=$(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR=$(JEMALLOC_PATH)/include/jemalloc
JEMALLOC_LDIR=$(JEMALLOC_PATH)/lib

LIBCONFIG_PATH=$(DEPS_PATH)/libconfig/libconfig-1.4.9
LIBCONFIG_IDIR=-I$(LIBCONFIG_PATH)/lib
LIBCONFIG_LDIR=-L$(LIBCONFIG_PATH)/lib/.libs

SQLITE3_DIR=$(DEPS_PATH)/sqlite3/sqlite3

IDIR=../../include
LDIR=../../lib
IDIRS=-I$(IDIR) -I$(RE2_IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) $(LIBCONFIG_IDIR) -I$(DAEMONPATH_IDIR) -I$(SQLITE3_DIR)
LDIRS=-L$(LDIR) -L$(JEMALLOC_LDIR) $(LIBCONFIG_LDIR) -L$(RE2_PATH)/obj -L$(MARIADB_LDIR) -L$(DAEMONPATH_LDIR)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	IDIRS+= -I/usr/local/opt/openssl/include
endif

LIBPROXYSQLAR=$(LDIR)/libproxysql.a

MYCPPFLAGS=-std=c++11 $(IDIRS) $(OPTZ) $(DEBUG) -ggdb
LDFLAGS+=
MYLIBS=-Wl,--export-dynamic -Wl,-Bstatic -lproxysql -ldaemon -ljemalloc -lre2 -lmariadbclient -Wl,-Bdynamic -lpthread -lm -lz -lrt -lcrypto -lssl $(EXTRALINK)

ifeq ($(UNAME_S),Darwin)
	MYLIBS=-lre2 -lpthread -lm -lz -liconv
endif
ifeq ($(UNAME_S),Linux)
	MYLIBS+= -ldl
endif
ifeq ($(UNAME_S),FreeBSD)
	MYLIBS+= -lexecinfo
endif

.PHONY: default
default: setparsertest

setparsertest: setparsertest.cpp $(RE2_PATH)/util/test.cc $(LDIR)/set_parser.cpp $(LIBPROXYSQLAR)
	$(CXX) -o $@ $@.cpp $(RE2_PATH)/util/test.cc $(LIBPROXYSQLAR) $(MYCPPFLAGS) $(CPPFLAGS) $(LDIRS) $(LIBS) $(LDFLAGS) $(MYLIBS)

clean:
	rm -f *~ core $(default)

