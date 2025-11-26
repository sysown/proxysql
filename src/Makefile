#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk


IDIRS := -I$(PROXYSQL_IDIR)       \
		-I$(JEMALLOC_IDIR)        \
		-I$(MARIADB_IDIR)         \
		-I$(LIBCONFIG_IDIR)       \
		-I$(LIBDAEMON_IDIR)       \
		-I$(RE2_IDIR)             \
		-I$(PCRE_IDIR)            \
		-I$(MICROHTTPD_IDIR)      \
		-I$(LIBHTTPSERVER_IDIR)   \
		-I$(LIBINJECTION_IDIR)    \
		-I$(CURL_IDIR)            \
		-I$(EV_IDIR)              \
		-I$(PROMETHEUS_IDIR)      \
		-I$(POSTGRESQL_IDIR)      \
		-I$(LIBUSUAL_IDIR)        \
		-I$(LIBSCRAM_IDIR)        \
		-I$(SQLITE3_IDIR)         \
		-I$(CLICKHOUSE_CPP_IDIR)  \
		-I$(JSON_IDIR)            \
		-I$(ABSL_IDIR)            \
		-I$(PROTOBUF_IDIR)        \
		-I$(OTEL_IDIR)            \
		-I$(SSL_IDIR)             \

LDIRS := -L$(PROXYSQL_LDIR)     \
		-L$(JEMALLOC_LDIR)      \
		-L$(MARIADB_LDIR)       \
		-L$(LIBCONFIG_LDIR)     \
		-L$(LIBDAEMON_LDIR)     \
		-L$(RE2_LDIR)           \
		-L$(PCRE_LDIR)          \
		-L$(MICROHTTPD_LDIR)    \
		-L$(LIBHTTPSERVER_LDIR) \
		-L$(LIBINJECTION_LDIR)  \
		-L$(CURL_LDIR)          \
		-L$(EV_LDIR)            \
		-L$(PROMETHEUS_LDIR)    \
		-L$(POSTGRESQL_LDIR)    \
		-L$(LIBUSUAL_LDIR)      \
		-L$(LIBSCRAM_LDIR)      \
		-L$(ABSL_LDIR)          \
		-L$(PROTOBUF_LDIR)      \
		-L$(OTEL_LDIR)          \
		-L$(SSL_LDIR)


ifeq ($(UNAME_S),Linux)
	LDIRS += -L$(COREDUMPER_LDIR)
endif
ifeq ($(UNAME_S),Darwin)
	IDIRS += -I/usr/local/include
	LDIRS += -L/usr/local/lib -L/opt/homebrew/lib
endif


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



MYCXXFLAGS := $(STDCPP)
ifeq ($(CXX),clang++)
	MYCXXFLAGS += -fuse-ld=lld
endif
MYCXXFLAGS += $(IDIRS) $(OPTZ) $(DEBUG) $(PSQLCH) -DGITVERSION=\"$(GIT_VERSION)\" $(NOJEM) $(WGCOV) $(WASAN)

STATICMYLIBS := -Wl,-Bstatic    \
				-lconfig        \
				-lproxysql      \
				-lopentelemetry \
				-lprotobuf      \
				-lutf8          \
				-labsl          \
				-ldaemon        \
				-lconfig++      \
				-lre2           \
				-lpcrecpp       \
				-lpcre          \
				-lmariadbclient \
				-lhttpserver    \
				-lmicrohttpd    \
				-linjection     \
				-lcurl          \
				-lev            \
				-lscram         \
				-lusual         \
				-lpq            \
				-lpgcommon      \
				-lpgport

ifneq ($(NOJEMALLOC),1)
	STATICMYLIBS += -ljemalloc
endif
ifeq ($(UNAME_S),Linux)
	STATICMYLIBS += -lcoredumper
endif

MYLIBS := -Wl,--export-dynamic $(STATICMYLIBS) -Wl,-Bdynamic -lgnutls -lpthread -lssl -lcrypto -lm -lz -lrt -lprometheus-cpp-pull -lprometheus-cpp-core -luuid $(EXTRALINK)

ifeq ($(UNAME_S),Darwin)
	MYLIBS :=-lre2 -lmariadbclient -lpq -lpthread -lm -lz -liconv -lgnutls -lprometheus-cpp-pull -lprometheus-cpp-core -luuid
else
	IDIRS += -L$(CURL_IDIR)
	LDIRS += -L$(CURL_LDIR)
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
LIBPROXYSQLAR += $(CITYHASH_LDIR)/libcityhash.a

ODIR := obj

EXECUTABLE := proxysql

_OBJ := main.o proxysql_global.o SQLite3_Server.o proxy_tls.o
OBJ := $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.cpp
	$(CXX) -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS) -Wall

$(EXECUTABLE): $(ODIR) $(OBJ) $(LIBPROXYSQLAR)
ifeq ($(PROXYSQLCLICKHOUSE),1)
	$(CXX) -o $@ $(OBJ) $(CLANGFIX) $(LIBPROXYSQLAR) $(CLICKHOUSE_CPP_LDIR)/libclickhouse-cpp-lib.a $(CLICKHOUSE_CPP_PATH)/contrib/zstd/zstd/libzstdstatic.a $(LZ4_LDIR)/liblz4.a $(MYCXXFLAGS) $(CXXFLAGS) $(LDIRS) $(LIBS) $(MYLIBS)
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
