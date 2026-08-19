#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk


IDIRS :=	-I$(PROXYSQL_IDIR) \
			-I$(JEMALLOC_IDIR) \
			-I$(MARIADB_IDIR) \
			-I$(LIBCONFIG_IDIR) \
			-I$(LIBDAEMON_IDIR) \
			-I$(RE2_IDIR) \
			-I$(PCRE_IDIR) \
			-I$(CLICKHOUSE_CPP_IDIR) \
			-I$(MICROHTTPD_IDIR) \
			-I$(LIBHTTPSERVER_IDIR) \
			-I$(LIBINJECTION_IDIR) \
			-I$(CURL_IDIR) \
			-I$(EV_IDIR) \
			-I$(PROMETHEUS_IDIR) \
			-I$(LIBUSUAL_IDIR) \
			-I$(LIBSCRAM_IDIR) \
			-I$(SQLITE3_IDIR) \
			-I$(POSTGRESQL_IDIR) \
			-I$(JSON_IDIR) \
			-I$(SSL_IDIR) \
			-I$(ZSTD_IDIR) \
			-I$(PARSERSQL_IDIR) \

LDIRS :=	-L$(PROXYSQL_LDIR) \
			-L$(JEMALLOC_LDIR) \
			-L$(MARIADB_LDIR) \
			-L$(LIBCONFIG_LDIR) \
			-L$(LIBDAEMON_LDIR) \
			-L$(RE2_LDIR) \
			-L$(ABSL_LDIR) \
			-L$(PCRE_LDIR) \
			-L$(MICROHTTPD_LDIR) \
			-L$(LIBHTTPSERVER_LDIR) \
			-L$(LIBINJECTION_LDIR) \
			-L$(CURL_LDIR) \
			-L$(EV_LDIR) \
			-L$(PROMETHEUS_LDIR) \
			-L$(POSTGRESQL_LDIR) \
			-L$(LIBUSUAL_LDIR) \
			-L$(LIBSCRAM_LDIR) \
			-L$(SSL_LDIR) \
			-L$(PARSERSQL_LDIR) \

ifeq ($(UNAME_S),Linux)
	LDIRS += -L$(COREDUMPER_LDIR)
endif
ifeq ($(UNAME_S),Darwin)
	IDIRS += -I/usr/local/include -I/opt/homebrew/include
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

PSQL40 :=
ifeq ($(PROXYSQL40),1)
	PSQL40 := -DPROXYSQL40
endif

PSQL31 :=
ifeq ($(PROXYSQL31),1)
	PSQL31 := -DPROXYSQL31
endif

PSQLFFTO :=
ifeq ($(PROXYSQLFFTO),1)
	PSQLFFTO := -DPROXYSQLFFTO
endif

PSQLTSDB :=
ifeq ($(PROXYSQLTSDB),1)
	PSQLTSDB := -DPROXYSQLTSDB
endif

PSQLED25519 :=
ifeq ($(PROXYSQLED25519),1)
	PSQLED25519 := -DPROXYSQLED25519
endif



MYCXXFLAGS := $(STDCPP)
ifeq ($(CXX),clang++)
ifneq ($(UNAME_S),Darwin)
	MYCXXFLAGS += -fuse-ld=lld
endif
endif
MYCXXFLAGS += $(IDIRS) $(OPTZ) $(DEBUG) $(PSQLCH) $(PSQL40) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB) $(PSQLED25519) -DGITVERSION=\"$(GIT_VERSION)\" $(NOJEM) $(WGCOV) $(WASAN)


STATICMYLIBS := -Wl,-Bstatic \
				-lconfig \
				-lproxysql \
				-ldaemon \
				-lconfig++ \
				$(RE2_STATIC_LIBS) \
				-lpcrecpp \
				-lpcre \
				-lmariadbclient \
				-lhttpserver \
				-lmicrohttpd \
				-linjection \
				-lcurl \
				-lev \
				-lscram \
				-lusual \
				-lpq \
				-lpgcommon \
				-lpgport \
				-lsqlparser \

ifneq ($(NOJEMALLOC),1)
	STATICMYLIBS += -ljemalloc
endif
ifeq ($(UNAME_S),Linux)
	STATICMYLIBS += -lcoredumper
endif

MYLIBS := -Wl,--export-dynamic $(STATICMYLIBS) -Wl,-Bdynamic -lgnutls -lpthread -lssl -lcrypto -lm -lz -lrt -lprometheus-cpp-pull -lprometheus-cpp-core -luuid $(EXTRALINK)
ifeq ($(DISTRO),almalinux)
ifeq ($(CENTOSVER),8)
	MYLIBS := -Wl,--export-dynamic $(STATICMYLIBS) -Wl,-Bdynamic -lgnutls -lpthread $(LIB_SSL_PATH) $(LIB_CRYPTO_PATH) -lm -lz -lrt -lprometheus-cpp-pull -lprometheus-cpp-core -luuid $(EXTRALINK)
endif
endif

ifeq ($(UNAME_S),Darwin)
	MYLIBS := $(RE2_STATIC_LIBS) -lmariadbclient -lssl -lcrypto -lpthread -lm -lz -liconv -lgnutls -lprometheus-cpp-pull -lprometheus-cpp-core
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

SQLITE_VEC_OBJ := $(DEPS_PATH)/sqlite3/sqlite3/vec.o
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
	LIBPROXYSQLAR += $(PARSERSQL_LDIR)/libsqlparser.a
	LIBPROXYSQLAR += $(LIBINJECTION_LDIR)/libinjection.a
	LIBPROXYSQLAR += $(EV_LDIR)/libev.a
	LIBPROXYSQLAR += $(LIBSCRAM_LDIR)/libscram.a
	LIBPROXYSQLAR += $(LIBUSUAL_LDIR)/libusual.a
	LIBPROXYSQLAR += $(POSTGRESQL_PATH)/interfaces/libpq/libpq.a
	LIBPROXYSQLAR += $(POSTGRESQL_PATH)/common/libpgcommon.a
	LIBPROXYSQLAR += $(POSTGRESQL_PATH)/port/libpgport.a
endif
LIBPROXYSQLAR += $(ZSTD_LDIR)/libzstd.a
LIBPROXYSQLAR += $(CITYHASH_LDIR)/libcityhash.a
ifeq ($(PROXYSQL40),1)
	LIBPROXYSQLAR += $(SQLITE_VEC_OBJ)
endif

ODIR := obj

EXECUTABLE := proxysql

_OBJ := main.o proxysql_global.o SQLite3_Server.o proxy_tls.o
OBJ := $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.cpp
	$(CXX) -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS) -Wall

$(EXECUTABLE): $(ODIR) $(OBJ) $(LIBPROXYSQLAR)
ifeq ($(PROXYSQLCLICKHOUSE),1)
	$(CXX) -o $@ $(OBJ) $(CLANGFIX) -Wl,--whole-archive $(PROXYSQL_LDIR)/libproxysql.a -Wl,--no-whole-archive $(filter-out $(PROXYSQL_LDIR)/libproxysql.a,$(LIBPROXYSQLAR)) $(CLICKHOUSE_CPP_LDIR)/libclickhouse-cpp-lib.a $(LZ4_LDIR)/liblz4.a $(MYCXXFLAGS) $(CXXFLAGS) $(LDIRS) $(LIBS) $(MYLIBS)
else ifeq ($(UNAME_S),Darwin)
	$(CXX) -o $@ $(OBJ) $(CLANGFIX) -force_load $(PROXYSQL_LDIR)/libproxysql.a $(filter-out $(PROXYSQL_LDIR)/libproxysql.a,$(LIBPROXYSQLAR)) $(MYCXXFLAGS) $(CXXFLAGS) $(LDIRS) $(LIBS) $(MYLIBS)
else
	$(CXX) -o $@ $(OBJ) $(CLANGFIX) -Wl,--whole-archive $(PROXYSQL_LDIR)/libproxysql.a -Wl,--no-whole-archive $(filter-out $(PROXYSQL_LDIR)/libproxysql.a,$(LIBPROXYSQLAR)) $(MYCXXFLAGS) $(CXXFLAGS) $(LDIRS) $(LIBS) $(MYLIBS)
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
