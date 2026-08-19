#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk


UTILSIDIR := ./lib
UTILSLDIR := ./obj


INCLUDEDIRS := -I$(TAP_IDIR) \
               -I$(RE2_IDIR) \
               -I$(PROXYSQL_IDIR) \
               -I$(JEMALLOC_IDIR) \
               -I$(LIBCONFIG_IDIR) \
               -I$(MARIADB_IDIR) \
               -I$(LIBDAEMON_IDIR) \
               -I$(MICROHTTPD_IDIR) \
               -I$(LIBHTTPSERVER_IDIR) \
               -I$(CURL_IDIR) -I$(EV_IDIR) \
               -I$(PROMETHEUS_IDIR) \
               -I$(DOTENV_DYN_IDIR) \
               -I$(SQLITE3_IDIR) \
               -I$(JSON_IDIR) \
               -I$(POSTGRESQL_IDIR) \
               -I$(LIBSCRAM_IDIR) \
               -I$(LIBUSUAL_IDIR) \
               -I$(SSL_IDIR) \
               -I$(UTILSIDIR)

LDIRS := -L$(TAP_LDIR) \
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
         -L$(PCRE2_LDIR) \
         -L$(LIBINJECTION_LDIR) \
         -L$(POSTGRESQL_LDIR) \
         -L$(LIBSCRAM_LDIR) \
         -L$(LIBUSUAL_LDIR) \
         -L$(SSL_LDIR)

ifeq ($(UNAME_S),Linux)
	LDIRS += -L$(COREDUMPER_LDIR)
endif


MYLIBS_DYNAMIC_PART := -Wl,--export-dynamic -Wl,-Bdynamic -lgnutls -lcpp_dotenv -lcurl -lssl -lcrypto -luuid
MYLIBS_STATIC_PART := -Wl,-Bstatic -lconfig -lproxysql -ldaemon -lconfig++ -lre2 $(PCRE2_LIBS) -lmariadbclient -lhttpserver -lmicrohttpd -linjection -lev -lprometheus-cpp-pull -lprometheus-cpp-core
MYLIBS_PG_PART := -Wl,-Bstatic -lpq -lpgcommon -lpgport
MYLIBS_LAST_PART := -Wl,-Bdynamic -lpthread -lm -lz -lzstd -lrt -ldl $(EXTRALINK)
MYLIBS := -Wl,-Bdynamic -ltap $(MYLIBS_DYNAMIC_PART) $(MYLIBS_STATIC_PART) $(MYLIBS_PG_PART) $(MYLIBS_LAST_PART)

MYLIBSJEMALLOC := -Wl,-Bstatic -ljemalloc
STATIC_LIBS := $(CITYHASH_LDIR)/libcityhash.a

ifeq ($(UNAME_S),Linux)
	STATIC_LIBS += $(COREDUMPER_LDIR)/libcoredumper.a
endif

ifeq ($(PROXYSQL40),1)
	STATIC_LIBS += $(SQLITE3_LDIR)/vec.o
endif


OBJ := $(PROXYSQL_LDIR)/obj/SpookyV2.oo


OPT := $(STDCPP) -O2 -ggdb -DDISABLE_WARNING_COUNT_LOGGING -Wl,--no-as-needed -Wl,-rpath,$(TAP_LDIR) -Wl,-rpath,$(POSTGRESQL_PATH)/interfaces/libpq -Wl,-rpath,$(RE2_LDIR) $(WGCOV) $(WASAN) -DGITVERSION=\"$(GIT_VERSION)\"

.PHONY: default
default: all

.PHONY: all
all: cluster_simulator

.PHONY: debug
debug: OPT := $(STDCPP) -O0 -DDEBUG -ggdb -DDISABLE_WARNING_COUNT_LOGGING -Wl,--no-as-needed -Wl,-rpath,$(TAP_LDIR) -Wl,-rpath,$(POSTGRESQL_PATH)/interfaces/libpq -Wl,-rpath,$(RE2_LDIR) $(WGCOV) $(WASAN) -DGITVERSION=\"$(GIT_VERSION)\"
debug: cluster_simulator

.PHONY: clean
clean:
	rm -f cluster_simulator common_utils_unit-t
	rm -rf $(UTILSLDIR)


$(UTILSLDIR):
	mkdir -p $(UTILSLDIR)

$(UTILSLDIR)/common_utils.o: lib/common_utils.cpp lib/common_utils.h | $(UTILSLDIR)
	$(CXX) -c lib/common_utils.cpp $(INCLUDEDIRS) $(OPT) -o $@

$(UTILSLDIR)/galera_utils.o: lib/galera_utils.cpp lib/galera_utils.h | $(UTILSLDIR)
	$(CXX) -c lib/galera_utils.cpp $(INCLUDEDIRS) $(OPT) -o $@

$(UTILSLDIR)/readonly_utils.o: lib/readonly_utils.cpp lib/readonly_utils.h | $(UTILSLDIR)
	$(CXX) -c lib/readonly_utils.cpp $(INCLUDEDIRS) $(OPT) -o $@

$(UTILSLDIR)/replicationlag_utils.o: lib/replicationlag_utils.cpp lib/replicationlag_utils.h | $(UTILSLDIR)
	$(CXX) -c lib/replicationlag_utils.cpp $(INCLUDEDIRS) $(OPT) -o $@

$(UTILSLDIR)/grouprep_utils.o: lib/grouprep_utils.cpp lib/grouprep_utils.h | $(UTILSLDIR)
	$(CXX) -c lib/grouprep_utils.cpp $(INCLUDEDIRS) $(OPT) -o $@

$(UTILSLDIR)/aurora_utils.o: lib/aurora_utils.cpp lib/aurora_utils.h | $(UTILSLDIR)
	$(CXX) -c lib/aurora_utils.cpp $(INCLUDEDIRS) $(OPT) -o $@

UTILS_OBJS := $(UTILSLDIR)/common_utils.o \
              $(UTILSLDIR)/galera_utils.o \
              $(UTILSLDIR)/readonly_utils.o \
              $(UTILSLDIR)/replicationlag_utils.o \
              $(UTILSLDIR)/grouprep_utils.o \
              $(UTILSLDIR)/aurora_utils.o

$(UTILSLDIR)/cluster_simulator_lib.a: $(UTILS_OBJS)
	ar rcs $@ $(UTILS_OBJS)

$(TAP_LDIR)/libtap.so:
	cd $(PROXYSQL_PATH)/test/tap && CC=$(CC) CXX=$(CXX) $(MAKE) tap

cluster_simulator: cluster_simulator.cpp $(UTILSLDIR)/cluster_simulator_lib.a $(TAP_LDIR)/libtap.so
	$(CXX) -o $@ $(OBJ) cluster_simulator.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) $(MYLIBSJEMALLOC) $(MYLIBS) $(STATIC_LIBS) $(UTILSLDIR)/cluster_simulator_lib.a

common_utils_unit-t: tests/common_utils_unit-t.cpp $(UTILSLDIR)/common_utils.o $(TAP_LDIR)/libtap.so
	$(CXX) -o $@ $(OBJ) tests/common_utils_unit-t.cpp $(UTILSLDIR)/common_utils.o $(INCLUDEDIRS) $(LDIRS) $(OPT) $(MYLIBSJEMALLOC) $(MYLIBS) $(STATIC_LIBS)

.PHONY: check
check: common_utils_unit-t
	LD_LIBRARY_PATH="$(TAP_LDIR):$${LD_LIBRARY_PATH:-}" ./common_utils_unit-t
