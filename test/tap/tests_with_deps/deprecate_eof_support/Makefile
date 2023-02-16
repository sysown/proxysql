include ../common_defs.Makefile

MARIADB_BASE_FOLDER=$(TEST_DEPS)/mariadb-client-library-3.1.9/
MARIADB_TEST_DEP=$(TEST_DEPS)/mariadb-client-library-3.1.9/mariadb-connector-c

BASE_DIR_EXIST := $(shell if [ -d $(MARIADB_BASE_FOLDER) ]; then echo 1; else echo 0; fi)
DEP_FOLDER_EMPTY := $(shell if [ -f $(MARIADB_TEST_DEP)/CMakeLists.txt ]; then echo 1; else echo 0; fi)

ifeq ($(BASE_DIR_EXIST), 1)

ifeq ($(DEP_FOLDER_EMPTY), 0)
    $(error "Dependency folder '$(MARIADB_TEST_DEP)' is empty. Make sure folder is initialized")
endif

.PHONY: all
all: build_deps tests

OPT=-O2 $(WGCOV) -Wl,--no-as-needed

.PHONY: debug
debug: OPT=-O0 -DDEBUG -ggdb -Wl,--no-as-needed $(WGCOV) $(WASAN)
debug: build_deps tests

$(MARIADB_TEST_DEP)/libmariadb/libmariadbclient.a:
	cd $(MARIADB_BASE_FOLDER) && CC=${CC} CXX=${CXX} ${MAKE} mariadb_client

.PHONY: build_deps
build_deps: $(MARIADB_TEST_DEP)/libmariadb/libmariadbclient.a

.PHONY: clean
clean:
	rm -f *-t
	rm -f fwd_eof_query
	rm -f fwd_eof_ok_query
	rm -f *.a *.o
	cd $(MARIADB_BASE_FOLDER) && ${MAKE} clean

WITHGCOVVAR := $(shell echo $(WITHGCOV))
ifeq ($(WITHGCOVVAR),1)
WGCOV=-DWITHGCOV --coverage -lgcov
else
WGCOV=
endif

WITHASANVAR := $(shell echo $(WITHASAN))
ifeq ($(WITHASANVAR),1)
WASAN=-fsanitize=address
else
WASAN=
endif

TESTS_DEPS=$(TAP_LIBDIR)/libtap.a $(MARIADB_TEST_DEP)/libmariadb/libmariadbclient.a

tests: $(patsubst %.cpp,%,$(wildcard *-t.cpp)) fwd_eof_query fwd_eof_ok_query

ok_packet_mixed_queries-t: eof_packet_mixed_queries-t.cpp $(TESTS_DEPS)
	$(CXX) -DDEBUG eof_packet_mixed_queries-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 -I$(TAP_LIBDIR) -L$(TAP_LIBDIR) -ltap $(MYLIBS) -Wl,--no-as-needed -ldl -lpthread -o ok_packet_mixed_queries-t -DGITVERSION=\"$(GIT_VERSION)\"

eof_packet_mixed_queries-t: ok_packet_mixed_queries-t $(TESTS_DEPS)
	$(CXX) -DNON_EOF_SUPPORT -DDEBUG eof_packet_mixed_queries-t.cpp -std=c++11 -I$(TAP_LIBDIR) -I $(MARIADB_TEST_DEP)/include/ -I $(IDIR) -L$(TAP_LIBDIR) -L$(TAP_DEPS_LIBS) -L $(MARIADB_TEST_DEP)/libmariadb -L$(SSL_LDIR) $(OPT) -ltap $(MYLIBS) -ldl -o eof_packet_mixed_queries-t -DGITVERSION=\"$(GIT_VERSION)\"

fwd_eof_query: fwd_eof_query.cpp $(TESTS_DEPS)
	$(CXX) -DNON_EOF_SUPPORT -DDEBUG fwd_eof_query.cpp $(OPT) -std=c++11 -I$(JSON_IDIR) -I$(TAP_LIBDIR) -I $(MARIADB_TEST_DEP)/include/ -I $(IDIR) -L$(TAP_LIBDIR) -L$(TAP_DEPS_LIBS) -L $(MARIADB_TEST_DEP)/libmariadb $(MYLIBS) -L$(SSL_LDIR) -ltap -ldl -o fwd_eof_query -DGITVERSION=\"$(GIT_VERSION)\"

#fwd_eof_ok_query: fwd_eof_query.cpp $(TESTS_DEPS)
#	$(CXX) -DDEBUG fwd_eof_query.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 -I$(TAP_LIBDIR) -L$(TAP_LIBDIR) $(MYLIBS) -L$(SSL_LDIR) -ltap -Wl,--no-as-needed -ldl -lpthread -o fwd_eof_ok_query -DGITVERSION=\"$(GIT_VERSION)\"

# NOTE: Compilation with 'libmysql' instead of 'libmariadb' client to confirm packet sequence id isn't check by 'libmariadb'
fwd_eof_ok_query: fwd_eof_query.cpp $(TAP_LIBDIR)/libtap.a
	$(CXX) -DDEBUG fwd_eof_query.cpp $(OPT) -std=c++11 -I$(JSON_IDIR) -I$(TAP_LIBDIR) -I /usr/include/mysql/ -I $(IDIR) -L$(TAP_LIBDIR) -L$(TAP_DEPS_LIBS) -L /usr/lib/x86_64-linux-gnu/ -lmysqlclient -ltap -ldl -o fwd_eof_ok_query -DGITVERSION=\"$(GIT_VERSION)\"

deprecate_eof_cache-t: deprecate_eof_cache-t.cpp $(TESTS_DEPS)
	$(CXX) -DDEBUG deprecate_eof_cache-t.cpp $(OPT) -std=c++11 -I$(JSON_IDIR) -I$(TAP_LIBDIR) -I $(MARIADB_TEST_DEP)/include/ -I $(IDIR) -L$(TAP_LIBDIR) -L$(TAP_DEPS_LIBS) -L$(MARIADB_TEST_DEP)/libmariadb -L$(SSL_LDIR) -L$(PROXYLDIR)  -ltap $(MYLIBS) -lproxysql -ldl -o deprecate_eof_cache-t -DGITVERSION=\"$(GIT_VERSION)\"

eof_cache_mixed_flags-t: eof_cache_mixed_flags-t.cpp $(TESTS_DEPS)
	$(CXX) -DDEBUG eof_cache_mixed_flags-t.cpp $(OPT) -std=c++11 -I$(JSON_IDIR) -I$(TAP_LIBDIR) -I $(MARIADB_TEST_DEP)/include/ -I $(IDIR) -L$(TAP_LIBDIR) -L$(TAP_DEPS_LIBS) -L $(MARIADB_TEST_DEP)/libmariadb -L$(SSL_LDIR) -ltap $(MYLIBS) -ldl -o eof_cache_mixed_flags-t -DGITVERSION=\"$(GIT_VERSION)\"

eof_mixed_flags_queries-t: eof_mixed_flags_queries-t.cpp $(TESTS_DEPS)
	$(CXX) -DDEBUG eof_mixed_flags_queries-t.cpp $(OPT) -std=c++11 -I$(JSON_IDIR) -I$(TAP_LIBDIR) -I $(MARIADB_TEST_DEP)/include/ -I $(IDIR) -L$(TAP_LIBDIR) -L$(TAP_DEPS_LIBS) -L $(MARIADB_TEST_DEP)/libmariadb -L$(SSL_LDIR) -ltap $(MYLIBS) -ldl -o eof_mixed_flags_queries-t -DGITVERSION=\"$(GIT_VERSION)\"

eof_conn_options_check-t: eof_conn_options_check-t.cpp $(TESTS_DEPS)
	$(CXX) -DDEBUG eof_conn_options_check-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 -I$(TAP_LIBDIR) -L$(TAP_LIBDIR) -L$(TAP_DEPS_LIBS) $(MYLIBS) -ltap -Wl,--no-as-needed -ldl -lpthread -o eof_conn_options_check-t -DGITVERSION=\"$(GIT_VERSION)\"

eof_fast_forward-t: eof_fast_forward-t.cpp $(TESTS_DEPS)
	$(CXX) -DDEBUG eof_fast_forward-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 -I$(TAP_LIBDIR) -L$(TAP_LIBDIR) -ltap $(MYLIBS) -Wl,--no-as-needed -ldl -lpthread -o eof_fast_forward-t -DGITVERSION=\"$(GIT_VERSION)\"

else
.PHONY: all
all:
	$(warning The required deps were not found. Tests 'deprecate_eof_support' wont be build)

.PHONY: debug
debug:
	$(warning The required deps were not found. Tests 'deprecate_eof_support' wont be build)

.PHONY: clean
clean:
	rm -f *-t
	rm -f fwd_eof_query
	rm -f fwd_eof_ok_query
	rm -f *.a *.o
endif
