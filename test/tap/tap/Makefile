#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk


IDIRS :=	-I$(PROXYSQL_IDIR) \
			-I$(JSON_IDIR) \
			-I${CURL_IDIR} \
			-I${SQLITE3_IDIR} \
			-I$(DOTENV_IDIR) \
			-I$(POSTGRESQL_IDIR) \
			-I$(RE2_IDIR)


LIBPROXYSQLAR := $(PROXYSQL_LDIR)/libproxysql.a

AR ?= ar

OPT := $(STDCPP) -O2 -ggdb $(WASAN)
ifneq ($(UNAME_S),Darwin)
OPT += -Wl,--no-as-needed
endif

# NOTE-LWGCOV (LinkWithGCOV):
# Linking against GCOV is required when ProxySQL is build with support for it. This is because
# 'sha256crypt.oo' is being used for 'libtap.a'. This requisite is imposed due to 'sha256_crypt_r'
# being used inside ProxySQL linked 'SQLite3', which is also used by `libtap.so`.
LWGCOV :=
ifeq ($(WITHGCOV),1)
	LWGCOV := -lgcov --coverage
endif


### main targets

.PHONY: default debug
default: all

.PHONY: all debug
all: libtap_mariadb.a libtap_mysql57.a libtap_mysql8.a \
	libtap.a libtap$(SHLIB_EXT) libcpp_dotenv$(SHLIB_EXT)

DEBUG_OPT := $(STDCPP) -O0 -DDEBUG -ggdb $(WASAN)
ifneq ($(UNAME_S),Darwin)
DEBUG_OPT += -Wl,--no-as-needed
endif
debug: OPT := $(DEBUG_OPT)
debug: libtap_mariadb.a libtap_mysql57.a libtap_mysql8.a libtap.a libtap$(SHLIB_EXT)

### helper targets

command_line.o: command_line.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a $(CURL_LDIR)/libcurl.a libcpp_dotenv$(SHLIB_EXT)
	$(CXX) -fPIC -c command_line.cpp $(IDIRS) $(OPT)

utils_mariadb.o: utils.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a $(CURL_LDIR)/libcurl.a libcpp_dotenv$(SHLIB_EXT)
	$(CXX) -fPIC -c utils.cpp $(IDIRS) -I$(MARIADB_IDIR) $(OPT) -o $@

utils_mysql57.o: utils.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a $(CURL_LDIR)/libcurl.a libcpp_dotenv$(SHLIB_EXT)
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING -fPIC -c utils.cpp $(IDIRS) -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) $(OPT) -o $@

utils_mysql8.o: utils.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a $(CURL_LDIR)/libcurl.a libcpp_dotenv$(SHLIB_EXT)
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING -fPIC -c utils.cpp $(IDIRS) -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL_EDIR) $(OPT) -o $@

tap.o: tap.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a $(CURL_LDIR)/libcurl.a libcpp_dotenv$(SHLIB_EXT)
	$(CXX) -fPIC -c tap.cpp $(IDIRS) $(OPT)

noise_utils_mariadb.o: noise_utils.cpp noise_utils.h utils.h command_line.h cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a $(CURL_LDIR)/libcurl.a libcpp_dotenv$(SHLIB_EXT)
	$(CXX) -DEXCLUDE_REPLACE_STR -fPIC -c noise_utils.cpp $(IDIRS) -I$(MARIADB_IDIR) -I$(POSTGRESQL_IDIR) $(OPT) -o $@

noise_utils_mysql57.o: noise_utils.cpp noise_utils.h utils.h command_line.h cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a $(CURL_LDIR)/libcurl.a libcpp_dotenv$(SHLIB_EXT)
	$(CXX) -DEXCLUDE_REPLACE_STR -DDISABLE_WARNING_COUNT_LOGGING -fPIC -c noise_utils.cpp $(IDIRS) -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -I$(POSTGRESQL_IDIR) $(OPT) -o $@

noise_utils_mysql8.o: noise_utils.cpp noise_utils.h utils.h command_line.h cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a $(CURL_LDIR)/libcurl.a libcpp_dotenv$(SHLIB_EXT)
	$(CXX) -DEXCLUDE_REPLACE_STR -DDISABLE_WARNING_COUNT_LOGGING -fPIC -c noise_utils.cpp $(IDIRS) -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL_EDIR) -I$(POSTGRESQL_IDIR) $(OPT) -o $@

mcp_client.o: mcp_client.cpp mcp_client.h $(CURL_LDIR)/libcurl.a
	$(CXX) -fPIC -c mcp_client.cpp $(IDIRS) $(OPT)

cluster_simulator.o: cluster_simulator.cpp cluster_simulator.h
	$(CXX) -fPIC -c cluster_simulator.cpp $(IDIRS) -I$(MARIADB_IDIR) $(OPT)

rds_bgd_simulator.o: rds_bgd_simulator.cpp rds_bgd_simulator.h cluster_simulator.h utils.h
	$(CXX) -fPIC -c rds_bgd_simulator.cpp $(IDIRS) -I$(MARIADB_IDIR) $(OPT)

libtap_mariadb.a: tap.o command_line.o utils_mariadb.o noise_utils_mariadb.o mcp_client.o cluster_simulator.o rds_bgd_simulator.o cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a
	$(AR) rcs libtap_mariadb.a tap.o command_line.o utils_mariadb.o noise_utils_mariadb.o mcp_client.o cluster_simulator.o rds_bgd_simulator.o $(SQLITE3_LDIR)/sqlite3.o $(PROXYSQL_LDIR)/obj/sha256crypt.oo

libtap_mysql57.a: tap.o command_line.o utils_mysql57.o noise_utils_mysql57.o mcp_client.o cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a
	$(AR) rcs libtap_mysql57.a tap.o command_line.o utils_mysql57.o noise_utils_mysql57.o mcp_client.o $(SQLITE3_LDIR)/sqlite3.o $(PROXYSQL_LDIR)/obj/sha256crypt.oo

libtap_mysql8.a: tap.o command_line.o utils_mysql8.o noise_utils_mysql8.o mcp_client.o cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a
	$(AR) rcs libtap_mysql8.a tap.o command_line.o utils_mysql8.o noise_utils_mysql8.o mcp_client.o $(SQLITE3_LDIR)/sqlite3.o $(PROXYSQL_LDIR)/obj/sha256crypt.oo

libtap.a: libtap_mariadb.a
	cp libtap_mariadb.a libtap.a

libtap$(SHLIB_EXT): libtap_mariadb.a cpp-dotenv/dynamic/cpp-dotenv/libcpp_dotenv$(SHLIB_EXT) $(RE2_STATIC_LIB)
ifeq ($(UNAME_S),Darwin)
	$(CXX) -dynamiclib -o libtap$(SHLIB_EXT) -force_load libtap_mariadb.a \
		$(CURL_LDIR)/libcurl.a -L$(ABSL_LDIR) $(RE2_STATIC_LIB) $(RE2_ABSL_LIBS) \
		-Wl,-undefined,dynamic_lookup $(LWGCOV)
else
	$(CXX) -shared -o libtap$(SHLIB_EXT) -Wl,--whole-archive libtap_mariadb.a \
		-Wl,--no-whole-archive $(CURL_LDIR)/libcurl.a \
		-L$(ABSL_LDIR) $(RE2_STATIC_LIB) $(RE2_ABSL_LIBS) $(LWGCOV)
endif


### tap deps targets

libcpp_dotenv$(SHLIB_EXT): cpp-dotenv/dynamic/cpp-dotenv/libcpp_dotenv$(SHLIB_EXT)
	find cpp-dotenv/dynamic/cpp-dotenv/ \( -name '*.so' -o -name '*.dylib' \) -exec cp -a {} . \;

cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a:
	cd cpp-dotenv/static && rm -rf cpp-dotenv-*/ || true
	cd cpp-dotenv/static && tar -zxf ../cpp-dotenv-*.tar.gz
	cd cpp-dotenv/static/cpp-dotenv && cmake . -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Debug -DCMAKE_POLICY_VERSION_MINIMUM=3.5
	cd cpp-dotenv/static/cpp-dotenv && CC=${CC} CXX=${CXX} ${MAKE}

cpp-dotenv/dynamic/cpp-dotenv/libcpp_dotenv$(SHLIB_EXT):
	cd cpp-dotenv/dynamic && rm -rf cpp-dotenv-*/ || true
	cd cpp-dotenv/dynamic && tar -zxf ../cpp-dotenv-*.tar.gz
	cd cpp-dotenv/dynamic/cpp-dotenv && cmake . -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_RPATH="../tap:../../tap" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_POLICY_VERSION_MINIMUM=3.5
	cd cpp-dotenv/dynamic/cpp-dotenv && CC=${CC} CXX=${CXX} ${MAKE}


### clean targets

.SILENT: clean_utils
.PHONY: clean_utils
clean_utils:
	find . -name 'utils_*.o' -delete || true
	find . -name 'noise_utils_*.o' -delete || true
	find . -name 'libtap_*.a' -delete || true
	find . -name 'libtap.so' -delete || true
	find . -name 'libtap.dylib' -delete || true

.SILENT: clean
.PHONY: clean
clean:
	# Clean build artifacts but exclude cpp-dotenv directories (preserve 213MB extracted source)
	find . -path ./cpp-dotenv -prune -o \( -name '*.a' -o -name '*.o' -o -name '*.so' -o -name '*.so.*' -o -name '*.dylib' -o -name '*.dylib.*' \) -delete || true

.SILENT: cleanall
.PHONY: cleanall
cleanall: clean
	# Remove cpp-dotenv source directories (213MB)
	cd cpp-dotenv/static && rm -rf cpp-dotenv-*/ || true
	cd cpp-dotenv/dynamic && rm -rf cpp-dotenv-*/ || true

# Rebuild archives when the Makefile itself changes (order-only).
LIBTAP_ARCHIVES := libtap_mariadb.a libtap_mysql57.a libtap_mysql8.a
$(LIBTAP_ARCHIVES): | Makefile

ifeq ($(wildcard noise_utils.cpp noise_utils.h),)
NOISE_UTILS_STUBS := noise_utils_mariadb.o noise_utils_mysql57.o noise_utils_mysql8.o

$(NOISE_UTILS_STUBS):
	$(CXX) -x c++ -fPIC -c /dev/null $(IDIRS) $(OPT) -o $@
endif
