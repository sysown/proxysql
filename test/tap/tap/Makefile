#!/bin/make -f


GIT_VERSION ?= $(shell git describe --long --abbrev=7)
ifndef GIT_VERSION
    $(error GIT_VERSION is not set)
endif


PROXYSQL_PATH := ../../..
PROXYSQL_IDIR := $(PROXYSQL_PATH)/include
PROXYSQL_LDIR := $(PROXYSQL_PATH)/lib

DEPS_PATH := $(PROXYSQL_PATH)/deps

JSON_PATH := $(DEPS_PATH)/json
JSON_IDIR := $(JSON_PATH)

MARIADB_PATH := $(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR := $(MARIADB_PATH)/include
MARIADB_LDIR := $(MARIADB_PATH)/libmariadb

TEST_DEPS_PATH := $(PROXYSQL_PATH)/test/deps

TEST_MYSQL_PATH := $(TEST_DEPS_PATH)/mysql-connector-c/mysql-connector-c
TEST_MYSQL_IDIR := $(TEST_MYSQL_PATH)/include
TEST_MYSQL_EDIR := $(TEST_MYSQL_PATH)/libbinlogevents/export/
TEST_MYSQL_LDIR := $(TEST_MYSQL_PATH)/libmysql

TEST_MYSQL8_PATH := $(TEST_DEPS_PATH)/mysql-connector-c-8.4.0/mysql-connector-c
TEST_MYSQL8_IDIR := $(TEST_MYSQL8_PATH)/include
TEST_MYSQL8_EDIR := $(TEST_MYSQL8_PATH)/libbinlogevents/export/
TEST_MYSQL8_LDIR := $(TEST_MYSQL8_PATH)/libmysql

CURL_PATH := $(DEPS_PATH)/curl/curl
CURL_IDIR := $(CURL_PATH)/include
CURL_LDIR := $(CURL_PATH)/lib/.libs

SQLITE3_PATH := $(DEPS_PATH)/sqlite3/sqlite3
SQLITE3_IDIR := $(SQLITE3_PATH)
SQLITE3_LDIR := $(SQLITE3_PATH)

DOTENV_PATH := ./cpp-dotenv/static/cpp-dotenv
DOTENV_IDIR := $(DOTENV_PATH)/include
DOTENV_LDIR := $(DOTENV_PATH)

RE2_PATH := $(DEPS_PATH)/re2/re2
RE2_IDIR := $(RE2_PATH)
RE2_LDIR := $(RE2_PATH)/obj

LIBPROXYSQLAR := $(PROXYSQL_LDIR)/libproxysql.a

IDIRS := -I$(PROXYSQL_IDIR) -I$(JSON_IDIR) -I${CURL_IDIR} -I${SQLITE3_IDIR} -I$(DOTENV_IDIR) -I$(RE2_IDIR)

### detect compiler support for c++11/17
CPLUSPLUS := $(shell ${CC} -std=c++17 -dM -E -x c++ /dev/null 2>/dev/null | grep -F __cplusplus | egrep -o '[0-9]{6}L')
ifneq ($(CPLUSPLUS),201703L)
	CPLUSPLUS := $(shell ${CC} -std=c++11 -dM -E -x c++ /dev/null 2>/dev/null| grep -F __cplusplus | egrep -o '[0-9]{6}L')
ifneq ($(CPLUSPLUS),201103L)
    $(error Compiler must support at least c++11)
endif
endif
STDCPP := -std=c++$(shell echo $(CPLUSPLUS) | cut -c3-4) -DCXX$(shell echo $(CPLUSPLUS) | cut -c3-4)

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

OPT := $(STDCPP) -O2 -ggdb -Wl,--no-as-needed $(WASAN)

# NOTE-LWGCOV (LinkWithGCOV):
# Linking against GCOV is required when ProxySQL is build with support for it. This is because
# 'sha256crypt.oo' is being used for 'libtap.a'. This requisite is imposed due to 'sha256_crypt_r'
# being used inside ProxySQL linked 'SQLite3', which is also used by `libtap.so`.
LWGCOV :=
ifeq ($(WITHGCOV),1)
	LWGCOV := -lgcov
endif


### main targets

.PHONY: default
default: all

.PHONY: all
all: libtap_mariadb.a libtap_mysql57.a libtap_mysql8.a \
	libtap.so libssl.so.3 libcrypto.so.3 libcpp_dotenv.so libre2.so

debug: OPT := $(STDCPP) -O0 -DDEBUG -ggdb -Wl,--no-as-needed $(WASAN)
debug: libtap_mariadb.a libtap_mysql57.a libtap_mysql8.a libtap.so


### helper targets

command_line.o: command_line.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a libcurl.so libssl.so.3 libcrypto.so.3 libcpp_dotenv.so
	$(CXX) -fPIC -c command_line.cpp $(IDIRS) $(OPT)

utils_mariadb.o: utils.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a libcurl.so libssl.so.3 libcrypto.so.3 libcpp_dotenv.so
	$(CXX) -fPIC -c utils.cpp $(IDIRS) -I$(MARIADB_IDIR) $(OPT) -o $@

utils_mysql57.o: utils.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a libcurl.so libssl.so.3 libcrypto.so.3 libcpp_dotenv.so
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING -fPIC -c utils.cpp $(IDIRS) -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) $(OPT) -o $@

utils_mysql8.o: utils.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a libcurl.so libssl.so.3 libcrypto.so.3 libcpp_dotenv.so
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING -fPIC -c utils.cpp $(IDIRS) -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL_EDIR) $(OPT) -o $@

tap.o: tap.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a libcurl.so libssl.so.3 libcrypto.so.3 libcpp_dotenv.so
	$(CXX) -fPIC -c tap.cpp $(IDIRS) $(OPT)

libtap_mariadb.a: tap.o command_line.o utils_mariadb.o cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a
	ar rcs libtap_mariadb.a tap.o command_line.o utils_mariadb.o $(SQLITE3_LDIR)/sqlite3.o $(PROXYSQL_LDIR)/obj/sha256crypt.oo

libtap_mysql57.a: tap.o command_line.o utils_mysql57.o cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a
	ar rcs libtap_mysql57.a tap.o command_line.o utils_mysql57.o $(SQLITE3_LDIR)/sqlite3.o $(PROXYSQL_LDIR)/obj/sha256crypt.oo

libtap_mysql8.a: tap.o command_line.o utils_mysql8.o cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a
	ar rcs libtap_mysql8.a tap.o command_line.o utils_mysql8.o $(SQLITE3_LDIR)/sqlite3.o $(PROXYSQL_LDIR)/obj/sha256crypt.oo

libtap.so: libtap_mariadb.a cpp-dotenv/dynamic/cpp-dotenv/libcpp_dotenv.so libre2.so
	$(CXX) -shared -o libtap.so -Wl,--whole-archive libtap_mariadb.a -Wl,--no-whole-archive $(LWGCOV)


### tap deps targets

libssl.so.3: $(DEPS_PATH)/libssl/openssl/libssl.so.3
	cp -a $(DEPS_PATH)/libssl/openssl/libssl.so* .

libcrypto.so.3: $(DEPS_PATH)/libssl/openssl/libcrypto.so.3
	cp -a $(DEPS_PATH)/libssl/openssl/libcrypto.so* .

libcpp_dotenv.so: cpp-dotenv/dynamic/cpp-dotenv/libcpp_dotenv.so
	find cpp-dotenv/dynamic/cpp-dotenv/ -name '*.so' -exec cp -a {} . \;

libcurl.so: $(DEPS_PATH)/curl/curl/lib/.libs/libcurl.so
	cp -a $(DEPS_PATH)/curl/curl/lib/.libs/libcurl.so* .

libre2.so: $(DEPS_PATH)/re2/re2/obj/so/libre2.so
	cp -a $(DEPS_PATH)/re2/re2/obj/so/libre2.so* .

cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a:
	cd cpp-dotenv/static && rm -rf cpp-dotenv-*/ || true
	cd cpp-dotenv/static && tar -zxf ../cpp-dotenv-*.tar.gz
	cd cpp-dotenv/static/cpp-dotenv && patch src/dotenv.cpp < ../../dotenv.cpp.patch
	cd cpp-dotenv/static/cpp-dotenv && patch include/dotenv.h < ../../dotenv.h.patch
	cd cpp-dotenv/static/cpp-dotenv && patch -p0 < ../../nm_clang_fix.patch
	cd cpp-dotenv/static/cpp-dotenv && cmake . -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Debug
	cd cpp-dotenv/static/cpp-dotenv && CC=${CC} CXX=${CXX} ${MAKE}

cpp-dotenv/dynamic/cpp-dotenv/libcpp_dotenv.so:
	cd cpp-dotenv/dynamic && rm -rf cpp-dotenv-*/ || true
	cd cpp-dotenv/dynamic && tar -zxf ../cpp-dotenv-*.tar.gz
	cd cpp-dotenv/dynamic/cpp-dotenv && patch src/dotenv.cpp < ../../dotenv.cpp.patch
	cd cpp-dotenv/dynamic/cpp-dotenv && patch include/dotenv.h < ../../dotenv.h.patch
	cd cpp-dotenv/dynamic/cpp-dotenv && patch -p0 < ../../nm_clang_fix.patch
	cd cpp-dotenv/dynamic/cpp-dotenv && cmake . -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_RPATH="../tap:../../tap" -DCMAKE_BUILD_TYPE=Debug
	cd cpp-dotenv/dynamic/cpp-dotenv && CC=${CC} CXX=${CXX} ${MAKE}


### clean targets

.SILENT: clean_utils
.PHONY: clean_utils
clean_utils:
	find . -name 'utils_*.*' -delete || true
	find . -name 'libtap_*.*' -delete || true
	find . -name 'libtap.so' -delete || true

.SILENT: clean
.PHONY: clean
clean:
	find . -name '*.a' -delete || true
	find . -name '*.o' -delete || true
	find . -name '*.so' -delete || true
	find . -name '*.so.*' -delete || true
	cd cpp-dotenv/static && rm -rf cpp-dotenv-*/ || true
	cd cpp-dotenv/dynamic && rm -rf cpp-dotenv-*/ || true

