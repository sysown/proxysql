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

CURL_PATH := $(DEPS_PATH)/curl/curl
CURL_IDIR := $(CURL_PATH)/include
CURL_LDIR := $(CURL_PATH)/lib/.libs

SQLITE3_PATH := $(DEPS_PATH)/sqlite3/sqlite3
SQLITE3_IDIR := $(SQLITE3_PATH)
SQLITE3_LDIR := $(SQLITE3_PATH)

DOTENV_PATH := ./cpp-dotenv/static/cpp-dotenv
DOTENV_IDIR := $(DOTENV_PATH)/include
DOTENV_LDIR := $(DOTENV_PATH)


LIBPROXYSQLAR := $(PROXYSQL_LDIR)/libproxysql.a

IDIRS := -I$(PROXYSQL_IDIR) -I$(JSON_IDIR) -I$(MARIADB_IDIR) -I${CURL_IDIR} -I${SQLITE3_IDIR} -I$(DOTENV_IDIR)

### detect compiler support for c++11/17
CPLUSPLUS := $(shell ${CC} -std=c++17 -dM -E -x c++ /dev/null 2>/dev/null | grep -F __cplusplus | grep -Po '\d\d\d\d\d\dL')
ifneq ($(CPLUSPLUS),201703L)
	CPLUSPLUS := $(shell ${CC} -std=c++11 -dM -E -x c++ /dev/null 2>/dev/null| grep -F __cplusplus | grep -Po '\d\d\d\d\d\dL')
ifneq ($(CPLUSPLUS),201103L)
	$(error Compiler must support at least c++11)
endif
endif
STDCPP := -std=c++$(shell echo $(CPLUSPLUS) | cut -c3-4) -DCXX$(shell echo $(CPLUSPLUS) | cut -c3-4)

WASAN :=
ifeq ($(WITHASAN),1)
	WASAN := -fsanitize=address
endif

OPT := $(STDCPP) -O2 -ggdb -Wl,--no-as-needed $(WASAN)


### main targets

.PHONY: default
default: all

.PHONY: all
all: libtap.a libtap.so libssl.so.3 libcrypto.so.3 libcpp_dotenv.so

debug: OPT := $(STDCPP) -O0 -DDEBUG -ggdb -Wl,--no-as-needed $(WASAN)
debug: libtap.a libtap.so


### helper targets

command_line.o: command_line.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a libcurl.so libssl.so.3 libcrypto.so.3 libcpp_dotenv.so
	$(CXX) -fPIC -c command_line.cpp $(IDIRS) $(OPT)

utils.o: utils.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a libcurl.so libssl.so.3 libcrypto.so.3 libcpp_dotenv.so
	$(CXX) -fPIC -c utils.cpp $(IDIRS) $(OPT)

tap.o: tap.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a libcurl.so libssl.so.3 libcrypto.so.3 libcpp_dotenv.so
	$(CXX) -fPIC -c tap.cpp $(IDIRS) $(OPT)

libtap.a: tap.o command_line.o utils.o cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a
	ar rcs libtap.a tap.o command_line.o utils.o $(SQLITE3_LDIR)/sqlite3.o

libtap.so: libtap.a cpp-dotenv/dynamic/cpp-dotenv/libcpp_dotenv.so
	$(CXX) -shared -o libtap.so -Wl,--whole-archive libtap.a -Wl,--no-whole-archive


### tap deps targets

libssl.so.3: $(DEPS_PATH)/libssl/openssl/libssl.so.3
	cp -a $(DEPS_PATH)/libssl/openssl/libssl.so* .

libcrypto.so.3: $(DEPS_PATH)/libssl/openssl/libcrypto.so.3
	cp -a $(DEPS_PATH)/libssl/openssl/libcrypto.so* .

libcpp_dotenv.so: cpp-dotenv/dynamic/cpp-dotenv/libcpp_dotenv.so
	find cpp-dotenv/dynamic/cpp-dotenv/ -name '*.so' -exec cp -a {} . \;

libcurl.so: $(DEPS_PATH)/curl/curl/lib/.libs/libcurl.so
	cp -a $(DEPS_PATH)/curl/curl/lib/.libs/libcurl.so* .

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

.SILENT: clean
.PHONY: clean
clean:
	find . -name '*.a' -delete || true
	find . -name '*.o' -delete || true
	find . -name '*.so' -delete || true
	find . -name '*.so.*' -delete || true
