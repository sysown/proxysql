DEPS_PATH=../../../deps

JSON_IDIR=$(DEPS_PATH)/json

MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include
MARIADB_LDIR=$(MARIADB_PATH)/libmariadb

CURL_DIR=$(DEPS_PATH)/curl/curl
CURL_IDIR=$(CURL_DIR)/include
CURL_LDIR=$(CURL_DIR)/lib/.libs

SQLITE3_DIR=$(DEPS_PATH)/sqlite3/sqlite3
SQLITE3_IDIR=$(SQLITE3_DIR)
SQLITE3_LDIR=$(SQLITE3_DIR)

DOTENV_DIR=./cpp-dotenv/cpp-dotenv
DOTENV_IDIR=$(DOTENV_DIR)/include
DOTENV_LDIR=$(DOTENV_DIR)

IDIR=../../../include
LDIR=../../../lib

LIBPROXYSQLAR=$(LDIR)/libproxysql.a
INCLUDEDIRS=-I$(IDIR) -I$(JSON_IDIR) -I$(MARIADB_IDIR) -I${CURL_IDIR} -I${SQLITE3_IDIR} -I$(DOTENV_IDIR)

.PHONY: all
all: libtap.a

.PHONY: clean
clean:
	rm -f *.o libtap.a || true
	find cpp-dotenv/cpp-dotenv/ -name '*.o' -or -name '*.a' -delete || true

OPT=-O2

debug: OPT = -O0 -DDEBUG -ggdb
debug: libtap.a

libtap.a: tap.cpp tap.h command_line.cpp command_line.h utils.cpp utils.h cpp-dotenv
	g++ -c tap.cpp command_line.cpp utils.cpp -std=c++11 $(INCLUDEDIRS) $(OPT)
	ar rcs libtap.a tap.o command_line.o utils.o $(SQLITE3_LDIR)/sqlite3.o $$(find $(DOTENV_DIR)/ -name '*.o')

cpp-dotenv/cpp-dotenv/libcpp_dotenv.a:
	cd cpp-dotenv && rm -rf cpp-dotenv-*/ || true
	cd cpp-dotenv && tar -zxf cpp-dotenv-*.tar.gz
	cd cpp-dotenv/cpp-dotenv && patch src/dotenv.cpp < ../dotenv.cpp.patch
	cd cpp-dotenv/cpp-dotenv && patch include/dotenv.h < ../dotenv.h.patch
	cd cpp-dotenv/cpp-dotenv && cmake . -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Debug
	cd cpp-dotenv/cpp-dotenv && CC=${CC} CXX=${CXX} ${MAKE}
cpp-dotenv: cpp-dotenv/cpp-dotenv/libcpp_dotenv.a
