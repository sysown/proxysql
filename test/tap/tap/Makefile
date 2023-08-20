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

DOTENV_DIR=./cpp-dotenv/static/cpp-dotenv
DOTENV_IDIR=$(DOTENV_DIR)/include
DOTENV_LDIR=$(DOTENV_DIR)

IDIR=../../../include
LDIR=../../../lib

LIBPROXYSQLAR=$(LDIR)/libproxysql.a
INCLUDEDIRS=-I$(IDIR) -I$(JSON_IDIR) -I$(MARIADB_IDIR) -I${CURL_IDIR} -I${SQLITE3_IDIR} -I$(DOTENV_IDIR)

.PHONY: all
all: libtap.a libtap.so libssl.so.3 libcrypto.so.3 libcpp_dotenv.so

.PHONY: clean
clean:
	rm -f *.o libtap.a libtap.so || true
	find cpp-dotenv/dynamic -name '*.o' -or -name '*.a' -delete || true
	find cpp-dotenv/static -name '*.o' -or -name '*.a' -delete || true

OPT=-O2

debug: OPT = -O0 -DDEBUG -ggdb
debug: libtap.a libtap.so libssl.so.3 libcrypto.so.3 libcpp_dotenv.so

command_line.o: command_line.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a
	g++ -fPIC -c command_line.cpp -std=c++11 $(INCLUDEDIRS) $(OPT)

utils.o: utils.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a
	g++ -fPIC -c utils.cpp -std=c++11 $(INCLUDEDIRS) $(OPT)

tap.o: tap.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a
	g++ -fPIC -c tap.cpp -std=c++11 $(INCLUDEDIRS) $(OPT)

libtap.a: tap.cpp tap.h command_line.cpp command_line.h utils.cpp utils.h tap.o command_line.o utils.o cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a
	ar rcs libtap.a tap.o command_line.o utils.o $(SQLITE3_LDIR)/sqlite3.o

libtap.so: libtap.a cpp-dotenv/dynamic/cpp-dotenv/libcpp_dotenv.so
	gcc -shared -o libtap.so -Wl,--whole-archive libtap.a ../../../deps/curl/curl/lib/.libs/libcurl.a ../../../deps/libssl/openssl/libcrypto.a ../../../deps/libssl/openssl/libssl.a -Wl,--no-whole-archive

libssl.so.3:
	ln -s $(DEPS_PATH)/libssl/openssl/libssl.so.3

libcrypto.so.3:
	ln -s $(DEPS_PATH)/libssl/openssl/libcrypto.so.3

libcpp_dotenv.so: cpp-dotenv/dynamic/cpp-dotenv/libcpp_dotenv.so
	ln -s ./cpp-dotenv/dynamic/cpp-dotenv/libcpp_dotenv.so .

cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a:
	cd cpp-dotenv/static && rm -rf cpp-dotenv-*/ || true
	cd cpp-dotenv/static && tar -zxf ../cpp-dotenv-*.tar.gz
	cd cpp-dotenv/static/cpp-dotenv && patch src/dotenv.cpp < ../../dotenv.cpp.patch
	cd cpp-dotenv/static/cpp-dotenv && patch include/dotenv.h < ../../dotenv.h.patch
	cd cpp-dotenv/static/cpp-dotenv && cmake . -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Debug
	cd cpp-dotenv/static/cpp-dotenv && CC=${CC} CXX=${CXX} ${MAKE}

cpp-dotenv/dynamic/cpp-dotenv/libcpp_dotenv.so:
	cd cpp-dotenv/dynamic && rm -rf cpp-dotenv-*/ || true
	cd cpp-dotenv/dynamic && tar -zxf ../cpp-dotenv-*.tar.gz
	cd cpp-dotenv/dynamic/cpp-dotenv && patch src/dotenv.cpp < ../../dotenv.cpp.patch
	cd cpp-dotenv/dynamic/cpp-dotenv && patch include/dotenv.h < ../../dotenv.h.patch
	cd cpp-dotenv/dynamic/cpp-dotenv && cmake . -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Debug
	cd cpp-dotenv/dynamic/cpp-dotenv && CC=${CC} CXX=${CXX} ${MAKE}
