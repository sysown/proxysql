#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk


IDIRS :=	-I$(PROXYSQL_IDIR) \
			-I$(JSON_IDIR) \
			-I${CURL_IDIR} \
			-I${SQLITE3_IDIR} \
			-I$(DOTENV_IDIR) \
			-I$(RE2_IDIR)


LIBPROXYSQLAR := $(PROXYSQL_LDIR)/libproxysql.a


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
	libtap.so libcpp_dotenv.so libre2.so

debug: OPT := $(STDCPP) -O0 -DDEBUG -ggdb -Wl,--no-as-needed $(WASAN)
debug: libtap_mariadb.a libtap_mysql57.a libtap_mysql8.a libtap.so

### helper targets

command_line.o: command_line.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a libcurl.so -lssl -lcrypto libcpp_dotenv.so
	$(CXX) -fPIC -c command_line.cpp $(IDIRS) $(OPT)

utils_mariadb.o: utils.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a libcurl.so -lssl -lcrypto libcpp_dotenv.so
	$(CXX) -fPIC -c utils.cpp $(IDIRS) -I$(MARIADB_IDIR) $(OPT) -o $@

utils_mysql57.o: utils.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a libcurl.so -lssl -lcrypto libcpp_dotenv.so
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING -fPIC -c utils.cpp $(IDIRS) -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) $(OPT) -o $@

utils_mysql8.o: utils.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a libcurl.so -lssl -lcrypto libcpp_dotenv.so
	$(CXX) -DDISABLE_WARNING_COUNT_LOGGING -fPIC -c utils.cpp $(IDIRS) -I$(TEST_MYSQL8_IDIR) -I$(TEST_MYSQL_EDIR) $(OPT) -o $@

tap.o: tap.cpp cpp-dotenv/static/cpp-dotenv/libcpp_dotenv.a libcurl.so -lssl -lcrypto libcpp_dotenv.so
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
	# Clean build artifacts but exclude cpp-dotenv directories (preserve 213MB extracted source)
	find . -path ./cpp-dotenv -prune -o \( -name '*.a' -o -name '*.o' -o -name '*.so' -o -name '*.so.*' \) -delete || true

.SILENT: cleanall
.PHONY: cleanall
cleanall: clean
	# Remove cpp-dotenv source directories (213MB)
	cd cpp-dotenv/static && rm -rf cpp-dotenv-*/ || true
	cd cpp-dotenv/dynamic && rm -rf cpp-dotenv-*/ || true

