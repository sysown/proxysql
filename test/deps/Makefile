#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)
DEPS_PATH := $(PROXYSQL_PATH)/deps
include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

CMAKE3 := $(shell command -v cmake3 2>/dev/null || command -v cmake 2>/dev/null)
OPENSSL_BUILD_STAMP_PATH := $(SSL_PATH)/.proxysql-build-complete
OPENSSL_CMAKE_FLAGS := -DOPENSSL_ROOT_DIR=$(SSL_PATH) \
	-DOPENSSL_INCLUDE_DIR=$(SSL_IDIR) \
	-DOPENSSL_SSL_LIBRARY=$(LIB_SSL_PATH) \
	-DOPENSSL_CRYPTO_LIBRARY=$(LIB_CRYPTO_PATH)
MYSQL57_OPENSSL_CMAKE_FLAGS := $(OPENSSL_CMAKE_FLAGS) \
	-DCMAKE_LIBRARY_PATH=$(SSL_PATH)

.DEFAULT: default
.PHONY: default
default: all

.PHONY: all
all: mariadb_client mysql_client mysql8_client


### test deps targets

$(OPENSSL_BUILD_STAMP_PATH):
	$(MAKE) -C $(DEPS_PATH) libssl

mariadb-connector-c/mariadb-connector-c/libmariadb/libmariadbclient.a: $(OPENSSL_BUILD_STAMP_PATH)
	cd mariadb-connector-c && rm -rf mariadb-connector-c-*/ || true
	cd mariadb-connector-c && tar -zxf mariadb-connector-c-*.tar.gz
	cd mariadb-connector-c/mariadb-connector-c && patch -p0 < ../CMakeLists.txt.patch
	cd mariadb-connector-c/mariadb-connector-c && patch -p0 < ../ConnectorName.cmake.patch
ifeq ($(UNAME_S),Darwin)
	cd mariadb-connector-c/mariadb-connector-c && cmake . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_POLICY_VERSION_MINIMUM=3.5 $(OPENSSL_CMAKE_FLAGS) -DICONV_LIBRARIES=$$(brew --prefix libiconv)/lib -DICONV_INCLUDE=$$(brew --prefix libiconv)/include
else
	cd mariadb-connector-c/mariadb-connector-c && cmake . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_POLICY_VERSION_MINIMUM=3.5 $(OPENSSL_CMAKE_FLAGS)
endif
ifeq ($(UNAME_S),Darwin)
	cd mariadb-connector-c/mariadb-connector-c && CC=${CC} CXX=${CXX} ${MAKE} -j1 mariadbclient
else
	cd mariadb-connector-c/mariadb-connector-c && CC=${CC} CXX=${CXX} ${MAKE} mariadbclient
endif

mariadb_client: mariadb-connector-c/mariadb-connector-c/libmariadb/libmariadbclient.a

# Robust tarball fetch: retry a clean download up to 5x (portable -- no curl
# --retry-all-errors, which needs curl >= 7.71 and breaks on e.g. EL8), abort a
# stalled transfer (--speed-limit/--speed-time), verify gzip integrity, and only
# then atomically rename into place so a partial never satisfies the target.
# $(1)=dir  $(2)=tarball  $(3)=url
define fetch_tarball
	cd $(1) && ( for i in 1 2 3 4 5; do \
		rm -f $(2).part; \
		curl -fL --connect-timeout 30 --speed-limit 1024 --speed-time 30 -o $(2).part $(3) && gzip -t $(2).part && mv $(2).part $(2) && exit 0; \
		echo "download of $(2) failed (attempt $$i/5), retrying in 5s..." >&2; sleep 5; \
	done; echo "ERROR: could not download $(2) after 5 attempts" >&2; exit 1 )
endef

mysql-connector-c/mysql-boost-5.7.44.tar.gz:
	$(call fetch_tarball,mysql-connector-c,mysql-boost-5.7.44.tar.gz,https://cdn.mysql.com//Downloads/MySQL-5.7/mysql-boost-5.7.44.tar.gz)

mysql-connector-c/mysql-connector-c/libmysql/libmysqlclient.a: mysql-connector-c/mysql-boost-5.7.44.tar.gz $(OPENSSL_BUILD_STAMP_PATH)
	cd mysql-connector-c && rm -rf mysql-*/ || true
	cd mysql-connector-c && tar -zxf mysql-boost-5.7.*.tar.gz
ifeq ($(UNAME_S),Darwin)
	cd mysql-connector-c && mysql_dir=$$(ls -1d mysql-5.7.*/) && \
		sed -i '' 's/CMAKE_POLICY(SET CMP0018 OLD)/CMAKE_POLICY(SET CMP0018 NEW)/' $${mysql_dir}CMakeLists.txt && \
		sed -i '' 's/CMAKE_POLICY(SET CMP0022 OLD)/CMAKE_POLICY(SET CMP0022 NEW)/' $${mysql_dir}CMakeLists.txt && \
		sed -i '' 's/CMAKE_POLICY(SET CMP0045 OLD)/CMAKE_POLICY(SET CMP0045 NEW)/' $${mysql_dir}CMakeLists.txt && \
		sed -i '' 's/CMAKE_POLICY(SET CMP0042 OLD)/CMAKE_POLICY(SET CMP0042 NEW)/' $${mysql_dir}CMakeLists.txt && \
		sed -i '' 's/CMAKE_POLICY(SET CMP0075 OLD)/CMAKE_POLICY(SET CMP0075 NEW)/' $${mysql_dir}CMakeLists.txt && \
		sed -i '' 's/#      ifndef fdopen/#      if !defined(fdopen) \&\& !defined(__APPLE__)/' $${mysql_dir}extra/zlib/zlib-1.2.13/zutil.h
	cd mysql-connector-c && ln -fsh $$(ls -1d mysql-5.7.*/) mysql-connector-c
	cd mysql-connector-c/mysql-connector-c && cmake . -DWITH_BOOST=./boost -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DCMAKE_C_FLAGS="-Wno-incompatible-pointer-types" \
		-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O0 -ggdb -DNDEBUG -fPIC" \
		-DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DWITH_SSL=$(SSL_PATH) $(MYSQL57_OPENSSL_CMAKE_FLAGS)
else
	cd mysql-connector-c && ln -fsT $$(ls -1d mysql-5.7.*/) mysql-connector-c
	cd mysql-connector-c/mysql-connector-c && $(CMAKE3) . -DWITH_BOOST=./boost \
		-DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_FLAGS="-Wno-incompatible-pointer-types" \
		-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O0 -ggdb -DNDEBUG -fPIC" \
		-DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DWITH_SSL=$(SSL_PATH) $(MYSQL57_OPENSSL_CMAKE_FLAGS)
endif
ifeq ($(UNAME_S),Darwin)
	cd mysql-connector-c/mysql-connector-c && CC=${CC} CXX=${CXX} ${MAKE} -j1 mysqlclient mysql
else
	cd mysql-connector-c/mysql-connector-c && CC=${CC} CXX=${CXX} ${MAKE} mysqlclient mysql
endif
	cd mysql-connector-c/mysql-connector-c && cp archive_output_directory/libmysqlclient.a libmysql/

mysql_client: mysql-connector-c/mysql-connector-c/libmysql/libmysqlclient.a

mysql-connector-c-8.4.0/mysql-8.4.0.tar.gz:
	$(call fetch_tarball,mysql-connector-c-8.4.0,mysql-8.4.0.tar.gz,https://cdn.mysql.com//Downloads/MySQL-8.4/mysql-8.4.0.tar.gz)

mysql-connector-c-8.4.0/mysql-connector-c/libmysql/libmysqlclient.a: mysql-connector-c-8.4.0/mysql-8.4.0.tar.gz $(OPENSSL_BUILD_STAMP_PATH)
	cd mysql-connector-c-8.4.0 && rm -rf mysql-*/ || true
	cd mysql-connector-c-8.4.0 && tar -zxf mysql-*.tar.gz
ifeq ($(UNAME_S),Darwin)
	cd mysql-connector-c-8.4.0 && mysql_dir=$$(ls -1d mysql-8.4.*/) && \
		sed -i '' 's/#      ifndef fdopen/#      if !defined(fdopen) \&\& !defined(__APPLE__)/' $${mysql_dir}extra/zlib/zlib-1.2.13/zutil.h
	cd mysql-connector-c-8.4.0 && ln -fsh $$(ls -1d mysql-8.4.*/) mysql-connector-c
	cd mysql-connector-c-8.4.0/mysql-connector-c && patch -p0 --batch < ../../mysql-8.4.0-clang17.patch
	cd mysql-connector-c-8.4.0/mysql-connector-c && cmake . -DFORCE_INSOURCE_BUILD=1 -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
		-DWITHOUT_SERVER=ON -DDOWNLOAD_BOOST=1 -DWITH_BOOST=./mysql-server/downloads/ -DWITH_UNIT_TESTS=OFF \
		-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O0 -ggdb -DNDEBUG -fPIC" -DWITH_SSL=$(SSL_PATH) $(OPENSSL_CMAKE_FLAGS)
else
	cd mysql-connector-c-8.4.0 && ln -fsT $$(ls -1d mysql-8.4.*/) mysql-connector-c
	cd mysql-connector-c-8.4.0/mysql-connector-c && cmake . -DFORCE_INSOURCE_BUILD=1 -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
		-DWITHOUT_SERVER=ON -DDOWNLOAD_BOOST=1 -DWITH_BOOST=./mysql-server/downloads/ -DWITH_UNIT_TESTS=OFF \
		-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O0 -ggdb -DNDEBUG -fPIC" -DWITH_SSL=$(SSL_PATH) $(OPENSSL_CMAKE_FLAGS)
endif
ifeq ($(UNAME_S),Darwin)
	cd mysql-connector-c-8.4.0/mysql-connector-c && CC=${CC} CXX=${CXX} ${MAKE} -j1
else
	cd mysql-connector-c-8.4.0/mysql-connector-c && CC=${CC} CXX=${CXX} ${MAKE}
endif
	cd mysql-connector-c-8.4.0/mysql-connector-c && cp archive_output_directory/libmysqlclient.a libmysql/

mysql8_client: mysql-connector-c-8.4.0/mysql-connector-c/libmysql/libmysqlclient.a

### clean targets

.PHONY: cleanall
.SILENT: cleanall
cleanall:
	cd mariadb-connector-c && rm -rf mariadb-connector-c-*/ || true
	cd mysql-connector-c && rm -rf mysql-5.7.*/ || true
	cd mysql-connector-c-8.4.0 && rm -rf mysql-8.4.*/ || true
	cd cluster_simulator && ${MAKE} clean

.PHONY: clean
.SILENT: clean
clean: cleanall

# NOTE: clean is now an alias of cleanall since the incremental clean
# was practically redundant due to build targets forcing full rebuilds anyway
