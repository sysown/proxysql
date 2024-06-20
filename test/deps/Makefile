#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)
DEPS_PATH := $(PROXYSQL_PATH)/deps


.DEFAULT: default
.PHONY: default
default: all

.PHONY: all
all: mariadb_client mysql_client mysql8_client


### test deps targets

mariadb-connector-c/mariadb-connector-c/libmariadb/libmariadbclient.a:
	cd mariadb-connector-c && rm -rf mariadb-connector-c-*/ || true
	cd mariadb-connector-c && tar -zxf mariadb-connector-c-*.tar.gz
	cd mariadb-connector-c/mariadb-connector-c && patch -p0 < ../CMakeLists.txt.patch
	cd mariadb-connector-c/mariadb-connector-c && patch -p0 < ../ConnectorName.cmake.patch
	cd mariadb-connector-c/mariadb-connector-c && cmake . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DOPENSSL_ROOT_DIR=$(DEPS_PATH)/libssl/openssl/
	cd mariadb-connector-c/mariadb-connector-c && CC=${CC} CXX=${CXX} ${MAKE} mariadbclient

mariadb_client: mariadb-connector-c/mariadb-connector-c/libmariadb/libmariadbclient.a

mysql-connector-c/mysql-boost-5.7.44.tar.gz:
	cd mysql-connector-c && curl -C - -O -s https://cdn.mysql.com//Downloads/MySQL-5.7/mysql-boost-5.7.44.tar.gz || wget -nc -q https://cdn.mysql.com//Downloads/MySQL-5.7/mysql-boost-5.7.44.tar.gz

mysql-connector-c/mysql-connector-c/libmysql/libmysqlclient.a: mysql-connector-c/mysql-boost-5.7.44.tar.gz
	cd mysql-connector-c && rm -rf mysql-*/ || true
	cd mysql-connector-c && tar -zxf mysql-boost-5.7.*.tar.gz
	cd mysql-connector-c && ln -fsT $$(ls -1d mysql-5.7.*/) mysql-connector-c
	cd mysql-connector-c/mysql-connector-c && cmake . -DWITH_BOOST=./boost -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O0 -ggdb -DNDEBUG -fPIC" -DOPENSSL_ROOT_DIR=$(DEPS_PATH)/libssl/openssl
	cd mysql-connector-c/mysql-connector-c && CC=${CC} CXX=${CXX} ${MAKE} mysqlclient mysql
	cd mysql-connector-c/mysql-connector-c && cp archive_output_directory/libmysqlclient.a libmysql/

mysql_client: mysql-connector-c/mysql-connector-c/libmysql/libmysqlclient.a

mysql-connector-c-8.4.0/mysql-8.4.0.tar.gz:
	cd mysql-connector-c-8.4.0 && curl -C - -O -s https://cdn.mysql.com//Downloads/MySQL-8.4/mysql-8.4.0.tar.gz || wget -nc -q https://cdn.mysql.com//Downloads/MySQL-8.4/mysql-8.4.0.tar.gz

mysql-connector-c-8.4.0/mysql-connector-c/libmysql/libmysqlclient.a: mysql-connector-c-8.4.0/mysql-8.4.0.tar.gz
	cd mysql-connector-c-8.4.0 && rm -rf mysql-*/ || true
	cd mysql-connector-c-8.4.0 && tar -zxf mysql-*.tar.gz
	cd mysql-connector-c-8.4.0 && ln -fsT $$(ls -1d mysql-8.4.*/) mysql-connector-c
	cd mysql-connector-c-8.4.0/mysql-connector-c && cmake . -DFORCE_INSOURCE_BUILD=1 -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DWITHOUT_SERVER=ON -DDOWNLOAD_BOOST=1 -DWITH_BOOST=./mysql-server/downloads/ -DWITH_UNIT_TESTS=OFF \
		-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O0 -ggdb -DNDEBUG -fPIC" -DOPENSSL_ROOT_DIR=$(DEPS_PATH)/libssl/openssl
	cd mysql-connector-c-8.4.0/mysql-connector-c && CC=${CC} CXX=${CXX} ${MAKE}
	cd mysql-connector-c-8.4.0/mysql-connector-c && cp archive_output_directory/libmysqlclient.a libmysql/

mysql8_client: mysql-connector-c-8.4.0/mysql-connector-c/libmysql/libmysqlclient.a

### clean targets

.PHONY: cleanall
.SILENT: cleanall
cleanall:
	cd mariadb-connector-c && rm -rf mariadb-connector-c-*/ || true
	cd mysql-connector-c && rm -rf mysql-5.7.*/ || true
	cd mysql-connector-c-8.4.0 && rm -rf mysql-8.4.*/ || true

.PHONY: clean
.SILENT: clean
clean:
	cd mariadb-connector-c/mariadb-connector-c && $(MAKE) --no-print-directory clean || true
	cd mariadb-connector-c/mariadb-connector-c && rm -f CMakeCache.txt || true
	cd mysql-connector-c/mysql-connector-c && $(MAKE) --no-print-directory clean || true
	cd mysql-connector-c/mysql-connector-c && rm -f CMakeCache.txt || true
	cd mysql-connector-c/mysql-connector-c && rm -f libmysql/libmysqlclient.a || true
	cd mysql-connector-c-8.4.0/mysql-connector-c && $(MAKE) --no-print-directory clean || true
	cd mysql-connector-c-8.4.0/mysql-connector-c && rm -f CMakeCache.txt || true
	cd mysql-connector-c-8.4.0/mysql-connector-c && rm -f libmysql/libmysqlclient.a || true
