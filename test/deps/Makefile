#!/bin/make -f


targets := mariadb_client mysql_client

.PHONY: default
default: $(targets)


### test deps targets

mariadb-connector-c/mariadb-connector-c/libmariadb/libmariadbclient.a:
	cd mariadb-connector-c && rm -rf mariadb-connector-c-*/ || true
	cd mariadb-connector-c && tar -zxf mariadb-connector-c-*.tar.gz
	cd mariadb-connector-c/mariadb-connector-c && patch -p0 < ../CMakeLists.txt.patch
	cd mariadb-connector-c/mariadb-connector-c && patch -p0 < ../ConnectorName.cmake.patch
	cd mariadb-connector-c/mariadb-connector-c && cmake . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DOPENSSL_ROOT_DIR=$(DEPS_PATH)/libssl/openssl/
	cd mariadb-connector-c/mariadb-connector-c && CC=${CC} CXX=${CXX} ${MAKE} mariadbclient

mariadb_client: mariadb-connector-c/mariadb-connector-c/libmariadb/libmariadbclient.a


mysql-connector-c/mysql-connector-c/libmysql/libmysqlclient.a:
	cd mysql-connector-c && rm -rf mysql-connector-c-*-src/ || true
	cd mysql-connector-c && tar -zxf mysql-connector-c-*-src.tar.gz
	cd mysql-connector-c/mysql-connector-c && patch -p0 < ../CMakeLists.txt.patch
	cd mysql-connector-c/mysql-connector-c && patch -p0 < ../install_macros.cmake.patch
	cd mysql-connector-c/mysql-connector-c && cmake . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DOPENSSL_ROOT_DIR=$(DEPS_PATH)/libssl/openssl
	cd mysql-connector-c/mysql-connector-c && CC=${CC} CXX=${CXX} ${MAKE} mysqlclient

mysql_client: mysql-connector-c/mysql-connector-c/libmysql/libmysqlclient.a


### clean targets

.SILENT: cleanall
.PHONY: cleanall
cleanall:
	cd mariadb-connector-c && rm -rf mariadb-connector-c-*/ || true
	cd mysql-connector-c && rm -rf mysql-connector-c-*-src/ || true

.SILENT: clean
.PHONY: clean
clean:
	cd mariadb-connector-c/mariadb-connector-c && $(MAKE) clean || true
	cd mariadb-connector-c/mariadb-connector-c && rm -f CMakeCache.txt
	cd mysql-connector-c/mysql-connector-c && $(MAKE) clean || true
	cd mysql-connector-c/mysql-connector-c && rm -f CMakeCache.txt
