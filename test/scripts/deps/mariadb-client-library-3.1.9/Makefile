DEPS_PATH=$(WORKSPACE)/deps

.SILENT: clean

mariadb-connector-c/libmariadb/libmariadbclient.a:
	cd mariadb-connector-c && git reset --hard
	cd mariadb-connector-c && git clean -f -d -x
	cd mariadb-connector-c && patch ./CMakeLists.txt < ../CMakeLists.txt.patch
	cd mariadb-connector-c && patch -p0 < ../ConnectorName.patch
	cd mariadb-connector-c && cmake . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DOPENSSL_ROOT_DIR=$(DEPS_PATH)/libssl/openssl/ -DOPENSSL_LIBRARIES=$(DEPS_PATH)/libssl/openssl/ .
	cd mariadb-connector-c && CC=${CC} CXX=${CXX} ${MAKE} mariadbclient

mariadb_client: mariadb-connector-c/libmariadb/libmariadbclient.a

.PHONY: clean
clean:
	cd mariadb-connector-c && $(MAKE) clean || true
	cd mariadb-connector-c && rm -f CMakeCache.txt
