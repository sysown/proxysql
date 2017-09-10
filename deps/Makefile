

PROXYDEBUG := $(shell echo $(PROXYDEBUG))
ifeq ($(PROXYDEBUG),1)
MYCFLAGS=-O0
MYJEOPT=--enable-xmalloc --enable-munmap --enable-prof --enable-fill --enable-debug
else
MYCFLAGS=-O2
MYJEOPT=--enable-xmalloc --enable-munmap --enable-prof
endif

PROXYSQLCLICKHOUSE := $(shell echo $(PROXYSQLCLICKHOUSE))
ifeq ($(PROXYSQLCLICKHOUSE),1)
default: libconfig libdaemon jemalloc mariadb_client re2 sqlite3 pcre clickhouse-cpp lz4 cityhash
else
default: libconfig libdaemon jemalloc mariadb_client re2 sqlite3 pcre
endif
.PHONY: default


cityhash/cityhash/src/.libs/libcityhash.a:
	cd cityhash && rm -rf cityhash || true
	cd cityhash && tar -zxf cityhash.tar.gz
	cd cityhash/cityhash && ./configure && CC=${CC} CXX=${CXX} ${MAKE}
cityhash: cityhash/cityhash/src/.libs/libcityhash.a

lz4/lz4/liblz4.a:
	cd lz4 && rm -rf lz4-1.7.5 || true
	cd lz4 && tar -zxf lz4-1.7.5.tar.gz
	cd lz4/lz4 && CC=${CC} CXX=${CXX} ${MAKE}
lz4: lz4/lz4/liblz4.a

clickhouse-cpp/clickhouse-cpp/clickhouse/libclickhouse-cpp-lib.a:
	cd clickhouse-cpp && rm -rf clickhouse-cpp || true
	cd clickhouse-cpp && tar -zxf clickhouse-cpp.tar.gz
	cd clickhouse-cpp/clickhouse-cpp && cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo .
	cd clickhouse-cpp/clickhouse-cpp && CC=${CC} CXX=${CXX} ${MAKE}

clickhouse-cpp: clickhouse-cpp/clickhouse-cpp/clickhouse/libclickhouse-cpp-lib.a


libdaemon/libdaemon/libdaemon/.libs/libdaemon.a: 
	cd libdaemon && rm -rf libdaemon-0.14
	cd libdaemon && tar -zxf libdaemon-0.14.tar.gz
	cd libdaemon/libdaemon && ./configure --disable-examples
	cd libdaemon/libdaemon && CC=${CC} CXX=${CXX} ${MAKE}

libdaemon: libdaemon/libdaemon/libdaemon/.libs/libdaemon.a

jemalloc/jemalloc/lib/libjemalloc.a:
	cd jemalloc && rm -rf jemalloc-4.3.1
	cd jemalloc && tar -jxf jemalloc-4.3.1.tar.bz2
	cd jemalloc/jemalloc && patch src/jemalloc.c < ../issue823.patch
	cd jemalloc/jemalloc && ./configure ${MYJEOPT}
	cd jemalloc/jemalloc && CC=${CC} CXX=${CXX} ${MAKE}

jemalloc: jemalloc/jemalloc/lib/libjemalloc.a


mariadb-client-library/mariadb_client/include/my_config.h:
#	cd mariadb-client-library && rm -rf mariadb-connector-c-2.1.0-src
#	cd mariadb-client-library && tar -zxf mariadb-connector-c-2.1.0-src.tar.gz
	cd mariadb-client-library && rm -rf mariadb-connector-c-2.3.1
	cd mariadb-client-library && tar -zxf mariadb-connector-c-2.3.1-src.tar.gz
	cd mariadb-client-library/mariadb_client && cmake .
	cd mariadb-client-library/mariadb_client && patch libmariadb/libmariadb.c < ../libmariadb.c.patch
	cd mariadb-client-library/mariadb_client && patch libmariadb/net.c < ../net.c.patch
#	cd mariadb-client-library/mariadb_client && patch libmariadb/mysql_async.c < ../mysql_async.c.patch
	cd mariadb-client-library/mariadb_client && patch libmariadb/password.c < ../password.c.patch
#	cd mariadb-client-library/mariadb_client && patch libmariadb/ma_secure.c < ../ma_secure.c.patch
	cd mariadb-client-library/mariadb_client && patch include/mysql.h < ../mysql.h.patch
	cd mariadb-client-library/mariadb_client && patch libmariadb/my_alloc.c < ../my_alloc.c.patch
	cd mariadb-client-library/mariadb_client && CC=${CC} CXX=${CXX} ${MAKE}
# cd mariadb-client-library/mariadb_client/include && make my_config.h

mariadb_client: mariadb-client-library/mariadb_client/include/my_config.h


sqlite3/sqlite3/sqlite3.o:
	cd sqlite3 && rm -rf sqlite-amalgamation-3190200
	cd sqlite3 && tar -zxf sqlite-amalgamation-3190200.tar.gz
	cd sqlite3/sqlite3 && patch sqlite3.c < ../from_unixtime.patch
	cd sqlite3/sqlite3 && ${CC} ${MYCFLAGS} -c -o sqlite3.o sqlite3.c -DSQLITE_ENABLE_MEMORY_MANAGEMENT

sqlite3: sqlite3/sqlite3/sqlite3.o

libconfig/libconfig/lib/.libs/libconfig++.a:
	cd libconfig && rm -rf libconfig-1.4.9
	cd libconfig && tar -zxf libconfig-1.4.9.tar.gz
	cd libconfig/libconfig && ./configure --disable-examples
	cd libconfig/libconfig && CC=${CC} CXX=${CXX} ${MAKE}

libconfig: libconfig/libconfig/lib/.libs/libconfig++.a


re2/re2/obj/libre2.a:
	cd re2 && rm -rf re2
#	cd re2 && tar -zxf re2-20140304.tgz
	cd re2 && tar -zxf re2.tar.gz
#	cd re2/re2 && sed -i -e 's/-O3 -g /-O3 -fPIC /' Makefile
#	cd re2 && patch re2/util/mutex.h < mutex.h.patch
	cd re2/re2 && sed -i -e 's/-O3 /-O3 -DMEMORY_SANITIZER /' Makefile
	cd re2/re2 && CC=${CC} CXX=${CXX} ${MAKE}

re2: re2/re2/obj/libre2.a

pcre/pcre/.libs/libpcre.a:
	cd pcre && rm -rf pcre-8.39
	cd pcre && tar -zxf pcre-8.39.tar.gz
	cd pcre/pcre && ./configure
	cd pcre/pcre && CC=${CC} CXX=${CXX} ${MAKE}
pcre: pcre/pcre/.libs/libpcre.a

cleanpart:
	cd mariadb-client-library && rm -rf mariadb-connector-c-2.3.1
	cd jemalloc && rm -rf jemalloc-4.2.1
	cd sqlite3/sqlite3 && rm -rf *
.PHONY: cleanpart

cleanall:
	cd libdaemon && rm -rf libdaemon-0.14
	cd jemalloc && rm -rf jemalloc-4.3.1
	cd mariadb-client-library && rm -rf mariadb-connector-c-2.3.1
	cd libconfig && rm -rf libconfig-1.4.9
	cd re2 && rm -rf re2
	cd pcre && rm -rf pcre-8.39
	cd sqlite3/sqlite3 && rm -rf * || true
	cd clickhouse-cpp/clickhouse-cpp && rm -rf * || true
	cd lz4 && rm -rf lz4-1.7.5 || true
.PHONY: cleanall

