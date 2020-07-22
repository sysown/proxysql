

PROXYDEBUG := $(shell echo $(PROXYDEBUG))
ifeq ($(PROXYDEBUG),1)
MYCFLAGS=-O0
MYJEOPT=--enable-xmalloc --enable-prof --enable-fill --enable-debug
else
MYCFLAGS=-O2
MYJEOPT=--enable-xmalloc --enable-prof
endif

ifneq (,$(wildcard /etc/system-release))
	CENTOSVER := $(shell cat /etc/system-release | awk '{print $$3}')
else
	CENTOSVER := Unknown
endif

PROXYSQLCLICKHOUSE := $(shell echo $(PROXYSQLCLICKHOUSE))
ifeq ($(PROXYSQLCLICKHOUSE),1)
default: libconfig libdaemon jemalloc mariadb_client re2 sqlite3 pcre clickhouse-cpp lz4 cityhash microhttpd curl ev libssl libhttpserver libinjection prometheus-cpp
else
default: libconfig libdaemon jemalloc mariadb_client re2 sqlite3 pcre microhttpd curl ev libssl libhttpserver libinjection prometheus-cpp
endif
.PHONY: default


libinjection/libinjection/src/libinjection.a:
	cd libinjection && rm -rf libinjection-3.10.0 || true
	cd libinjection && tar -zxf libinjection-3.10.0.tar.gz
	cd libinjection/libinjection && CC=${CC} CXX=${CXX} ${MAKE}
libinjection: libinjection/libinjection/src/libinjection.a

libssl/openssl/libssl.a:
#	cd libssl && rm -rf openssl-1.1.0h || true
#	cd libssl && tar -zxf openssl-1.1.0h.tar.gz
	cd libssl && rm -rf openssl-1.1.1d || true
	cd libssl && rm -rf openssl-1.1.0h || true
	cd libssl && rm -rf openssl-1.1.1g || true
	cd libssl && tar -zxf openssl-1.1.1g.tar.gz
	cd libssl/openssl  && ./config no-ssl3
	cd libssl/openssl && CC=${CC} CXX=${CXX} ${MAKE}
	cd libssl/openssl && ln -s . lib # curl wants this path
libssl: libssl/openssl/libssl.a

libhttpserver/libhttpserver/build/src/.libs/libhttpserver.a: libmicrohttpd/libmicrohttpd/src/microhttpd/.libs/libmicrohttpd.a
	cd libhttpserver && rm -rf libhttpserver-master_20191121 || true
	cd libhttpserver && tar -zxf libhttpserver-master_20191121.tar.gz
	cd libhttpserver/libhttpserver && ./bootstrap && mkdir build
	cd libhttpserver/libhttpserver/build && LDFLAGS=-L$(shell pwd)/libmicrohttpd/libmicrohttpd/src/microhttpd/.libs/ CPPFLAGS=-I$(shell pwd)/libmicrohttpd/libmicrohttpd/src/include ../configure --disable-doxygen-doc --disable-doxygen-dot --disable-doxygen-man --disable-doxygen-html
	cd libhttpserver/libhttpserver/build && CC=${CC} CXX=${CXX} ${MAKE}
libhttpserver: libhttpserver/libhttpserver/build/src/.libs/libhttpserver.a

libev/libev/.libs/libev.a:
	cd libev && rm -rf libev-4.24 || true
	cd libev && tar -zxf libev-4.24.tar.gz
	cd libev/libev  && ./configure
	cd libev/libev && CC=${CC} CXX=${CXX} ${MAKE}
ev: libev/libev/.libs/libev.a

curl/curl/lib/.libs/libcurl.a: libssl/openssl/libssl.a
	cd curl && rm -rf curl-7.57.0 || true
	cd curl && tar -zxf curl-7.57.0.tar.gz
	#cd curl/curl && ./configure --disable-debug --disable-ftp --disable-ldap --disable-ldaps --disable-rtsp --disable-proxy --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp --disable-gopher --disable-manual --disable-ipv6 --disable-sspi --disable-crypto-auth --disable-ntlm-wb --disable-tls-srp --without-nghttp2 --without-libidn2 --without-libssh2 --without-brotli --with-ssl=$(shell pwd)/../../libssl/openssl/ && CC=${CC} CXX=${CXX} ${MAKE}
	cd curl/curl && ./configure --disable-debug --disable-ftp --disable-ldap --disable-ldaps --disable-rtsp --disable-proxy --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp --disable-gopher --disable-manual --disable-ipv6 --disable-sspi --disable-crypto-auth --disable-ntlm-wb --disable-tls-srp --without-nghttp2 --without-libidn2 --without-libssh2 --without-brotli --without-librtmp --without-libpsl --with-ssl=$(shell pwd)/libssl/openssl/ --enable-shared=no && CC=${CC} CXX=${CXX} ${MAKE}
curl: curl/curl/lib/.libs/libcurl.a

libmicrohttpd/libmicrohttpd/src/microhttpd/.libs/libmicrohttpd.a:
	cd libmicrohttpd && rm -rf libmicrohttpd-0.9.55 || true
	cd libmicrohttpd && rm -rf libmicrohttpd-0.9.68 || true
	cd libmicrohttpd && rm -f libmicrohttpd || true
ifeq ($(CENTOSVER),6.7)
	cd libmicrohttpd && ln -s libmicrohttpd-0.9.55 libmicrohttpd
	cd libmicrohttpd && tar -zxf libmicrohttpd-0.9.55.tar.gz
else
	cd libmicrohttpd && ln -s libmicrohttpd-0.9.68 libmicrohttpd
	cd libmicrohttpd && tar -zxf libmicrohttpd-0.9.68.tar.gz
endif
	cd libmicrohttpd/libmicrohttpd && ./configure --enable-https && CC=${CC} CXX=${CXX} ${MAKE}
microhttpd: libmicrohttpd/libmicrohttpd/src/microhttpd/.libs/libmicrohttpd.a

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
	cd jemalloc && rm -rf jemalloc-5.2.0
	cd jemalloc && tar -jxf jemalloc-5.2.0.tar.bz2
	cd jemalloc/jemalloc && patch src/jemalloc.c < ../issue823.520.patch
	cd jemalloc/jemalloc && patch src/jemalloc.c < ../issue2358.patch
	cd jemalloc/jemalloc && ./configure ${MYJEOPT}
#	cd jemalloc/jemalloc && sed -i -e 's/-O3 /-O3 -fPIC /' Makefile
	cd jemalloc/jemalloc && CC=${CC} CXX=${CXX} ${MAKE}

jemalloc: jemalloc/jemalloc/lib/libjemalloc.a


mariadb-client-library/mariadb_client/libmariadb/libmariadbclient.a: libssl/openssl/libssl.a
	cd mariadb-client-library && rm -rf mariadb-connector-c-3.1.9-src
	cd mariadb-client-library && tar -zxf mariadb-connector-c-3.1.9-src.tar.gz
	cd mariadb-client-library/mariadb_client && patch ./plugins/auth/CMakeLists.txt < ../plugin_auth_CMakeLists.txt.patch
	 cd mariadb-client-library/mariadb_client && patch ./CMakeLists.txt < ../CMakeLists.txt.patch
#	cd mariadb-client-library/mariadb_client && cmake . -DOPENSSL_ROOT_DIR=$(shell pwd)/libssl/openssl/ -DOPENSSL_LIBRARIES=$(shell pwd)/libssl/openssl/ .
	cd mariadb-client-library/mariadb_client && cmake . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DOPENSSL_ROOT_DIR=$(shell pwd)/libssl/openssl/ -DOPENSSL_LIBRARIES=$(shell pwd)/libssl/openssl/ .
#	cd mariadb-client-library/mariadb_client && cmake . -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl # this is needed on MacOSX
	cd mariadb-client-library/mariadb_client && patch libmariadb/mariadb_stmt.c < ../mariadb_stmt.c.patch
	cd mariadb-client-library/mariadb_client && patch libmariadb/mariadb_lib.c < ../mariadb_lib.c.patch
#	cd mariadb-client-library/mariadb_client && patch libmariadb/net.c < ../net.c.patch
	cd mariadb-client-library/mariadb_client && patch libmariadb/mariadb_async.c < ../mariadb_async.c.patch
	cd mariadb-client-library/mariadb_client && patch libmariadb/ma_password.c < ../ma_password.c.patch
#	cd mariadb-client-library/mariadb_client && patch libmariadb/ma_secure.c < ../ma_secure.c.patch
	cd mariadb-client-library/mariadb_client && patch include/mysql.h < ../mysql.h.patch
	cd mariadb-client-library/mariadb_client && patch include/mariadb_com.h < ../mariadb_com.h.patch
	cd mariadb-client-library/mariadb_client && patch libmariadb/ma_alloc.c < ../ma_alloc.c.patch
	cd mariadb-client-library/mariadb_client && patch libmariadb/ma_charset.c < ../ma_charset.c.patch
#	cd mariadb-client-library/mariadb_client && patch libmariadb/ma_pvio.c < ../ma_pvio.c.patch
	cd mariadb-client-library/mariadb_client && patch unittest/libmariadb/basic-t.c < ../unittest_basic-t.c.patch
	cd mariadb-client-library/mariadb_client && patch unittest/libmariadb/charset.c < ../unittest_charset.c.patch
	cd mariadb-client-library/mariadb_client && CC=${CC} CXX=${CXX} ${MAKE} mariadbclient
# cd mariadb-client-library/mariadb_client/include && make my_config.h

mariadb_client: mariadb-client-library/mariadb_client/libmariadb/libmariadbclient.a


sqlite3/sqlite3/sqlite3.o:
	cd sqlite3 && rm -rf sqlite-amalgamation-3190200
	cd sqlite3 && tar -zxf sqlite-amalgamation-3190200.tar.gz
	cd sqlite3/sqlite3 && patch sqlite3.c < ../from_unixtime.patch
	cd sqlite3/sqlite3 && ${CC} ${MYCFLAGS} -fPIC -c -o sqlite3.o sqlite3.c -DSQLITE_ENABLE_MEMORY_MANAGEMENT -DSQLITE_ENABLE_JSON1 -DSQLITE_DLL=1
	cd sqlite3/sqlite3 && ${CC} -shared -o libsqlite3.so sqlite3.o

sqlite3: sqlite3/sqlite3/sqlite3.o

libconfig/libconfig/lib/.libs/libconfig++.a:
	cd libconfig && rm -rf libconfig-1.7.2
	cd libconfig && tar -zxf libconfig-1.7.2.tar.gz
	cd libconfig/libconfig && ./configure --disable-examples
	cd libconfig/libconfig && CC=${CC} CXX=${CXX} ${MAKE}

libconfig: libconfig/libconfig/lib/.libs/libconfig++.a

prometheus-cpp/prometheus-cpp/lib/libprometheus-cpp-core.a:
	cd prometheus-cpp && rm -rf prometheus-cpp-0.9.0
	cd prometheus-cpp && tar -zxf v0.9.0.tar.gz
	cd prometheus-cpp && tar --strip-components=1 -zxf civetweb-v1.11.tar.gz -C prometheus-cpp/3rdparty/civetweb
	cd prometheus-cpp/prometheus-cpp && patch -p1 < ../serial_exposer.patch
	cd prometheus-cpp/prometheus-cpp && cmake . -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DENABLE_PUSH=OFF
	cd prometheus-cpp/prometheus-cpp && CC=${CC} CXX=${CXX} ${MAKE}

prometheus-cpp: prometheus-cpp/prometheus-cpp/lib/libprometheus-cpp-core.a

re2/re2/obj/libre2.a:
#	cd re2 && rm -rf re2-2018-07-01
	cd re2 && rm -rf re2-2020-07-06
#	cd re2 && tar -zxf re2-20140304.tgz
	cd re2 && tar -zxf re2.tar.gz
#	cd re2/re2 && sed -i -e 's/-O3 -g /-O3 -fPIC /' Makefile
#	cd re2 && patch re2/util/mutex.h < mutex.h.patch
	cd re2/re2 && sed -i -e 's/-O3 /-O3 -DMEMORY_SANITIZER -DRE2_ON_VALGRIND /' Makefile
	cd re2/re2 && CC=${CC} CXX=${CXX} ${MAKE}

re2: re2/re2/obj/libre2.a

pcre/pcre/.libs/libpcre.a:
	cd pcre && rm -rf pcre-8.44
	cd pcre && tar -zxf pcre-8.44.tar.gz
	cd pcre/pcre && ./configure
	cd pcre/pcre && CC=${CC} CXX=${CXX} ${MAKE}
pcre: pcre/pcre/.libs/libpcre.a

cleanpart:
	cd mariadb-client-library && rm -rf mariadb-connector-c-2.3.1
	cd mariadb-client-library && rm -rf mariadb-connector-c-3.0.2-src
	cd mariadb-client-library && rm -rf mariadb-connector-c-3.1.4-src
	cd mariadb-client-library && rm -rf mariadb-connector-c-3.1.9-src
	cd jemalloc && rm -rf jemalloc-4.2.1
	cd sqlite3/sqlite3 && rm -rf *
.PHONY: cleanpart

cleanall:
	cd libinjection && rm -rf libinjection-3.10.0 || true
	cd libhttpserver && rm -rf libhttpserver-master_20191121 || true
	cd libdaemon && rm -rf libdaemon-0.14
	cd jemalloc && rm -rf jemalloc-4.3.1 || true
	cd jemalloc && rm -rf jemalloc-5.2.0 || true
	cd mariadb-client-library && rm -rf mariadb-connector-c-2.3.1
	cd mariadb-client-library && rm -rf mariadb-connector-c-3.0.2-src
	cd mariadb-client-library && rm -rf mariadb-connector-c-3.1.4-src
	cd mariadb-client-library && rm -rf mariadb-connector-c-3.1.9-src
	cd libconfig && rm -rf libconfig-1.4.9
	cd re2 && rm -rf re2-2020-07-06
	cd pcre && rm -rf pcre-8.44
	cd sqlite3/sqlite3 && rm -rf * || true
	cd clickhouse-cpp/clickhouse-cpp && rm -rf * || true
	cd lz4 && rm -rf lz4-1.7.5 || true
	cd libmicrohttpd && rm -f libmicrohttpd || true
	cd libmicrohttpd && rm -rf libmicrohttpd-0.9.55 || true
	cd libmicrohttpd && rm -rf libmicrohttpd-0.9.68 || true
	cd curl && rm -rf curl-7.57.0 || true
	cd libev && rm -rf libev-4.24 || true
	cd libssl && rm -rf openssl-1.1.0h || true
	cd libssl && rm -rf openssl-1.1.1b || true
	cd libssl && rm -rf openssl-1.1.1d || true
	cd libssl && rm -rf openssl-1.1.1g || true
	cd libconfig && rm -rf libconfig-1.7.2 || true
	cd prometheus-cpp && rm -rf prometheus-cpp-0.9.0 || true
.PHONY: cleanall

