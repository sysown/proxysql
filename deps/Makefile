

default: libconfig libdaemon jemalloc mariadb_client re2
.PHONY: default


libdaemon/libdaemon/libdaemon/.libs/libdaemon.a: 
	cd libdaemon && rm -rf libdaemon-0.14
	cd libdaemon && tar -zxf libdaemon-0.14.tar.gz
	cd libdaemon/libdaemon && ./configure
	cd libdaemon/libdaemon && make

libdaemon: libdaemon/libdaemon/libdaemon/.libs/libdaemon.a



jemalloc/jemalloc/lib/libjemalloc.a:
	cd jemalloc && rm -rf jemalloc-3.6.0
	cd jemalloc && tar -jxf jemalloc-3.6.0.tar.bz2
	cd jemalloc/jemalloc && ./configure --enable-xmalloc
	cd jemalloc/jemalloc && make

jemalloc: jemalloc/jemalloc/lib/libjemalloc.a



mariadb-client-library/mariadb_client/include/my_global.h:
	cd mariadb-client-library && rm -rf mariadb_client-2.0.0-src
	cd mariadb-client-library && tar -zxf mariadb_client-2.0.0-src.tar.gz
	cd mariadb-client-library/mariadb_client && cmake .
#	cd mariadb-client-library/mariadb_client && make 
	cd mariadb-client-library/mariadb_client/include && make my_config.h

mariadb_client: mariadb-client-library/mariadb_client/include/my_global.h



#sqlite3/sqlite3/sqlite3.o:
#	cd sqlite3 && rm -rf sqlite-amalgamation-3080403
#	cd sqlite3 && unzip sqlite-amalgamation-3080403.zip
#	cd sqlite3/sqlite3 && cc -O2 -c -o sqlite3.o sqlite3.c
#
#sqlite3: sqlite3/sqlite3/sqlite3.o


libconfig/libconfig/lib/.libs/libconfig++.a:
	cd libconfig && rm -rf libconfig-1.4.9
	cd libconfig && tar -zxf libconfig-1.4.9.tar.gz
	cd libconfig/libconfig && ./configure
	cd libconfig/libconfig && make

libconfig: libconfig/libconfig/lib/.libs/libconfig++.a


re2/re2/obj/libre2.a:
	cd re2 && rm -rf re2
	cd re2 && tar -zxf re2-20140304.tgz
	cd re2/re2 && sed -i -e 's/-O3 -g /-O3 -fPIC /' Makefile
	cd re2 && patch re2/util/mutex.h < mutex.h.patch
	cd re2/re2 && make

re2: re2/re2/obj/libre2.a

cleanall:
	cd libdaemon && rm -rf libdaemon-0.14
	cd memcached && rm -rf memcached-1.4.20
	cd jemalloc && rm -rf jemalloc-3.6.0
	cd mariadb-client-library && rm -rf mariadb_client-2.0.0-src
	cd libconfig && rm -rf libconfig-1.4.9
	cd re2 && rm -rf re2
#	cd glib && rm -rf glib-2.40.0
#	cd libevent && rm -rf libevent-2.0.21-stable
#	cd sqlite3 && rm -rf sqlite-amalgamation-3080403
.PHONY: cleanall

