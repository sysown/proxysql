#!/bin/make -f

PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

.DEFAULT_GOAL := default

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/common_mk/openssl_flags.mk
include $(PROXYSQL_PATH)/common_mk/openssl_version_check.mk
include $(PROXYSQL_PATH)/common_mk/aws_sdk_cpp_flags.mk


# to compile libmariadb_client with support for valgrind enabled, run:
# export USEVALGRIND=1

ifeq ($(PROXYDEBUG),1)
	MYCFLAGS := -O0
	MYJEOPT := --enable-xmalloc --enable-prof --enable-fill --enable-debug
else
	MYCFLAGS := -O2
	MYJEOPT := --enable-xmalloc --enable-prof
endif
# jemalloc page size must match the runtime system page size.
# Auto-detect from the build system. Override with JE_LG_PAGE env
# var when cross-compiling (e.g. JE_LG_PAGE=16 for 64KB targets).
ifdef JE_LG_PAGE
	MYJEOPT += --with-lg-page=$(JE_LG_PAGE)
else
	JE_PAGE_SIZE := $(shell getconf PAGESIZE 2>/dev/null)
	ifneq ($(JE_PAGE_SIZE),)
		ifeq ($(JE_PAGE_SIZE),8192)
			MYJEOPT += --with-lg-page=13
		else ifeq ($(JE_PAGE_SIZE),16384)
			MYJEOPT += --with-lg-page=14
		else ifeq ($(JE_PAGE_SIZE),32768)
			MYJEOPT += --with-lg-page=15
		else ifeq ($(JE_PAGE_SIZE),65536)
			MYJEOPT += --with-lg-page=16
		endif
	endif
endif


targets :=	check_openssl_version \
			libconfig \
			libdaemon \
			jemalloc \
			mariadb_client \
			re2 \
			sqlite3 \
			pcre \
			lz4 \
			zstd \
			cityhash \
			microhttpd \
			curl \
			ev \
			libhttpserver \
			libinjection \
			prometheus-cpp \
			postgresql \
			libusual \
			libscram \
			parsersql

ifeq ($(UNAME_S),Linux)
	targets += coredumper
endif

ifeq ($(PROXYSQL40),1)
	targets += protobuf
endif

ifeq ($(PROXYSQLCLICKHOUSE),1)
	targets += clickhouse-cpp
endif

ifeq ($(PROXYSQL40),1)
	targets += sqlite-vec
endif

ifeq ($(PROXYSQL40),1)
targets += $(AWS_SDK_CPP_RDS_LIB)
endif

default: $(targets)
.PHONY: default


### deps targets

AWS_SDK_CPP_DRY_RUN := $(if $(filter n%,$(MAKEFLAGS)),1,0)


libinjection/libinjection/src/libinjection.a:
	cd libinjection && rm -rf libinjection-*/ || true
	cd libinjection && tar -zxf libinjection-3.10.0.tar.gz
ifneq ($(CENTOSVER),6)
	cd libinjection/libinjection && patch -p1 < ../update-build-py3.diff
	cd libinjection/libinjection && patch -p1 < ../libinjection_sqli.c.patch
endif
ifeq ($(UNAME_S),Darwin)
	sed -i '' 's/CC=/CC?=/' libinjection/libinjection/src/Makefile
else
	sed -i -e 's/CC=/CC?=/' libinjection/libinjection/src/Makefile
endif
	cd libinjection/libinjection && CC=${CC} CXX=${CXX} ${MAKE}

libinjection: libinjection/libinjection/src/libinjection.a


libhttpserver/libhttpserver/build/src/.libs/libhttpserver.a: libmicrohttpd/libmicrohttpd/src/microhttpd/.libs/libmicrohttpd.a re2/re2/obj/libre2.a
	cd libhttpserver && rm -rf libhttpserver-*/ || true
	cd libhttpserver && tar -zxf libhttpserver-*.tar.gz
	cd libhttpserver/libhttpserver && patch -p1 < ../noexcept.patch
	cd libhttpserver/libhttpserver && patch -p1 < ../re2_regex.patch
	cd libhttpserver/libhttpserver && patch -p1 < ../final_val_post_process.patch
	cd libhttpserver/libhttpserver && patch -p1 < ../empty_uri_log_crash.patch
	cd libhttpserver/libhttpserver && patch -p0 < ../expose_raw_url.patch
	cd libhttpserver/libhttpserver && patch -p0 < ../replace_static_global_strings.patch
ifeq ($(UNAME_S),FreeBSD)
	sed -i -e 's/\/bin\/bash/\/usr\/local\/bin\/bash/' libhttpserver/libhttpserver/bootstrap
endif
	cd libhttpserver/libhttpserver && ./bootstrap && mkdir build
	cd libhttpserver/libhttpserver/build && LDFLAGS=-L$(shell pwd)/libmicrohttpd/libmicrohttpd/src/microhttpd/.libs/ CPPFLAGS=-I$(shell pwd)/libmicrohttpd/libmicrohttpd/src/include ../configure --disable-doxygen-doc --disable-doxygen-dot --disable-doxygen-man --disable-doxygen-html --enable-fastopen=false --disable-examples
	cd libhttpserver/libhttpserver/build && CC=${CC} CXX=${CXX} ${MAKE}

libhttpserver: libhttpserver/libhttpserver/build/src/.libs/libhttpserver.a


libev/libev/.libs/libev.a:
	cd libev && rm -rf libev-*/ || true
	cd libev && tar -zxf libev-*.tar.gz
	cd libev/libev && patch ev.c < ../ev.c-multiplication-overflow.patch
	cd libev/libev && ./configure
	cd libev/libev && CC=${CC} CXX=${CXX} ${MAKE}

ev: libev/libev/.libs/libev.a


coredumper/coredumper/src/libcoredumper.a:
	cd coredumper && rm -rf coredumper-*/ || true
	cd coredumper && tar -zxf coredumper-*.tar.gz
	cd coredumper/coredumper && cmake . -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Debug -DCMAKE_POLICY_VERSION_MINIMUM=3.5
	cd coredumper/coredumper && CC=${CC} CXX=${CXX} ${MAKE}

coredumper: coredumper/coredumper/src/libcoredumper.a


curl/curl/lib/.libs/libcurl.a:
	cd curl && rm -rf curl-*/ || true
	cd curl && tar -zxf curl-*.tar.gz
	cd curl/curl && autoreconf -fi
ifeq ($(UNAME_S),Darwin)
	cd curl/curl && sed -i '' 's/as_fn_error \$$? "one or more libs available at link-time are not available run-time/echo "Skipped check: one or more libs available at link-time are not available run-time/' configure
	cd curl/curl && CPPFLAGS="-I$(SSL_IDIR)" LDFLAGS="$(LIB_SSL_PATH) $(LIB_CRYPTO_PATH)" DYLD_LIBRARY_PATH="$(SSL_LDIR):$$DYLD_LIBRARY_PATH" ./configure --disable-debug --disable-ftp --disable-ldap --disable-ldaps --disable-rtsp --disable-proxy --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp --disable-gopher --disable-manual --disable-ipv6 --disable-sspi --disable-ntlm-wb --disable-tls-srp --without-nghttp2 --without-libidn2 --without-libssh2 --without-brotli --without-librtmp --without-libpsl --without-zstd --with-ssl --enable-shared=yes
else
	cd curl/curl && CPPFLAGS="-I$(SSL_IDIR)" LDFLAGS="$(LIB_SSL_PATH) $(LIB_CRYPTO_PATH)" ./configure --disable-debug --disable-ftp --disable-ldap --disable-ldaps --disable-rtsp --disable-proxy --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp --disable-gopher --disable-manual --disable-ipv6 --disable-sspi --disable-ntlm-wb --disable-tls-srp --without-nghttp2 --without-libidn2 --without-libssh2 --without-brotli --without-librtmp --without-libpsl --without-zstd --with-ssl --enable-shared=yes
endif
	cd curl/curl && CFLAGS=-fPIC CC=${CC} CXX=${CXX} ${MAKE}

curl: curl/curl/lib/.libs/libcurl.a


libmicrohttpd/libmicrohttpd/src/microhttpd/.libs/libmicrohttpd.a:
	cd libmicrohttpd && rm -rf libmicrohttpd-*/ || true
	cd libmicrohttpd && tar -zxf libmicrohttpd-*.tar.gz
	cd libmicrohttpd/libmicrohttpd && ./configure --enable-https && CC=${CC} CXX=${CXX} ${MAKE}

microhttpd: libmicrohttpd/libmicrohttpd/src/microhttpd/.libs/libmicrohttpd.a


cityhash/cityhash/src/.libs/libcityhash.a:
	cd cityhash && rm -rf cityhash-*/ || true
	cd cityhash && tar -zxf cityhash-*.tar.gz
	cd cityhash/cityhash && cp ../config.guess . && chmod +x config.guess && cp ../config.sub . && chmod +x config.sub
	cd cityhash/cityhash && ./configure && CC=${CC} CXX=${CXX} ${MAKE}

cityhash: cityhash/cityhash/src/.libs/libcityhash.a


lz4/lz4/lib/liblz4.a:
	cd lz4 && rm -rf lz4-*/ || true
	cd lz4 && tar -zxf lz4-*.tar.gz
	cd lz4/lz4 && CC=${CC} CXX=${CXX} ${MAKE} MOREFLAGS=-fPIC

lz4: lz4/lz4/lib/liblz4.a


# zstd - Zstandard compression library
# Used for compressed protocol support in MySQL/PostgreSQL connections
# Source: https://github.com/facebook/zstd
zstd/zstd/lib/libzstd.a:
	cd zstd && rm -rf zstd-*/ || true
	cd zstd && tar -zxf zstd-*.tar.gz
	cd zstd/zstd/lib && CC=${CC} CXX=${CXX} ${MAKE} MOREFLAGS=-fPIC libzstd.a

zstd: zstd/zstd/lib/libzstd.a


PROTOBUF_VERSION := 3.21.12
PROTOBUF_SRC_DIR := $(PROXYSQL_PATH)/deps/protobuf/protobuf-$(PROTOBUF_VERSION)
PROTOBUF_INSTALL_DIR := $(PROTOBUF_SRC_DIR)/install
PROTOBUF_LIB := $(PROTOBUF_INSTALL_DIR)/lib/libprotobuf.a

$(PROTOBUF_LIB):
	cd protobuf && rm -rf protobuf-*/ || true
	cd protobuf && tar -zxf protobuf-$(PROTOBUF_VERSION).tar.gz
	cd protobuf/protobuf-$(PROTOBUF_VERSION) && CC=${CC} CXX=${CXX} cmake -S . -B build \
		-DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DCMAKE_INSTALL_PREFIX=$(PROTOBUF_INSTALL_DIR) \
		-DCMAKE_INSTALL_LIBDIR=lib \
		-DCMAKE_POSITION_INDEPENDENT_CODE=ON \
		-Dprotobuf_BUILD_TESTS=OFF \
		-Dprotobuf_BUILD_CONFORMANCE=OFF \
		-Dprotobuf_BUILD_EXAMPLES=OFF \
		-Dprotobuf_BUILD_PROTOC_BINARIES=OFF \
		-Dprotobuf_BUILD_LIBPROTOC=OFF \
		-Dprotobuf_BUILD_SHARED_LIBS=OFF \
		-Dprotobuf_WITH_ZLIB=OFF
	cd protobuf/protobuf-$(PROTOBUF_VERSION) && CC=${CC} CXX=${CXX} ${MAKE} -C build install

protobuf: $(PROTOBUF_LIB)


$(AWS_SDK_CPP_IDENTITY_STAMP):
	mkdir -p "$(AWS_SDK_CPP_IDENTITY_DIR)"
	touch "$@"


$(AWS_SDK_CPP_RDS_LIB): $(AWS_SDK_CPP_ARCHIVE_PATH) $(AWS_SDK_CPP_CURL_LIB) \
		$(AWS_SDK_CPP_BUNDLE_DIR)/aws-sdk-cpp-$(AWS_SDK_CPP_VERSION)-with-crt.sha256 \
		$(AWS_SDK_CPP_BUNDLE_DIR)/aws-sdk-cpp-$(AWS_SDK_CPP_VERSION)-sources.json \
		$(AWS_SDK_CPP_BUNDLE_DIR)/build-sdk.cmake \
		$(AWS_SDK_CPP_IDENTITY_STAMP)
	cmake \
		-DAWS_BUNDLE_DIR="$(AWS_SDK_CPP_BUNDLE_DIR)" \
		-DAWS_ARCHIVE="$(AWS_SDK_CPP_ARCHIVE_PATH)" \
		-DAWS_SOURCE_DIR="$(AWS_SDK_CPP_SOURCE_DIR)" \
		-DAWS_BUILD_DIR="$(AWS_SDK_CPP_BUILD_DIR)" \
		-DAWS_INSTALL_DIR="$(AWS_SDK_CPP_INSTALL_DIR)" \
		-DAWS_RDS_LIB="$(AWS_SDK_CPP_RDS_LIB)" \
		-DAWS_CORE_LIB="$(AWS_SDK_CPP_CORE_LIB)" \
		-DAWS_CURL_INCLUDE_DIR="$(AWS_SDK_CPP_CURL_INCLUDE_DIR)" \
		-DAWS_CURL_LIBRARY="$(AWS_SDK_CPP_CURL_LIB)" \
		-DAWS_IDENTITY="$(AWS_SDK_CPP_INPUT_ID)" \
		-DAWS_LOCK_FILE="$(AWS_SDK_CPP_BUNDLE_DIR)/.build.lock" \
		-DAWS_DRY_RUN="$(AWS_SDK_CPP_DRY_RUN)" \
		-DAWS_CC="$(CC)" -DAWS_CXX="$(CXX)" -DAWS_MAKE_COMMAND="$(MAKE)" \
		-P "$(AWS_SDK_CPP_BUNDLE_DIR)/build-sdk.cmake"

.PHONY: aws_sdk_cpp_clean
aws_sdk_cpp_clean:
	rm -rf "$(AWS_SDK_CPP_SOURCE_DIR)"
	rm -rf "$(AWS_SDK_CPP_IDENTITY_DIR)"
	rm -f "$(AWS_SDK_CPP_BUNDLE_DIR)/.build.lock"


clickhouse-cpp/clickhouse-cpp/clickhouse/libclickhouse-cpp-lib.a:
	cd clickhouse-cpp && rm -rf clickhouse-cpp-*/ || true
	cd clickhouse-cpp && tar -zxf clickhouse-cpp-*.tar.gz
	cd clickhouse-cpp/clickhouse-cpp && cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo .
	cd clickhouse-cpp/clickhouse-cpp && CC=${CC} CXX=${CXX} ${MAKE}

clickhouse-cpp: clickhouse-cpp/clickhouse-cpp/clickhouse/libclickhouse-cpp-lib.a


libdaemon/libdaemon/libdaemon/.libs/libdaemon.a:
	cd libdaemon && rm -rf libdaemon-*/ || true
	cd libdaemon && tar -zxf libdaemon-0.14.tar.gz
	cd libdaemon/libdaemon && patch -p0 < ../daemon_fork_umask.patch
	cd libdaemon/libdaemon && cp ../config.guess . && chmod +x config.guess && cp ../config.sub . && chmod +x config.sub && ./configure --disable-examples
	cd libdaemon/libdaemon && CC=${CC} CXX=${CXX} ${MAKE}

libdaemon: libdaemon/libdaemon/libdaemon/.libs/libdaemon.a


jemalloc/jemalloc/lib/libjemalloc.a:
	cd jemalloc && rm -rf jemalloc-*/ || true
	cd jemalloc && tar --no-same-owner -jxf jemalloc-5.2.0.tar.bz2
	cd jemalloc/jemalloc && patch src/jemalloc.c < ../issue823.520.patch
	cd jemalloc/jemalloc && patch src/jemalloc.c < ../issue2358.patch
	cd jemalloc/jemalloc && patch -p0 < ../nothrow.patch
	cd jemalloc/jemalloc && patch src/jemalloc_cpp.cpp < ../throw-bad-alloc.patch
	cd jemalloc/jemalloc && ./configure ${MYJEOPT}
#	cd jemalloc/jemalloc && sed -i -e 's/-O3 /-O3 -fPIC /' Makefile
	cd jemalloc/jemalloc && CC=${CC} CXX=${CXX} ${MAKE}

jemalloc: jemalloc/jemalloc/lib/libjemalloc.a


mariadb-client-library/mariadb_client/libmariadb/libmariadbclient.a:
	cd mariadb-client-library && rm -rf mariadb-connector-c-*/ || true
	cd mariadb-client-library && tar -zxf mariadb-connector-c-3.3.8-src.tar.gz
	cd mariadb-client-library/mariadb_client && patch -p0 < ../plugin_auth_CMakeLists.txt.patch
ifeq ($(UNAME_S),Darwin)
	cd mariadb-client-library/mariadb_client && patch -p0 < ../zutil.c.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../zutil.h.patch
endif
ifeq ($(UNAME_S),Darwin)
	cd mariadb-client-library/mariadb_client && cmake . -Wno-dev -DCMAKE_BUILD_TYPE=RelWithDebInfo -DOPENSSL_ROOT_DIR=$(SSL_IDIR) -DOPENSSL_LIBRARIES=$(SSL_LDIR) -DICONV_LIBRARIES=$$(brew --prefix libiconv)/lib -DICONV_INCLUDE=$$(brew --prefix libiconv)/include -DCMAKE_POLICY_VERSION_MINIMUM=3.5 .
else
	cd mariadb-client-library/mariadb_client && cmake . -Wno-dev -DCMAKE_BUILD_TYPE=RelWithDebInfo -DOPENSSL_ROOT_DIR=$(SSL_IDIR) -DOPENSSL_LIBRARIES=$(SSL_LDIR) -DCMAKE_POLICY_VERSION_MINIMUM=3.5 .
endif
ifneq ($(UNAME_S),Darwin)
ifeq ($(PROXYDEBUG),1)
	cd mariadb-client-library/mariadb_client && patch -p0 < ../ma_context.h.patch
else ifeq ($(USEVALGRIND),1)
	cd mariadb-client-library/mariadb_client && patch -p0 < ../ma_context.h.patch
endif
endif
	cd mariadb-client-library/mariadb_client && patch -p0 < ../mariadb_stmt.c.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../mariadb_lib.c.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../mariadb_lib.c.collation.patch # make sure this path is applied after mariadb_lib.c.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../mariadb_lib.c.ipv6_fix.patch # make sure this patch is applied after mariadb_lib.c.collation.patch
#	cd mariadb-client-library/mariadb_client && patch libmariadb/net.c < ../net.c.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../mariadb_async.c.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../ma_password.c.patch
#	cd mariadb-client-library/mariadb_client && patch libmariadb/ma_secure.c < ../ma_secure.c.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../mysql.h.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../tls_server_name.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../ma_priv.h.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../ma_alloc.c.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../ma_charset.c.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../unittest_basic-t.c.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../unittest_charset.c.patch
ifeq ($(WITHASAN),1)
	cd mariadb-client-library/mariadb_client && patch -p0 < ../mariadb_asan.patch
endif
	cd mariadb-client-library/mariadb_client && patch -p0 < ../mariadb_dyncol.c-multiplication-overflow.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../ma_array.c-multiplication-overflow.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../zutil.c-multiplication-overflow.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../cr_new_stmt_metadata_removal.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../ps_buffer_stmt_read_all_rows.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../mariadb_stmt_store_result_err.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../empty_split_compress_packet.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../sslkeylogfile.patch
	#cd mariadb-client-library/mariadb_client && patch libmariadb/ma_pvio.c < ../ma_pvio.c.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../client_deprecate_eof.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../mariadb_com.h.patch
	# patches for x509 cache . See https://github.com/sysown/proxysql/issues/4117 (Slow connection time with SSL and large CA file , relevant on Aurora)
	cd mariadb-client-library/mariadb_client && patch -p0 < ../x509cache.patch
	# patches for replication testing
	cd mariadb-client-library/mariadb_client && patch -p0 < ../mariadb_rpl.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../cmakelists.txt.patch
	cd mariadb-client-library/mariadb_client && patch -p0 < ../mariadb_lib.c.metadata_column_check.patch
	# new compilers fix
	cd mariadb-client-library/mariadb_client && patch -p0 < ../bool_keyword.patch

	cd mariadb-client-library/mariadb_client && CC=${CC} CXX=${CXX} ${MAKE} mariadbclient VERBOSE=1
#	cd mariadb-client-library/mariadb_client/include && make my_config.h

mariadb_client: mariadb-client-library/mariadb_client/libmariadb/libmariadbclient.a


# NOTE: When running Valgrind on ProxySQL, remove -DSQLITE_ENABLE_MEMORY_MANAGEMENT
# to avoid false positives in SQLite's internal memory allocator (pcache*, memjrnl*, etc.)
sqlite3/sqlite3/sqlite3.o:
	cd sqlite3 && rm -rf sqlite-amalgamation-*/ || true
	cd sqlite3 && tar -zxf sqlite-amalgamation-*.tar.gz
	cd sqlite3/sqlite3 && patch -p0 < ../from_unixtime.patch
	cd sqlite3/sqlite3 && patch -p0 < ../sqlite3_pass_exts.patch
	cd sqlite3/sqlite3 && patch -p0 < ../throw.patch
	cd sqlite3/sqlite3 && ${CC} ${MYCFLAGS} -fPIC -c -o sqlite3.o sqlite3.c -DSQLITE_ENABLE_MEMORY_MANAGEMENT -DSQLITE_ENABLE_JSON1 -DSQLITE_ENABLE_FTS5 -DSQLITE_DLL=1 -DSQLITE_ENABLE_MATH_FUNCTIONS
ifeq ($(UNAME_S),Darwin)
	cd sqlite3/sqlite3 && ${CC} -dynamiclib -undefined dynamic_lookup -install_name @rpath/libsqlite3.so -o libsqlite3.so sqlite3.o
else
	cd sqlite3/sqlite3 && ${CC} -shared -o libsqlite3.so sqlite3.o
endif

sqlite3/sqlite3/vec.o: sqlite3/sqlite3/sqlite3.o
	cd sqlite3/sqlite3 && cp ../sqlite-vec-source/sqlite-vec.c . && cp ../sqlite-vec-source/sqlite-vec.h .
	cd sqlite3/sqlite3 && ${CC} ${MYCFLAGS} -fPIC -c -o vec.o sqlite-vec.c -DSQLITE_CORE -DSQLITE_VEC_STATIC -DSQLITE_ENABLE_MEMORY_MANAGEMENT -DSQLITE_ENABLE_JSON1 -DSQLITE_ENABLE_FTS5 -DSQLITE_DLL=1

ifeq ($(PROXYSQL40),1)
sqlite3: sqlite3/sqlite3/sqlite3.o sqlite3/sqlite3/vec.o
else
sqlite3: sqlite3/sqlite3/sqlite3.o
endif

# sqlite-vec: Vector similarity search extension (for GenAI)
sqlite-vec: sqlite3/sqlite3/vec.o


libconfig/libconfig/out/libconfig++.a:
	cd libconfig && rm -rf libconfig-*/ || true
	cd libconfig && tar -zxf libconfig-*.tar.gz
	cd libconfig/libconfig && patch -p1 < ../restore_unknown_escape_passthrough.patch
	cd libconfig/libconfig && cmake -DBUILD_SHARED_LIBS=0 -DBUILD_EXAMPLES=0 -DBUILD_TESTS=0 -DBUILD_FUZZERS=0 .
	cd libconfig/libconfig && CC=${CC} CXX=${CXX} ${MAKE}

libconfig: libconfig/libconfig/out/libconfig++.a


prometheus-cpp/prometheus-cpp/lib/libprometheus-cpp-core.a:
	cd prometheus-cpp && rm -rf prometheus-cpp-*/ || true
	cd prometheus-cpp && tar -zxf prometheus-cpp-*.tar.gz
	cd prometheus-cpp && tar --strip-components=1 -zxf civetweb-*.tar.gz -C prometheus-cpp/3rdparty/civetweb
	cd prometheus-cpp/prometheus-cpp && patch -p1 < ../serial_exposer.patch
	cd prometheus-cpp/prometheus-cpp && patch -p1 < ../registry_counters_reset.patch
	cd prometheus-cpp/prometheus-cpp && patch -p1 < ../fix_old_distros.patch
	cd prometheus-cpp/prometheus-cpp && cmake . -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DENABLE_PUSH=OFF
	cd prometheus-cpp/prometheus-cpp && CC=${CC} CXX=${CXX} ${MAKE}

prometheus-cpp: prometheus-cpp/prometheus-cpp/lib/libprometheus-cpp-core.a


re2/re2/obj/libre2.a:
	cd re2 && rm -rf re2-*/ || true
	cd re2 && tar -zxf re2-*.tar.gz
#	cd re2/re2 && sed -i -e 's/-O3 -g /-O3 -fPIC /' Makefile
#	cd re2/re2 && patch util/mutex.h < ../mutex.h.patch
	cd re2/re2 && patch re2/onepass.cc < ../onepass.cc-multiplication-overflow.patch
ifeq ($(UNAME_S),Darwin)
	cd re2/re2 && sed -i '' -e 's/-O3 -g/-O3 -g -${STDCPP} -fPIC -DMEMORY_SANITIZER -DRE2_ON_VALGRIND /' Makefile
#	cd re2/re2 && sed -i '' -e 's/RE2_CXXFLAGS?=-std=c++11 /RE2_CXXFLAGS?=-std=c++11 -fPIC /' Makefile
else
	cd re2/re2 && sed -i -e 's/-O3 -g/-O3 -g ${STDCPP} -fPIC -DMEMORY_SANITIZER -DRE2_ON_VALGRIND /' Makefile
#	cd re2/re2 && sed -i -e 's/RE2_CXXFLAGS?=-std=c++11 /RE2_CXXFLAGS?=-std=c++11 -fPIC /' Makefile
endif
	cd re2/re2 && CC=${CC} CXX=${CXX} ${MAKE}

re2: re2/re2/obj/libre2.a


pcre/pcre/.libs/libpcre.a:
	cd pcre && rm -rf pcre-*/ || true
	cd pcre && tar -zxf pcre-*.tar.gz
	cd pcre/pcre && patch pcretest.c < ../pcretest.c-multiplication-overflow.patch
	cd pcre/pcre && ./configure
	cd pcre/pcre && CC=${CC} CXX=${CXX} ${MAKE}

pcre: pcre/pcre/.libs/libpcre.a
postgresql/postgresql/src/interfaces/libpq/libpq.a:
	cd postgresql && rm -rf postgresql-*/ || true
	cd postgresql && tar -zxf postgresql-*.tar.gz
	cd postgresql/postgresql && patch -p0 < ../get_result_from_pgconn.patch
	cd postgresql/postgresql && patch -p0 < ../handle_row_data.patch
	cd postgresql/postgresql && patch -p0 < ../fmt_err_msg.patch
	cd postgresql/postgresql && patch -p0 < ../bind_fmt_text.patch
	cd postgresql/postgresql && patch -p0 < ../pqsendpipelinesync.patch
	cd postgresql/postgresql && patch -p0 < ../sslkeylogfile.patch
ifeq ($(UNAME_S),Darwin)
	cd postgresql/postgresql && LDFLAGS="-L$$(brew --prefix icu4c)/lib" CPPFLAGS="-I$$(brew --prefix icu4c)/include" PKG_CONFIG_PATH="$$(brew --prefix icu4c)/lib/pkgconfig:$$PKG_CONFIG_PATH" DYLD_LIBRARY_PATH="$(SSL_LDIR):$$DYLD_LIBRARY_PATH" ./configure --with-ssl=openssl --with-includes="$(SSL_IDIR)" --with-libraries="$(SSL_LDIR)" --without-readline --with-icu
else
	cd postgresql/postgresql && LD_LIBRARY_PATH="$(SSL_LDIR)" ./configure --with-ssl=openssl --with-includes="$(SSL_IDIR)" --with-libraries="$(SSL_LDIR)" --without-readline
endif
	cd postgresql/postgresql/src/interfaces/libpq && CC=${CC} CXX=${CXX} ${MAKE} MAKELEVEL=0

postgresql: postgresql/postgresql/src/interfaces/libpq/libpq.a


libusual/libusual/.libs/libusual.a:
	cd libusual && rm -rf libusual-*/ || true
	cd libusual && tar -zxf libusual-*.tar.gz
	cd libusual/libusual && ./autogen.sh
ifeq ($(UNAME_S),Darwin)
	cd libusual/libusual &&  CPPFLAGS="-I$(SSL_IDIR)" LDFLAGS="$(LIB_SSL_PATH) $(LIB_CRYPTO_PATH)" DYLD_LIBRARY_PATH="$(SSL_LDIR):$$DYLD_LIBRARY_PATH" ./configure --with-openssl="$(patsubst %/include,%,$(SSL_IDIR))" --disable-shared
else
	cd libusual/libusual &&  CPPFLAGS="-I$(SSL_IDIR)" LDFLAGS="$(LIB_SSL_PATH) $(LIB_CRYPTO_PATH)" ./configure --with-openssl="$(SSL_LDIR)" --disable-shared
endif
	cd libusual/libusual && CC=${CC} CXX=${CXX} ${MAKE}

libusual: libusual/libusual/.libs/libusual.a


libscram/lib/libscram.a:postgresql/postgresql/src/interfaces/libpq/libpq.a
	cd libscram && rm -rf lib/* || true
	cd libscram && CC=${CC} CXX=${CXX} ${MAKE} LIBOPENSSL_DIR="$(SSL_IDIR)" POSTGRESQL_DIR="$(shell pwd)/postgresql/postgresql/"

libscram: libscram/lib/libscram.a


parsersql/parsersql/libsqlparser.a:
	cd parsersql && rm -rf parsersql-*/ ParserSQL-*/ || true
	cd parsersql && tar -zxf parsersql-*.tar.gz
	cd parsersql && for d in ParserSQL-*/; do [ -d "$$d" ] && mv "$$d" "parsersql-$${d#ParserSQL-}"; done || true
	cd parsersql/parsersql && CC=${CC} CXX=${CXX} ${MAKE} lib

parsersql: parsersql/parsersql/libsqlparser.a


### clean targets

cleanpart:
	cd mariadb-client-library && rm -rf mariadb-connector-c-*/ || true
	cd jemalloc && rm -rf jemalloc-*/ || true
	cd sqlite3 && rm -rf sqlite-amalgamation-*/ || true
	cd postgresql && rm -rf postgresql-*/ || true
	cd postgresql && rm -rf postgres-*/ || true
	cd protobuf && rm -rf protobuf-*/ || true
.PHONY: cleanpart

cleanall: aws_sdk_cpp_clean
	cd libinjection && rm -rf libinjection-*/ || true
	cd libhttpserver && rm -rf libhttpserver-*/ || true
	cd libdaemon && rm -rf libdaemon-*/ || true
	cd jemalloc && rm -rf jemalloc-*/ || true
	cd mariadb-client-library && rm -rf mariadb-connector-c-*/ || true
	cd libconfig && rm -rf libconfig-*/ || true
	cd re2 && rm -rf re2-*/ || true
	cd pcre && rm -rf pcre-*/ || true
	cd sqlite3 && rm -rf sqlite-amalgamation-*/ || true
	cd clickhouse-cpp/ && rm -rf clickhouse-cpp-*/ || true
	cd lz4 && rm -rf lz4-*/ || true
	cd libmicrohttpd && rm -rf libmicrohttpd-*/ || true
	cd curl && rm -rf curl-*/ || true
	cd libev && rm -rf libev-*/ || true
	cd libconfig && rm -rf libconfig-*/ || true
	cd prometheus-cpp && rm -rf prometheus-cpp-*/ || true
	cd cityhash && rm -rf cityhash-*/ || true
	cd coredumper && rm -rf coredumper-*/ || true
	cd postgresql && rm -rf postgresql-*/ || true
	cd postgresql && rm -rf postgres-*/ || true
	cd libusual && rm -rf libusual-*/ || true
	cd libscram && rm -rf lib/* obj/* || true
	cd json && rm -rf json-*/ || true
	cd protobuf && rm -rf protobuf-*/ || true
	cd zstd && rm -rf zstd-*/ || true
	cd parsersql && rm -rf parsersql-*/ ParserSQL-*/ || true
.PHONY: cleanall
