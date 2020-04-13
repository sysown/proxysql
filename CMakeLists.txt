cmake_minimum_required(VERSION 3.10)

# set the project name
project(proxysql
        VERSION 2.0.11
        DESCRIPTION "High-performance MySQL proxy with a GPL license"
        HOMEPAGE_URL "https://www.proxysql.com")

# Call it using:
# cmake -H. -B _builds
# cmake --build _builds --type Release --parallel 4
#
# More complete example (FreeBSD):
#  cmake -H. -B_builds -DWITH_CLICKHOUSE=OFF -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++

include(ExternalProject)
include(FeatureSummary)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckCXXSourceCompiles)

option(WITH_CLICKHOUSE "Enable building of clickhouse proxy" ON)
add_feature_info(Clickhouse WITH_CLICKHOUSE "Enable building with support for proxying clickhouse.")

option(WITH_JEMALLOC "Enable building using jemalloc" ON)
add_feature_info(jemalloc WITH_JEMALLOC "Enable building with support for jemalloc.")


MESSAGE(STATUS "SYSTEM processor: ${CMAKE_SYSTEM_PROCESSOR}")
SET(CPACK_PACKAGE_VENDOR "sysown")
SET(CPACK_PACKAGE_DESCRIPTION "High-performance MySQL proxy with a GPL license")
SET(CPACK_PACKAGE_NAME "proxysql")
STRING(TOLOWER ${CMAKE_SYSTEM_NAME} system_name)
SET(CPACK_PACKAGE_VERSION ${CMAKE_PROJECT_VERSION})
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
SET(CPACK_SOURCE_PACKAGE_FILE_NAME "proxysql${CPACK_PACKAGE_VERSION}-src")
SET(CPACK_PACKAGE_FILE_NAME "proxysql-${CPACK_PACKAGE_VERSION}-${system_name}-${CMAKE_SYSTEM_PROCESSOR}")
SET(CPACK_PACKAGE_HOMEPAGE_URL https://www.proxysql.com)
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "support@proxysql.com")
SET(CPACK_SOURCE_GENERATOR "DEB RPM")
set(CPACK_RPM_PACKAGE_REQUIRES "python >= 2.5.0, cmake >= 2.8")
set(CPACK_RPM_PACKAGE_REQUIRES_PRE "shadow-utils")
set(CPACK_RPM_PACKAGE_REQUIRES_POST "shadow-utils, initscripts, systemd")
set(CPACK_RPM_PACKAGE_REQUIRES_POSTUN "systemd")
set(CPACK_RPM_PACKAGE_REQUIRES_PREUN "systemd")
set(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/rpm-preinstall.sh")

include(GNUInstallDirs)

set (CMAKE_INSTALL_PREFIX /usr CACHE PATH "" FORCE)
set (CMAKE_INSTALL_SYSCONFDIR /etc CACHE PATH "" FORCE)
set (CMAKE_INSTALL_DATAROOTDIR /usr/share/${CMAKE_PROJECT_NAME} CACHE PATH "" FORCE)

install(PROGRAMS    ${CMAKE_CURRENT_BINARY_DIR}/proxysql
        DESTINATION  ${CMAKE_INSTALL_BINDIR}
)

install(FILES       ${CMAKE_CURRENT_SOURCE_DIR}/src/proxysql.cfg
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
)

# Create empty /var/lib/proxysql
install(DIRECTORY   "lib/proxysql"
        DESTINATION CMAKE_INSTALL_DATADIR)


include(CPack)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_POSITION_INDEPENDENT_CODE True)

set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")
set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -ggdb")

if (CMAKE_BUILD_TYPE STREQUAL "Release")
  set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS_RELEASE})
  set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS_RELEASE})
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS_DEBUG})
  set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS_DEBUG})
endif()


if (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  # cmake -H. -B_builds -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=YES -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON
  # -DWITH_CLICKHOUSE=OFF -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++"
    set(CMAKE_INSTALL_PREFIX "/usr/local")

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
      message(FATAL_ERROR "${CMAKE_PROJECT_NAME} needs GCC for compiling. Please install it and use -DCMAKE_CXX_COMPILER=g++")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
      # if multiple g++ versions are installed, pick the right libraries
      # XXX this is brittle: update for g++7, g++8, ...
      if (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER "8.0.0")
        string(REGEX REPLACE "([0-9]+).*$" "\\1" GCC_COMPILER_VERSION_MAJOR ${CMAKE_CXX_COMPILER_VERSION})
        set (CMAKE_EXE_LINKER_FLAGS "-lstdc++ -lgcc")
        set (CMAKE_EXE_LINKER_FLAGS "-Wl,-rpath=/usr/local/lib/gcc${GCC_COMPILER_VERSION_MAJOR} ${CMAKE_EXE_LINKER_FLAGS}")
      endif()
    else()
      message(FATAL_ERROR "FreeBSD:unknown compiler")
    endif()
endif()

find_program(MAKE_EXE NAMES gmake make nmake)

find_package(Patch)

# For the GIT_STATUS -D
find_package (Git)
if (GIT_FOUND)
  execute_process(COMMAND ${GIT_EXECUTABLE} describe --long
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      RESULT_VARIABLE result
      OUTPUT_VARIABLE repo_git_version
      ERROR_QUIET
      OUTPUT_STRIP_TRAILING_WHITESPACE)

  message(STATUS "Using GITVERSION=${repo_git_version}")
else()
  message(WARNING "No GIT_VERSION will be added to resulting binary.")
  set(repo_git_version "undefined")
endif()

set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION}-${repo_git_version})

find_package(Iconv REQUIRED)
if (Iconv_FOUND)
  message(STATUS "Using Iconv")
endif()

find_package(Backtrace REQUIRED)

if (Backtrace_FOUND)
  configure_file(${PROJECT_SOURCE_DIR}/include/backtrace.h.in ${PROJECT_SOURCE_DIR}/include/backtrace.h)
  message(STATUS "Configuring Backtrace")
else()
  message(WARNING "No Backtrace library found.")
endif()


find_package(ZLIB REQUIRED)

set(THREADS_PREFER_PTHREAD_FLAG True)
find_package(Threads REQUIRED)

add_compile_definitions(GITVERSION="${repo_git_version}")

if (WITH_JEMALLOC)
  add_compile_definitions(JEMALLOC)
endif()


# ifeq ($(wildcard /usr/lib/systemd/system), /usr/lib/systemd/system)
# 	SYSTEMD=1
# else
# 	SYSTEMD=0
# endif

# Require GNU TLS for building the libmicrohttpd library
find_package(GnuTLS REQUIRED)
if(GNUTLS_FOUND)
  message(STATUS "Library 'GnuTLS' found at ${GNUTLS_LIBRARIES}")
else()
  message(FATAL_ERROR "Library 'GnuTLS' not found! Install it vie e.g. 'brew install gnutls' or 'dnf install gnutls-devel'")
endif()

# Libinjection uses python for generating stuff
# code is written in py2 syntax
find_package (Python REQUIRED COMPONENTS Interpreter)

set(LIBINJECTION_PATCH_COMMAND "")

if (Python_VERSION_MAJOR EQUAL "3")
  message(STATUS "Will patch libinjection for python3 support")
  set(LIBINJECTION_PATCH_COMMAND 2to3 -w src/fingerprints2sqli.py src/make_parens.py src/sqlparse2c.py src/sqlparse_map.py)
  set(LIBINJECTION_PATCH_SHEBANG sed -i.bak -e "s:python:python3:g" src/make_parens.py src/sqlparse2c.py src/sqlparse_map.py)
else()
  set(LIBINJECTION_PATCH_COMMAND "echo applying https://patch-diff.githubusercontent.com/raw/client9/libinjection/pull/144.patch")
  set(LIBINJECTION_PATCH_SHEBANG sed -i.bak -e "s:python:python2:g" src/make_parens.py src/sqlparse2c.py src/sqlparse_map.py)
endif()

# Typically you don't care so much for a third party library's tests to be
# run from your own project's code.
set(JSON_BuildTests OFF CACHE INTERNAL "")

# If you only include this third party in PRIVATE source files, you do not
# need to install it when your main project gets installed.
# set(JSON_Install OFF CACHE INTERNAL "")

SET(JSON_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/json)

ExternalProject_Add(libconfig_ext
	PREFIX						deps
  URL               file://${CMAKE_SOURCE_DIR}/deps/libconfig/libconfig-1.7.2.tar.gz
  CONFIGURE_COMMAND ./configure "CFLAGS=${CMAKE_C_FLAGS}" "CXXFLAGS=${CMAKE_CXX_FLAGS}" "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}"
  BUILD_IN_SOURCE 1
  BUILD_COMMAND     ${MAKE_EXE}
  UPDATE_COMMAND ""
  INSTALL_COMMAND ""
)

SET(LIBCONFIG_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libconfig_ext/lib)
SET(LIBCONFIG_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libconfig_ext/lib/.libs)
add_library(libconfig STATIC IMPORTED)
add_library(libconfig++ STATIC IMPORTED)
set_target_properties(libconfig PROPERTIES IMPORTED_LOCATION ${LIBCONFIG_LIB_DIR}/libconfig.a)
set_target_properties(libconfig++ PROPERTIES IMPORTED_LOCATION ${LIBCONFIG_LIB_DIR}/libconfig++.a)

ExternalProject_Add(libdaemon_ext
	PREFIX						deps
  URL               file://${CMAKE_SOURCE_DIR}/deps/libdaemon/libdaemon-0.14.tar.gz
  CONFIGURE_COMMAND  ./configure --disable-examples "CFLAGS=${CMAKE_C_FLAGS}" "CXXFLAGS=${CMAKE_CXX_FLAGS}" CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER}
  BUILD_IN_SOURCE 1
  BUILD_COMMAND     ${MAKE_EXE}
  UPDATE_COMMAND ""
  INSTALL_COMMAND ""
)

SET(LIBDAEMON_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libdaemon_ext)
SET(LIBDAEMON_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libdaemon_ext/libdaemon/.libs)
add_library(libdaemon STATIC IMPORTED)
set_target_properties(libdaemon PROPERTIES IMPORTED_LOCATION ${LIBDAEMON_LIB_DIR}/libdaemon.a)

if (WITH_JEMALLOC)

  ExternalProject_Add(jemalloc_ext
    PREFIX						deps
    URL               file://${CMAKE_SOURCE_DIR}/deps/jemalloc/jemalloc-5.2.0.tar.bz2
    CONFIGURE_COMMAND  ./configure "CFLAGS=${CMAKE_C_FLAGS}" "CXXFLAGS=${CMAKE_CXX_FLAGS}" CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER}
    BUILD_IN_SOURCE 1
    BUILD_COMMAND     ${MAKE_EXE}
    UPDATE_COMMAND ""
    INSTALL_COMMAND ""
    PATCH_COMMAND		${Patch_EXECUTABLE} src/jemalloc.c < ${CMAKE_SOURCE_DIR}/deps/jemalloc/issue823.520.patch
    COMMAND			    ${Patch_EXECUTABLE} src/jemalloc.c < ${CMAKE_SOURCE_DIR}/deps/jemalloc/issue2358.patch
  )

  SET(JEMALLOC_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/jemalloc_ext/include/jemalloc)
  SET(JEMALLOC_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/jemalloc_ext/lib)
  add_library(jemalloc STATIC IMPORTED)
  set_target_properties(jemalloc PROPERTIES IMPORTED_LOCATION ${JEMALLOC_LIB_DIR}/libjemalloc.a)

endif (WITH_JEMALLOC)

if (WITH_CLICKHOUSE)
  ExternalProject_Add(clickhouse-cpp_ext
    PREFIX						deps
    URL               file://${CMAKE_SOURCE_DIR}/deps/clickhouse-cpp/clickhouse-cpp.tar.gz
    CMAKE_ARGS        -DCMAKE_C_FLAGS=${CMAKE_C_CLAGS} -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER} -DCMAKE_BUILD_TYPE=RelWithDebInfo
    BUILD_IN_SOURCE 1
    UPDATE_COMMAND ""
    INSTALL_COMMAND ""
  )

  SET(CLICKHOUSE_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/clickhouse-cpp_ext/clickhouse)
  SET(CLICKHOUSE_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/clickhouse-cpp_ext/clickhouse)
  add_library(clickhouse-cpp STATIC IMPORTED)
  set_target_properties(clickhouse-cpp PROPERTIES IMPORTED_LOCATION ${CLICKHOUSE_LIB_DIR}/libclickhouse-cpp-lib.a)

  ExternalProject_Add(cityhash_ext
    PREFIX						deps
    URL               file://${CMAKE_SOURCE_DIR}/deps/cityhash/cityhash.tar.gz
    CONFIGURE_COMMAND ./configure "CFLAGS=${CMAKE_C_FLAGS}" "CXXFLAGS=${CMAKE_CXX_FLAGS}" "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}"
    BUILD_IN_SOURCE 1
    BUILD_COMMAND     ${MAKE_EXE}
    UPDATE_COMMAND ""
    INSTALL_COMMAND ""
  )

  SET(CITYHASH_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/cityhash_ext/include)
  SET(CITYHASH_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/cityhash_ext/src/.libs)
  add_library(cityhash STATIC IMPORTED)
  set_target_properties(cityhash PROPERTIES IMPORTED_LOCATION ${CITYHASH_LIB_DIR}/libcityhash.a)

  ExternalProject_Add(lz4_ext
    PREFIX						deps
    URL               file://${CMAKE_SOURCE_DIR}/deps/lz4/lz4-1.7.5.tar.gz
    CONFIGURE_COMMAND ""
    BUILD_IN_SOURCE 1
    BUILD_COMMAND     "gmake"
    UPDATE_COMMAND    ""
    INSTALL_COMMAND   ""
    PATCH_COMMAND			""
  )

  SET(LZ4_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/lz4_ext)
  SET(LZ4_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/lz4_ext)
  add_library(lz4 STATIC IMPORTED)
  set_target_properties(lz4 PROPERTIES IMPORTED_LOCATION ${LZ4_LIB_DIR}/liblz4.a)

endif(WITH_CLICKHOUSE)

ExternalProject_Add(libinjection_ext
	PREFIX						deps
  URL               file://${CMAKE_SOURCE_DIR}/deps/libinjection/libinjection-3.10.0.tar.gz
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_COMMAND     ${MAKE_EXE} -C src all
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   ""
  PATCH_COMMAND     ${LIBINJECTION_PATCH_COMMAND}
  COMMAND           ${LIBINJECTION_PATCH_SHEBANG}
)

SET(LIBINJECTION_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libinjection_ext/src)
SET(LIBINJECTION_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libinjection_ext/src/)
add_library(libinjection STATIC IMPORTED)
set_target_properties(libinjection PROPERTIES IMPORTED_LOCATION ${LIBINJECTION_LIB_DIR}/libinjection.a)

ExternalProject_Add(openssl_ext
	PREFIX						deps
  URL               file://${CMAKE_SOURCE_DIR}/deps/libssl/openssl-1.1.1d.tar.gz
  CONFIGURE_COMMAND ./config no-shared threads enable-egd "CFLAGS=${CMAKE_C_FLAGS}" "CXXFLAGS=${CMAKE_CXX_FLAGS}" "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}"
  BUILD_IN_SOURCE 1
  BUILD_COMMAND     ${MAKE_EXE}
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   ""
  PATCH_COMMAND			""
)

SET(OPENSSL_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/openssl_ext)
SET(OPENSSL_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/openssl_ext)
SET(OPENSSL_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/openssl_ext/include)
add_library(ssl STATIC IMPORTED)
set_target_properties(ssl PROPERTIES IMPORTED_LOCATION ${OPENSSL_DIR}/libssl.a)
add_library(crypto STATIC IMPORTED)
set_target_properties(crypto PROPERTIES IMPORTED_LOCATION ${OPENSSL_DIR}/libcrypto.a)

ExternalProject_Add(curl_ext
	PREFIX						deps
  URL               file://${CMAKE_SOURCE_DIR}/deps/curl/curl-7.57.0.tar.gz
  CONFIGURE_COMMAND  ./configure --disable-debug --disable-ftp --disable-ldap  --without-depssh2 --without-brotli --disable-shared --with-ssl=${OPENSSL_DIR}
                      --disable-ldaps --disable-rtsp --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap
                      --disable-smb --disable-smtp --disable-gopher --disable-manual --disable-ipv6 --disable-sspi
                      --disable-crypto-auth --disable-ntlm-wb --disable-tls-srp --without-nghttp2 --without-libidn2
                    "CFLAGS=${CMAKE_C_FLAGS}" "CXXFLAGS=${CMAKE_CXX_FLAGS}" "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}" "LDFLAGS=-L${OPENSSL_LIB_DIR}"
  BUILD_IN_SOURCE 1
  BUILD_COMMAND     ${MAKE_EXE}
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   ""
  PATCH_COMMAND			""
  DEPENDS           openssl_ext
)

SET(CURL_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/curl_ext/lib/.libs)
SET(CURL_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/curl_ext/include)
add_library(curl STATIC IMPORTED)
set_target_properties(curl PROPERTIES IMPORTED_LOCATION ${CURL_LIB_DIR}/libcurl.a)

ExternalProject_Add(libev_ext
	PREFIX						deps
  URL               file://${CMAKE_SOURCE_DIR}/deps/libev/libev-4.24.tar.gz
  CONFIGURE_COMMAND ./configure "CFLAGS=${CMAKE_C_FLAGS}" "CXXFLAGS=${CMAKE_CXX_FLAGS}" "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}"
  BUILD_IN_SOURCE 1
  BUILD_COMMAND     ${MAKE_EXE}
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   ""
  PATCH_COMMAND			""
)

SET(LIBEV_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libev_ext/.libs)
SET(LIBEV_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libev_ext/)
add_library(libev STATIC IMPORTED)
set_target_properties(libev PROPERTIES IMPORTED_LOCATION ${LIBEV_LIB_DIR}/libev.a)

ExternalProject_Add(libre2_ext
	PREFIX						deps
  URL               file://${CMAKE_SOURCE_DIR}/deps/re2/2018-07-01.tar.gz
  BUILD_IN_SOURCE 1
  CMAKE_ARGS        -DCMAKE_C_FLAGS="-O3 -DMEMORY_SANITIZER -DRE2_ON_VALGRIND" -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER} -DRE2_BUILD_TESTING=OFF -DBUILD_TESTING=OFF
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   ""
  PATCH_COMMAND			""
)

SET(LIBRE2_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libre2_ext)
SET(LIBRE2_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libre2_ext)
add_library(libre2 STATIC IMPORTED)
set_target_properties(libre2 PROPERTIES IMPORTED_LOCATION ${LIBRE2_LIB_DIR}/libre2.a)

ExternalProject_Add(libmicrohttpd_ext
	PREFIX						deps
  URL               file://${CMAKE_SOURCE_DIR}/deps/libmicrohttpd/libmicrohttpd-0.9.68.tar.gz
  CONFIGURE_COMMAND ./configure --enable-https "CFLAGS=${CMAKE_C_FLAGS}" "CXXFLAGS=${CMAKE_CXX_FLAGS}" "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}"
  BUILD_IN_SOURCE 1
  BUILD_COMMAND     ${MAKE_EXE}
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   ""
  PATCH_COMMAND			""
)

SET(LIBMICROHTTPD_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libmicrohttpd_ext/src/microhttpd/.libs)
SET(LIBMICROHTTPD_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libmicrohttpd_ext/src/include)
# We need both dirs for the libproxysql
SET(LIBMICROHTTPD_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libmicrohttpd_ext/src/include ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libmicrohttpd_ext)
add_library(microhttpd STATIC IMPORTED)
set_target_properties(microhttpd PROPERTIES IMPORTED_LOCATION ${LIBMICROHTTPD_LIB_DIR}/libmicrohttpd.a)

# Until https://github.com/etr/libhttpserver/pull/192 is merged, and the deps is updated here, we need this one.
if (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  set(libhttpserver_patch_cmd patch -p1 < ${CMAKE_SOURCE_DIR}/deps/libhttpserver/libhttpserver_freebsd.patch)
else()
  set(libhttpserver_patch_cmd "")
endif()

# Note: This project needs GNU make
ExternalProject_Add(libhttpserver_ext
	PREFIX						deps
  URL               file://${CMAKE_SOURCE_DIR}/deps/libhttpserver/libhttpserver-master_20191121.tar.gz
  CONFIGURE_COMMAND rm -rf build && MAKE=${MAKE_EXE} autoreconf -i && mkdir build && cd build && ../configure --enable-static --disable-shared
                        --disable-doxygen-doc --disable-doxygen-dot --disable-doxygen-man --disable-doxygen-html
                        --disable-examples "CFLAGS=${CMAKE_C_FLAGS}" "LD_LIBRARY_PATH=${LIBMICROHTTPD_LIB_DIR}"
			                "CXXFLAGS=${CMAKE_CXX_FLAGS}" "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}"
                      "MAKE=${MAKE_EXE}" "CPPFLAGS=-I${LIBMICROHTTPD_INCLUDE_DIR}" "LIBS=-lmicrohttpd" "LDFLAGS=-L${LIBMICROHTTPD_LIB_DIR}"
  BUILD_IN_SOURCE 1
  BUILD_COMMAND     ${MAKE_EXE} -C build
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   ""
  PATCH_COMMAND			${libhttpserver_patch_cmd}
  DEPENDS           libmicrohttpd_ext
)

SET(LIBHTTPSERVER_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libhttpserver_ext/build/src/.libs)
SET(LIBHTTPSERVER_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/libhttpserver_ext/src)
add_library(httpserver STATIC IMPORTED)
set_target_properties(httpserver PROPERTIES IMPORTED_LOCATION ${LIBHTTPSERVER_LIB_DIR}/libhttpserver.a)
add_dependencies(httpserver libmicrohttpd_ext)

ExternalProject_Add(mariadb-client-library_ext
	PREFIX						deps
  URL               file://${CMAKE_SOURCE_DIR}/deps/mariadb-client-library/mariadb-connector-c-3.1.4-src.tar.gz
  BUILD_IN_SOURCE 1
  CMAKE_ARGS        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
                    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                    -DWITH_UNIT_TESTS="OFF" -DCMAKE_C_FLAGS_RELWITHDEBINFO="-ggdb" -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-ggdb"
                    -DCMAKE_BUILD_TYPE=RelWithDebInfo -DOPENSSL_ROOT_DIR=${OPENSSL_DIR} -DOPENSSL_LIBRARIES=${OPENSSL_LIB_DIR}
                    -DCLIENT_PLUGIN_MYSQL_CLEAR_PASSWORD=STATIC -DCLIENT_PLUGIN_SHA256_PASSWORD=STATIC
                    -DCLIENT_PLUGIN_CACHING_SHA2_PASSWORD=STATIC
  PATCH_COMMAND ${Patch_EXECUTABLE} libmariadb/mariadb_stmt.c < ${CMAKE_SOURCE_DIR}/deps/mariadb-client-library/mariadb_stmt.c.patch
  COMMAND ${Patch_EXECUTABLE} libmariadb/mariadb_lib.c < ${CMAKE_SOURCE_DIR}/deps/mariadb-client-library/mariadb_lib.c.patch
  COMMAND ${Patch_EXECUTABLE} libmariadb/mariadb_async.c < ${CMAKE_SOURCE_DIR}/deps/mariadb-client-library/mariadb_async.c.patch
  COMMAND ${Patch_EXECUTABLE} libmariadb/ma_password.c < ${CMAKE_SOURCE_DIR}/deps/mariadb-client-library/ma_password.c.patch
  COMMAND ${Patch_EXECUTABLE} include/mysql.h < ${CMAKE_SOURCE_DIR}/deps/mariadb-client-library/mysql.h.patch
  COMMAND ${Patch_EXECUTABLE} include/mariadb_com.h < ${CMAKE_SOURCE_DIR}/deps/mariadb-client-library/mariadb_com.h.patch
  COMMAND ${Patch_EXECUTABLE} libmariadb/ma_alloc.c < ${CMAKE_SOURCE_DIR}/deps/mariadb-client-library/ma_alloc.c.patch
  COMMAND ${Patch_EXECUTABLE} libmariadb/ma_charset.c < ${CMAKE_SOURCE_DIR}/deps/mariadb-client-library/ma_charset.c.patch
  COMMAND ${Patch_EXECUTABLE} unittest/libmariadb/basic-t.c < ${CMAKE_SOURCE_DIR}/deps/mariadb-client-library/unittest_basic-t.c.patch
  COMMAND ${Patch_EXECUTABLE} unittest/libmariadb/charset.c < ${CMAKE_SOURCE_DIR}/deps/mariadb-client-library/unittest_charset.c.patch
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   ""
  DEPENDS           openssl_ext
)

SET(MARIADB_CLIENT_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/mariadb-client-library_ext/libmariadb)
SET(MARIADB_CLIENT_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/mariadb-client-library_ext/include)
add_library(mariadbclient STATIC IMPORTED)
set_target_properties(mariadbclient PROPERTIES IMPORTED_LOCATION ${MARIADB_CLIENT_LIB_DIR}/libmariadbclient.a)

ExternalProject_Add(pcre_ext
	PREFIX						deps
  URL               file://${CMAKE_SOURCE_DIR}/deps/pcre/pcre-8.39.tar.gz
  CONFIGURE_COMMAND  ./configure "CFLAGS=${CMAKE_C_FLAGS}" "CXXFLAGS=${CMAKE_CXX_FLAGS}" "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}"
  BUILD_IN_SOURCE 1
  BUILD_COMMAND     ${MAKE_EXE}
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   ""
  PATCH_COMMAND			""
)

SET(PCRE_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/pcre_ext/.libs)
SET(PCRE_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/pcre_ext)
add_library(pcre STATIC IMPORTED)
set_target_properties(pcre PROPERTIES IMPORTED_LOCATION ${PCRE_LIB_DIR}/libpcre.a)
add_library(pcrecpp STATIC IMPORTED)
set_target_properties(pcrecpp PROPERTIES IMPORTED_LOCATION ${PCRE_LIB_DIR}/libpcrecpp.a)

# Needs GnuTLS static library for compiling
# ExternalProject_Add(gnutls_ext
# 	PREFIX						deps
#   URL               https://www.gnupg.org/ftp/gcrypt/gnutls/v3.6/gnutls-3.6.12.tar.xz
#   URL_HASH          SHA1=fa498b4d026e3ddfa74aa79adac27bfcd14e8b76
#   CONFIGURE_COMMAND ./configure
#   BUILD_IN_SOURCE 1
#   BUILD_COMMAND     ${MAKE_EXE}
#   UPDATE_COMMAND    ""
#   INSTALL_COMMAND   ""
#   PATCH_COMMAND			""
# )

# SET(GNUTLS_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/gnutls_ext/.libs)
# SET(GNUTLS_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/gnutls_ext)
# add_library(gnutls STATIC IMPORTED)
# set_target_properties(gnutls PROPERTIES IMPORTED_LOCATION ${GNUTLS_LIB_DIR}/libgnutls.a)


ExternalProject_Add(sqlite3_ext
	PREFIX						deps
  URL               https://www.sqlite.org/2017/sqlite-amalgamation-3190200.zip
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_COMMAND     ${CMAKE_C_COMPILER} -O0 -ggdb -c -o sqlite3.o sqlite3.c -DSQLITE_ENABLE_MEMORY_MANAGEMENT -DSQLITE_ENABLE_JSON1
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   ""
  PATCH_COMMAND			${Patch_EXECUTABLE} -p0 < ${CMAKE_CURRENT_SOURCE_DIR}/deps/sqlite3/from_unixtime.patch
)


SET(SQLITE3_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/sqlite3_ext)
SET(SQLITE3_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/sqlite3_ext)
SET(SQLITE3_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/src/sqlite3_ext)
add_library(sqlite3 STATIC IMPORTED)
set_target_properties(sqlite3 PROPERTIES IMPORTED_LOCATION ${SQLITE3_DIR}/sqlite3.o)

SET(libproxysql_FILES lib/ProxySQL_GloVars.cpp lib/network.cpp lib/debug.cpp lib/configfile.cpp lib/Query_Cache.cpp
            lib/SpookyV2.cpp lib/MySQL_Authentication.cpp lib/gen_utils.cpp lib/sqlite3db.cpp lib/mysql_connection.cpp
            lib/MySQL_HostGroups_Manager.cpp lib/mysql_data_stream.cpp lib/MySQL_Thread.cpp lib/MySQL_Session.cpp lib/MySQL_Protocol.cpp
            lib/mysql_backend.cpp lib/Query_Processor.cpp lib/ProxySQL_Admin.cpp lib/ProxySQL_Config.cpp lib/ProxySQL_Restapi.cpp
            lib/MySQL_Monitor.cpp lib/MySQL_Logger.cpp lib/thread.cpp lib/MySQL_PreparedStatement.cpp lib/ProxySQL_Cluster.cpp
             lib/ProxySQL_Statistics.cpp lib/Chart_bundle_js.cpp
            lib/ProxySQL_HTTP_Server.cpp lib/ProxySQL_RESTAPI_Server.cpp lib/font-awesome.min.css.cpp lib/main-bundle.min.css.cpp
            lib/set_parser.cpp lib/c_tokenizer.c)

SET(libproxysql_DEPS libev_ext openssl_ext libmicrohttpd_ext libconfig_ext libhttpserver_ext
                     libdaemon_ext curl_ext pcre_ext libre2_ext mariadb-client-library_ext
                     libinjection_ext)

SET(libproxysql_LIBS httpserver libev libdaemon curl pcrecpp pcre
    mariadbclient libinjection microhttpd libconfig++ libconfig libre2 ssl crypto)

SET(libproxysql_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/include"
                        "${MARIADB_CLIENT_INCLUDE_DIR}"
                        "${CURL_INCLUDE_DIR}"
                        "${OPENSSL_INCLUDE_DIR}"
                        "${JSON_INCLUDE_DIR}"
                        "${LIBINJECTION_INCLUDE_DIR}"
                        "${LIBCONFIG_INCLUDE_DIR}"
                        "${LIBDAEMON_INCLUDE_DIR}"
                        "${LIBHTTPSERVER_INCLUDE_DIR}"
                        "${LIBMICROHTTPD_INCLUDE_DIRS}"
                        "${LIBRE2_INCLUDE_DIR}"
                        "${PCRE_INCLUDE_DIR}"
                        "${SQLITE3_INCLUDE_DIR}"
                        "${LIBEV_INCLUDE_DIR}")
if (WITH_CLICKHOUSE)
  list(APPEND libproxysql_FILES lib/ClickHouse_Authentication.cpp lib/ClickHouse_Server.cpp)
  list(APPEND libproxysql_DEPS clickhouse-cpp_ext lz4_ext cityhash_ext)
  list(APPEND libproxysql_LIBS clickhouse-cpp lz4 cityhash)
  list(APPEND libproxysql_INCLUDES ${CITIHASH_INCLUDE_DIR} ${CITIHASH_INCLUDE_DIR} ${LZ4_INCLUDE_DIR})
  add_compile_definitions(CLICKHOUSE)
endif()

add_library(libproxysql STATIC ${libproxysql_FILES})


if (WITH_JEMALLOC)
  list(APPEND libproxysql_DEPS jemalloc_ext)
  list(APPEND libproxysql_LIBS jemalloc)
  list(APPEND libproxysql_INCLUDES ${JEMALLOC_INCLUDE_DIR})
endif()

add_dependencies(libproxysql ${libproxysql_DEPS})

target_link_libraries(libproxysql PRIVATE ${libproxysql_LIBS})

target_include_directories(libproxysql PRIVATE ${libproxysql_INCLUDES})

# add the executable
add_executable(proxysql src/main.cpp src/proxysql_global.cpp src/SQLite3_Server.cpp)

SET(proxysql_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/include"
                      "${MARIADB_CLIENT_INCLUDE_DIR}"
                      "${OPENSSL_INCLUDE_DIR}"
                      "${JSON_INCLUDE_DIR}"
                      "${LIBINJECTION_INCLUDE_DIR}"
                      "${LIBCONFIG_INCLUDE_DIR}"
                      "${LIBDAEMON_INCLUDE_DIR}"
                      "${LIBHTTPSERVER_INCLUDE_DIR}"
                      "${LIBMICROHTTPD_INCLUDE_DIRS}"
                      "${LIBRE2_INCLUDE_DIR}"
                      "${PCRE_INCLUDE_DIR}"
                      "${SQLITE3_INCLUDE_DIR}"
                      "${LIBEV_INCLUDE_DIR}"
                      "${CURL_INCLUDE_DIR}"
                      )

set(proxysql_LIBS libproxysql libdaemon pcrecpp pcre
                  mariadbclient httpserver microhttpd
                  libconfig libconfig++ libinjection
                  curl libev libre2 sqlite3 ssl crypto)

if (WITH_JEMALLOC)
  list(APPEND proxysql_DEPS jemalloc_ext)
  list(APPEND proxysql_LIBS jemalloc)
  list(APPEND proxysql_INCLUDES ${JEMALLOC_INCLUDE_DIR})
endif()


target_include_directories(proxysql PRIVATE ${proxysql_INCLUDES})

add_dependencies(proxysql openssl_ext libev_ext libmicrohttpd_ext libhttpserver_ext libdaemon_ext 
                          libconfig_ext curl_ext pcre_ext libre2_ext mariadb-client-library_ext sqlite3_ext)

target_compile_features(proxysql PRIVATE cxx_std_11)

target_link_libraries(proxysql PUBLIC "-Wl,--no-whole-archive"
			 "-Wl,--start-group"
       ${proxysql_LIBS}
			 "-Wl,--end-group"
       ${Backtrace_LIBRARIES} GnuTLS::GnuTLS ZLIB::ZLIB dl Threads::Threads -lm -lrt )

if(PRINT_SUMMARY)
    # This will print ENABLED, REQUIRED and DISABLED
    feature_summary(WHAT ALL)
else()
    # This will only print ENABLED and DISABLED feature
    feature_summary(WHAT ENABLED_FEATURES DESCRIPTION "Enabled features:")
    feature_summary(WHAT DISABLED_FEATURES DESCRIPTION "Disabled features:")
endif()
