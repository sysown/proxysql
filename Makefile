#!/bin/make -f


### NOTES:
### version string is fetched from git history
### when not available, specify GIT_VERSION on commnad line:
###
### ```
### export GIT_VERSION=2.x-dev
### ```

ifndef GIT_VERSION
GIT_VERSION := $(shell git describe --long --abbrev=7)
ifndef GIT_VERSION
$(error GIT_VERSION is not set)
endif
endif

### NOTES:
### to compile without jemalloc, set environment variable NOJEMALLOC=1
### to compile with gcov code coverage, set environment variable WITHGCOV=1
### to compile with ASAN, set environment variables NOJEMALLOC=1, WITHASAN=1:
###   * To perform a full ProxySQL build with ASAN then execute:
###
###     ```
###     make build_deps_debug -j$(nproc) && make debug -j$(nproc) && make build_tap_test_debug -j$(nproc)
###     ```

O0=-O0
O2=-O2
O1=-O1
O3=-O3 -mtune=native
#OPTZ=$(O2)
EXTRALINK=#-pg
ALL_DEBUG=-ggdb -DDEBUG
NO_DEBUG=
DEBUG=${ALL_DEBUG}
#export DEBUG
#export OPTZ
#export EXTRALINK
export MAKE
export CURVER?=2.5.0
ifneq (,$(wildcard /etc/os-release))
	DISTRO := $(shell gawk -F= '/^NAME/{print $$2}' /etc/os-release)
else
	DISTRO := Unknown
endif

NPROCS := 1
OS := $(shell uname -s)
ifeq ($(OS),Linux)
	NPROCS := $(shell nproc)
endif
ifeq ($(OS),Darwin)
	NPROCS := $(shell sysctl -n hw.ncpu)
endif

export MAKEOPT=-j ${NPROCS}

ifeq ($(wildcard /usr/lib/systemd/system), /usr/lib/systemd/system)
	SYSTEMD=1
else
	SYSTEMD=0
endif
USERCHECK := $(shell getent passwd proxysql)
GROUPCHECK := $(shell getent group proxysql)


.PHONY: default
default: build_deps build_lib build_src

.PHONY: debug
debug: build_deps_debug build_lib_debug build_src_debug

.PHONY: testaurora
testaurora: build_deps_debug build_lib_testaurora build_src_testaurora
	cd test/tap && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA" CC=${CC} CXX=${CXX} ${MAKE}
	cd test/tap/tests && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA" CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)

.PHONY: testgalera
testgalera: build_deps_debug build_lib_testgalera build_src_testgalera
	cd test/tap && OPTZ="${O0} -ggdb -DDEBUG -DTEST_GALERA" CC=${CC} CXX=${CXX} ${MAKE}
	cd test/tap/tests && OPTZ="${O0} -ggdb -DDEBUG -DTEST_GALERA" CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)

.PHONY: testgrouprep
testgrouprep: build_deps_debug build_lib_testgrouprep build_src_testgrouprep

.PHONY: testreadonly
testreadonly: build_deps_debug build_lib_testreadonly build_src_testreadonly

.PHONY: testall
testall: build_deps_debug build_lib_testall build_src_testall

.PHONY: clickhouse
clickhouse: build_deps_clickhouse build_lib_clickhouse build_src_clickhouse

.PHONY: debug_clickhouse
debug_clickhouse: build_deps_debug_clickhouse build_lib_debug_clickhouse build_src_debug_clickhouse



.PHONY: build_deps
build_deps:
	cd deps && OPTZ="${O2} -ggdb" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib
build_lib: build_deps
	cd lib && OPTZ="${O2} -ggdb" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src
build_src: build_deps build_lib
	cd src && OPTZ="${O2} -ggdb" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_deps_debug
build_deps_debug:
	cd deps && OPTZ="${O0} -ggdb -DDEBUG" PROXYDEBUG=1 CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_debug
build_lib_debug: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_testaurora
build_src_testaurora: build_deps build_lib_testaurora
	cd src && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_testaurora
build_lib_testaurora: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_testgalera
build_src_testgalera: build_deps build_lib_testgalera
	cd src && OPTZ="${O0} -ggdb -DDEBUG -DTEST_GALERA" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_testgalera
build_lib_testgalera: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG -DTEST_GALERA" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_testgrouprep
build_src_testgrouprep: build_deps build_lib_testgrouprep
	cd src && OPTZ="${O0} -ggdb -DDEBUG -DTEST_GROUPREP" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_testgrouprep
build_lib_testgrouprep: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG -DTEST_GROUPREP" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_testreadonly
build_src_testreadonly: build_deps build_lib_testreadonly
	cd src && OPTZ="${O0} -ggdb -DDEBUG -DTEST_READONLY" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_testreadonly
build_lib_testreadonly: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG -DTEST_READONLY" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_testall
build_src_testall: build_deps build_lib_testall
	cd src && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA -DTEST_GALERA -DTEST_GROUPREP -DTEST_READONLY" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_testall
build_lib_testall: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA -DTEST_GALERA -DTEST_GROUPREP -DTEST_READONLY" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_tap_test
build_tap_test: build_src
	cd test/tap && OPTZ="${O0} -ggdb -DDEBUG" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_tap_test_debug
build_tap_test_debug: build_src_debug
	cd test/tap && OPTZ="${O0} -ggdb -DDEBUG" CC=${CC} CXX=${CXX} ${MAKE} debug

.PHONY: build_src_debug
build_src_debug: build_deps build_lib_debug
	cd src && OPTZ="${O0} -ggdb -DDEBUG" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_deps_clickhouse
build_deps_clickhouse:
	cd deps && OPTZ="${O2} -ggdb" PROXYSQLCLICKHOUSE=1 CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_deps_debug_clickhouse
build_deps_debug_clickhouse:
	cd deps && OPTZ="${O0} -ggdb -DDEBUG" PROXYSQLCLICKHOUSE=1 PROXYDEBUG=1 CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_clickhouse
build_lib_clickhouse: build_deps_clickhouse
	cd lib && OPTZ="${O2} -ggdb" PROXYSQLCLICKHOUSE=1 CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_debug_clickhouse
build_lib_debug_clickhouse: build_deps_debug_clickhouse
	cd lib && OPTZ="${O0} -ggdb -DDEBUG" PROXYSQLCLICKHOUSE=1 CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_clickhouse
build_src_clickhouse: build_deps_clickhouse build_lib_clickhouse
	cd src && OPTZ="${O2} -ggdb" PROXYSQLCLICKHOUSE=1 CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_debug_clickhouse
build_src_debug_clickhouse: build_deps build_lib_debug_clickhouse
	cd src && OPTZ="${O0} -ggdb -DDEBUG" PROXYSQLCLICKHOUSE=1 CC=${CC} CXX=${CXX} ${MAKE}



.PHONY: clean
clean:
	cd lib && ${MAKE} clean
	cd src && ${MAKE} clean
	cd test/tap && ${MAKE} clean



packages: amd64-packages arm64-packages
.PHONY: packages

amd64-packages: amd64-centos amd64-ubuntu amd64-debian amd64-fedora amd64-opensuse amd64-almalinux
.PHONY: amd64-packages

amd64-centos: centos6 centos6-dbg centos7 centos7-dbg centos8 centos8-clang centos8-dbg
.PHONY: amd64-centos

amd64-ubuntu: ubuntu14 ubuntu14-dbg ubuntu16 ubuntu16-dbg ubuntu18 ubuntu18-dbg ubuntu20 ubuntu20-clang ubuntu20-dbg ubuntu22 ubuntu22-clang ubuntu22-dbg
.PHONY: amd64-ubuntu

amd64-debian: debian8 debian8-dbg debian9 debian9-dbg debian10 debian10-dbg debian11 debian11-clang debian11-dbg
.PHONY: amd64-debian

amd64-fedora: fedora27 fedora27-dbg fedora28 fedora28-dbg fedora33 fedora33-dbg fedora34 fedora34-clang fedora34-dbg fedora36 fedora36-clang fedora36-dbg fedora37 fedora37-clang fedora37-dbg
.PHONY: amd64-fedora

amd64-opensuse: opensuse15 opensuse15-clang opensuse15-dbg
.PHONY: amd64-opensuse

amd64-almalinux: almalinux8 almalinux8-clang almalinux8-dbg almalinux9 almalinux9-clang almalinux9-dbg
.PHONY: amd64-almalinux




arm64-packages: arm64-centos arm64-debian arm64-ubuntu arm64-fedora arm64-opensuse arm64-almalinux
.PHONY: arm64-packages

arm64-centos: centos7-arm64 centos8-arm64
.PHONY: arm64-centos

arm64-debian: debian9-arm64 debian10-arm64 debian11-arm64
.PHONY: arm64-debian

arm64-ubuntu: ubuntu16-arm64 ubuntu18-arm64 ubuntu20-arm64 ubuntu22-arm64
.PHONY: arm64-ubuntu

arm64-fedora: fedora33-arm64 fedora34-arm64 fedora36-arm64 fedora37-arm64
.PHONY: arm64-fedora

arm64-opensuse: opensuse15-arm64
.PHONY: arm64-opensuse

arm64-almalinux: almalinux8-arm64 almalinux9-arm64
.PHONY: arm64-almalinux





centos6: binaries/proxysql-${CURVER}-1-centos6.x86_64.rpm
.PHONY: centos6

centos6-dbg: binaries/proxysql-${CURVER}-1-dbg-centos6.x86_64.rpm
.PHONY: centos6-dbg


centos7: binaries/proxysql-${CURVER}-1-centos7.x86_64.rpm
.PHONY: centos7

centos7-arm64: binaries/proxysql-${CURVER}-1-centos7.aarch64.rpm
.PHONY: centos7-arm64

centos7-dbg: binaries/proxysql-${CURVER}-1-dbg-centos7.x86_64.rpm
.PHONY: centos7-dbg


centos8: binaries/proxysql-${CURVER}-1-centos8.x86_64.rpm
.PHONY: centos8

centos8-clang: binaries/proxysql-${CURVER}-1-centos8-clang.x86_64.rpm
.PHONY: centos8-clang

centos8-arm64: binaries/proxysql-${CURVER}-1-centos8.aarch64.rpm
.PHONY: centos8-arm64

centos8-dbg: binaries/proxysql-${CURVER}-1-dbg-centos8.x86_64.rpm
.PHONY: centos8-dbg


fedora27: binaries/proxysql-${CURVER}-1-fedora27.x86_64.rpm
.PHONY: fedora27

fedora27-dbg: binaries/proxysql-${CURVER}-1-dbg-fedora27.x86_64.rpm
.PHONY: fedora27-dbg


fedora28: binaries/proxysql-${CURVER}-1-fedora28.x86_64.rpm
.PHONY: fedora28

fedora28-dbg: binaries/proxysql-${CURVER}-1-dbg-fedora28.x86_64.rpm
.PHONY: fedora28-dbg


fedora33: binaries/proxysql-${CURVER}-1-fedora33.x86_64.rpm
.PHONY: fedora33

fedora33-arm64: binaries/proxysql-${CURVER}-1-fedora33.aarch64.rpm
.PHONY: fedora33-arm64

fedora33-dbg: binaries/proxysql-${CURVER}-1-dbg-fedora33.x86_64.rpm
.PHONY: fedora33-dbg


fedora34: binaries/proxysql-${CURVER}-1-fedora34.x86_64.rpm
.PHONY: fedora34

fedora34-arm64: binaries/proxysql-${CURVER}-1-fedora34.aarch64.rpm
.PHONY: fedora34-arm64

fedora34-clang: binaries/proxysql-${CURVER}-1-fedora34-clang.x86_64.rpm
.PHONY: fedora34-clang

fedora34-dbg: binaries/proxysql-${CURVER}-1-dbg-fedora34.x86_64.rpm
.PHONY: fedora34-dbg


fedora36: binaries/proxysql-${CURVER}-1-fedora36.x86_64.rpm
.PHONY: fedora36

fedora36-arm64: binaries/proxysql-${CURVER}-1-fedora36.aarch64.rpm
.PHONY: fedora36-arm64

fedora36-clang: binaries/proxysql-${CURVER}-1-fedora36-clang.x86_64.rpm
.PHONY: fedora36-clang

fedora36-dbg: binaries/proxysql-${CURVER}-1-dbg-fedora36.x86_64.rpm
.PHONY: fedora36-dbg


fedora37: binaries/proxysql-${CURVER}-1-fedora37.x86_64.rpm
.PHONY: fedora36

fedora37-arm64: binaries/proxysql-${CURVER}-1-fedora37.aarch64.rpm
.PHONY: fedora36-arm64

fedora37-clang: binaries/proxysql-${CURVER}-1-fedora37-clang.x86_64.rpm
.PHONY: fedora36-clang

fedora37-dbg: binaries/proxysql-${CURVER}-1-dbg-fedora37.x86_64.rpm
.PHONY: fedora36-dbg


ubuntu14: binaries/proxysql_${CURVER}-ubuntu14_amd64.deb
.PHONY: ubuntu14

ubuntu14-dbg: binaries/proxysql_${CURVER}-dbg-ubuntu14_amd64.deb
.PHONY: ubuntu14-dbg


ubuntu16: binaries/proxysql_${CURVER}-ubuntu16_amd64.deb
.PHONY: ubuntu16

ubuntu16-arm64: binaries/proxysql_${CURVER}-ubuntu16_arm64.deb
.PHONY: ubuntu16-arm64

ubuntu16-dbg: binaries/proxysql_${CURVER}-dbg-ubuntu16_amd64.deb
.PHONY: ubuntu16-dbg


ubuntu18: binaries/proxysql_${CURVER}-ubuntu18_amd64.deb
.PHONY: ubuntu18

ubuntu18-arm64: binaries/proxysql_${CURVER}-ubuntu18_arm64.deb
.PHONY: ubuntu18-arm64

ubuntu18-dbg: binaries/proxysql_${CURVER}-dbg-ubuntu18_amd64.deb
.PHONY: ubuntu18-dbg


ubuntu20: binaries/proxysql_${CURVER}-ubuntu20_amd64.deb
.PHONY: ubuntu20

ubuntu20-clang: binaries/proxysql_${CURVER}-ubuntu20-clang_amd64.deb
.PHONY: ubuntu20-clang

ubuntu20-arm64: binaries/proxysql_${CURVER}-ubuntu20_arm64.deb
.PHONY: ubuntu20-arm64

ubuntu20-dbg: binaries/proxysql_${CURVER}-dbg-ubuntu20_amd64.deb
.PHONY: ubuntu20-dbg


ubuntu22: binaries/proxysql_${CURVER}-ubuntu22_amd64.deb
.PHONY: ubuntu22

ubuntu22-clang: binaries/proxysql_${CURVER}-ubuntu22-clang_amd64.deb
.PHONY: ubuntu22-clang

ubuntu22-arm64: binaries/proxysql_${CURVER}-ubuntu22_arm64.deb
.PHONY: ubuntu22-arm64

ubuntu22-dbg: binaries/proxysql_${CURVER}-dbg-ubuntu22_amd64.deb
.PHONY: ubuntu22-dbg


debian8: binaries/proxysql_${CURVER}-debian8_amd64.deb
.PHONY: debian8

debian8-dbg: binaries/proxysql_${CURVER}-dbg-debian8_amd64.deb
.PHONY: debian8-dbg


debian9: binaries/proxysql_${CURVER}-debian9_amd64.deb
.PHONY: debian9

debian9-arm64: binaries/proxysql_${CURVER}-debian9_arm64.deb
.PHONY: debian9-arm64

debian9-dbg: binaries/proxysql_${CURVER}-dbg-debian9_amd64.deb
.PHONY: debian9-dbg


debian10: binaries/proxysql_${CURVER}-debian10_amd64.deb
.PHONY: debian10

debian10-arm64: binaries/proxysql_${CURVER}-debian10_arm64.deb
.PHONY: debian10-arm64

debian10-dbg: binaries/proxysql_${CURVER}-dbg-debian10_amd64.deb
.PHONY: debian10-dbg


debian11: binaries/proxysql_${CURVER}-debian11_amd64.deb
.PHONY: debian11

debian11-clang: binaries/proxysql_${CURVER}-debian11-clang_amd64.deb
.PHONY: debian11-clang

debian11-arm64: binaries/proxysql_${CURVER}-debian11_arm64.deb
.PHONY: debian11-arm64

debian11-dbg: binaries/proxysql_${CURVER}-dbg-debian11_amd64.deb
.PHONY: debian11-dbg


opensuse15: binaries/proxysql-${CURVER}-1-opensuse15.x86_64.rpm
.PHONY: opensuse15

opensuse15-arm64: binaries/proxysql-${CURVER}-1-opensuse15.aarch64.rpm
.PHONY: opensuse15-arm64

opensuse15-clang: binaries/proxysql-${CURVER}-1-opensuse15-clang.x86_64.rpm
.PHONY: opensuse15-clang

opensuse15-dbg: binaries/proxysql-${CURVER}-1-opensuse15-dbg.x86_64.rpm
.PHONY: opensuse15-dbg


almalinux8: binaries/proxysql-${CURVER}-1-almalinux8.x86_64.rpm
.PHONY: almalinux8

almalinux8-arm64: binaries/proxysql-${CURVER}-1-almalinux8.aarch64.rpm
.PHONY: almalinux8-arm64

almalinux8-clang: binaries/proxysql-${CURVER}-1-almalinux8-clang.x86_64.rpm
.PHONY: almalinux8-clang

almalinux8-dbg: binaries/proxysql-${CURVER}-1-almalinux8-dbg.x86_64.rpm
.PHONY: almalinux8-dbg


almalinux9: binaries/proxysql-${CURVER}-1-almalinux9.x86_64.rpm
.PHONY: almalinux8

almalinux9-arm64: binaries/proxysql-${CURVER}-1-almalinux9.aarch64.rpm
.PHONY: almalinux9-arm64

almalinux9-clang: binaries/proxysql-${CURVER}-1-almalinux9-clang.x86_64.rpm
.PHONY: almalinux9-clang

almalinux9-dbg: binaries/proxysql-${CURVER}-1-almalinux9-dbg.x86_64.rpm
.PHONY: almalinux9-dbg



binaries/proxysql-${CURVER}-1-centos6.x86_64.rpm:
	docker-compose up centos6_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-centos6.x86_64.rpm:
	docker-compose up centos6_dbg_build
	docker-compose rm -f


binaries/proxysql-${CURVER}-1-centos7.x86_64.rpm:
	docker-compose up centos7_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-centos7.aarch64.rpm:
	docker-compose up centos7_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-centos7.x86_64.rpm:
	docker-compose up centos7_dbg_build
	docker-compose rm -f


binaries/proxysql-${CURVER}-1-centos8.x86_64.rpm:
	docker-compose up centos8_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-centos8-clang.x86_64.rpm:
	docker-compose up centos8_clang_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-centos8.aarch64.rpm:
	docker-compose up centos8_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-centos8.x86_64.rpm:
	docker-compose up centos8_dbg_build
	docker-compose rm -f


binaries/proxysql-${CURVER}-1-dbg-fedora27.x86_64.rpm:
	docker-compose up fedora27_dbg_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-fedora27.x86_64.rpm:
	docker-compose up fedora27_build
	docker-compose rm -f


binaries/proxysql-${CURVER}-1-fedora28.x86_64.rpm:
	docker-compose up fedora28_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-fedora28.x86_64.rpm:
	docker-compose up fedora28_dbg_build
	docker-compose rm -f


binaries/proxysql-${CURVER}-1-fedora33.x86_64.rpm:
	docker-compose up fedora33_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-fedora33.x86_64.rpm:
	docker-compose up fedora33_dbg_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-fedora33.aarch64.rpm:
	docker-compose up fedora33_build
	docker-compose rm -f


binaries/proxysql-${CURVER}-1-fedora34.x86_64.rpm:
	docker-compose up fedora34_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-fedora34.aarch64.rpm:
	docker-compose up fedora34_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-fedora34-clang.x86_64.rpm:
	docker-compose up fedora34_clang_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-fedora34.x86_64.rpm:
	docker-compose up fedora34_dbg_build
	docker-compose rm -f


binaries/proxysql-${CURVER}-1-fedora36.x86_64.rpm:
	docker-compose up fedora36_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-fedora36.aarch64.rpm:
	docker-compose up fedora36_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-fedora36-clang.x86_64.rpm:
	docker-compose up fedora36_clang_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-fedora36.x86_64.rpm:
	docker-compose up fedora36_dbg_build
	docker-compose rm -f


binaries/proxysql-${CURVER}-1-fedora37.x86_64.rpm:
	docker-compose up fedora37_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-fedora37.aarch64.rpm:
	docker-compose up fedora37_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-fedora37-clang.x86_64.rpm:
	docker-compose up fedora37_clang_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-fedora37.x86_64.rpm:
	docker-compose up fedora37_dbg_build
	docker-compose rm -f


binaries/proxysql_${CURVER}-ubuntu14_amd64.deb:
	docker-compose up ubuntu14_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-ubuntu14_amd64.deb:
	docker-compose up ubuntu14_dbg_build
	docker-compose rm -f


binaries/proxysql_${CURVER}-ubuntu16_amd64.deb:
	docker-compose up ubuntu16_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-ubuntu16_arm64.deb:
	docker-compose up ubuntu16_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-ubuntu16_amd64.deb:
	docker-compose up ubuntu16_dbg_build
	docker-compose rm -f


binaries/proxysql_${CURVER}-ubuntu18_amd64.deb:
	docker-compose up ubuntu18_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-ubuntu18_amd64.deb:
	docker-compose up ubuntu18_dbg_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-ubuntu18_arm64.deb:
	docker-compose up ubuntu18_build
	docker-compose rm -f


binaries/proxysql_${CURVER}-dbg-ubuntu20_amd64.deb:
	docker-compose up ubuntu20_dbg_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-ubuntu20_amd64.deb:
	docker-compose up ubuntu20_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-ubuntu20-clang_amd64.deb:
	docker-compose up ubuntu20_clang_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-ubuntu20_arm64.deb:
	docker-compose up ubuntu20_build
	docker-compose rm -f


binaries/proxysql_${CURVER}-dbg-ubuntu22_amd64.deb:
	docker-compose up ubuntu22_dbg_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-ubuntu22_amd64.deb:
	docker-compose up ubuntu22_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-ubuntu22-clang_amd64.deb:
	docker-compose up ubuntu22_clang_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-ubuntu22_arm64.deb:
	docker-compose up ubuntu22_build
	docker-compose rm -f


binaries/proxysql_${CURVER}-debian8_amd64.deb:
	docker-compose up debian8_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-debian8_amd64.deb:
	docker-compose up debian8_dbg_build
	docker-compose rm -f


binaries/proxysql_${CURVER}-debian9_amd64.deb:
	docker-compose up debian9_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-debian9_amd64.deb:
	docker-compose up debian9_dbg_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-debian9_arm64.deb:
	docker-compose up debian9_build
	docker-compose rm -f


binaries/proxysql_${CURVER}-debian10_amd64.deb:
	docker-compose up debian10_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-debian10_arm64.deb:
	docker-compose up debian10_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-debian10_amd64.deb:
	docker-compose up debian10_dbg_build
	docker-compose rm -f


binaries/proxysql_${CURVER}-debian11_amd64.deb:
	docker-compose up debian11_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-debian11-clang_amd64.deb:
	docker-compose up debian11_clang_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-debian11_arm64.deb:
	docker-compose up debian11_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-debian11_amd64.deb:
	docker-compose up debian11_dbg_build
	docker-compose rm -f


binaries/proxysql-${CURVER}-1-opensuse15.x86_64.rpm:
	docker-compose up opensuse15_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-opensuse15.aarch64.rpm:
	docker-compose up opensuse15_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-opensuse15-clang.x86_64.rpm:
	docker-compose up opensuse15_clang_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-opensuse15-dbg.x86_64.rpm:
	docker-compose up opensuse15_dbg_build
	docker-compose rm -f


binaries/proxysql-${CURVER}-1-almalinux8.x86_64.rpm:
	docker-compose up almalinux8_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-almalinux8.aarch64.rpm:
	docker-compose up almalinux8_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-almalinux8-clang.x86_64.rpm:
	docker-compose up almalinux8_clang_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-almalinux8-dbg.x86_64.rpm:
	docker-compose up almalinux8_dbg_build
	docker-compose rm -f


binaries/proxysql-${CURVER}-1-almalinux9.x86_64.rpm:
	docker-compose up almalinux9_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-almalinux9.aarch64.rpm:
	docker-compose up almalinux9_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-almalinux9-clang.x86_64.rpm:
	docker-compose up almalinux9_clang_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-almalinux9-dbg.x86_64.rpm:
	docker-compose up almalinux9_dbg_build
	docker-compose rm -f



.PHONY: cleanall
cleanall:
	cd deps && ${MAKE} cleanall
	cd lib && ${MAKE} clean
	cd src && ${MAKE} clean
	cd test/tap && ${MAKE} clean
	rm -f binaries/*deb || true
	rm -f binaries/*rpm || true
	rm -f binaries/*id-hash || true

.PHONY: cleanbuild
cleanbuild:
	cd deps && ${MAKE} cleanall
	cd lib && ${MAKE} clean
	cd src && ${MAKE} clean

.PHONY: install
install: src/proxysql
	install -m 0755 src/proxysql /usr/bin
	install -m 0600 etc/proxysql.cnf /etc
	if [ ! -d /var/lib/proxysql ]; then mkdir /var/lib/proxysql ; fi
ifeq ($(findstring proxysql,$(USERCHECK)),)
	@echo "Creating proxysql user and group"
	useradd -r -U -s /bin/false proxysql
endif
ifeq ($(SYSTEMD), 1)
	install -m 0644 systemd/system/proxysql.service /usr/lib/systemd/system/
	systemctl enable proxysql.service
else
	install -m 0755 etc/init.d/proxysql /etc/init.d
ifeq ($(DISTRO),"CentOS Linux")
		chkconfig --level 0123456 proxysql on
else
ifeq ($(DISTRO),"Rocky Linux")
		chkconfig --level 0123456 proxysql on
else
ifeq ($(DISTRO),"Red Hat Enterprise Linux Server")
		chkconfig --level 0123456 proxysql on
else
ifeq ($(DISTRO),"Ubuntu")
		update-rc.d proxysql defaults
else
ifeq ($(DISTRO),"Debian GNU/Linux")
		update-rc.d proxysql defaults
else
ifeq ($(DISTRO),"Unknown")
		$(warning Not sure how to install proxysql service on this OS)
endif
endif
endif
endif
endif
endif
endif

.PHONY: uninstall
uninstall:
	if [ -f /etc/proxysql.cnf ]; then rm /etc/proxysql.cnf ; fi
	if [ -f /usr/bin/proxysql ]; then rm /usr/bin/proxysql ; fi
	if [ -d /var/lib/proxysql ]; then rmdir /var/lib/proxysql 2>/dev/null || true ; fi
ifeq ($(SYSTEMD), 1)
		systemctl stop proxysql.service
		if [ -f /usr/lib/systemd/system/proxysql.service ]; then rm /usr/lib/systemd/system/proxysql.service ; fi
		find /etc/systemd -name "proxysql.service" -exec rm {} \;
		systemctl daemon-reload
else
ifeq ($(DISTRO),"CentOS Linux")
		chkconfig --level 0123456 proxysql off
		if [ -f /etc/init.d/proxysql ]; then rm /etc/init.d/proxysql ; fi
else
ifeq ($(DISTRO),"Red Hat Enterprise Linux Server")
		chkconfig --level 0123456 proxysql off
		if [ -f /etc/init.d/proxysql ]; then rm /etc/init.d/proxysql ; fi
else
ifeq ($(DISTRO),"Ubuntu")
		if [ -f /etc/init.d/proxysql ]; then rm /etc/init.d/proxysql ; fi
		update-rc.d proxysql remove
else
ifeq ($(DISTRO),"Debian GNU/Linux")
		if [ -f /etc/init.d/proxysql ]; then rm /etc/init.d/proxysql ; fi
		update-rc.d proxysql remove
else
ifeq ($(DISTRO),"Unknown")
		$(warning Not sure how to uninstall proxysql service on this OS)
endif
endif
endif
endif
endif
endif
ifneq ($(findstring proxysql,$(USERCHECK)),)
	@echo "Deleting proxysql user"
	userdel proxysql
endif
ifneq ($(findstring proxysql,$(GROUPCHECK)),)
	@echo "Deleting proxysql group"
	groupdel proxysql
endif
