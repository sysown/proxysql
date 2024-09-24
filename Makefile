#!/bin/make -f


### NOTES:
### version string is fetched from git history
### when not available, specify GIT_VERSION on commnad line:
###
### ```
### export GIT_VERSION=2.x-dev
### ```

GIT_VERSION ?= $(shell git describe --long --abbrev=7)
ifndef GIT_VERSION
    $(error GIT_VERSION is not set)
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
###
### ** to use on-demand coredump generation feature, compile code without ASAN option (WITHASAN=0).

O0 := -O0
O2 := -O2
O1 := -O1
O3 := -O3 -mtune=native

#EXTRALINK := #-pg
ALL_DEBUG := $(O0) -ggdb -DDEBUG
NO_DEBUG := $(O2) -ggdb
DEBUG := $(ALL_DEBUG)
CURVER ?= 2.7.x
#export DEBUG
#export EXTRALINK
export MAKE
export CURVER

### detect compiler support for c++11/17
CPLUSPLUS := $(shell ${CC} -std=c++17 -dM -E -x c++ /dev/null 2>/dev/null | grep -F __cplusplus | egrep -o '[0-9]{6}L')
ifneq ($(CPLUSPLUS),201703L)
	CPLUSPLUS := $(shell ${CC} -std=c++11 -dM -E -x c++ /dev/null 2>/dev/null| grep -F __cplusplus | egrep -o '[0-9]{6}L')
	LEGACY_BUILD := 1
ifneq ($(CPLUSPLUS),201103L)
    $(error Compiler must support at least c++11)
endif
endif
STDCPP := -std=c++$(shell echo $(CPLUSPLUS) | cut -c3-4) -DCXX$(shell echo $(CPLUSPLUS) | cut -c3-4)

### detect distro
DISTRO := Unknown
ifneq (,$(wildcard /etc/os-release))
	DISTRO := $(shell awk -F= '/^NAME/{print $$2}' /etc/os-release)
endif

### multiprocessing
NPROCS := 1
OS := $(shell uname -s)
ifeq ($(OS),Linux)
	NPROCS := $(shell nproc)
endif
ifneq (,$(findstring $(OS),Darwin FreeBSD))
	NPROCS := $(shell sysctl -n hw.ncpu)
	LEGACY_BUILD := 1
    export CC=gcc
    export CXX=g++
endif
export MAKEOPT := -j${NPROCS}

### systemd
SYSTEMD := 0
ifeq ($(wildcard /usr/lib/systemd/system), /usr/lib/systemd/system)
	SYSTEMD := 1
endif

### check user/group
USERCHECK := $(shell getent passwd proxysql)
GROUPCHECK := $(shell getent group proxysql)


### main targets

.DEFAULT: default
.PHONY: default
default: build_src

.PHONY: debug
debug: build_src_debug

.PHONY: testaurora_random
testaurora_random: build_src_testaurora_random

.PHONY: testaurora
testaurora: build_src_testaurora
	# cd test/tap && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA" CC=${CC} CXX=${CXX} ${MAKE}
	# cd test/tap/tests && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA" CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)

.PHONY: testgalera
testgalera: build_src_testgalera
	cd test/tap && OPTZ="${O0} -ggdb -DDEBUG -DTEST_GALERA" CC=${CC} CXX=${CXX} ${MAKE}
	cd test/tap/tests && OPTZ="${O0} -ggdb -DDEBUG -DTEST_GALERA" CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)

.PHONY: testgrouprep
testgrouprep: build_src_testgrouprep

.PHONY: testreadonly
testreadonly: build_src_testreadonly

.PHONY: testreplicationlag
testreplicationlag: build_src_testreplicationlag

.PHONY: testall
testall: build_src_testall

.PHONY: clickhouse
clickhouse: build_src_clickhouse

.PHONY: debug_clickhouse
debug_clickhouse: build_src_debug_clickhouse


### helper targets

.PHONY: build_deps
build_deps: $(if $(LEGACY_BUILD),build_deps_legacy,build_deps_default)

.PHONY: build_lib
build_lib: $(if $(LEGACY_BUILD),build_lib_legacy,build_lib_default)

.PHONY: build_src
build_src: $(if $(LEGACY_BUILD),build_src_legacy,build_src_default)

.PHONY: build_deps_debug
build_deps_debug: $(if $(LEGACY_BUILD),build_deps_debug_legacy,build_deps_debug_default)

.PHONY: build_lib_debug
build_lib_debug: $(if $(LEGACY_BUILD),build_lib_debug_legacy,build_lib_debug_default)

.PHONY: build_src_debug
build_src_debug: $(if $(LEGACY_BUILD),build_src_debug_legacy,build_src_debug_default)

# legacy build targets (pre c++17)
.PHONY: build_deps_legacy
build_deps_legacy:
	cd deps && OPTZ="${O2} -ggdb" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_legacy
build_lib_legacy: build_deps_legacy
	cd lib && OPTZ="${O2} -ggdb" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_legacy
build_src_legacy: build_lib_legacy
	cd src && OPTZ="${O2} -ggdb" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_deps_debug_legacy
build_deps_debug_legacy:
	cd deps && OPTZ="${O0} -ggdb -DDEBUG" PROXYDEBUG=1 CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_debug_legacy
build_lib_debug_legacy: build_deps_debug_legacy
	cd lib && OPTZ="${O0} -ggdb -DDEBUG" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_debug_legacy
build_src_debug_legacy: build_lib_debug_legacy
	cd src && OPTZ="${O0} -ggdb -DDEBUG" CC=${CC} CXX=${CXX} ${MAKE}
#--

.PHONY: build_src_testaurora
build_src_testaurora: build_lib_testaurora
	cd src && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_testaurora_random
build_src_testaurora_random: build_lib_testaurora_random
	cd src && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA -DTEST_AURORA_RANDOM" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_testaurora
build_lib_testaurora: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_testaurora_random
build_lib_testaurora_random: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA -DTEST_AURORA_RANDOM" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_testgalera
build_src_testgalera: build_lib_testgalera
	cd src && OPTZ="${O0} -ggdb -DDEBUG -DTEST_GALERA" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_testgalera
build_lib_testgalera: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG -DTEST_GALERA" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_testgrouprep
build_src_testgrouprep: build_lib_testgrouprep
	cd src && OPTZ="${O0} -ggdb -DDEBUG -DTEST_GROUPREP" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_testgrouprep
build_lib_testgrouprep: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG -DTEST_GROUPREP" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_testreadonly
build_src_testreadonly: build_lib_testreadonly
	cd src && OPTZ="${O0} -ggdb -DDEBUG -DTEST_READONLY" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_testreadonly
build_lib_testreadonly: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG -DTEST_READONLY" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_testreplicationlag
build_src_testreplicationlag: build_lib_testreplicationlag
	cd src && OPTZ="${O0} -ggdb -DDEBUG -DTEST_REPLICATIONLAG" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_testreplicationlag
build_lib_testreplicationlag: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG -DTEST_REPLICATIONLAG" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_testall
build_src_testall: build_lib_testall
	cd src && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA -DTEST_GALERA -DTEST_GROUPREP -DTEST_READONLY -DTEST_REPLICATIONLAG" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_testall
build_lib_testall: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA -DTEST_GALERA -DTEST_GROUPREP -DTEST_READONLY -DTEST_REPLICATIONLAG" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_tap_test
build_tap_test: build_tap_tests
.PHONY: build_tap_tests
build_tap_tests: build_src
	cd test/tap && OPTZ="${O2} -ggdb" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_tap_test_debug
build_tap_test_debug: build_tap_tests_debug
.PHONY: build_tap_tests_debug
build_tap_tests_debug: build_src_debug
	cd test/tap && OPTZ="${O0} -ggdb -DDEBUG" CC=${CC} CXX=${CXX} ${MAKE} debug

# ClickHouse build targets are now default build targets. 
# To maintain backward compatibility, ClickHouse targets are still available.
.PHONY: build_deps_clickhouse
build_deps_clickhouse: build_deps_default

.PHONY: build_deps_debug_clickhouse
build_deps_debug_clickhouse: build_deps_debug_default

.PHONY: build_lib_clickhouse
build_lib_clickhouse: build_lib_default

.PHONY: build_lib_debug_clickhouse
build_lib_debug_clickhouse: build_lib_debug_default

.PHONY: build_src_clickhouse
build_src_clickhouse: build_src_default

.PHONY: build_src_debug_clickhouse
build_src_debug_clickhouse: build_src_debug_default
#--

.PHONY: build_deps_default
build_deps_default:
	cd deps && OPTZ="${O2} -ggdb" PROXYSQLCLICKHOUSE=1 CC=${CC} CXX=${CXX} ${MAKE}

PHONY: build_deps_debug_default
build_deps_debug_default:
	cd deps && OPTZ="${O0} -ggdb -DDEBUG" PROXYSQLCLICKHOUSE=1 PROXYDEBUG=1 CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_default
build_lib_default: build_deps_default
	cd lib && OPTZ="${O2} -ggdb" PROXYSQLCLICKHOUSE=1 CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_debug_default
build_lib_debug_default: build_deps_debug_default
	cd lib && OPTZ="${O0} -ggdb -DDEBUG" PROXYSQLCLICKHOUSE=1 CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_default
build_src_default: build_lib_default
	cd src && OPTZ="${O2} -ggdb" PROXYSQLCLICKHOUSE=1 CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_debug_default
build_src_debug_default: build_lib_debug_default
	cd src && OPTZ="${O0} -ggdb -DDEBUG" PROXYSQLCLICKHOUSE=1 CC=${CC} CXX=${CXX} ${MAKE}


### packaging targets

SYS_KERN := $(shell uname -s)
#SYS_DIST := $(shell source /etc/os-release &>/dev/null; if [ -z ${NAME} ]; then head -1 /etc/redhat-release; else echo ${NAME}; fi | awk '{ print $1 })
SYS_ARCH := $(shell uname -m)
REL_ARCH := $(subst x86_64,amd64,$(subst aarch64,arm64,$(SYS_ARCH)))
RPM_ARCH := .$(SYS_ARCH)
DEB_ARCH := _$(REL_ARCH)
REL_VERS := $(shell echo ${GIT_VERSION} | grep -Po '(?<=^v|^)[\d\.]+')
RPM_VERS := -$(REL_VERS)-1
DEB_VERS := _$(REL_VERS)

packages: $(REL_ARCH)-packages ;
almalinux: $(REL_ARCH)-almalinux ;
centos: $(REL_ARCH)-centos ;
debian: $(REL_ARCH)-debian ;
fedora: $(REL_ARCH)-fedora ;
opensuse: $(REL_ARCH)-opensuse ;
ubuntu: $(REL_ARCH)-ubuntu ;

amd64-packages: amd64-centos amd64-ubuntu amd64-debian amd64-fedora amd64-opensuse amd64-almalinux
amd64-almalinux: almalinux8 almalinux8-clang almalinux8-dbg almalinux9 almalinux9-clang almalinux9-dbg
amd64-centos: centos7 centos7-dbg centos8 centos8-clang centos8-dbg centos9 centos9-clang centos9-dbg
amd64-debian: debian10 debian10-dbg debian11 debian11-clang debian11-dbg debian12 debian12-clang debian12-dbg
amd64-fedora: fedora38 fedora38-clang fedora38-dbg fedora39 fedora39-clang fedora39-dbg fedora40 fedora40-clang fedora40-dbg fedora41 fedora41-clang fedora41-dbg
amd64-opensuse: opensuse15 opensuse15-clang opensuse15-dbg
amd64-ubuntu: ubuntu16 ubuntu16-dbg ubuntu18 ubuntu18-dbg ubuntu20 ubuntu20-clang ubuntu20-dbg ubuntu22 ubuntu22-clang ubuntu22-dbg ubuntu24 ubuntu24-clang ubuntu24-dbg

arm64-packages: arm64-centos arm64-debian arm64-ubuntu arm64-fedora arm64-opensuse arm64-almalinux
arm64-almalinux: almalinux8 almalinux9
arm64-centos: centos7 centos8 centos9
arm64-debian: debian10 debian11 debian12
arm64-fedora: fedora38 fedora39 fedora40
arm64-opensuse: opensuse15
arm64-ubuntu: ubuntu16 ubuntu18 ubuntu20 ubuntu22 ubuntu24

almalinux%: build-almalinux% ;
centos%: build-centos% ;
debian%: build-debian% ;
fedora%: build-fedora% ;
opensuse%: build-opensuse% ;
ubuntu%: build-ubuntu% ;


.PHONY: build-%
.NOTPARALLEL: build-%
build-%: BLD_NAME=$(patsubst build-%,%,$@)
build-%: PKG_VERS=$(if $(filter $(shell echo ${BLD_NAME} | grep -Po '[a-z]+'),debian ubuntu),$(DEB_VERS),$(RPM_VERS))
build-%: PKG_TYPE=$(if $(filter $(shell echo $(BLD_NAME) | grep -Po '\-de?bu?g'),-dbg -debug),-dbg,)
build-%: PKG_NAME=$(firstword $(subst -, ,$(BLD_NAME)))
build-%: PKG_COMP=$(if $(filter $(shell echo $(BLD_NAME) | grep -Po '\-clang'),-clang),-clang,)
build-%: PKG_ARCH=$(if $(filter $(shell echo ${BLD_NAME} | grep -Po '[a-z]+'),debian ubuntu),$(DEB_ARCH),$(RPM_ARCH))
build-%: PKG_KIND=$(if $(filter $(shell echo ${BLD_NAME} | grep -Po '[a-z]+'),debian ubuntu),deb,rpm)
build-%: PKG_FILE=binaries/proxysql$(PKG_VERS)$(PKG_TYPE)-$(PKG_NAME)$(PKG_COMP)$(PKG_ARCH).$(PKG_KIND)
build-%:
	@echo 'building $@'
	@IMG_NAME=$(PKG_NAME) IMG_TYPE=$(subst -,_,$(PKG_TYPE)) IMG_COMP=$(subst -,_,$(PKG_COMP)) $(MAKE) $(PKG_FILE)

.NOTPARALLEL: binaries/proxysql%
binaries/proxysql%:
	cd deps && ${MAKE} cleanall
	cd lib && ${MAKE} clean
	cd src && ${MAKE} clean
	cd test/tap && ${MAKE} clean
	cd test/deps && ${MAKE} cleanall
	find . -not -path "./binaries/*" -not -path "./.git/*" -exec touch -h --date=@`git show -s --format=%ct HEAD` {} \;
	@docker compose -p proxysql down -v --remove-orphans
	@docker compose -p proxysql up $(IMG_NAME)$(IMG_TYPE)$(IMG_COMP)_build
	@docker compose -p proxysql down -v --remove-orphans


### clean targets

.PHONY: clean
clean:
	cd lib && ${MAKE} clean
	cd src && ${MAKE} clean
	cd test/tap && ${MAKE} clean
	cd test/deps && ${MAKE} clean
	rm -f pkgroot || true

.PHONY: cleanall
cleanall:
	cd deps && ${MAKE} cleanall
	cd lib && ${MAKE} clean
	cd src && ${MAKE} clean
	cd test/tap && ${MAKE} clean
	cd test/deps && ${MAKE} cleanall
	rm -f binaries/*deb || true
	rm -f binaries/*rpm || true
	rm -f binaries/*id-hash || true
	rm -rf pkgroot || true

.PHONY: cleanbuild
cleanbuild:
	cd deps && ${MAKE} cleanall
	cd lib && ${MAKE} clean
	cd src && ${MAKE} clean


### install targets

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
