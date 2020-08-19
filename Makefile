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
export CURVER?=2.0.9
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

# Force to 8 for automatic build
export MAKEOPT=-j 8

#export MAKEOPT=-j ${NPROCS}

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

.PHONY: build_src_testall
build_src_testall: build_deps build_lib_testall
	cd src && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA -DTEST_GALERA -DTEST_GROUPREP" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_testall
build_lib_testall: build_deps_debug
	cd lib && OPTZ="${O0} -ggdb -DDEBUG -DTEST_AURORA -DTEST_GALERA -DTEST_GROUPREP" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_tap_test
build_tap_test: build_src
	cd test/tap && OPTZ="${O0} -ggdb -DDEBUG" CC=${CC} CXX=${CXX} ${MAKE}

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

packages: centos7 centos7-dbg centos7-clickhouse centos8 centos8-dbg centos8-clickhouse ubuntu14 ubuntu14-dbg ubuntu16 ubuntu16-dbg ubuntu16-clickhouse ubuntu18 ubuntu18-dbg ubuntu18-clickhouse debian8 debian8-dbg debian9 debian9-dbg debian9-clickhouse debian10 debian10-dbg debian10-clickhouse fedora24 fedora24-dbg  fedora24-clickhouse fedora27 fedora27-dbg fedora27-clickhouse fedora28 fedora28-dbg fedora28-clickhouse
.PHONY: packages

centos5: binaries/proxysql-${CURVER}-1-centos5.x86_64.rpm
.PHONY: centos5

centos5-dbg: binaries/proxysql-${CURVER}-1-dbg-centos5.x86_64.rpm
.PHONY: centos5-dbg

centos6.7: binaries/proxysql-${CURVER}-1-centos67.x86_64.rpm
.PHONY: centos6.7

centos7: binaries/proxysql-${CURVER}-1-centos7.x86_64.rpm
.PHONY: centos7

centos8: binaries/proxysql-${CURVER}-1-centos8.x86_64.rpm
.PHONY: centos8

centos6.7-dbg: binaries/proxysql-${CURVER}-1-dbg-centos67.x86_64.rpm
.PHONY: centos6.7-dbg

centos7-dbg: binaries/proxysql-${CURVER}-1-dbg-centos7.x86_64.rpm
.PHONY: centos7-dbg

centos8-dbg: binaries/proxysql-${CURVER}-1-dbg-centos8.x86_64.rpm
.PHONY: centos8-dbg

fedora24: binaries/proxysql-${CURVER}-1-fedora24.x86_64.rpm
.PHONY: fedora24

fedora24-dbg: binaries/proxysql-${CURVER}-1-dbg-fedora24.x86_64.rpm
.PHONY: fedora24-dbg

fedora27: binaries/proxysql-${CURVER}-1-fedora27.x86_64.rpm
.PHONY: fedora27

fedora27-dbg: binaries/proxysql-${CURVER}-1-dbg-fedora27.x86_64.rpm
.PHONY: fedora27-dbg

fedora28: binaries/proxysql-${CURVER}-1-fedora28.x86_64.rpm
.PHONY: fedora28

fedora28-dbg: binaries/proxysql-${CURVER}-1-dbg-fedora28.x86_64.rpm
.PHONY: fedora28-dbg

ubuntu14: binaries/proxysql_${CURVER}-ubuntu14_amd64.deb
.PHONY: ubuntu14

ubuntu16: binaries/proxysql_${CURVER}-ubuntu16_amd64.deb
.PHONY: ubuntu16

ubuntu18: binaries/proxysql_${CURVER}-ubuntu18_amd64.deb
.PHONY: ubuntu18

debian7: binaries/proxysql_${CURVER}-debian7_amd64.deb
.PHONY: debian7

debian8: binaries/proxysql_${CURVER}-debian8_amd64.deb
.PHONY: debian8

debian9: binaries/proxysql_${CURVER}-debian9_amd64.deb
.PHONY: debian9

debian10: binaries/proxysql_${CURVER}-debian10_amd64.deb
.PHONY: debian10

ubuntu14-dbg: binaries/proxysql_${CURVER}-dbg-ubuntu14_amd64.deb
.PHONY: ubuntu14-dbg

ubuntu16-dbg: binaries/proxysql_${CURVER}-dbg-ubuntu16_amd64.deb
.PHONY: ubuntu16-dbg

ubuntu18-dbg: binaries/proxysql_${CURVER}-dbg-ubuntu18_amd64.deb
.PHONY: ubuntu18-dbg

ubuntu16-clickhouse: binaries/proxysql_${CURVER}-clickhouse-ubuntu16_amd64.deb
.PHONY: ubuntu16-clickhouse

ubuntu18-clickhouse: binaries/proxysql_${CURVER}-clickhouse-ubuntu18_amd64.deb
.PHONY: ubuntu18-clickhouse

debian7-dbg: binaries/proxysql_${CURVER}-dbg-debian7_amd64.deb
.PHONY: debian7-dbg

debian8-dbg: binaries/proxysql_${CURVER}-dbg-debian8_amd64.deb
.PHONY: debian8-dbg

debian9-dbg: binaries/proxysql_${CURVER}-dbg-debian9_amd64.deb
.PHONY: debian9-dbg

debian9-clickhouse: binaries/proxysql_${CURVER}-clickhouse-debian9_amd64.deb
.PHONY: debian9-clickhouse

debian9.4: binaries/proxysql_${CURVER}-debian9.4_amd64.deb
.PHONY: debian9.4

debian9.4-dbg: binaries/proxysql_${CURVER}-dbg-debian9.4_amd64.deb
.PHONY: debian9.4-dbg

debian9.4-clickhouse: binaries/proxysql_${CURVER}-clickhouse-debian9.4_amd64.deb
.PHONY: debian9.4-clickhouse

debian10-dbg: binaries/proxysql_${CURVER}-dbg-debian10_amd64.deb
.PHONY: debian10-dbg

debian10-clickhouse: binaries/proxysql_${CURVER}-clickhouse-debian10_amd64.deb
.PHONY: debian10-clickhouse

centos7-clickhouse: binaries/proxysql-${CURVER}-clickhouse-1-centos7.x86_64.rpm
.PHONY: centos7-clickhouse

centos8-clickhouse: binaries/proxysql-${CURVER}-clickhouse-1-centos8.x86_64.rpm
.PHONY: centos8-clickhouse

fedora24-clickhouse: binaries/proxysql-${CURVER}-clickhouse-1-fedora24.x86_64.rpm
.PHONY: fedora24-clickhouse

fedora27-clickhouse: binaries/proxysql-${CURVER}-clickhouse-1-fedora27.x86_64.rpm
.PHONY: fedora27-clickhouse

fedora28-clickhouse: binaries/proxysql-${CURVER}-clickhouse-1-fedora28.x86_64.rpm
.PHONY: fedora28-clickhouse

binaries/proxysql-${CURVER}-1-centos5.x86_64.rpm:
	docker-compose up centos5_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-centos5.x86_64.rpm:
	docker-compose up centos5_dbg_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-centos67.x86_64.rpm:
	docker-compose up centos67_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-centos67.x86_64.rpm:
	docker-compose up centos67_dbg_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-centos7.x86_64.rpm:
	docker-compose up centos7_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-clickhouse-1-centos7.x86_64.rpm:
	docker-compose up centos7_ch_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-centos7.x86_64.rpm:
	docker-compose up centos7_dbg_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-centos8.x86_64.rpm:
		docker-compose up centos8_build
		#docker-compose rm -f

binaries/proxysql-${CURVER}-clickhouse-1-centos8.x86_64.rpm:
		docker-compose up centos8_ch_build
		docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-centos8.x86_64.rpm:
		docker-compose up centos8_dbg_build
		docker-compose rm -f

binaries/proxysql-${CURVER}-1-fedora24.x86_64.rpm:
	docker-compose up fedora24_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-clickhouse-1-fedora24.x86_64.rpm:
	docker-compose up fedora24_ch_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-fedora24.x86_64.rpm:
	docker-compose up fedora24_dbg_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-fedora27.x86_64.rpm:
	docker-compose up fedora27_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-clickhouse-1-fedora27.x86_64.rpm:
	docker-compose up fedora27_ch_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-fedora27.x86_64.rpm:
	docker-compose up fedora27_dbg_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-fedora28.x86_64.rpm:
	docker-compose up fedora28_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-clickhouse-1-fedora28.x86_64.rpm:
	docker-compose up fedora28_ch_build
	docker-compose rm -f

binaries/proxysql-${CURVER}-1-dbg-fedora28.x86_64.rpm:
	docker-compose up fedora28_dbg_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-ubuntu12_amd64.deb:
	docker-compose up ubuntu12_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-ubuntu14_amd64.deb:
	docker-compose up ubuntu14_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-ubuntu16_amd64.deb:
	docker-compose up ubuntu16_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-ubuntu18_amd64.deb:
	docker-compose up ubuntu18_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-debian7_amd64.deb:
	docker-compose up debian7_build
	#docker-compose rm -f

binaries/proxysql_${CURVER}-debian8_amd64.deb:
	docker-compose up debian8_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-debian9_amd64.deb:
	docker-compose up debian9_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-debian9.4_amd64.deb:
	docker-compose up debian9_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-debian10_amd64.deb:
	docker-compose up debian10_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-clickhouse-debian9_amd64.deb:
	docker-compose up debian9_ch_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-clickhouse-debian9.4_amd64.deb:
	docker-compose up debian9.4_ch_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-clickhouse-debian10_amd64.deb:
	docker-compose up debian10_ch_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-ubuntu14_amd64.deb:
	docker-compose up ubuntu14_dbg_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-ubuntu16_amd64.deb:
	docker-compose up ubuntu16_dbg_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-clickhouse-ubuntu16_amd64.deb:
	docker-compose up ubuntu16_ch_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-ubuntu18_amd64.deb:
	docker-compose up ubuntu18_dbg_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-clickhouse-ubuntu18_amd64.deb:
	docker-compose up ubuntu18_ch_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-debian7_amd64.deb:
	docker-compose up debian7_dbg_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-debian8_amd64.deb:
	docker-compose up debian8_dbg_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-debian9_amd64.deb:
	docker-compose up debian9_dbg_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-debian9.4_amd64.deb:
	docker-compose up debian9_dbg_build
	docker-compose rm -f

binaries/proxysql_${CURVER}-dbg-debian10_amd64.deb:
	docker-compose up debian10_dbg_build
	docker-compose rm -f

.PHONY: cleanall
cleanall:
	cd deps && ${MAKE} cleanall
	cd lib && ${MAKE} clean
	cd src && ${MAKE} clean
	rm binaries/*deb || true
	rm binaries/*rpm || true

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
