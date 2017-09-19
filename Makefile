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
CURVER?=1.4.4
MAKEOPT=-j 4
DISTRO := $(shell gawk -F= '/^NAME/{print $$2}' /etc/os-release)
ifeq ($(wildcard /usr/lib/systemd/system), /usr/lib/systemd/system)
	SYSTEMD=1
else
	SYSTEMD=0
endif

.PHONY: default
default: build_deps build_lib build_src

.PHONY: debug
debug: build_deps_debug build_lib_debug build_src_debug

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

packages: centos6.7 centos7 centos6.7-dbg centos7-dbg centos5 centos5-dbg ubuntu12 ubuntu14 debian7 debian8 ubuntu14-dbg debian7-dbg debian8-dbg ubuntu16 ubuntu16-dbg fedora24 fedora24-dbg debian9 debian9-dbg ubuntu16-clickhouse debian9-clickhouse centos7-clickhouse fedora24-clickhouse
.PHONY: packages

centos5: binaries/proxysql-${CURVER}-1-centos5.x86_64.rpm
.PHONY: centos5

centos5-dbg: binaries/proxysql-${CURVER}-1-dbg-centos5.x86_64.rpm
.PHONY: centos5-dbg

centos6.7: binaries/proxysql-${CURVER}-1-centos67.x86_64.rpm
.PHONY: centos6.7

centos7: binaries/proxysql-${CURVER}-1-centos7.x86_64.rpm
.PHONY: centos7

centos6.7-dbg: binaries/proxysql-${CURVER}-1-dbg-centos67.x86_64.rpm
.PHONY: centos6.7-dbg

centos7-dbg: binaries/proxysql-${CURVER}-1-dbg-centos7.x86_64.rpm
.PHONY: centos7-dbg

fedora24: binaries/proxysql-${CURVER}-1-fedora24.x86_64.rpm
.PHONY: fedora24

fedora24-dbg: binaries/proxysql-${CURVER}-1-dbg-fedora24.x86_64.rpm
.PHONY: fedora24-dbg

ubuntu12: binaries/proxysql_${CURVER}-ubuntu12_amd64.deb
.PHONY: ubuntu12

ubuntu14: binaries/proxysql_${CURVER}-ubuntu14_amd64.deb
.PHONY: ubuntu14

ubuntu16: binaries/proxysql_${CURVER}-ubuntu16_amd64.deb
.PHONY: ubuntu16

debian7: binaries/proxysql_${CURVER}-debian7_amd64.deb
.PHONY: debian7

debian8: binaries/proxysql_${CURVER}-debian8_amd64.deb
.PHONY: debian8

debian9: binaries/proxysql_${CURVER}-debian9_amd64.deb
.PHONY: debian9

ubuntu14-dbg: binaries/proxysql_${CURVER}-dbg-ubuntu14_amd64.deb
.PHONY: ubuntu14-dbg

ubuntu16-dbg: binaries/proxysql_${CURVER}-dbg-ubuntu16_amd64.deb
.PHONY: ubuntu16-dbg

ubuntu16-clickhouse: binaries/proxysql_${CURVER}-clickhouse-ubuntu16_amd64.deb
.PHONY: ubuntu16-clickhouse

debian7-dbg: binaries/proxysql_${CURVER}-dbg-debian7_amd64.deb
.PHONY: debian7-dbg

debian8-dbg: binaries/proxysql_${CURVER}-dbg-debian8_amd64.deb
.PHONY: debian8-dbg

debian9-dbg: binaries/proxysql_${CURVER}-dbg-debian9_amd64.deb
.PHONY: debian9-dbg

debian9-clickhouse: binaries/proxysql_${CURVER}-clickhouse-debian9_amd64.deb
.PHONY: debian9-clickhouse

centos7-clickhouse: binaries/proxysql-${CURVER}-clickhouse-1-centos7.x86_64.rpm
.PHONY: centos7-clickhouse

fedora24-clickhouse: binaries/proxysql-${CURVER}-clickhouse-1-fedora24.x86_64.rpm
.PHONY: fedora24-clickhouse

binaries/proxysql-${CURVER}-1-centos5.x86_64.rpm:
	docker stop centos5_build || true
	docker rm centos5_build || true
	docker create --name centos5_build renecannao/proxysql:build-centos5 bash -c "while : ; do sleep 10 ; done"
	docker start centos5_build
	docker exec centos5_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	docker exec centos5_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT}"
	docker exec -it centos5_build bash -c "cd /opt/proxysql ; mkdir -p proxysql/usr/bin; mkdir -p proxysql/etc; cp src/proxysql proxysql/usr/bin/; cp -a etc proxysql ; mkdir -p proxysql/usr/share/proxysql/tools ; cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql/usr/share/proxysql/tools ; mv proxysql proxysql-${CURVER} ; tar czvf proxysql-${CURVER}.tar.gz proxysql-${CURVER}"
	docker exec -it centos5_build bash -c "mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}"
	sleep 2
	docker cp docker/images/proxysql/centos5-build/rpmmacros centos5_build:/root/.rpmmacros
	sleep 2
	docker cp docker/images/proxysql/centos5-build/proxysql.spec centos5_build:/root/rpmbuild/SPECS/proxysql.spec
	sleep 10
	docker exec -it centos5_build bash -c "cp /opt/proxysql/proxysql-${CURVER}.tar.gz /root/rpmbuild/SOURCES"
	sleep 2
	docker exec -it centos5_build bash -c "cd /root/rpmbuild; rpmbuild -ba SPECS/proxysql.spec --define \"version ${CURVER}\""
	sleep 10
	docker exec -it centos5_build bash -c "cp /root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm /root/rpm"
	sleep 2
	docker cp centos5_build:/root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm ./binaries/proxysql-${CURVER}-1-centos5.x86_64.rpm
	docker stop centos5_build
	docker rm centos5_build

binaries/proxysql-${CURVER}-1-dbg-centos5.x86_64.rpm:
	docker stop centos5_build || true
	docker rm centos5_build || true
	docker create --name centos5_build renecannao/proxysql:build-centos5 bash -c "while : ; do sleep 10 ; done"
	docker start centos5_build
	docker exec centos5_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec centos5_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT} debug"
	sleep 2
	docker exec -it centos5_build bash -c "cd /opt/proxysql ; mkdir -p proxysql/usr/bin; mkdir -p proxysql/etc; cp src/proxysql proxysql/usr/bin/; cp -a etc proxysql ; mkdir -p proxysql/usr/share/proxysql/tools ; cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql/usr/share/proxysql/tools ; mv proxysql proxysql-${CURVER} ; tar czvf proxysql-${CURVER}.tar.gz proxysql-${CURVER}"
	sleep 2
	docker exec -it centos5_build bash -c "mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}"
	sleep 2
	docker cp docker/images/proxysql/centos5-build/rpmmacros centos5_build:/root/.rpmmacros
	sleep 2
	docker cp docker/images/proxysql/centos5-build/proxysql.spec centos5_build:/root/rpmbuild/SPECS/proxysql.spec
	sleep 10
	docker exec -it centos5_build bash -c "cp /opt/proxysql/proxysql-${CURVER}.tar.gz /root/rpmbuild/SOURCES"
	sleep 2
	docker exec -it centos5_build bash -c "cd /root/rpmbuild; rpmbuild -ba SPECS/proxysql.spec --define \"version ${CURVER}\""
	sleep 10
	docker exec -it centos5_build bash -c "cp /root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm /root/rpm"
	sleep 2
	docker cp centos5_build:/root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm ./binaries/proxysql-${CURVER}-1-dbg-centos5.x86_64.rpm
	docker stop centos5_build
	docker rm centos5_build

binaries/proxysql-${CURVER}-1-centos67.x86_64.rpm:
	docker stop centos67_build || true
	docker rm centos67_build || true
	docker create --name centos67_build renecannao/proxysql:build-centos6.7 bash -c "while : ; do sleep 10 ; done"
	docker start centos67_build
	docker exec centos67_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	docker exec centos67_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT}"
	docker exec -it centos67_build bash -c "cd /opt/proxysql ; mkdir -p proxysql/usr/bin; mkdir -p proxysql/etc; cp src/proxysql proxysql/usr/bin/; cp -a etc proxysql ; mkdir -p proxysql/usr/share/proxysql/tools ; cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql/usr/share/proxysql/tools ; mv proxysql proxysql-${CURVER} ; tar czvf proxysql-${CURVER}.tar.gz proxysql-${CURVER}"
	docker exec -it centos67_build bash -c "mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}"
	docker cp docker/images/proxysql/centos67-build/rpmmacros centos67_build:/root/.rpmmacros
	docker cp docker/images/proxysql/centos67-build/proxysql.spec centos67_build:/root/rpmbuild/SPECS/proxysql.spec
	sleep 10
	docker exec -it centos67_build bash -c "cp /opt/proxysql/proxysql-${CURVER}.tar.gz /root/rpmbuild/SOURCES"
	sleep 2
	docker exec -it centos67_build bash -c "cd /root/rpmbuild; rpmbuild -ba SPECS/proxysql.spec --define \"version ${CURVER}\""
	sleep 10
	docker exec -it centos67_build bash -c "cp /root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm /root/rpm"
	sleep 2
	docker cp centos67_build:/root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm ./binaries/proxysql-${CURVER}-1-centos67.x86_64.rpm
	docker stop centos67_build
	docker rm centos67_build

binaries/proxysql-${CURVER}-1-dbg-centos67.x86_64.rpm:
	docker stop centos67_build || true
	docker rm centos67_build || true
	docker create --name centos67_build renecannao/proxysql:build-centos6.7 bash -c "while : ; do sleep 10 ; done"
	docker start centos67_build
	docker exec centos67_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec centos67_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT} debug"
	sleep 2
	docker exec -it centos67_build bash -c "cd /opt/proxysql ; mkdir -p proxysql/usr/bin; mkdir -p proxysql/etc; cp src/proxysql proxysql/usr/bin/; cp -a etc proxysql ; mkdir -p proxysql/usr/share/proxysql/tools ; cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql/usr/share/proxysql/tools ; mv proxysql proxysql-${CURVER} ; tar czvf proxysql-${CURVER}.tar.gz proxysql-${CURVER}"
	sleep 2
	docker exec -it centos67_build bash -c "mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}"
	sleep 2
	docker cp docker/images/proxysql/centos67-build/rpmmacros centos67_build:/root/.rpmmacros
	sleep 2
	docker cp docker/images/proxysql/centos67-build/proxysql.spec centos67_build:/root/rpmbuild/SPECS/proxysql.spec
	sleep 10
	docker exec -it centos67_build bash -c "cp /opt/proxysql/proxysql-${CURVER}.tar.gz /root/rpmbuild/SOURCES"
	sleep 2
	docker exec -it centos67_build bash -c "cd /root/rpmbuild; rpmbuild -ba SPECS/proxysql.spec --define \"version ${CURVER}\""
	sleep 10
	docker exec -it centos67_build bash -c "cp /root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm /root/rpm"
	sleep 2
	docker cp centos67_build:/root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm ./binaries/proxysql-${CURVER}-1-dbg-centos67.x86_64.rpm
	docker stop centos67_build
	docker rm centos67_build

binaries/proxysql-${CURVER}-1-centos7.x86_64.rpm:
	docker stop centos7_build || true
	docker rm centos7_build || true
	docker create --name centos7_build renecannao/proxysql:build-centos7 bash -c "while : ; do sleep 10 ; done"
	docker start centos7_build
	docker exec centos7_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec centos7_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT}"
	sleep 2
	docker exec -it centos7_build bash -c "cd /opt/proxysql ; mkdir -p proxysql/usr/bin; mkdir -p proxysql/etc; cp src/proxysql proxysql/usr/bin/; cp -a etc proxysql ; mkdir -p proxysql/usr/share/proxysql/tools ; cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql/usr/share/proxysql/tools ; mv proxysql proxysql-${CURVER} ; tar czvf proxysql-${CURVER}.tar.gz proxysql-${CURVER}"
	sleep 2
	docker exec -it centos7_build bash -c "mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}"
	sleep 2
	docker cp docker/images/proxysql/centos7-build/rpmmacros centos7_build:/root/.rpmmacros
	sleep 2
	docker cp docker/images/proxysql/centos7-build/proxysql.spec centos7_build:/root/rpmbuild/SPECS/proxysql.spec
	sleep 10
	docker exec -it centos7_build bash -c "cp /opt/proxysql/proxysql-${CURVER}.tar.gz /root/rpmbuild/SOURCES"
	sleep 2
	docker exec -it centos7_build bash -c "cd /root/rpmbuild; rpmbuild -ba SPECS/proxysql.spec --define \"version ${CURVER}\""
	sleep 10
	docker exec -it centos7_build bash -c "cp /root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm /root/rpm"
	sleep 2
	docker cp centos7_build:/root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm ./binaries/proxysql-${CURVER}-1-centos7.x86_64.rpm
	docker stop centos7_build
	docker rm centos7_build

binaries/proxysql-${CURVER}-clickhouse-1-centos7.x86_64.rpm:
	docker stop centos7_build || true
	docker rm centos7_build || true
	docker create --name centos7_build renecannao/proxysql:build-centos7 bash -c "while : ; do sleep 10 ; done"
	docker start centos7_build
	docker exec centos7_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec centos7_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps_clickhouse && ${MAKE} clickhouse ${MAKEOPT}"
	sleep 2
	docker exec -it centos7_build bash -c "cd /opt/proxysql ; mkdir -p proxysql/usr/bin; mkdir -p proxysql/etc; cp src/proxysql proxysql/usr/bin/; cp -a etc proxysql ; mkdir -p proxysql/usr/share/proxysql/tools ; cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql/usr/share/proxysql/tools ; mv proxysql proxysql-${CURVER} ; tar czvf proxysql-${CURVER}.tar.gz proxysql-${CURVER}"
	sleep 2
	docker exec -it centos7_build bash -c "mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}"
	sleep 2
	docker cp docker/images/proxysql/centos7-build/rpmmacros centos7_build:/root/.rpmmacros
	sleep 2
	docker cp docker/images/proxysql/centos7-build/proxysql.spec centos7_build:/root/rpmbuild/SPECS/proxysql.spec
	sleep 10
	docker exec -it centos7_build bash -c "cp /opt/proxysql/proxysql-${CURVER}.tar.gz /root/rpmbuild/SOURCES"
	sleep 2
	docker exec -it centos7_build bash -c "cd /root/rpmbuild; rpmbuild -ba SPECS/proxysql.spec --define \"version ${CURVER}\""
	sleep 10
	docker exec -it centos7_build bash -c "cp /root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm /root/rpm"
	sleep 2
	docker cp centos7_build:/root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm ./binaries/proxysql-${CURVER}-clickhouse-1-centos7.x86_64.rpm
	docker stop centos7_build
	docker rm centos7_build

binaries/proxysql-${CURVER}-1-dbg-centos7.x86_64.rpm:
	docker stop centos7_build || true
	docker rm centos7_build || true
	docker create --name centos7_build renecannao/proxysql:build-centos7 bash -c "while : ; do sleep 10 ; done"
	docker start centos7_build
	docker exec centos7_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec centos7_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT} debug"
	sleep 2
	docker exec -it centos7_build bash -c "cd /opt/proxysql ; mkdir -p proxysql/usr/bin; mkdir -p proxysql/etc; cp src/proxysql proxysql/usr/bin/; cp -a etc proxysql ; mkdir -p proxysql/usr/share/proxysql/tools ; cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql/usr/share/proxysql/tools ; mv proxysql proxysql-${CURVER} ; tar czvf proxysql-${CURVER}.tar.gz proxysql-${CURVER}"
	sleep 2
	docker exec -it centos7_build bash -c "mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}"
	sleep 2
	docker cp docker/images/proxysql/centos7-build/rpmmacros centos7_build:/root/.rpmmacros
	sleep 2
	docker cp docker/images/proxysql/centos7-build/proxysql.spec centos7_build:/root/rpmbuild/SPECS/proxysql.spec
	sleep 10
	docker exec -it centos7_build bash -c "cp /opt/proxysql/proxysql-${CURVER}.tar.gz /root/rpmbuild/SOURCES"
	sleep 2
	docker exec -it centos7_build bash -c "cd /root/rpmbuild; rpmbuild -ba SPECS/proxysql.spec --define \"version ${CURVER}\""
	sleep 10
	docker exec -it centos7_build bash -c "cp /root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm /root/rpm"
	sleep 2
	docker cp centos7_build:/root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm ./binaries/proxysql-${CURVER}-1-dbg-centos7.x86_64.rpm
	docker stop centos7_build
	docker rm centos7_build


binaries/proxysql-${CURVER}-1-fedora24.x86_64.rpm:
	docker stop fedora24_build || true
	docker rm fedora24_build || true
	docker create --name fedora24_build renecannao/proxysql:build-fedora24 bash -c "while : ; do sleep 10 ; done"
	docker start fedora24_build
	docker exec fedora24_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec fedora24_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT}"
	sleep 2
	docker exec -it fedora24_build bash -c "cd /opt/proxysql ; mkdir -p proxysql/usr/bin; mkdir -p proxysql/etc; cp src/proxysql proxysql/usr/bin/; cp -a etc proxysql ; mkdir -p proxysql/usr/share/proxysql/tools ; cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql/usr/share/proxysql/tools ; mv proxysql proxysql-${CURVER} ; tar czvf proxysql-${CURVER}.tar.gz proxysql-${CURVER}"
	sleep 2
	docker exec -it fedora24_build bash -c "mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}"
	sleep 2
	docker cp docker/images/proxysql/fedora24-build/rpmmacros fedora24_build:/root/.rpmmacros
	sleep 2
	docker cp docker/images/proxysql/fedora24-build/proxysql.spec fedora24_build:/root/rpmbuild/SPECS/proxysql.spec
	sleep 10
	docker exec -it fedora24_build bash -c "cp /opt/proxysql/proxysql-${CURVER}.tar.gz /root/rpmbuild/SOURCES"
	sleep 2
	docker exec -it fedora24_build bash -c "cd /root/rpmbuild; rpmbuild -ba SPECS/proxysql.spec --define \"version ${CURVER}\""
	sleep 10
	docker exec -it fedora24_build bash -c "cp /root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm /root/rpm"
	sleep 2
	docker cp fedora24_build:/root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm ./binaries/proxysql-${CURVER}-1-fedora24.x86_64.rpm
	docker stop fedora24_build
	docker rm fedora24_build

binaries/proxysql-${CURVER}-clickhouse-1-fedora24.x86_64.rpm:
	docker stop fedora24_build || true
	docker rm fedora24_build || true
	docker create --name fedora24_build renecannao/proxysql:build-fedora24 bash -c "while : ; do sleep 10 ; done"
	docker start fedora24_build
	docker exec fedora24_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec fedora24_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps_clickhouse && ${MAKE} clickhouse ${MAKEOPT}"
	sleep 2
	docker exec -it fedora24_build bash -c "cd /opt/proxysql ; mkdir -p proxysql/usr/bin; mkdir -p proxysql/etc; cp src/proxysql proxysql/usr/bin/; cp -a etc proxysql ; mkdir -p proxysql/usr/share/proxysql/tools ; cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql/usr/share/proxysql/tools ; mv proxysql proxysql-${CURVER} ; tar czvf proxysql-${CURVER}.tar.gz proxysql-${CURVER}"
	sleep 2
	docker exec -it fedora24_build bash -c "mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}"
	sleep 2
	docker cp docker/images/proxysql/fedora24-build/rpmmacros fedora24_build:/root/.rpmmacros
	sleep 2
	docker cp docker/images/proxysql/fedora24-build/proxysql.spec fedora24_build:/root/rpmbuild/SPECS/proxysql.spec
	sleep 10
	docker exec -it fedora24_build bash -c "cp /opt/proxysql/proxysql-${CURVER}.tar.gz /root/rpmbuild/SOURCES"
	sleep 2
	docker exec -it fedora24_build bash -c "cd /root/rpmbuild; rpmbuild -ba SPECS/proxysql.spec --define \"version ${CURVER}\""
	sleep 10
	docker exec -it fedora24_build bash -c "cp /root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm /root/rpm"
	sleep 2
	docker cp fedora24_build:/root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm ./binaries/proxysql-${CURVER}-clickhouse-1-fedora24.x86_64.rpm
	docker stop fedora24_build
	docker rm fedora24_build

binaries/proxysql-${CURVER}-1-dbg-fedora24.x86_64.rpm:
	docker stop fedora24_build || true
	docker rm fedora24_build || true
	docker create --name fedora24_build renecannao/proxysql:build-fedora24 bash -c "while : ; do sleep 10 ; done"
	docker start fedora24_build
	docker exec fedora24_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec fedora24_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT} debug"
	sleep 2
	docker exec -it fedora24_build bash -c "cd /opt/proxysql ; mkdir -p proxysql/usr/bin; mkdir -p proxysql/etc; cp src/proxysql proxysql/usr/bin/; cp -a etc proxysql ; mkdir -p proxysql/usr/share/proxysql/tools ; cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql/usr/share/proxysql/tools ; mv proxysql proxysql-${CURVER} ; tar czvf proxysql-${CURVER}.tar.gz proxysql-${CURVER}"
	sleep 2
	docker exec -it fedora24_build bash -c "mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}"
	sleep 2
	docker cp docker/images/proxysql/fedora24-build/rpmmacros fedora24_build:/root/.rpmmacros
	sleep 2
	docker cp docker/images/proxysql/fedora24-build/proxysql.spec fedora24_build:/root/rpmbuild/SPECS/proxysql.spec
	sleep 10
	docker exec -it fedora24_build bash -c "cp /opt/proxysql/proxysql-${CURVER}.tar.gz /root/rpmbuild/SOURCES"
	sleep 2
	docker exec -it fedora24_build bash -c "cd /root/rpmbuild; rpmbuild -ba SPECS/proxysql.spec --define \"version ${CURVER}\""
	sleep 10
	docker exec -it fedora24_build bash -c "cp /root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm /root/rpm"
	sleep 2
	docker cp fedora24_build:/root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm ./binaries/proxysql-${CURVER}-1-dbg-fedora24.x86_64.rpm
	docker stop fedora24_build
	docker rm fedora24_build

binaries/proxysql_${CURVER}-ubuntu12_amd64.deb:
	docker stop ubuntu12_build || true
	docker rm ubuntu12_build || true
	docker create --name ubuntu12_build renecannao/proxysql:build-ubuntu12 bash -c "while : ; do sleep 10 ; done"
	docker start ubuntu12_build
	docker exec ubuntu12_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec ubuntu12_build bash -c "cd /opt/proxysql; sed -i -e 's/c++11/c++0x/' lib/Makefile ; sed -i -e 's/c++11/c++0x/' src/Makefile"
	docker exec ubuntu12_build bash -c "cd /opt/proxysql/deps/re2 ; rm re2.tar.gz ; wget -O re2.tar.gz https://github.com/sysown/proxysql/raw/v1.3.9/deps/re2/re2-20140304.tgz"
	docker exec ubuntu12_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT}"
	sleep 2
	docker cp docker/images/proxysql/ubuntu-12.04-build/proxysql.ctl ubuntu12_build:/opt/proxysql/
	sleep 2
	docker exec ubuntu12_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	sleep 2
	docker cp ubuntu12_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-ubuntu12_amd64.deb
	docker stop ubuntu12_build
	docker rm ubuntu12_build

binaries/proxysql_${CURVER}-ubuntu14_amd64.deb:
	docker stop ubuntu14_build || true
	docker rm ubuntu14_build || true
	docker create --name ubuntu14_build renecannao/proxysql:build-ubuntu14 bash -c "while : ; do sleep 10 ; done"
	docker start ubuntu14_build
	docker exec ubuntu14_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec ubuntu14_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT}"
	sleep 2
	docker cp docker/images/proxysql/ubuntu-14.04-build/proxysql.ctl ubuntu14_build:/opt/proxysql/
	sleep 2
	docker exec ubuntu14_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	sleep 2
	docker cp ubuntu14_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-ubuntu14_amd64.deb
	docker stop ubuntu14_build
	docker rm ubuntu14_build

binaries/proxysql_${CURVER}-ubuntu16_amd64.deb:
	docker stop ubuntu16_build || true
	docker rm ubuntu16_build || true
	docker create --name ubuntu16_build renecannao/proxysql:build-ubuntu16 bash -c "while : ; do sleep 10 ; done"
	docker start ubuntu16_build
	docker exec ubuntu16_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec ubuntu16_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT}"
	sleep 2
	docker cp docker/images/proxysql/ubuntu-16.04-build/proxysql.ctl ubuntu16_build:/opt/proxysql/
	sleep 2
	docker exec ubuntu16_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	sleep 2
	docker cp ubuntu16_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-ubuntu16_amd64.deb
	docker stop ubuntu16_build
	docker rm ubuntu16_build

binaries/proxysql_${CURVER}-debian7_amd64.deb:
	docker stop debian7_build || true
	docker rm debian7_build || true
	docker create --name debian7_build renecannao/proxysql:build-debian7 bash -c "while : ; do sleep 10 ; done"
	docker start debian7_build
	docker exec debian7_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec debian7_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT}"
	sleep 2
	docker cp docker/images/proxysql/debian-7.8-build/proxysql.ctl debian7_build:/opt/proxysql/
	sleep 2
	docker exec debian7_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	sleep 2
	docker cp debian7_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-debian7_amd64.deb
	docker stop debian7_build
	docker rm debian7_build

binaries/proxysql_${CURVER}-debian8_amd64.deb:
	docker stop debian8_build || true
	docker rm debian8_build || true
	docker create --name debian8_build renecannao/proxysql:build-debian8 bash -c "while : ; do sleep 10 ; done"
	docker start debian8_build
	docker exec debian8_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec debian8_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT}"
	sleep 2
	docker cp docker/images/proxysql/debian-8.2-build/proxysql.ctl debian8_build:/opt/proxysql/
	sleep 2
	docker exec debian8_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	sleep 2
	docker cp debian8_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-debian8_amd64.deb
	docker stop debian8_build
	docker rm debian8_build

binaries/proxysql_${CURVER}-debian9_amd64.deb:
	docker stop debian9_build || true
	docker rm debian9_build || true
	docker create --name debian9_build renecannao/proxysql:build-debian9 bash -c "while : ; do sleep 10 ; done"
	docker start debian9_build
	docker exec debian9_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec debian9_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT}"
	sleep 2
	docker cp docker/images/proxysql/debian-9-build/proxysql.ctl debian9_build:/opt/proxysql/
	sleep 2
	docker exec debian9_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	sleep 2
	docker cp debian9_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-debian9_amd64.deb
	docker stop debian9_build
	docker rm debian9_build

binaries/proxysql_${CURVER}-clickhouse-debian9_amd64.deb:
	docker stop debian9_build || true
	docker rm debian9_build || true
	docker create --name debian9_build renecannao/proxysql:build-debian9 bash -c "while : ; do sleep 10 ; done"
	docker start debian9_build
	docker exec debian9_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec debian9_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps_clickhouse && ${MAKE} clickhouse ${MAKEOPT}"
	sleep 2
	docker cp docker/images/proxysql/debian-9-build/proxysql.ctl debian9_build:/opt/proxysql/
	sleep 2
	docker exec debian9_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	sleep 2
	docker cp debian9_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-clickhouse-debian9_amd64.deb
	docker stop debian9_build
	docker rm debian9_build

binaries/proxysql_${CURVER}-dbg-ubuntu14_amd64.deb:
	docker stop ubuntu14_build || true
	docker rm ubuntu14_build || true
	docker create --name ubuntu14_build renecannao/proxysql:build-ubuntu14 bash -c "while : ; do sleep 10 ; done"
	docker start ubuntu14_build
	docker exec ubuntu14_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec ubuntu14_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT} debug"
	sleep 2
	docker cp docker/images/proxysql/ubuntu-14.04-build/proxysql.ctl ubuntu14_build:/opt/proxysql/
	sleep 2
	docker exec ubuntu14_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	sleep 2
	docker cp ubuntu14_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-dbg-ubuntu14_amd64.deb
	docker stop ubuntu14_build
	docker rm ubuntu14_build

binaries/proxysql_${CURVER}-dbg-ubuntu16_amd64.deb:
	docker stop ubuntu16_build || true
	docker rm ubuntu16_build || true
	docker create --name ubuntu16_build renecannao/proxysql:build-ubuntu16 bash -c "while : ; do sleep 10 ; done"
	docker start ubuntu16_build
	docker exec ubuntu16_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec ubuntu16_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT} debug"
	sleep 2
	docker cp docker/images/proxysql/ubuntu-16.04-build/proxysql.ctl ubuntu16_build:/opt/proxysql/
	sleep 2
	docker exec ubuntu16_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	sleep 2
	docker cp ubuntu16_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-dbg-ubuntu16_amd64.deb
	docker stop ubuntu16_build
	docker rm ubuntu16_build

binaries/proxysql_${CURVER}-clickhouse-ubuntu16_amd64.deb:
	docker stop ubuntu16_build || true
	docker rm ubuntu16_build || true
	docker create --name ubuntu16_build renecannao/proxysql:build-ubuntu16 bash -c "while : ; do sleep 10 ; done"
	docker start ubuntu16_build
	docker exec ubuntu16_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec ubuntu16_build bash --login -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps_clickhouse && ${MAKE} clickhouse ${MAKEOPT}"
	sleep 2
	docker cp docker/images/proxysql/ubuntu-16.04-build/proxysql.ctl ubuntu16_build:/opt/proxysql/
	sleep 2
	docker exec ubuntu16_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	sleep 2
	docker cp ubuntu16_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-clickhouse-ubuntu16_amd64.deb
	docker stop ubuntu16_build
	docker rm ubuntu16_build

binaries/proxysql_${CURVER}-dbg-debian7_amd64.deb:
	docker stop debian7_build || true
	docker rm debian7_build || true
	docker create --name debian7_build renecannao/proxysql:build-debian7 bash -c "while : ; do sleep 10 ; done"
	docker start debian7_build
	docker exec debian7_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec debian7_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT} debug"
	sleep 2
	docker cp docker/images/proxysql/debian-7.8-build/proxysql.ctl debian7_build:/opt/proxysql/
	sleep 2
	docker exec debian7_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	sleep 2
	docker cp debian7_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-dbg-debian7_amd64.deb
	docker stop debian7_build
	docker rm debian7_build

binaries/proxysql_${CURVER}-dbg-debian8_amd64.deb:
	docker stop debian8_build || true
	docker rm debian8_build || true
	docker create --name debian8_build renecannao/proxysql:build-debian8 bash -c "while : ; do sleep 10 ; done"
	docker start debian8_build
	docker exec debian8_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec debian8_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT} debug"
	sleep 2
	docker cp docker/images/proxysql/debian-8.2-build/proxysql.ctl debian8_build:/opt/proxysql/
	sleep 2
	docker exec debian8_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	sleep 2
	docker cp debian8_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-dbg-debian8_amd64.deb
	docker stop debian8_build
	docker rm debian8_build

binaries/proxysql_${CURVER}-dbg-debian9_amd64.deb:
	docker stop debian9_build || true
	docker rm debian9_build || true
	docker create --name debian9_build renecannao/proxysql:build-debian8 bash -c "while : ; do sleep 10 ; done"
	docker start debian9_build
	docker exec debian9_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	sleep 2
	docker exec debian9_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} ${MAKEOPT} build_deps && ${MAKE} ${MAKEOPT} debug"
	sleep 2
	docker cp docker/images/proxysql/debian-9-build/proxysql.ctl debian9_build:/opt/proxysql/
	sleep 2
	docker exec debian9_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	sleep 2
	docker cp debian9_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-dbg-debian9_amd64.deb
	docker stop debian9_build
	docker rm debian9_build


.PHONY: cleanall
cleanall:
	cd deps && ${MAKE} cleanall
	cd lib && ${MAKE} clean
	cd src && ${MAKE} clean
	rm binaries/*deb || true
	rm binaries/*rpm || true

install: src/proxysql
	install -m 0755 src/proxysql /usr/bin
	install -m 0600 etc/proxysql.cnf /etc
	if [ ! -d /var/lib/proxysql ]; then mkdir /var/lib/proxysql ; fi
ifeq ($(SYSTEMD), 1)
	install -m 0644 systemd/proxysql.service /usr/lib/systemd/system/
	systemctl daemon-reload
	systemctl enable proxysql.service
else
	install -m 0755 etc/init.d/proxysql /etc/init.d
ifeq ($(DISTRO),"CentOS Linux")
		chkconfig --level 0123456 proxysql on
else
ifeq ($(DISTRO),"Red Hat Enterprise Linux Server")
		chkconfig --level 0123456 proxysql on
else
		update-rc.d proxysql defaults
endif
endif
endif
.PHONY: install

uninstall:
	rm /etc/proxysql.cnf
	rm /usr/bin/proxysql
	rmdir /var/lib/proxysql 2>/dev/null || true
ifeq ($(SYSTEMD), 1)
		systemctl stop proxysql.service
		rm /usr/lib/systemd/system/proxysql.service
else
ifeq ($(DISTRO),"CentOS Linux")
		chkconfig --level 0123456 proxysql off
		rm /etc/init.d/proxysql
else
ifeq ($(DISTRO),"Red Hat Enterprise Linux Server")
		chkconfig --level 0123456 proxysql off
		rm /etc/init.d/proxysql
else
		rm /etc/init.d/proxysql
		update-rc.d proxysql remove
endif
endif
endif
.PHONY: uninstall
