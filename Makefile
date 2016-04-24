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
CURVER=1.2.0

.PHONY: default
default: build_deps build_lib build_src

.PHONY: debug
debug: build_deps_debug build_lib_debug build_src_debug

.PHONY: build_deps
build_deps:
	cd deps && OPTZ="${O2} -ggdb" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib
build_lib:
	cd lib && OPTZ="${O2} -ggdb" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src
build_src:
	cd src && OPTZ="${O2} -ggdb" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_deps_debug
build_deps_debug:
	cd deps && OPTZ="${O0} -ggdb -DDEBUG" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_lib_debug
build_lib_debug:
	cd lib && OPTZ="${O0} -ggdb -DDEBUG" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: build_src_debug
build_src_debug:
	cd src && OPTZ="${O0} -ggdb -DDEBUG" CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: clean
clean:
	cd lib && ${MAKE} clean
	cd src && ${MAKE} clean

packages: centos6.7 centos7 ubuntu12 ubuntu14 debian7 debian8 ubuntu12-dbg ubuntu14-dbg debian7-dbg debian8-dbg
.PHONY: packages


centos6.7: binaries/proxysql-${CURVER}-1-centos67.x86_64.rpm
.PHONY: centos6.7

centos7: binaries/proxysql-${CURVER}-1.x86_64.rpm
.PHONY: centos

ubuntu12: binaries/proxysql_${CURVER}-ubuntu12_amd64.deb
.PHONY: ubuntu12

ubuntu14: binaries/proxysql_${CURVER}-ubuntu14_amd64.deb
.PHONY: ubuntu14

debian7: binaries/proxysql_${CURVER}-debian7_amd64.deb
.PHONY: debian7

debian8: binaries/proxysql_${CURVER}-debian8_amd64.deb
.PHONY: debian8

ubuntu12-dbg: binaries/proxysql_${CURVER}-dbg-ubuntu12_amd64.deb
.PHONY: ubuntu12-dbg

ubuntu14-dbg: binaries/proxysql_${CURVER}-dbg-ubuntu14_amd64.deb
.PHONY: ubuntu14-dbg

debian7-dbg: binaries/proxysql_${CURVER}-dbg-debian7_amd64.deb
.PHONY: debian7-dbg

debian8-dbg: binaries/proxysql_${CURVER}-dbg-debian8_amd64.deb
.PHONY: debian8-dbg

binaries/proxysql-v${CURVER}-1.x86_64.rpm:
	# Create CentOS 7 rpm file by creating docker image, running a container and extracting the RPM from the temp container
	docker build -t centos7_proxysql --no-cache=true ./docker/images/proxysql/centos7-build
	docker run -i --name=centos7_build centos7_proxysql bash &
	sleep 5
	docker cp centos7_build:/root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm ./binaries
#	docker kill centos7_build
	docker rm centos7_build

binaries/proxysql-${CURVER}-1-centos67.x86_64.rpm:
	docker stop centos67_build || true
	docker rm centos67_build || true
	docker create --name centos67_build renecannao/proxysql:build-centos67 bash -c "while : ; do sleep 10 ; done"
	docker start centos67_build
	docker exec centos67_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	docker exec centos67_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} -j 4 build_deps && ${MAKE}"
	docker exec -it centos67_build bash -c "cd /opt/proxysql ; mkdir -p proxysql/usr/bin; mkdir -p proxysql/etc; cp src/proxysql proxysql/usr/bin/; cp -a etc proxysql ; mv proxysql proxysql-${CURVER} ; tar czvf proxysql-${CURVER}.tar.gz proxysql-${CURVER}"
	docker exec -it centos67_build bash -c "mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}"
	docker cp docker/images/proxysql/centos67-build/rpmmacros centos67_build:/root/.rpmmacros
	docker cp docker/images/proxysql/centos67-build/proxysql.spec centos67_build:/root/rpmbuild/SPECS/proxysql.spec
	docker exec -it centos67_build bash -c "cp /opt/proxysql/proxysql-${CURVER}.tar.gz /root/rpmbuild/SOURCES"
	docker exec -it centos67_build bash -c "cd /root/rpmbuild; rpmbuild -ba SPECS/proxysql.spec"
	docker exec -it centos67_build bash -c "cp /root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm /root/rpm"
	docker cp centos67_build:/root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm ./binaries/proxysql-${CURVER}-1-centos67.x86_64.rpm
	docker stop centos67_build
	docker rm centos67_build

binaries/proxysql_${CURVER}-ubuntu12_amd64.deb:
	docker stop ubuntu12_build || true
	docker rm ubuntu12_build || true
	docker create --name ubuntu12_build renecannao/proxysql:build-ubuntu12 bash -c "while : ; do sleep 10 ; done"
	docker start ubuntu12_build
	docker exec ubuntu12_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	docker exec ubuntu12_build bash -c "cd /opt/proxysql; sed -i -e 's/c++11/c++0x/' lib/Makefile ; sed -i -e 's/c++11/c++0x/' src/Makefile ; ${MAKE} clean && ${MAKE} -j 4 build_deps && ${MAKE} -j 4"
	docker cp docker/images/proxysql/ubuntu-12.04-build/proxysql.ctl ubuntu12_build:/opt/proxysql/
	docker exec ubuntu12_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	docker cp ubuntu12_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-ubuntu12_amd64.deb
	docker stop ubuntu12_build
	docker rm ubuntu12_build

binaries/proxysql_${CURVER}-ubuntu14_amd64.deb:
	docker stop ubuntu14_build || true
	docker rm ubuntu14_build || true
	docker create --name ubuntu14_build renecannao/proxysql:build-ubuntu14 bash -c "while : ; do sleep 10 ; done"
	docker start ubuntu14_build
	docker exec ubuntu14_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	docker exec ubuntu14_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} -j 4 build_deps && ${MAKE} -j 4"
	docker cp docker/images/proxysql/ubuntu-14.04-build/proxysql.ctl ubuntu14_build:/opt/proxysql/
	docker exec ubuntu14_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	docker cp ubuntu14_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-ubuntu14_amd64.deb
	docker stop ubuntu14_build
	docker rm ubuntu14_build

binaries/proxysql_${CURVER}-debian7_amd64.deb:
	docker stop debian7_build || true
	docker rm debian7_build || true
	docker create --name debian7_build renecannao/proxysql:build-debian7 bash -c "while : ; do sleep 10 ; done"
	docker start debian7_build
	docker exec debian7_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	docker exec debian7_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} -j 4 build_deps && ${MAKE} -j 4"
	docker cp docker/images/proxysql/debian-7.8-build/proxysql.ctl debian7_build:/opt/proxysql/
	docker exec debian7_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	docker cp debian7_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-debian7_amd64.deb
	docker stop debian7_build
	docker rm debian7_build

binaries/proxysql_${CURVER}-debian8_amd64.deb:
	docker stop debian8_build || true
	docker rm debian8_build || true
	docker create --name debian8_build renecannao/proxysql:build-debian8 bash -c "while : ; do sleep 10 ; done"
	docker start debian8_build
	docker exec debian8_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	docker exec debian8_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} -j 4 build_deps && ${MAKE} -j 4"
	docker cp docker/images/proxysql/debian-8.2-build/proxysql.ctl debian8_build:/opt/proxysql/
	docker exec debian8_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	docker cp debian8_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-debian8_amd64.deb
	docker stop debian8_build
	docker rm debian8_build


binaries/proxysql_${CURVER}-dbg-ubuntu12_amd64.deb:
	docker stop ubuntu12_build || true
	docker rm ubuntu12_build || true
	docker create --name ubuntu12_build renecannao/proxysql:build-ubuntu12 bash -c "while : ; do sleep 10 ; done"
	docker start ubuntu12_build
	docker exec ubuntu12_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	docker exec ubuntu12_build bash -c "cd /opt/proxysql; sed -i -e 's/c++11/c++0x/' lib/Makefile ; sed -i -e 's/c++11/c++0x/' src/Makefile ; ${MAKE} clean && ${MAKE} -j 4 build_deps && ${MAKE} -j 4 debug"
	docker cp docker/images/proxysql/ubuntu-12.04-build/proxysql.ctl ubuntu12_build:/opt/proxysql/
	docker exec ubuntu12_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	docker cp ubuntu12_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-dbg-ubuntu12_amd64.deb
	docker stop ubuntu12_build
	docker rm ubuntu12_build

binaries/proxysql_${CURVER}-dbg-ubuntu14_amd64.deb:
	docker stop ubuntu14_build || true
	docker rm ubuntu14_build || true
	docker create --name ubuntu14_build renecannao/proxysql:build-ubuntu14 bash -c "while : ; do sleep 10 ; done"
	docker start ubuntu14_build
	docker exec ubuntu14_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	docker exec ubuntu14_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} -j 4 build_deps && ${MAKE} -j 4 debug"
	docker cp docker/images/proxysql/ubuntu-14.04-build/proxysql.ctl ubuntu14_build:/opt/proxysql/
	docker exec ubuntu14_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	docker cp ubuntu14_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-dbg-ubuntu14_amd64.deb
	docker stop ubuntu14_build
	docker rm ubuntu14_build

binaries/proxysql_${CURVER}-dbg-debian7_amd64.deb:
	docker stop debian7_build || true
	docker rm debian7_build || true
	docker create --name debian7_build renecannao/proxysql:build-debian7 bash -c "while : ; do sleep 10 ; done"
	docker start debian7_build
	docker exec debian7_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	docker exec debian7_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} -j 4 build_deps && ${MAKE} -j 4 debug"
	docker cp docker/images/proxysql/debian-7.8-build/proxysql.ctl debian7_build:/opt/proxysql/
	docker exec debian7_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	docker cp debian7_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-dbg-debian7_amd64.deb
	docker stop debian7_build
	docker rm debian7_build

binaries/proxysql_${CURVER}-dbg-debian8_amd64.deb:
	docker stop debian8_build || true
	docker rm debian8_build || true
	docker create --name debian8_build renecannao/proxysql:build-debian8 bash -c "while : ; do sleep 10 ; done"
	docker start debian8_build
	docker exec debian8_build bash -c "cd /opt; git clone -b v${CURVER} https://github.com/sysown/proxysql.git proxysql"
	docker exec debian8_build bash -c "cd /opt/proxysql; ${MAKE} clean && ${MAKE} -j 4 build_deps && ${MAKE} -j 4 debug"
	docker cp docker/images/proxysql/debian-8.2-build/proxysql.ctl debian8_build:/opt/proxysql/
	docker exec debian8_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	docker cp debian8_build:/opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-dbg-debian8_amd64.deb
	docker stop debian8_build
	docker rm debian8_build


.PHONY: cleanall
cleanall:
	cd deps && ${MAKE} cleanall
	cd lib && ${MAKE} clean
	cd src && ${MAKE} clean
	rm binaries/*deb || true
	rm binaries/*rpm || true

install: src/proxysql
	install -m 0755 src/proxysql /usr/local/bin
	install -m 0600 etc/proxysql.cnf /etc
	install -m 0755 etc/init.d/proxysql /etc/init.d
	if [ ! -d /var/lib/proxysql ]; then mkdir /var/lib/proxysql ; fi
	update-rc.d proxysql defaults
.PHONY: install

uninstall:
	rm /etc/init.d/proxysql
	rm /etc/proxysql.cnf
	rm /usr/local/bin/proxysql
	rmdir /var/lib/proxysql 2>/dev/null || true
	update-rc.d proxysql remove
.PHONY: uninstall
