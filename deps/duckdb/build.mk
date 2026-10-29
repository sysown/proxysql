# These settings are shared by source compilation and artifact identity.
DUCKDB_VERSION := 1.4.5
DUCKDB_CMAKE_FLAGS ?= -DCMAKE_BUILD_TYPE=Release -DBUILD_UNITTESTS=OFF -DBUILD_SHELL=OFF -DENABLE_SANITIZER=OFF -DBUILD_EXTENSIONS="" -DDUCKDB_EXPLICIT_VERSION=v1.4.5
DUCKDB_TSAN_CMAKE_FLAGS :=
ifeq ($(WITHTSAN),1)
override DEPS_MODE := source
# This option also selects DuckDB's TSAN-aware code paths, rather than merely
# linking its uninstrumented release archive into an instrumented executable.
# DuckDB's Linux default extension set independently enables bundled jemalloc.
# CMake uses the last definition. Append both requirements after caller flags,
# including conflicting values and strings containing option-like substrings.
DUCKDB_TSAN_CMAKE_FLAGS := -DENABLE_THREAD_SANITIZER=ON -DSKIP_EXTENSIONS=jemalloc
endif
export DUCKDB_CMAKE_FLAGS CC CXX
DEPS_MODE ?= auto

.PHONY: force-prepare-duckdb
force-prepare-duckdb:

duckdb/duckdb/build/release/src/libduckdb_static.a: force-prepare-duckdb
	+@bash $(PROXYSQL_PATH)/deps/artifacts/prepare.bash duckdb "$(PROXYSQL_PATH)" "$(DEPS_MODE)"

duckdb/duckdb/.proxysql-source-complete: duckdb/duckdb-$(DUCKDB_VERSION).tar.gz duckdb/build.mk duckdb/verify-source.bash
	cd duckdb && ./verify-source.bash
	cd duckdb && rm -rf duckdb-*/ duckdb || true
	cd duckdb && tar -zxf duckdb-$(DUCKDB_VERSION).tar.gz && mv duckdb-$(DUCKDB_VERSION)/ duckdb
	# Force DuckDB's version: git describe in this bare extraction finds ProxySQL's tags.
	cd duckdb/duckdb && cmake -S . -B build/release $(DUCKDB_CMAKE_FLAGS) $(DUCKDB_TSAN_CMAKE_FLAGS)
	cd duckdb/duckdb && CC=${CC} CXX=${CXX} cmake --build build/release -j$(NPROCS)
	@test -s duckdb/duckdb/build/release/src/libduckdb_static.a
	touch $@

.PHONY: dependency-source-duckdb
dependency-source-duckdb: duckdb/duckdb/.proxysql-source-complete
