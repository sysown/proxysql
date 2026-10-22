# These settings are shared by source compilation and artifact identity.
DUCKDB_VERSION := 1.4.5
DUCKDB_CMAKE_FLAGS := -DCMAKE_BUILD_TYPE=Release -DBUILD_UNITTESTS=OFF -DBUILD_SHELL=OFF -DENABLE_SANITIZER=OFF -DBUILD_EXTENSIONS="" -DDUCKDB_EXPLICIT_VERSION=v1.4.5
export DUCKDB_CMAKE_FLAGS

duckdb/duckdb/build/release/src/libduckdb_static.a:
	cd duckdb && ./verify-source.bash
	cd duckdb && rm -rf duckdb-*/ duckdb || true
	cd duckdb && tar -zxf duckdb-$(DUCKDB_VERSION).tar.gz && mv duckdb-$(DUCKDB_VERSION)/ duckdb
	# Force DuckDB's version: git describe in this bare extraction finds ProxySQL's tags.
	cd duckdb/duckdb && cmake -S . -B build/release $(DUCKDB_CMAKE_FLAGS)
	cd duckdb/duckdb && CC=${CC} CXX=${CXX} cmake --build build/release -j$(NPROCS)
	@test -f $@ || { echo "ERROR: duckdb build did not produce $@" >&2; exit 1; }

.PHONY: dependency-source-duckdb
dependency-source-duckdb: duckdb/duckdb/build/release/src/libduckdb_static.a
