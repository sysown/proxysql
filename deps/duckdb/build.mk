# These settings are shared by source compilation and artifact identity.
DUCKDB_VERSION := 2.0.0
DUCKDB_CMAKE_FLAGS ?= -DCMAKE_BUILD_TYPE=Release -DDUCKDB_OPTIMIZATION_PROFILE=NONE -DDUCKDB_CAPABILITIES="httplib;loadable_extensions" -DBUILD_UNITTESTS=OFF -DBUILD_SHELL=OFF -DENABLE_SANITIZER=OFF -DBUILD_EXTENSIONS="" -DDUCKDB_EXPLICIT_VERSION=v2.0.0
DUCKDB_TSAN_CMAKE_FLAGS :=
ifeq ($(WITHTSAN),1)
override DEPS_MODE := source
# This option also selects DuckDB's TSAN-aware code paths, rather than merely
# linking its uninstrumented release archive into an instrumented executable.
# DuckDB 2.0 enables bundled jemalloc as a third-party library on Linux.
# CMake uses the last definition. Append both requirements after caller flags,
# including conflicting values and strings containing option-like substrings.
DUCKDB_TSAN_CMAKE_FLAGS := -DENABLE_THREAD_SANITIZER=ON -DENABLE_JEMALLOC=OFF
endif
export DUCKDB_CMAKE_FLAGS CC CXX
DEPS_MODE ?= auto

.PHONY: force-prepare-duckdb
force-prepare-duckdb:

duckdb/duckdb/build/release/src/libduckdb_static.a: force-prepare-duckdb
	+@bash $(PROXYSQL_PATH)/deps/artifacts/prepare.bash duckdb "$(PROXYSQL_PATH)" "$(DEPS_MODE)"

duckdb/duckdb/.proxysql-source-complete: duckdb/duckdb-$(DUCKDB_VERSION).tar.xz duckdb/build.mk duckdb/verify-source.bash
	cd duckdb && ./verify-source.bash
	cd duckdb && rm -rf duckdb-*/ duckdb || true
	cd duckdb && tar -xf duckdb-$(DUCKDB_VERSION).tar.xz && mv duckdb-$(DUCKDB_VERSION)/ duckdb
	# DuckDB 2.0: libstdc++ 8 cannot convert reference_wrapper<T> to reference_wrapper<const T>.
	# Keep the rewrite in this recipe so its contents are included in the dependency cache key.
	perl -pi -e '$$changes += s/equivalence_set_map\[right_expr\]/equivalence_set_map[std::cref(right_expr.get())]/; END { die "Expected one DuckDB optimizer compatibility rewrite\n" unless $$changes == 1 }' \
		duckdb/duckdb/src/optimizer/filter_combiner.cpp
	# GCC 8 needs the explicit callback type when comparing these function templates.
	perl -pi -e '$$changes += s/== (CMIntegralDeserialize<GetIntegral(?:Compress|Decompress)FunctionInputSwitch>)/== static_cast<function_deserialize_t>(&$$1)/; END { die "Expected two DuckDB callback compatibility rewrites\n" unless $$changes == 2 }' \
		duckdb/duckdb/src/function/scalar/compressed_materialization/compress_integral.cpp
	# GCC 8 rejects the out-of-line defaulted noexcept move constructor.
	# Spell out the member moves to retain the declared noexcept contract.
	perl -pi \
		-e 'my $$replacement = "SerializationData::SerializationData(SerializationData &&other) noexcept\n" .' \
		-e '"    : contexts(std::move(other.contexts)), databases(std::move(other.databases)), catalogs(std::move(other.catalogs)),\n" .' \
		-e '"      enums(std::move(other.enums)), parameter_data(std::move(other.parameter_data)), types(std::move(other.types)),\n" .' \
		-e '"      function_children(std::move(other.function_children)), compression_infos(std::move(other.compression_infos)),\n" .' \
		-e '"      customs(std::move(other.customs)) {\n}";' \
		-e '$$changes += s/^\QSerializationData::SerializationData(SerializationData &&) noexcept = default;\E$$/$$replacement/;' \
		-e 'END { die "Expected one DuckDB serialization compatibility rewrite\n" unless $$changes == 1 }' \
		duckdb/duckdb/src/common/serializer/serialization_data.cpp
	# Force DuckDB's version: git describe in this bare extraction finds ProxySQL's tags.
	cd duckdb/duckdb && cmake -S . -B build/release $(DUCKDB_CMAKE_FLAGS) $(DUCKDB_TSAN_CMAKE_FLAGS)
	cd duckdb/duckdb && CC=${CC} CXX=${CXX} cmake --build build/release -j$(NPROCS)
	@test -s duckdb/duckdb/build/release/src/libduckdb_static.a
	touch $@

.PHONY: dependency-source-duckdb
dependency-source-duckdb: duckdb/duckdb/.proxysql-source-complete
