#!/bin/make -f

# Walk upward until we find the repo root (src/proxysql_global.cpp).  A hop
# counter stops the climb at / on a sparse checkout that omits the marker
# file -- otherwise we'd loop forever.  Fails fast with a clear message so
# build output doesn't look like it's hanging.
PROXYSQL_PATH := $(shell set -e; d="$$PWD"; for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do if [ -f "$$d/src/proxysql_global.cpp" ]; then echo "$$d"; exit 0; fi; if [ "$$d" = "/" ]; then break; fi; d="$$(dirname "$$d")"; done; echo "ERROR: plugins/duckdb/Makefile: could not find src/proxysql_global.cpp (repo root) from $$PWD; sparse checkout missing include/ and src/proxysql_global.cpp?" >&2; exit 1)

ifneq (,$(findstring ERROR,$(PROXYSQL_PATH)))
$(error $(PROXYSQL_PATH))
endif

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

PLUGIN_DIR := $(PROXYSQL_PATH)/plugins/duckdb
ODIR := $(PLUGIN_DIR)/obj
PLUGIN_SO := $(PLUGIN_DIR)/ProxySQL_DuckDB_Plugin.so

# duckdb_session.cpp is the first plugin source to include the full
# MySQL_Session.h / PgSQL_Session.h stack (needed for the templated
# session handler): that chain pulls in cpp.h -> PgSQL_Thread.h ->
# proxysql_admin.h -> ProxySQL_RESTAPI_Server.hpp -> httpserver.hpp,
# plus prometheus's Exposer and libcurl/libev/libdaemon/microhttpd
# headers that Admin's REST API server declares inline. None of the
# earlier plugin sources needed these, so they were not in IDIRS before.
IDIRS := -I$(PROXYSQL_IDIR) -I$(PLUGIN_DIR)/include -I$(SQLITE3_IDIR) \
	-I$(DUCKDB_IDIR) -I$(SSL_IDIR) -I$(PROMETHEUS_IDIR) -I$(LIBCONFIG_IDIR) \
	-I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) -I$(RE2_IDIR) -I$(ZSTD_IDIR) \
	-I$(POSTGRESQL_IDIR) -I$(LIBUSUAL_IDIR) \
	-I$(LIBHTTPSERVER_IDIR) -I$(MICROHTTPD_IDIR) -I$(CURL_IDIR) \
	-I$(EV_IDIR) -I$(LIBDAEMON_IDIR) -I$(JSON_IDIR) -I$(LIBSCRAM_IDIR) \
	-I$(PARSERSQL_IDIR) \
	-I$(PROXYSQL_PATH)/deps/lz4/lz4/lib

OPTZ ?= -O2 -ggdb
# Propagate feature-tier flags from the top-level build.  These MUST match
# the flags libproxysql.a was built with; a mismatch silently changes the
# ProxySQL_PluginDescriptor / ProxySQL_PluginServices layout the core and
# the plugin each see, and the loader then reads past the end of the
# plugin's static descriptor.
#
# Tier cascade (mirrors the top-level Makefile):
#   PROXYSQL40=1 ⇒ PROXYSQL31=1 ⇒ PROXYSQLFFTO=1 + PROXYSQLTSDB=1
ifeq ($(PROXYSQL40),1)
	PROXYSQL31 := 1
endif
ifeq ($(PROXYSQL31),1)
	PROXYSQLFFTO := 1
	PROXYSQLTSDB := 1
endif

PSQL40 :=
ifeq ($(PROXYSQL40),1)
	PSQL40 := -DPROXYSQL40
endif
PSQL31 :=
ifeq ($(PROXYSQL31),1)
	PSQL31 := -DPROXYSQL31
endif
PSQLFFTO :=
ifeq ($(PROXYSQLFFTO),1)
	PSQLFFTO := -DPROXYSQLFFTO
endif
PSQLTSDB :=
ifeq ($(PROXYSQLTSDB),1)
	PSQLTSDB := -DPROXYSQLTSDB
endif

# -fvisibility=hidden + -fvisibility-inlines-hidden hides every C++ symbol by
# default; only the explicitly extern "C"-declared
# proxysql_plugin_descriptor_v1 entry point is exported. This prevents ODR
# collisions with the proxysql core when the .so is dlopen'd, and avoids
# leaking template instantiations across the boundary.
CXXFLAGS := $(STDCPP) -fPIC -fvisibility=hidden -fvisibility-inlines-hidden \
	$(OPTZ) $(WGCOV) $(WASAN) -pthread \
	$(PSQL40) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB)

# Hardening flags. Skip _FORTIFY_SOURCE under ASAN (incompatible) and when
# OPTZ contains -O0 (requires optimisation to take effect).
ifeq ($(WASAN),)
    ifeq (,$(findstring -O0,$(OPTZ)))
        CXXFLAGS += -D_FORTIFY_SOURCE=2
    endif
endif
CXXFLAGS += -fstack-protector-strong

.DEFAULT_GOAL := all

# libduckdb_static.a alone does not satisfy DuckDB's symbols -- the vendored
# build produces 16 static archives (src/ + 12 third_party/ + 3 extension/),
# with circular references between them. libduckdb_static.a is kept as the
# make PREREQUISITE that triggers the deps/duckdb build (via $(DUCKDB_AR)
# below); DUCKDB_ARS enumerates the full set for the actual link. It's a
# recursively-expanded (=) variable, not simply-expanded (:=), so the `find`
# runs when the link recipe executes -- after the $(DUCKDB_AR) prerequisite
# has forced deps/duckdb to build -- rather than at Makefile parse time, when
# a fresh checkout wouldn't have any of these archives on disk yet.
DUCKDB_AR := $(DUCKDB_LDIR)/libduckdb_static.a
DUCKDB_ARS = $(shell find $(DUCKDB_PATH)/build/release -name '*.a' 2>/dev/null)

# $(DUCKDB_AR) as a prerequisite only re-triggers the deps build when
# libduckdb_static.a itself is missing. An interrupted or partial deps/duckdb
# build can leave that one archive present while others under third_party/ or
# extension/ are absent or stale; `find` would then silently return a short
# list, the -shared link below would "succeed" anyway (shared objects
# tolerate undefined symbols), and the plugin would only fail later at
# dlopen(RTLD_NOW) -- exactly the failure mode DUCKDB_ARS exists to avoid.
# So: assert the count before linking. 16 is what DuckDB 1.4.5's vendored
# CMake build produces (1 src/ + 12 third_party/ + 3 extension/ archives,
# confirmed via `find deps/duckdb/duckdb/build/release -name '*.a'`); a
# future DuckDB version bump that legitimately changes the archive count
# should update this constant, not silently pass a stale check.
DUCKDB_MIN_ARCHIVES := 16

SRCS := $(PLUGIN_DIR)/src/duckdb_plugin.cpp $(PLUGIN_DIR)/src/duckdb_config.cpp $(PLUGIN_DIR)/src/duckdb_engine.cpp $(PLUGIN_DIR)/src/duckdb_result.cpp $(PLUGIN_DIR)/src/duckdb_admin_schema.cpp $(PLUGIN_DIR)/src/duckdb_session.cpp $(PLUGIN_DIR)/src/duckdb_listener.cpp
HEADERS := $(wildcard $(PLUGIN_DIR)/include/*.h) $(PROXYSQL_PATH)/include/ProxySQL_Plugin.h
OBJS := $(patsubst $(PLUGIN_DIR)/src/%.cpp,$(ODIR)/%.o,$(SRCS))

$(ODIR):
	mkdir -p $(ODIR)

$(DUCKDB_AR):
	$(MAKE) -C $(PROXYSQL_PATH)/deps PROXYSQL40=1 duckdb
	@test -f $@ || { echo "ERROR: deps duckdb build did not produce $@" >&2; exit 1; }

$(ODIR)/%.o: $(PLUGIN_DIR)/src/%.cpp $(HEADERS) $(DUCKDB_AR) | $(ODIR)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(IDIRS)

# The 16 vendored DuckDB archives were built by DuckDB's own CMake, not by
# this Makefile, so none of their objects carry -fvisibility=hidden -- that
# flag only applies to duckdb_plugin.o/duckdb_config.o/duckdb_engine.o
# above. As long as no plugin code referenced any DuckDB symbol (true
# through Task 3), --start-group never pulled any archive member into the
# .so and this went unnoticed. Task 4 is the first to call duckdb_open_ext
# et al., which pulls in real archive objects and, with their default
# visibility, re-exposes thousands of DuckDB-internal symbols (fmt, hll,
# mbedtls, re2, ...) from the plugin .so -- exactly the ODR-collision risk
# -fvisibility=hidden exists to prevent. This is a per-linker problem, not a
# Linux-only one: static-archive objects retain default visibility on both
# ELF and Mach-O, since the archives were compiled by DuckDB's own CMake
# build with no knowledge of this plugin's CXXFLAGS. Each linker needs its
# own explicit instrument to re-hide them:
#   - GNU ld (Linux): --exclude-libs,ALL treats every symbol pulled from a
#     static archive as local in the output.
#   - Apple's ld64 (macOS): no --exclude-libs equivalent exists.
#     -exported_symbol,_<name> is the ld64 analogue -- it hides everything
#     except the named symbol(s) (Mach-O prepends "_" to C symbol names).
#     Used in the single-flag form (rather than -exported_symbols_list with
#     a file) because exactly one symbol -- the extern "C" entry point
#     proxysql_plugin_descriptor_v1 -- is meant to be exported.
# Neither branch changes which archives/objects get linked (unlike
# --whole-archive or hand-listing archives).
#
# The Darwin branch is unverified locally (no macOS environment here); it
# is confirmed by the first macOS CI run (CI-build-macos-macos-14-genai.yml
# sets PROXYSQL40=1 and builds this plugin). The named symbol certainly
# exists (it's this plugin's own extern "C" entry point), so ld64's
# "exported symbol not found" error should not fire; if the flag is
# otherwise wrong, CI fails loudly rather than leaking symbols silently.
PLUGIN_LDFLAGS :=
ifeq ($(UNAME_S),Darwin)
PLUGIN_LDFLAGS += -Wl,-undefined,dynamic_lookup -Wl,-exported_symbol,_proxysql_plugin_descriptor_v1
else
PLUGIN_LDFLAGS += -Wl,--exclude-libs,ALL
endif

# --start-group/--end-group (not --whole-archive) resolves the circular
# references between the 16 DuckDB archives without pulling every object
# from every archive into the .so -- --whole-archive was tried and works,
# but bloats the .so enormously since it forces in the whole set
# unconditionally instead of just what's referenced.
#
# Apple's ld64 does not understand GNU --start-group/--end-group (and does
# not need it: ld64 resolves archive member references in multiple passes
# by default), so the group flags are Linux-only. macOS CI does build this
# plugin (CI-build-macos-macos-14-genai.yml sets PROXYSQL40=1), so this is
# not a hypothetical.
DUCKDB_LINK_GROUP_START :=
DUCKDB_LINK_GROUP_END :=
ifneq ($(UNAME_S),Darwin)
DUCKDB_LINK_GROUP_START := -Wl,--start-group
DUCKDB_LINK_GROUP_END := -Wl,--end-group
endif

$(PLUGIN_SO): $(OBJS) $(DUCKDB_AR)
	@n=$$(echo "$(DUCKDB_ARS)" | wc -w); \
	if [ "$$n" -lt $(DUCKDB_MIN_ARCHIVES) ]; then \
		echo "ERROR: expected at least $(DUCKDB_MIN_ARCHIVES) DuckDB static archives under $(DUCKDB_PATH)/build/release (DuckDB 1.4.5 layout: src/ + third_party/ + extension/), found $$n. This usually means an interrupted or partial deps/duckdb build; rerun: make -C $(PROXYSQL_PATH)/deps PROXYSQL40=1 duckdb" >&2; \
		exit 1; \
	fi
	$(CXX) -shared -o $@ $(OBJS) $(CXXFLAGS) -pthread \
		$(DUCKDB_LINK_GROUP_START) $(DUCKDB_ARS) $(DUCKDB_LINK_GROUP_END) \
		-L$(SSL_LDIR) -lssl -lcrypto $(PLUGIN_LDFLAGS) -lstdc++ -lm -ldl -lpthread

.PHONY: all
all: $(PLUGIN_SO)

.PHONY: clean
clean:
	rm -rf $(ODIR) $(PLUGIN_SO)
