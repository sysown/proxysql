#!/bin/make -f

AI_GENAI_UNIT_TESTS := \
	genai_config_query_unit-t \
	genai_discovery_schema_unit-t \
	genai_fts_string_unit-t \
	genai_llm_clients_unit-t \
	genai_mcp_endpoint_unit-t \
	genai_mcp_thread_unit-t \
	genai_mysql_catalog_unit-t \
	genai_query_handler_unit-t \
	genai_rag_fetch_from_source_unit-t \
	genai_stats_parsing_unit-t \
	genai_thread_unit-t
AI_GENAI_STAGE_DIR := tap_tests_ai_unit

AI_GENAI_HANDOFF_ENABLED := 0
ifeq ($(PROXYSQL40),1)
ifeq ($(WITHGCOV),1)
ifeq ($(SKIP_GENAI_UNIT_TESTS),1)
AI_GENAI_HANDOFF_ENABLED := 1
endif
endif
endif

.DEFAULT: all
.PHONY: all
all: tests tests_with_deps unit_tests pgsql_user_sync_assets

.PHONY: debug
debug: tests tests_with_deps unit_tests pgsql_user_sync_assets

# CI test workflows restore only the build outputs below src/ and test/.
# Stage the canonical user-sync sample below test/ so its TAP tests exercise
# the same files that are shipped to operators without duplicating them.
.PHONY: pgsql_user_sync_assets
pgsql_user_sync_assets:
	mkdir -p pgsql_user_sync/tests
	cp ../../tools/pgsql_user_sync/proxysql_pgsql_user_sync.py pgsql_user_sync/
	cp ../../tools/pgsql_user_sync/proxysql_pgsql_user_sync.ini.example pgsql_user_sync/
	cp ../../tools/pgsql_user_sync/create_source_function.sql pgsql_user_sync/
	cp ../../tools/pgsql_user_sync/requirements.txt pgsql_user_sync/
	cp ../../tools/pgsql_user_sync/README.md pgsql_user_sync/
	cp ../../tools/pgsql_user_sync/tests/test_pgsql_user_sync.py pgsql_user_sync/tests/

.PHONY: test_deps
test_deps:
	cd ../deps && CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: tap
tap: test_deps
	cd tap && CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: tests
# `tests` contains the test_mysqlx_admin_tables-t bridge, which recursively
# builds its real binary under tests/unit.  Building that bridge concurrently
# with unit_tests launches two independent make processes in tests/unit and
# races on the shared obj/test_*.o helper files.  Finish the canonical unit
# build first so the bridge only creates its symlink to an already-built
# binary.
tests: unit_tests pgsql_user_sync_assets tap test_deps
	cd tests && CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)

.PHONY: tests_no_infra
tests_no_infra: tap test_deps
	cd tests && CC=${CC} CXX=${CXX} ${MAKE} tests_no_infra

.PHONY: tests_with_deps
tests_with_deps: tap test_deps
	cd tests_with_deps && CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)


# `tap test_deps` is NOT optional here, even though nothing under tests/unit is
# built by those targets. The unit tests link -lcurl with -L$(TAP_LDIR), i.e.
# test/tap/tap, and the `tap` recipe populates that directory by copying the
# vendored library into it:
#
#     libcurl$(SHLIB_EXT): $(DEPS_PATH)/curl/curl/lib/.libs/libcurl$(SHLIB_EXT)
#             cp -a $(DEPS_PATH)/curl/curl/lib/.libs/libcurl$(SHLIB_EXT)* .
#
# Without this prerequisite `unit_tests` runs CONCURRENTLY with `tap` under the
# `all`/`debug` targets above, so a unit test's linker can open libcurl.so while
# that cp is still writing it and fail with `file too short`. Intermittent by
# nature -- it needs the copy and a link to overlap -- and it presents as a
# corrupt library rather than a build-order problem, which makes it easy to
# misread as a real toolchain or dependency failure. Every sibling target here
# (tests, tests_no_infra, tests_with_deps) already declares these prerequisites;
# unit_tests was the only one that did not.
.PHONY: unit_tests
unit_tests: tap test_deps
	cd tests/unit && CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)
	@if [ "$(AI_GENAI_HANDOFF_ENABLED)" = "1" ]; then \
		$(MAKE) ai_genai_unit_tests; \
	fi


.PHONY: ai_genai_unit_tests stage_ai_genai_unit_tests
.NOTPARALLEL: ai_genai_unit_tests
ai_genai_unit_tests: tap test_deps
	cd tests/unit && CC=${CC} CXX=${CXX} ${MAKE} ai_genai_unit_tests
	$(MAKE) stage_ai_genai_unit_tests

stage_ai_genai_unit_tests:
	@set -eu; \
		rm -rf "$(AI_GENAI_STAGE_DIR)"; \
		mkdir -p "$(AI_GENAI_STAGE_DIR)"; \
		for test_name in $(AI_GENAI_UNIT_TESTS); do \
			test -x "tests/unit/$$test_name"; \
			ln "tests/unit/$$test_name" "$(AI_GENAI_STAGE_DIR)/$$test_name"; \
		done; \
		printf '%s\n' $(AI_GENAI_UNIT_TESTS) | LC_ALL=C sort > "$(AI_GENAI_STAGE_DIR)/manifest.txt"; \
		find "$(AI_GENAI_STAGE_DIR)" -maxdepth 1 -type f ! -name manifest.txt -printf '%f\n' \
			| LC_ALL=C sort | cmp -s "$(AI_GENAI_STAGE_DIR)/manifest.txt" -; \
		for test_name in $(AI_GENAI_UNIT_TESTS); do \
			rm -f "tests/unit/$$test_name"; \
		done


.PHONY: clean_utils
.SILENT: clean_utils
clean_utils:
	cd tap && ${MAKE} -s clean_utils

.PHONY: clean
.SILENT: clean
clean:
	cd tap && ${MAKE} -s clean
	cd tests && ${MAKE} -s clean
	cd tests_with_deps && ${MAKE} -s clean
	cd tests/unit && ${MAKE} -s clean
	rm -rf pgsql_user_sync $(AI_GENAI_STAGE_DIR)

.PHONY: cleanall
.SILENT: cleanall
cleanall:
	cd ../deps && ${MAKE} -s clean
	cd tap && ${MAKE} -s cleanall
	cd tests && ${MAKE} -s clean
	cd tests_with_deps && ${MAKE} -s clean
	cd tests/unit && ${MAKE} -s clean
	rm -rf $(AI_GENAI_STAGE_DIR)
