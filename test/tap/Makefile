#!/bin/make -f


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
tests: pgsql_user_sync_assets tap test_deps
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
	rm -rf pgsql_user_sync

.PHONY: cleanall
.SILENT: cleanall
cleanall:
	cd ../deps && ${MAKE} -s clean
	cd tap && ${MAKE} -s cleanall
	cd tests && ${MAKE} -s clean
	cd tests_with_deps && ${MAKE} -s clean
	cd tests/unit && ${MAKE} -s clean
