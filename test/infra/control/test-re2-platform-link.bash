#!/usr/bin/env bash
set -euo pipefail
script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
flags() {
    make --no-print-directory -s -f - PROXYSQL_PATH="$repo_root" UNAME_S="$1" <<'MAKE'
include $(PROXYSQL_PATH)/include/makefiles_paths.mk
.PHONY: print
print:
	@echo '$(RE2_STATIC_LIBS)'
MAKE
}
darwin=$(flags Darwin)
linux=$(flags Linux)
[[ "$darwin" == *'-framework CoreFoundation'* ]] || { echo 'Darwin static Abseil requires CoreFoundation' >&2; exit 1; }
[[ "$linux" != *'-framework'* ]] || { echo 'Apple frameworks leaked into Linux flags' >&2; exit 1; }
unit_flags() {
    make --no-print-directory -s -C "$repo_root/test/tap/tests/unit" \
        -f Makefile -f - UNAME_S="$1" print-platform-link <<'MAKE'
.PHONY: print-platform-link
print-platform-link:
	@echo '$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS)'
MAKE
}
darwin_unit=$(unit_flags Darwin)
linux_unit=$(unit_flags Linux)
[[ "$darwin_unit" == *'-framework CoreFoundation'* ]] || { echo 'Darwin unit linker omits CoreFoundation' >&2; exit 1; }
[[ "$linux_unit" != *'-framework'* ]] || { echo 'Apple frameworks leaked into Linux unit linker' >&2; exit 1; }
echo 'RE2/Abseil platform link flags passed'
