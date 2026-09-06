#!/bin/bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

actual="$(make -s -f - -C "${root}" WITHGCOV=1 <<'MAKE'
include include/makefiles_vars.mk
print:
	@printf '%s\n' "$(WGCOV)"
MAKE
)"

test "${actual}" = '-DWITHGCOV -lgcov --coverage -fprofile-update=atomic'
