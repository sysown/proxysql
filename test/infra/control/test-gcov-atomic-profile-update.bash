#!/bin/bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

actual="$(make -s -f - -C "${root}" WITHGCOV=1 GIT_VERSION=control CPLUSPLUS=201703L <<'MAKE'
include include/makefiles_vars.mk
print:
	@printf '%s\n' "$(WGCOV)"
MAKE
)"

case " ${actual} " in
  *' -fprofile-update=atomic '*) ;;
  *)
    echo "missing -fprofile-update=atomic from WGCOV: ${actual}" >&2
    exit 1
    ;;
esac
