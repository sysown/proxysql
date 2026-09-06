#!/bin/bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
workflow="${root}/.github/workflows/ci-mysqlx.yml"

step="$(awk '
  /^      - name: Install dbdeployer$/ { capture = 1 }
  capture { print }
  capture && /^      - name: Download and unpack MySQL 8\.4$/ { exit }
' "${workflow}")"

printf '%s\n' "${step}" | grep -Fq 'if ! command -v dbdeployer >/dev/null 2>&1; then'
printf '%s\n' "${step}" | grep -Fq 'curl -fsSL https://raw.githubusercontent.com/ProxySQL/dbdeployer/master/scripts/dbdeployer-install.sh | bash'
printf '%s\n' "${step}" | grep -Fq 'dbdeployer --version'
