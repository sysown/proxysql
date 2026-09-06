#!/bin/bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
workflow="${root}/.github/workflows/ci-mysqlx.yml"

step="$(awk '
  /^      - name: Install dbdeployer$/ { capture = 1 }
  capture { print }
  capture && /^      - name: Download and unpack MySQL 8\.4$/ { exit }
' "${workflow}")"

guard_body="$(printf '%s\n' "${step}" | awk '
  /if ! command -v dbdeployer >\/dev\/null 2>&1; then/ { capture = 1 }
  capture { print }
  capture && /^          fi$/ { exit }
')"

printf '%s\n' "${guard_body}" | grep -Fqx '          if ! command -v dbdeployer >/dev/null 2>&1; then'
printf '%s\n' "${guard_body}" | grep -Fqx '            curl --fail --location --proto '\''=https'\'' --tlsv1.2 \\'
printf '%s\n' "${guard_body}" | grep -Fq 'https://raw.githubusercontent.com/ProxySQL/dbdeployer/0982f16ad02a20df13caf02838d2722a1e304e4f/scripts/dbdeployer-install.sh'
printf '%s\n' "${guard_body}" | grep -Fq '04ef082fb20dc3e5ad9b164dd96374e6c01034d068ccc891684fabc1be52f6b5'
printf '%s\n' "${guard_body}" | grep -Fqx '            bash "${installer}"'
printf '%s\n' "${step}" | grep -Fqx '          dbdeployer --version'
