#!/bin/bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
workflow="${root}/.github/workflows/ci-mysqlx.yml"

e2e_job="$(awk '
  /^  e2e-tests:$/ { capture = 1 }
  capture { print }
  capture && /^  [[:alnum:]_-]+:$/ && $0 !~ /^  e2e-tests:$/ { exit }
' "${workflow}")"

printf '%s\n' "${e2e_job}" | grep -Eq '^    runs-on: ubuntu-24\.04$' || {
	echo 'MySQL dbdeployer sandbox must run on ubuntu-24.04' >&2
	exit 1
}

runtime_step="$(printf '%s\n' "${e2e_job}" | awk '
  /^      - name: Install MySQL 8\.4 runtime libs$/ { capture = 1 }
  capture && /^      - name:/ && $0 !~ /Install MySQL 8\.4 runtime libs/ { exit }
  capture { print }
')"

printf '%s\n' "${runtime_step}" | grep -Eq '^[[:space:]]+libaio1t64 libnuma1 libncurses6 libtinfo6$' || {
	echo 'MySQL dbdeployer sandbox must install the Ubuntu 24 runtime libraries' >&2
	exit 1
}
printf '%s\n' "${runtime_step}" | grep -Eq '^[[:space:]]+LIBAIO_T64=.*libaio\.so\.1t64' || {
	echo 'MySQL dbdeployer sandbox must locate Noble libaio by SONAME' >&2
	exit 1
}
printf '%s\n' "${runtime_step}" | grep -Fq 'ln -s "${LIBAIO_T64}" "${MYSQLX_COMPAT_LIB_DIR}/libaio.so.1"' || {
	echo 'MySQL dbdeployer sandbox must provide the Noble libaio compatibility link' >&2
	exit 1
}

download_step="$(printf '%s\n' "${e2e_job}" | awk '
  /^      - name: Download and unpack MySQL 8\.4$/ { capture = 1 }
  capture && /^      - name:/ && $0 !~ /Download and unpack MySQL 8\.4/ { exit }
  capture { print }
')"

printf '%s\n' "${download_step}" | grep -Eq '^[[:space:]]+MYSQL_URL=.*linux-glibc2\.28-x86_64-minimal\.tar\.xz' || {
	echo 'MySQL dbdeployer sandbox must use the glibc 2.28 minimal archive' >&2
	exit 1
}
printf '%s\n' "${download_step}" | grep -Fq 'dbdeployer downloads get "${MYSQL_URL}"' || {
	echo 'MySQL archive must be downloaded through dbdeployer' >&2
	exit 1
}
if printf '%s\n' "${e2e_job}" | grep -Fq 'mysql:8.4'; then
	echo 'MySQL e2e infrastructure must remain dbdeployer-based' >&2
	exit 1
fi
if printf '%s\n' "${e2e_job}" | grep -Fq -- '--skip-library-check'; then
	echo 'dbdeployer library validation must remain enabled' >&2
	exit 1
fi

step="$(awk '
  /^      - name: Install dbdeployer$/ { capture = 1 }
  capture { print }
  capture && /^      - name: Download and unpack MySQL 8\.4$/ { exit }
' "${workflow}")"

guard_body="$(printf '%s\n' "${step}" | awk '
  /if ! command -v dbdeployer >\/dev\/null 2>&1; then/ {
    capture = 1
    depth = 1
    first_if = 1
  }
  capture {
    print
    if ($0 ~ /^[[:space:]]*if .*; then[[:space:]]*$/) {
      if (first_if) {
        first_if = 0
      } else {
        depth++
      }
    }
    if ($0 ~ /^[[:space:]]*fi[[:space:]]*$/) {
      depth--
      if (depth == 0) exit
    }
  }
')"

printf '%s\n' "${guard_body}" | grep -Fq 'if ! command -v dbdeployer >/dev/null 2>&1; then'
printf '%s\n' "${guard_body}" | grep -Fq "curl --fail --location --proto '=https' --tlsv1.2"
printf '%s\n' "${guard_body}" | grep -Fq 'https://raw.githubusercontent.com/ProxySQL/dbdeployer/0982f16ad02a20df13caf02838d2722a1e304e4f/scripts/dbdeployer-install.sh'
printf '%s\n' "${guard_body}" | grep -Fq '04ef082fb20dc3e5ad9b164dd96374e6c01034d068ccc891684fabc1be52f6b5'
printf '%s\n' "${guard_body}" | grep -Fq 'sha256sum --check --status'
printf '%s\n' "${guard_body}" | grep -Fq 'bash "${installer}"'
printf '%s\n' "${step}" | grep -Fq 'dbdeployer --version'
