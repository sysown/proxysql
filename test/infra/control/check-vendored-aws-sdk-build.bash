#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
validator="$repo_root/deps/aws-sdk-cpp/verify-bundle.bash"
deps_makefile="$repo_root/deps/Makefile"
plugin_makefile="$repo_root/plugins/aws/Makefile"
workflow="$repo_root/.github/workflows/CI-aws.yml"
builder="$repo_root/deps/aws-sdk-cpp/build-sdk.cmake"
real_bundle="$repo_root/deps/aws-sdk-cpp"
temporary_root=$(mktemp -d)
trap 'find "$temporary_root" -depth -delete' EXIT

fail() {
	printf 'not ok - %s\n' "$*" >&2
	exit 1
}

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum -- "$1" | awk '{print $1}'
	else
		shasum -a 256 -- "$1" | awk '{print $1}'
	fi
}

expect_failure() {
	local expected=$1
	shift
	local output
	if output=$("$@" 2>&1); then
		fail "command unexpectedly succeeded: $*"
	fi
	if [[ $output != "$expected" ]]; then
		printf 'expected diagnostic: %s\nactual output:\n%s\n' "$expected" "$output" >&2
		fail 'command failed without the expected diagnostic'
	fi
}

pack_fixture() {
	local bundle=$1
	local tree=$2
	tar --sort=name --format=gnu --mtime='@0' --owner=0 --group=0 --numeric-owner \
		-cJf "$bundle/aws-sdk-cpp-1.11.869-with-crt.tar.xz" \
		-C "$tree" aws-sdk-cpp-1.11.869
	local digest
	digest=$(sha256_file "$bundle/aws-sdk-cpp-1.11.869-with-crt.tar.xz")
	printf '%s  %s\n' "$digest" aws-sdk-cpp-1.11.869-with-crt.tar.xz \
		>"$bundle/aws-sdk-cpp-1.11.869-with-crt.sha256"
}

pin_fixture_validator() {
	local bundle=$1
	local fixture_validator=$2
	local digest
	digest=$(sha256_file "$bundle/aws-sdk-cpp-1.11.869-with-crt.tar.xz")
	python3 - "$validator" "$fixture_validator" "$digest" <<'PY'
import re
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    script = source.read()
script, replacements = re.subn(
    r"(?m)^expected_archive_sha256=[0-9a-f]{64}$",
    "expected_archive_sha256=" + sys.argv[3],
    script,
)
if replacements != 1:
    raise SystemExit("could not pin fixture validator digest")
with open(sys.argv[2], "w", encoding="utf-8") as output:
    output.write(script)
PY
	chmod +x "$fixture_validator"
}

new_fixture() {
	local name=$1
	fixture_bundle="$temporary_root/$name/bundle with spaces \$literal"
	fixture_tree="$temporary_root/$name/tree with spaces \$literal"
	fixture_root="$fixture_tree/aws-sdk-cpp-1.11.869"
	fixture_validator="$temporary_root/$name/verify-bundle.bash"
	mkdir -p "$fixture_bundle" "$fixture_root/crt/aws-crt-cpp/path with spaces"
	printf 'fixture source\n' >"$fixture_root/source.cpp"
	printf 'credential-shaped source fixture\n' \
		>"$fixture_root/crt/aws-crt-cpp/path with spaces/private-key-test.pem"
	printf 'literal path fixture\n' \
		>"$fixture_root/crt/aws-crt-cpp/path with spaces/\$literal.c"
	cp "$real_bundle/aws-sdk-cpp-1.11.869-sources.json" "$fixture_bundle/"
	cp "$real_bundle/LICENSE" "$real_bundle/NOTICE" \
		"$real_bundle/THIRD_PARTY_NOTICES.md" "$fixture_bundle/"
	pack_fixture "$fixture_bundle" "$fixture_tree"
	pin_fixture_validator "$fixture_bundle" "$fixture_validator"
}

[[ -x $validator ]] \
	|| fail "AWS IAM vendor bundle validator is missing or not executable: $validator"
[[ -f $plugin_makefile ]] || fail 'general AWS plugin Makefile is missing'
[[ -f $workflow ]] || fail 'general AWS CI workflow is missing'
[[ -f $builder ]] || fail 'serialized AWS SDK builder is missing'

deps_default_goal=$(PROXYSQL40=1 make -C "$repo_root/deps" -pn \
	check_openssl_version 2>/dev/null \
	| sed -n 's/^\.DEFAULT_GOAL := //p')
[[ $deps_default_goal == default ]] ||
	fail "deps Makefile default goal is '$deps_default_goal', expected 'default'"

if git -C "$repo_root" grep -n -E \
	'PROXYSQLAWSIAM([[:space:]=]|$)|PROXYSQLAWS([[:space:]=]|$)|ProxySQL_AwsIam_Plugin\.so|plugins/aws_iam' -- \
	Makefile deps/Makefile common_mk plugins .github docker README.md doc etc \
	test/tap/tests/unit ':(exclude)test/infra/control/check-vendored-aws-sdk-build.bash'; then
	fail 'obsolete AWS plugin build flag, artifact, or path remains'
fi

if ! grep -Fq 'COMMAND bash "${AWS_VERIFIER}" "${AWS_BUNDLE_DIR}"' "$builder"; then
	fail 'deps AWS SDK build rule does not validate the immutable bundle before extraction'
fi
if ! grep -Fq -- '-DAWS_MAKE_COMMAND="$(MAKE)"' "$deps_makefile"; then
	fail 'deps AWS SDK build rule does not use make jobserver recursion'
fi
if [[ $(grep -Fc 'fetch-depth: 0' "$workflow") -ne 4 ]]; then
	fail 'AWS CI checkouts do not fetch full history and tags'
fi
if grep -Eq 'nm .*[|].*(rg|grep)[[:space:]]+-q' "$workflow"; then
	fail 'AWS CI symbol checks use a pipe that is unsafe under pipefail'
fi
grep -Fq '$(AWS_SDK_CPP_IDENTITY_STAMP)' "$deps_makefile" || \
	fail 'AWS SDK archive target is not invalidated by build identity'
grep -Fq 'build-sdk.cmake' "$deps_makefile" || \
	fail 'AWS SDK archive target does not use the serialized builder'
grep -Fq 'file(LOCK "${AWS_LOCK_FILE}"' "$builder" || \
	fail 'AWS SDK builder does not serialize the shared build tree'
grep -Fq 'installed_identity' "$builder" || \
	fail 'AWS SDK builder does not recheck identity after acquiring the lock'
verify_line=$(grep -n -m1 'COMMAND bash "${AWS_VERIFIER}"' "$builder" | cut -d: -f1)
identity_line=$(grep -n -m1 'if(EXISTS "${AWS_RDS_LIB}"' "$builder" | cut -d: -f1)
if [[ -z $verify_line || -z $identity_line || $verify_line -ge $identity_line ]]; then
	fail 'AWS SDK builder can accept an installed identity before verifying the bundle'
fi
darwin_link=$(PROXYSQL40=1 make -j -n -C "${repo_root}/plugins/aws" UNAME_S=Darwin)
if grep -Eq -- '(^|[[:space:]])-ldl($|[[:space:]])|(^|[[:space:]])-lrt($|[[:space:]])' <<<"$darwin_link"; then
	fail 'AWS IAM plugin links Linux-only dl/rt libraries on Darwin'
fi
if ! grep -Fq 'aws_dso_pattern=' "$workflow" || \
	! grep -Fq 'for artifact in src/proxysql plugins/aws/ProxySQL_Aws_Plugin.so' "$workflow"; then
	fail 'AWS IAM CI does not reject AWS and CRT DSOs in both artifacts'
fi
for workflow_path in \
	"'Makefile'" \
	"'src/Makefile'" \
	"'lib/Makefile'" \
	"'src/main.cpp'" \
	"'lib/ProxySQL_PluginManager.cpp'" \
	"'include/ProxySQL_Plugin.h'" \
	"'docker/images/proxysql/**'"; do
	grep -Fq "$workflow_path" "$workflow" || \
		fail "AWS IAM CI path filter omits $workflow_path"
done
for packaging_entrypoint in \
	"$repo_root/docker/images/proxysql/deb-compliant/entrypoint/entrypoint.bash" \
	"$repo_root/docker/images/proxysql/rhel-compliant/entrypoint/entrypoint.bash" \
	"$repo_root/docker/images/proxysql/suse-compliant/entrypoint/entrypoint.bash" \
	"$repo_root/docker/images/proxysql/tarball-compliant/entrypoint/entrypoint.bash"; do
	grep -Fq 'LICENSE NOTICE THIRD_PARTY_NOTICES.md' "$packaging_entrypoint" || \
		fail "AWS IAM package entrypoint omits the vendored attribution list"
	grep -Fq 'deps/aws-sdk-cpp/${attribution}' "$packaging_entrypoint" || \
		fail 'AWS IAM package entrypoint does not stage vendored attribution files'
	grep -Fq 'ProxySQL_Aws_Plugin.so' "$packaging_entrypoint" || \
		fail 'v4 package entrypoint does not stage the general AWS plugin'
done
for retired_gate in \
	"$repo_root/test/infra/control/check-aws-iam-build-gate.bash" \
	"$repo_root/test/infra/control/check-aws-iam-linkage.bash" \
	"$repo_root/test/infra/control/check-aws-iam-linkage-test.bash"; do
	[[ ! -e $retired_gate ]] || fail "retired system-SDK gate remains: ${retired_gate##*/}"
done
if [[ $(grep -Fc 'cd plugins/aws && ${MAKE} clean' "$repo_root/Makefile") -ne 4 ]]; then
	fail 'AWS plugin clean recursion does not consistently use make jobserver recursion'
fi

new_fixture valid
"$fixture_validator" "$fixture_bundle" >/dev/null \
	|| fail 'valid synthetic AWS SDK bundle was rejected'

new_fixture bad_checksum
printf '%064d  %s\n' 0 aws-sdk-cpp-1.11.869-with-crt.tar.xz \
	>"$fixture_bundle/aws-sdk-cpp-1.11.869-with-crt.sha256"
expect_failure 'AWS IAM vendor bundle checksum mismatch' \
	"$fixture_validator" "$fixture_bundle"

new_fixture changed_archive_and_checksum
printf 'changed archive content\n' >"$fixture_root/changed.cpp"
pack_fixture "$fixture_bundle" "$fixture_tree"
expect_failure 'AWS IAM vendor bundle checksum mismatch' \
	"$fixture_validator" "$fixture_bundle"

new_fixture bad_revision
python3 - "$fixture_bundle/aws-sdk-cpp-1.11.869-sources.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    manifest = json.load(source)
manifest["submodules"][0]["revision"] = "0" * 40
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(manifest, output, indent=2)
    output.write("\n")
PY
expect_failure 'AWS IAM vendor bundle manifest is invalid' \
	"$fixture_validator" "$fixture_bundle"

new_fixture missing_crt
find "$fixture_root/crt/aws-crt-cpp" -depth -delete
pack_fixture "$fixture_bundle" "$fixture_tree"
pin_fixture_validator "$fixture_bundle" "$fixture_validator"
expect_failure 'AWS IAM vendor bundle is missing crt/aws-crt-cpp' \
	"$fixture_validator" "$fixture_bundle"

new_fixture missing_license
rm "$fixture_bundle/LICENSE"
expect_failure 'AWS IAM vendor bundle is missing LICENSE' \
	"$fixture_validator" "$fixture_bundle"

new_fixture missing_notice
rm "$fixture_bundle/NOTICE"
expect_failure 'AWS IAM vendor bundle is missing NOTICE' \
	"$fixture_validator" "$fixture_bundle"

new_fixture hostile_link
ln -s '../../../outside' "$fixture_root/crt/aws-crt-cpp/hostile-link"
pack_fixture "$fixture_bundle" "$fixture_tree"
pin_fixture_validator "$fixture_bundle" "$fixture_validator"
expect_failure 'AWS IAM vendor bundle archive contains an unsafe path' \
	"$fixture_validator" "$fixture_bundle"

new_fixture prebuilt_artifact
printf 'archive fixture\n' >"$fixture_root/crt/aws-crt-cpp/prebuilt.a"
pack_fixture "$fixture_bundle" "$fixture_tree"
pin_fixture_validator "$fixture_bundle" "$fixture_validator"
expect_failure 'AWS IAM vendor bundle contains prohibited build or binary artifacts' \
	"$fixture_validator" "$fixture_bundle"

"$validator" "$real_bundle"
real_listing="$temporary_root/committed-archive.list"
tar -tJf "$real_bundle/aws-sdk-cpp-1.11.869-with-crt.tar.xz" >"$real_listing"
for required_probe in \
	aws-sdk-cpp-1.11.869/crt/aws-crt-cpp/crt/aws-lc/tests/compiler_features_tests/stdalign_check.c \
	aws-sdk-cpp-1.11.869/crt/aws-crt-cpp/crt/s2n/tests/features/S2N_LIBCRYPTO_SANITY_PROBE.c; do
	grep -Fxq "$required_probe" "$real_listing" \
		|| fail "committed AWS SDK bundle is missing required probe: $required_probe"
done

printf 'Vendored AWS SDK bundle fixture matrix and committed complete bundle: verified\n'
