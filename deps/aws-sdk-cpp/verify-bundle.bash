#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

fail() {
	printf '%s\n' "$1" >&2
	exit 1
}

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum -- "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 -- "$1" | awk '{print $1}'
	else
		fail 'AWS IAM vendor bundle requires sha256sum or shasum'
	fi
}

bundle_dir=${1:-}
[[ -n $bundle_dir && -d $bundle_dir ]] \
	|| fail 'AWS IAM vendor bundle directory is missing'

archive_name=aws-sdk-cpp-1.11.869-with-crt.tar.xz
checksum_name=aws-sdk-cpp-1.11.869-with-crt.sha256
manifest_name=aws-sdk-cpp-1.11.869-sources.json
expected_archive_sha256=5737158953b0a46f4c9ad68254cc9abdeecc16853dbdec04ba7c74aa885dc573
archive="$bundle_dir/$archive_name"
checksum="$bundle_dir/$checksum_name"
manifest="$bundle_dir/$manifest_name"

for attribution in LICENSE NOTICE THIRD_PARTY_NOTICES.md; do
	[[ -f $bundle_dir/$attribution && ! -L $bundle_dir/$attribution \
		&& -s $bundle_dir/$attribution ]] \
		|| fail "AWS IAM vendor bundle is missing $attribution"
done
if cmp -s "$bundle_dir/LICENSE" "$bundle_dir/NOTICE" \
	|| cmp -s "$bundle_dir/LICENSE" "$bundle_dir/THIRD_PARTY_NOTICES.md" \
	|| cmp -s "$bundle_dir/NOTICE" "$bundle_dir/THIRD_PARTY_NOTICES.md"; then
	fail 'AWS IAM vendor bundle attribution files must be distinct'
fi

[[ -f $archive && ! -L $archive ]] \
	|| fail 'AWS IAM vendor bundle archive is missing'
[[ -f $checksum && ! -L $checksum ]] \
	|| fail 'AWS IAM vendor bundle checksum file is missing'
[[ -f $manifest && ! -L $manifest ]] \
	|| fail 'AWS IAM vendor bundle manifest is missing'

[[ $(wc -l <"$checksum") -eq 1 ]] \
	|| fail 'AWS IAM vendor bundle checksum file is invalid'
read -r recorded_checksum recorded_filename extra <"$checksum" \
	|| fail 'AWS IAM vendor bundle checksum file is invalid'
[[ $recorded_checksum =~ ^[0-9a-f]{64}$ \
	&& $recorded_filename == "$archive_name" && -z ${extra:-} ]] \
	|| fail 'AWS IAM vendor bundle checksum file is invalid'
actual_checksum=$(sha256_file "$archive")
[[ $recorded_checksum == "$expected_archive_sha256" \
	&& $actual_checksum == "$expected_archive_sha256" ]] \
	|| fail 'AWS IAM vendor bundle checksum mismatch'

temporary_root=$(mktemp -d)
cleanup() {
	find "$temporary_root" -depth -delete
}
trap cleanup EXIT
listing="$temporary_root/archive.list"
if ! tar -tJf "$archive" >"$listing"; then
	fail 'AWS IAM vendor bundle archive cannot be listed'
fi

if ! python3 - "$archive" <<'PY'
import posixpath
import sys
import tarfile

archive = sys.argv[1]
expected_root = "aws-sdk-cpp-1.11.869"
required_crt = expected_root + "/crt/aws-crt-cpp"

def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)

def normalized_member(name):
    trimmed = name.rstrip("/")
    parts = trimmed.split("/")
    if (
        not trimmed
        or name.startswith("/")
        or "" in parts
        or "." in parts
        or ".." in parts
        or parts[0] != expected_root
    ):
        fail("AWS IAM vendor bundle archive contains an unsafe path")
    return trimmed, parts

try:
    with tarfile.open(archive, "r:xz") as source:
        members = source.getmembers()
        if not members:
            fail("AWS IAM vendor bundle archive contains an unsafe path")
        has_crt = False
        for member in members:
            name, parts = normalized_member(member.name)
            if name == required_crt or name.startswith(required_crt + "/"):
                has_crt = True
            if member.ischr() or member.isblk() or member.isfifo():
                fail("AWS IAM vendor bundle archive contains an unsafe path")
            if member.issym():
                target = posixpath.normpath(
                    posixpath.join(posixpath.dirname(name), member.linkname)
                )
                if member.linkname.startswith("/") or not target.startswith(expected_root + "/"):
                    fail("AWS IAM vendor bundle archive contains an unsafe path")
            elif member.islnk():
                target = posixpath.normpath(member.linkname)
                if member.linkname.startswith("/") or not target.startswith(expected_root + "/"):
                    fail("AWS IAM vendor bundle archive contains an unsafe path")

            lowered = [part.lower() for part in parts]
            prohibited = (
                ".git" in parts
                or "CMakeCache.txt" in parts
                or "CMakeFiles" in parts
                or any(
                    lowered[index:index + 2] in ([".aws", "credentials"], [".aws", "config"])
                    for index in range(len(parts) - 1)
                )
                or name.endswith((".a", ".o", ".so", ".dylib", ".dll", ".obj"))
            )
            if prohibited:
                fail("AWS IAM vendor bundle contains prohibited build or binary artifacts")
        if not has_crt:
            fail("AWS IAM vendor bundle is missing crt/aws-crt-cpp")
except (OSError, tarfile.TarError):
    fail("AWS IAM vendor bundle archive cannot be listed")
PY
then
	exit 1
fi

if ! python3 - "$manifest" <<'PY'
import json
import sys

expected_sdk = {
    "tag": "1.11.869",
    "repository": "https://github.com/aws/aws-sdk-cpp.git",
    "revision": "c84017197daa00de9cc05b1166e9106e1079f7f3",
}
expected_submodules = {
    "crt/aws-crt-cpp": ("https://github.com/awslabs/aws-crt-cpp.git", "851d8d003c9d5150edab56807e2393013f3771de"),
    "crt/aws-crt-cpp/crt/aws-c-auth": ("https://github.com/awslabs/aws-c-auth.git", "4b5d524bf1a511b05e0fffe5bdc51800770b9427"),
    "crt/aws-crt-cpp/crt/aws-c-cal": ("https://github.com/awslabs/aws-c-cal.git", "8aa2a48a09f93c65d4cf06388e143a6584de6321"),
    "crt/aws-crt-cpp/crt/aws-c-common": ("https://github.com/awslabs/aws-c-common.git", "3c69b871dfa1815231802febf1bb6899f84cccdb"),
    "crt/aws-crt-cpp/crt/aws-c-compression": ("https://github.com/awslabs/aws-c-compression.git", "d8264e64f698341eb03039b96b4f44702a9b3f83"),
    "crt/aws-crt-cpp/crt/aws-c-event-stream": ("https://github.com/awslabs/aws-c-event-stream.git", "51bef3c44e1058b1689751539170b2e0f589ccdb"),
    "crt/aws-crt-cpp/crt/aws-c-http": ("https://github.com/awslabs/aws-c-http.git", "8aefd899fc3210bfd0e3fd414011a3cb708bf6e4"),
    "crt/aws-crt-cpp/crt/aws-c-io": ("https://github.com/awslabs/aws-c-io.git", "e2946c99521fa12d285c9a0829c92b1bf713922b"),
    "crt/aws-crt-cpp/crt/aws-c-mqtt": ("https://github.com/awslabs/aws-c-mqtt.git", "2ef9605ec9c50bea3f921e08022ddd57eed70901"),
    "crt/aws-crt-cpp/crt/aws-c-s3": ("https://github.com/awslabs/aws-c-s3.git", "a852faa2df3ab2b31fb4cfd64fd3379a2f4ae22e"),
    "crt/aws-crt-cpp/crt/aws-c-sdkutils": ("https://github.com/awslabs/aws-c-sdkutils.git", "a1cc19f53b63658f1b1400b36f199eafeeb895a6"),
    "crt/aws-crt-cpp/crt/aws-checksums": ("https://github.com/awslabs/aws-checksums.git", "1d5f2f1f3e5d013aae8810878ceb5b3f6f258c4e"),
    "crt/aws-crt-cpp/crt/aws-lc": ("https://github.com/awslabs/aws-lc.git", "f6acf748df0ea6157d55e640730b38d21a7751cd"),
    "crt/aws-crt-cpp/crt/s2n": ("https://github.com/awslabs/s2n.git", "66b1c94d1dfc99b237427cbde230eca63bb8b89c"),
    "crt/aws-crt-cpp/crt/s2n/tests/cbmc/aws-verification-model-for-libcrypto": ("https://github.com/awslabs/aws-verification-model-for-libcrypto.git", "4a6839e2a9cf5194a7789f63b1a3a45b5e86add1"),
}

def invalid():
    print("AWS IAM vendor bundle manifest is invalid", file=sys.stderr)
    raise SystemExit(1)

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        manifest = json.load(source)
    if set(manifest) != {"manifest_version", "sdk", "submodules"}:
        invalid()
    if manifest["manifest_version"] != 1 or manifest["sdk"] != expected_sdk:
        invalid()
    entries = manifest["submodules"]
    if not isinstance(entries, list) or len(entries) != len(expected_submodules):
        invalid()
    actual = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "repository", "revision"}:
            invalid()
        path = entry["path"]
        if not isinstance(path, str) or path in actual:
            invalid()
        actual[path] = (entry["repository"], entry["revision"])
    if actual != expected_submodules:
        invalid()
except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
    invalid()
PY
then
	exit 1
fi

printf 'AWS IAM vendor bundle verified: AWS SDK for C++ 1.11.869 complete recursive sources\n'
