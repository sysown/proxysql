# Vendored AWS SDK for C++ source notices

This directory contains the complete recursively expanded source checkout for
AWS SDK for C++ 1.11.869 at the revisions recorded in
`aws-sdk-cpp-1.11.869-sources.json`. CMake controls which upstream targets are
built; tests, feature probes, fixtures, examples, tools, generated sources,
and documentation remain in the source archive.

The bundle-level `LICENSE` and `NOTICE` are unmodified copies of the AWS SDK
for C++ `LICENSE` and `NOTICE.txt` at the pinned revision. The archive retains
the following upstream attribution for every manifest source tree:

| Manifest tree | License material | Notice material |
| --- | --- | --- |
| SDK root | `LICENSE`, `LICENSE.txt` | `NOTICE.txt` |
| `crt/aws-crt-cpp` | `crt/aws-crt-cpp/LICENSE` | `crt/aws-crt-cpp/NOTICE` |
| `crt/aws-crt-cpp/crt/aws-c-auth` | `crt/aws-crt-cpp/crt/aws-c-auth/LICENSE` | `crt/aws-crt-cpp/crt/aws-c-auth/NOTICE` |
| `crt/aws-crt-cpp/crt/aws-c-cal` | `crt/aws-crt-cpp/crt/aws-c-cal/LICENSE` | `crt/aws-crt-cpp/crt/aws-c-cal/NOTICE` |
| `crt/aws-crt-cpp/crt/aws-c-common` | `crt/aws-crt-cpp/crt/aws-c-common/LICENSE` and `THIRD-PARTY-LICENSES.txt` | `crt/aws-crt-cpp/crt/aws-c-common/NOTICE` |
| `crt/aws-crt-cpp/crt/aws-c-compression` | `crt/aws-crt-cpp/crt/aws-c-compression/LICENSE` | `crt/aws-crt-cpp/crt/aws-c-compression/NOTICE` |
| `crt/aws-crt-cpp/crt/aws-c-event-stream` | `crt/aws-crt-cpp/crt/aws-c-event-stream/LICENSE` | `crt/aws-crt-cpp/crt/aws-c-event-stream/NOTICE` |
| `crt/aws-crt-cpp/crt/aws-c-http` | `crt/aws-crt-cpp/crt/aws-c-http/LICENSE` | `crt/aws-crt-cpp/crt/aws-c-http/NOTICE` |
| `crt/aws-crt-cpp/crt/aws-c-io` | `crt/aws-crt-cpp/crt/aws-c-io/LICENSE` | `crt/aws-crt-cpp/crt/aws-c-io/NOTICE` |
| `crt/aws-crt-cpp/crt/aws-c-mqtt` | `crt/aws-crt-cpp/crt/aws-c-mqtt/LICENSE` | `crt/aws-crt-cpp/crt/aws-c-mqtt/NOTICE` |
| `crt/aws-crt-cpp/crt/aws-c-s3` | `crt/aws-crt-cpp/crt/aws-c-s3/LICENSE` | `crt/aws-crt-cpp/crt/aws-c-s3/NOTICE` |
| `crt/aws-crt-cpp/crt/aws-c-sdkutils` | `crt/aws-crt-cpp/crt/aws-c-sdkutils/LICENSE` | `crt/aws-crt-cpp/crt/aws-c-sdkutils/NOTICE` |
| `crt/aws-crt-cpp/crt/aws-checksums` | `crt/aws-crt-cpp/crt/aws-checksums/LICENSE` | No separate NOTICE is present in the pinned upstream tree. |
| `crt/aws-crt-cpp/crt/aws-lc` | `crt/aws-crt-cpp/crt/aws-lc/LICENSE` and retained `third_party/*/LICENSE*` files | `crt/aws-crt-cpp/crt/aws-lc/NOTICE` and retained `third_party/*/NOTICE` files |
| `crt/aws-crt-cpp/crt/s2n` | `crt/aws-crt-cpp/crt/s2n/LICENSE` | `crt/aws-crt-cpp/crt/s2n/NOTICE` |
| `crt/aws-crt-cpp/crt/s2n/tests/cbmc/aws-verification-model-for-libcrypto` | its `LICENSE` | its `NOTICE` |

All paths in the table are relative to the archive's single
`aws-sdk-cpp-1.11.869/` directory.
