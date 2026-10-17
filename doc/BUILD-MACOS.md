# Compiling ProxySQL on macOS

This guide provides step-by-step instructions for compiling ProxySQL from source on macOS (Intel or Apple Silicon) using Homebrew.

## Prerequisites

Ensure you have [Homebrew](https://brew.sh/) installed.

### Install Dependencies

Run the following command to install the required build tools and libraries:

```bash
brew install automake bzip2 cmake make git gpatch gnutls openssl@3 icu4c pkg-config libiconv libtool zlib
```

## Compilation Steps

To compile ProxySQL, you must set the following environment variables so the build system can locate OpenSSL and other Homebrew-provided libraries.

### 1. Set Environment Variables

```bash
export PATH="/opt/homebrew/bin:$PATH"
export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig:$PKG_CONFIG_PATH"
export OPENSSL_ROOT_DIR="/opt/homebrew/opt/openssl@3"
```

### 2. Run the Build

You can now run the standard build command:

```bash
make
```

Or for a debug build:

```bash
make debug
```

ClickHouse support is compiled into both release and debug builds on macOS,
just as on Linux. `LEGACY_BUILD` no longer selects a reduced feature set;
the old `build_*_legacy` targets are compatibility aliases for the normal build.
Compiling the support does not start the ClickHouse listener: use the
`--clickhouse-server` runtime option when you want to enable it.

For the v4 plugin chassis, build with `gmake -j$(sysctl -n hw.ncpu) PROXYSQL40=1`.
Existing macOS/FreeBSD checkouts need a **clean rebuild of core and all plugins**
when updating to this default; an incremental `make` can reuse incompatible
objects built without ClickHouse. The same clean-rebuild requirement applies
whenever feature flags change:
`PROXYSQLCLICKHOUSE` changes shared C++ class layouts. Its default is now `1`
on every platform. An explicitly customized build using `PROXYSQLCLICKHOUSE=0`
must use that same value for **all** plugins, including the WebUI plugin.

## Troubleshooting

### Local build regression checks

Use Homebrew GNU Make for the CI checks as well as the build: Apple's bundled
Make is too old for some of the test Makefiles. The shell checks below also
work with macOS's bundled Bash 3.2.

```bash
export PATH="$(brew --prefix make)/libexec/gnubin:$PATH"
python3 -m unittest discover -s test/infra/control -p 'test_*.py'
CI_ENGINE_REF="$(cat .github/ci-tier-engine-ref)" bash test/infra/control/run-ci-lint.bash
```

The explicit CI-engine pin keeps the paired workflow checks aligned with this
checkout. Testing against a newer `origin/GH-Actions` catalogue can otherwise
report missing callers that have not yet landed in the matching core revision.

### Linking Issues
If the linker fails to find `libssl` or `libcrypto`, ensure that `OPENSSL_ROOT_DIR` and `PKG_CONFIG_PATH` are correctly set to point to your Homebrew OpenSSL installation.

### Missing ICU Headers
The build system is configured to find `icu4c` via Homebrew. If you encounter errors related to ICU, ensure `icu4c` is installed and the Homebrew prefix is correct.

### Building TAP Tests (Optional)

If you wish to run the TAP tests, you need to build the test dependencies first:

```bash
export OPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
make build_tap_test_debug
```

This will automatically:
1. Build the main ProxySQL debug binary.
2. Download and build MariaDB and MySQL connectors (patched for macOS compatibility).
3. Build the TAP test framework.
