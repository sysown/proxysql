# Compiling ProxySQL on macOS

This guide provides step-by-step instructions for compiling ProxySQL from source on macOS (Intel or Apple Silicon) using Homebrew.

## Prerequisites

Ensure you have [Homebrew](https://brew.sh/) installed.

### Install Dependencies

Run the following command to install the required build tools and libraries:

```bash
brew install automake bzip2 cmake make git gpatch gnutls openssl@3 icu4c pkg-config libiconv zlib
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

## Troubleshooting

### Linking Issues
If the linker fails to find `libssl` or `libcrypto`, ensure that `OPENSSL_ROOT_DIR` and `PKG_CONFIG_PATH` are correctly set to point to your Homebrew OpenSSL installation.

### Missing ICU Headers
The build system is configured to find `icu4c` via Homebrew. If you encounter errors related to ICU, ensure `icu4c` is installed and the Homebrew prefix is correct.
