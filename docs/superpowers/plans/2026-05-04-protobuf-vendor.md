# Protobuf 3 Vendoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Vendor protobuf 3 into `deps/` and make the mysqlx plugin link against it on Linux and macOS without depending on Homebrew or the system `libprotobuf`.

**Architecture:** Add a protobuf 3 source archive and a small `deps/Makefile` recipe that builds a static `libprotobuf.a` from that archive into a local `deps/protobuf` build tree. Then update `plugins/mysqlx/Makefile` so the plugin uses the vendored protobuf include and library paths unconditionally on both Linux and macOS, while keeping the existing generated `*.pb.cc` sources unchanged.

**Tech Stack:** GNU make, CMake, C++17, protobuf 3.21.12 source release.

---

### Task 1: Add vendored protobuf source and build recipe

**Files:**
- Create: `deps/protobuf/protobuf-3.21.12.tar.gz`
- Modify: `deps/Makefile`

- [ ] **Step 1: Add the protobuf source archive**

Download `https://github.com/protocolbuffers/protobuf/releases/download/v3.21.12/protobuf-3.21.12.tar.gz` into `deps/protobuf/`.

- [ ] **Step 2: Add a failing build target**

Extend `deps/Makefile` with a `protobuf` target that extracts the archive and runs a CMake build for a static runtime library. The target should produce a stable artifact path that other makefiles can consume, such as `deps/protobuf/protobuf-3.21.12/build/libprotobuf.a` or a local install tree under `deps/protobuf/install/`.

- [ ] **Step 3: Run the dependency build**

Run: `make -C deps protobuf -j24`

Expected: protobuf 3.21.12 configures and builds a static runtime library without touching the mysqlx plugin yet.

- [ ] **Step 4: Commit**

```bash
git add deps/protobuf/protobuf-3.21.12.tar.gz deps/Makefile
git commit -m "Vendor protobuf 3 for mysqlx"
```

### Task 2: Link mysqlx against vendored protobuf

**Files:**
- Modify: `plugins/mysqlx/Makefile`

- [ ] **Step 1: Update the mysqlx build inputs**

Replace the `pkg-config protobuf` dependency check with explicit include/library paths that point at the vendored protobuf build or install tree from Task 1. Keep the existing `PROTOBUF_GENERATED_VERSION := 3.21.12` guard so the build still fails if the archive is missing or the wrong protobuf tree is selected.

- [ ] **Step 2: Build the plugin on Linux**

Run: `make -C plugins/mysqlx PROXYSQL40=1 -j24`

Expected: the plugin links successfully against the vendored `libprotobuf.a`.

- [ ] **Step 3: Build the plugin on macOS**

Run the same `make -C plugins/mysqlx PROXYSQL40=1 -j24` flow on macOS.

Expected: the build no longer depends on Homebrew `protobuf@3` and does not trip the ABI guard.

- [ ] **Step 4: Commit**

```bash
git add plugins/mysqlx/Makefile
git commit -m "Link mysqlx against vendored protobuf"
```

### Task 3: Verify the full build

**Files:**
- None

- [ ] **Step 1: Rebuild the tree**

Run:

```bash
export PROXYSQL40=1
make cleanall
make build_deps -j24
make debug -j24
make build_tap_test_debug -j24
```

Expected: the full Linux build passes with vendored protobuf and the mysqlx plugin still builds.

- [ ] **Step 2: Inspect any remaining platform-specific warnings**

If the macOS build reveals any path or linker differences, adjust only the vendored protobuf wiring rather than reintroducing a system-protobuf dependency.

- [ ] **Step 3: Commit verification notes**

Record the exact commands and any residual warnings in the branch notes or PR description.
