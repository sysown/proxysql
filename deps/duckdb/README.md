# Vendored DuckDB

DuckDB source is vendored under this directory and built from source as a
static library (`libduckdb_static.a`) for the `PROXYSQL40` plugin-chassis
tier. The release archive is committed directly to git (like every other
dependency under `deps/`), alongside a committed SHA-256 sidecar and a
`verify-source.bash` preflight. The verifier fails fast and legibly if the
archive is missing, corrupted, or tampered with.

## Pinned version

- **Version:** DuckDB **v1.4.5** (DuckDB's LTS release line)
- **Upstream URL:** https://github.com/duckdb/duckdb/archive/refs/tags/v1.4.5.tar.gz
- **Release page:** https://github.com/duckdb/duckdb/releases/tag/v1.4.5
- **Archive:** `deps/duckdb/duckdb-1.4.5.tar.gz`
- **SHA-256:** `29931ac91cf9077292773099a900c67be6d13b933978e176249b6e5b75b0b958`
  (also recorded in `deps/duckdb/duckdb-1.4.5.tar.gz.sha256`)
- **Archive root:** `duckdb-1.4.5/`

v1.4.5 was chosen (over the latest v1.5.5) because it is DuckDB's LTS line
and targets an older toolchain floor, matching the AlmaLinux 8 floor in this
project's package build matrix (`.github/workflows/CI-package-*almalinux8*.yml`).

## The archive is vendored directly in git

`deps/duckdb/duckdb-1.4.5.tar.gz` is a regular git blob — no Git LFS, no
extra fetch step. A plain `git clone` contains the full 98 MB archive, so
`deps/duckdb/verify-source.bash` only has to guard against corruption or
tampering (SHA-256 + archive-root checks), and no workflow needs any
LFS-related `actions/checkout` setting.

## Building

```bash
make -C deps PROXYSQL40=1 duckdb
```

produces `deps/duckdb/duckdb/build/release/src/libduckdb_static.a` and
headers under `deps/duckdb/duckdb/src/include/`. The paths are exposed to
the rest of the build via `include/makefiles_paths.mk`:

```make
DUCKDB_PATH := $(DEPS_PATH)/duckdb/duckdb
DUCKDB_IDIR := $(DUCKDB_PATH)/src/include
DUCKDB_LDIR := $(DUCKDB_PATH)/build/release/src
```

Note: `targets += duckdb` in `deps/Makefile`'s `PROXYSQL40` block only wires
the target into the top-level `default` target of `deps/Makefile` itself.
The top-level repo `Makefile`'s `build_deps_default` /
`build_deps_debug_default` rules do **not** propagate `PROXYSQL40` into the
deps sub-make, so a bare `make` at the repo root will not build DuckDB. The
DuckDB plugin's own Makefile (added in a later task) is expected to invoke
`make -C deps PROXYSQL40=1 duckdb` (or depend on
`deps/duckdb/duckdb/build/release/src/libduckdb_static.a` directly) as part
of its on-demand build rule.

## Bumping the version

1. Download the new release archive and compute its checksum:
   ```bash
   cd deps/duckdb
   curl -L -o duckdb-<new-version>.tar.gz \
     https://github.com/duckdb/duckdb/archive/refs/tags/v<new-version>.tar.gz
   sha256sum duckdb-<new-version>.tar.gz | awk '{print $1"  duckdb-<new-version>.tar.gz"}' \
     > duckdb-<new-version>.tar.gz.sha256
   tar -tzf duckdb-<new-version>.tar.gz | head -1   # confirm the archive root
   ```
2. Update `deps/duckdb/verify-source.bash`:
   - `archive` default path -> `duckdb-<new-version>.tar.gz`
   - `required_root` -> the root printed by `tar -tzf ... | head -1` (usually
     `duckdb-<new-version>`, but verify — do not assume)
3. If the archive root pattern changed (unlikely — it has always been
   `duckdb-<version>/`), update the `tar -zxf duckdb-*.tar.gz && mv
   duckdb-*/ duckdb` glob in `deps/Makefile`'s `duckdb` recipe accordingly.
4. Commit the new archive and checksum file directly (`git add
   deps/duckdb/duckdb-<new-version>.tar.gz
   deps/duckdb/duckdb-<new-version>.tar.gz.sha256`) — no Git LFS.
   Remove the old archive and checksum file (`git rm
   deps/duckdb/duckdb-<old-version>.tar.gz
   deps/duckdb/duckdb-<old-version>.tar.gz.sha256`).
   Note: GitHub blocks individual files over 100 MB in regular git; if a
   future DuckDB archive exceeds that, the vendoring strategy must be
   revisited (e.g. download-on-demand at build time) instead of LFS —
   LFS bandwidth is metered and was the reason LFS was removed.
5. Re-run the verifier test:
   ```bash
   bash test/infra/control/test-vendored-duckdb-source.bash
   ```
6. Rebuild and re-check the result-API shape (see below) in case it changed:
   ```bash
   make -C deps PROXYSQL40=1 duckdb
   grep -c "duckdb_value_varchar\|duckdb_row_count\|duckdb_value_is_null" \
     deps/duckdb/duckdb/src/include/duckdb.h
   ```
7. Update this README's "Pinned version" and "Result-API shape" sections.

## Build cost

Design decision D2 (`docs/superpowers/specs/2026-08-26-duckdb-server-plugin-design.md`,
§4) committed to measuring the real cost of this dep build rather than
leaving the original 10–30 minute estimate standing.

**This is an observation, not a controlled from-scratch measurement.**
A true `cleanall` + timed rebuild was not performed in the session that
recorded these numbers, specifically to avoid destroying the working
DuckDB build tree that later verification and review depend on (per that
task's explicit instructions). What follows is the actual wall-clock this
dep build took the two times it was genuinely built from scratch during
this sub-project's development, read back from that session's own
transcript rather than re-measured:

| Run | What happened | Wall-clock | Cores |
|---|---|---|---|
| Initial vendoring build | `make -C deps PROXYSQL40=1 duckdb` — verify, extract, cmake configure, `cmake --build build/release -j32` | ~10 minutes | 32 (`nproc`) |
| Rebuild after the `DUCKDB_EXPLICIT_VERSION` fix | `libduckdb_static.a` deleted and the same recipe re-run in full (re-verify, re-extract, reconfigure, rebuild) | ~7 minutes | 32 (`nproc`) |

No peak-RSS figure was captured for either run (`/usr/bin/time -v` was
not used at the time); only wall-clock is known. Both runs were on the
same 32-core machine this repository's DuckDB build tree currently lives
on. Artifact sizes at the time of writing:

- `deps/duckdb/duckdb-1.4.5.tar.gz` (the vendored source archive): 98,359,161 bytes (~94 MiB)
- `deps/duckdb/duckdb/build/release/src/libduckdb_static.a` (the built static library): 73,663,416 bytes (~70 MiB)
- `deps/duckdb/duckdb/` (full extracted + built tree): ~606 MiB

**Verdict on D2's gating decision, pending a real controlled measurement:**
~7–10 minutes wall-clock on 32 cores is well inside the original 10–30
minute estimate's low end, not near its high end — DuckDB's build does not
appear to be the largest compile in the tree in practice, at least on a
high-core-count machine. A slower/fewer-core CI runner will see a larger
number; anyone revisiting D2 should get a genuine `/usr/bin/time -v make
-C deps PROXYSQL40=1 duckdb` run (after `cleanall`) on the actual CI
runner class, not extrapolate from this workstation figure.

## Result-API shape (checked against v1.4.5)

`deps/duckdb/duckdb/src/include/duckdb.h` in the pinned v1.4.5 tree still
declares the deprecated scalar-value result accessors:

```
grep -c "duckdb_value_varchar\|duckdb_row_count\|duckdb_value_is_null" \
  deps/duckdb/duckdb/src/include/duckdb.h
# => 6
```

All three symbols (`duckdb_value_varchar`, `duckdb_row_count`,
`duckdb_value_is_null`) are present and usable, but each is guarded by
`#ifndef DUCKDB_API_NO_DEPRECATED` and individually documented with a
`**DEPRECATION NOTICE**: This method is scheduled for removal in a future
release.` comment (DuckDB does not define `DUCKDB_API_NO_DEPRECATED` in this
build, so they compile in normally). Practically:

- A later task (result-materialization, e.g. Task 5) **may** use
  `duckdb_value_varchar` / `duckdb_row_count` / `duckdb_value_is_null`
  against this pinned version — they exist and work.
- Because they are marked for future removal, prefer implementing against
  `duckdb_fetch_chunk` + `duckdb_vector_get_data` +
  `duckdb_validity_row_is_valid` instead if avoiding a forced rewrite on the
  next version bump matters more than short-term implementation speed. This
  is the fallback strategy this task's brief specified for the case where
  the deprecated accessors are *absent* (count == 0); here they are present,
  so using them is a valid choice, but not future-proof.
- On any future version bump, re-run the Step 8 grep above — if the count
  drops to 0, the deprecated accessors have been removed and the chunk-based
  API becomes mandatory, not just preferred.
