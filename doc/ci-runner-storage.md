# CI runner storage

The shared handoff restore in `.github/scripts/ci_tier_artifacts.py` uses
`RUNNER_TEMP` for its downloaded archive. GitHub Actions
[clears this directory at job boundaries](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#runner-context),
provided the runner user can delete the files. This also covers a cancelled
restore whose Python process was killed before its normal cleanup could run.
Outside Actions, the restore falls back to Python's default temporary directory.

Parallel HTTP ranges write directly at their offsets in one temporary ZIP.
Interrupted ranges resume independently; no part-file assembly copy is needed.
When supplied, the artifact SHA-256 is checked before publishing that ZIP.

Restore pipes the ZIP's `cache_full.tar.zst` member into zstd and extracts its
output directly into the checkout in one pass. It writes neither a separate
`.tar.zst` nor an uncompressed tar, and performs no preliminary decompression
scan. Path and link checks run as each tar entry is extracted. ZIP/decompression
failures still fail the restore, but may leave files already extracted into the
checkout; the next job's checkout cleans these like other incomplete build files.

Scratch storage is one compressed ZIP; peak restore storage is that ZIP plus
the extracted build, existing workspace files, and filesystem overhead. For
PR #6532's artifact, the successful path writes about 22.7 GB (6.8 GB downloaded
plus 15.9 GB extracted), rather than about 36.3 GB with the assembly and compressed
payload copies. These are logical file-write volumes, not physical-device
measurements; retries and filesystems can change actual I/O.

## Existing self-hosted runner leftovers

Changing the scratch location does not remove files left by older workflow
versions. On `ci-vm-1`, the 2026-10-01 investigation found:

- `/tmp/tmpa9wv4rtz`: 6.5 GiB from cancelled run
  [36853930836](https://github.com/sysown/proxysql/actions/runs/36853930836),
  containing `cache_full.tar.zst` and a partial `full.tar`.
- `/home/ci/_work/proxysql/proxysql`: an older root-level checkout with about
  17 GiB outside the current nested `proxysql/` checkout. Cleaning the nested
  checkout does not reclaim these older build outputs.
- Approximately 29.4 GiB in Docker/containerd image storage and an 8 GiB swap
  file on a 100 GiB virtual disk.

The installed `/home/ci/fix-perms-hook.sh` fixes workspace ownership and removes
`*.tar.zst` below `_work*`; it does not clean `/tmp` or remove old build trees.
The job-completed hook releases the VM job lock only.

For one-time maintenance:

1. Drain every runner service on the VM, including the other repositories,
   and wait for active jobs to finish. Stop the runner services before deleting
   workspaces so a queued job cannot start during maintenance.
2. Inspect disk use and running processes:

   ```sh
   df -h / /tmp /home/ci
   df -i /
   sudo du -x -h -d1 /home/ci/_work /tmp /var/lib/containerd
   pgrep -af 'Runner.Worker|ci_tier_runtime|zstd'
   ```

3. Inspect the exact abandoned scratch directory, its file timestamps, and
   open files before removing it. For the directory identified above:

   ```sh
   sudo find /tmp/tmpa9wv4rtz -maxdepth 2 -type f -ls
   sudo lsof +D /tmp/tmpa9wv4rtz
   ```

   Once confirmed abandoned, remove that exact directory. Do not sweep arbitrary
   `/tmp/tmp*` directories: other applications use the same naming scheme.
4. Inspect and preserve any files needed from the old workspace. With all runner
   services stopped, remove the verified disposable repository workspace, or
   move retained files to storage outside the runner disk first. The next job
   checks out its source again. Do not apply an indiscriminate cleanup from a
   running test job or remove the Actions runner installation.
5. Recheck free space, restart the runner services, and trigger a fresh CI run
   whose producer uses the updated `GH-Actions` control SHA. Existing manifests
   pin the control revision, so rerunning an old consumer may retain the old
   restore code.

Docker image pruning is optional maintenance, not part of handoff restore.
Cached images are reused by other jobs on these persistent VMs.

## Regression tests

```sh
python3 -m unittest discover -s .github/scripts/tests -p 'test_ci_tier*.py'
```

The download tests exercise real HTTP ranges, interrupted transfers, and a
one-archive write budget. The restore tests use real zip/zstd/tar payloads,
check that extraction uses one decompression and no intermediate payload copy,
force-kill a child restore to check scratch placement, and impose a file-size
limit that permits every output file but rejects an intermediate uncompressed
archive. They also check cleanup under pipe backpressure, corrupt streams,
unsafe paths during extraction, and local use without `RUNNER_TEMP`.
