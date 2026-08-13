# Updating the vendored AWS SDK for C++

ProxySQL vendors the complete, unmodified AWS SDK for C++ source tree and its
recursive CRT submodules as a Git LFS tarball. This checklist is for the rare
SDK update; it is intentionally not an executable CI test.

1. Check out the selected upstream release and initialize every recursive
   submodule. Do not edit, prune, regenerate, or reformat upstream files.
2. Record the SDK tag, SDK commit, and every recursive submodule commit in
   `aws-sdk-cpp-<version>-sources.json`.
3. Create `aws-sdk-cpp-<version>-with-crt.tar.xz` with one top-level
   `aws-sdk-cpp-<version>/` directory and no `.git` directories or build
   outputs.
4. Copy the corresponding upstream `LICENSE`, `NOTICE`, and third-party notice
   material into this directory.
5. Generate `aws-sdk-cpp-<version>-with-crt.sha256`, update the expected digest
   in `build-sdk.cmake`, and confirm the archive is tracked by Git LFS:

   ```console
   sha256sum -c aws-sdk-cpp-<version>-with-crt.sha256
   git lfs ls-files
   ```

6. Build through ProxySQL's dependency graph and verify the general AWS plugin:

   ```console
   PROXYSQL40=1 make -C deps -j
   PROXYSQL40=1 make -C plugins/aws -j
   ```

7. Confirm `ProxySQL_Aws_Plugin.so` contains the expected AWS SDK symbols and
   has no dynamic dependency on an AWS SDK or CRT library. Confirm
   `src/proxysql` contains no AWS SDK symbols.
8. Review the source manifest and license files as part of the SDK-update pull
   request.
