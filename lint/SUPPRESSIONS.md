Lint suppressions policy

- Prefer fixing issues over suppressing.
- Use `// NOLINT(<check>): reason` for clang-tidy only when necessary.
- For cppcheck, use `// cppcheck-suppress <id>` inline if unavoidable.
- Document the reason and add a TODO for revisit.
