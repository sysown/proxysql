# Release Notes Directory

This directory contains draft and final release notes for ProxySQL.

## Files

| File | Description |
|------|-------------|
| `DRAFT-3.0.6-4.0.6.md` | Draft release notes for 3.0.6 / 4.0.6 |
| `CHANGELOG-3.0.6-4.0.6-detailed.md` | Detailed commit-by-commit changelog |
| `CHANGELOG-3.0.6-4.0.6-commits.md` | Commits categorized by type and component |

## Version Scheme

ProxySQL 3.0.x and 4.0.x share the same codebase:

- **3.0.x**: Core proxy functionality (MySQL, PostgreSQL, routing, caching, monitoring)
- **4.0.x**: All 3.0.x features + GenAI/MCP/RAG capabilities (build with `PROXYSQLGENAI=1`)

## Workflow

1. **Draft Phase**: Release notes are maintained as drafts in this directory
2. **Updates**: As new commits are merged, update the draft files
3. **Review**: Before release, review and finalize the notes
4. **Publish**: Copy final notes to GitHub release and website

## Regenerating Changelogs

To regenerate the changelog files from the current commit range:

```bash
# From the ProxySQL root directory
./scripts/release-tools/generate-changelog.sh 7e9e00997d7d9fa4811c86c3a3bec9c886386e1f HEAD
```

## Commit Categorization

Commits are categorized by:
- **Type**: Feature, Fix, Test, Improvement, Docs, Build, Merge
- **Component**: MCP, GenAI, RAG, FFTO, TSDB, PostgreSQL, MySQL, Core, etc.

## Contributing

When adding significant features, consider updating the draft release notes to document:
- Feature description and use case
- New configuration variables
- New admin tables or commands
- Breaking changes or deprecations
