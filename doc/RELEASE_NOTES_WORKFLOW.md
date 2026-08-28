# ProxySQL Release Notes Workflow

This document describes the complete workflow for generating release notes like ProxySQL v3.0.3.

## Quick Start (For ProxySQL 3.0.4)

```bash
# 1. Run the orchestration script
python scripts/release-tools/orchestrate_release.py \
  --from-tag v3.0.3 \
  --to-tag v3.0 \
  --output-dir release-data \
  --verbose

# 2. Provide the generated files to LLM with this prompt:
cat release-data/llm-prompt-v3.0.md
```

## Complete Procedure

### Step 1: Prepare Environment
```bash
git fetch --tags
git checkout v3.0  # Ensure you're on the release branch
```

### Step 2: Run Orchestration Script
```bash
python scripts/release-tools/orchestrate_release.py \
  --from-tag PREVIOUS_TAG \
  --to-tag CURRENT_BRANCH_OR_NEW_TAG \
  --output-dir release-data
```

This generates:
- `release-data/pr-data-*.json` - PR details from GitHub
- `release-data/pr-summary-*.md` - PR summary
- `release-data/structured-notes-*.md` - Commit-level data
- `release-data/llm-prompt-*.md` - Complete LLM prompt
- `release-data/workflow-summary.md` - Instructions

### Step 3: Provide Files to LLM

Give the LLM:
1. All files in `release-data/` directory
2. The prompt: `release-data/llm-prompt-*.md`

### Step 4: LLM Generates Release Notes

The LLM should create:
- `ProxySQL-X.X.X-Release-Notes.md` - Main release notes
- `CHANGELOG-X.X.X-detailed.md` - Detailed changelog
- `CHANGELOG-X.X.X-commits.md` - Complete commit list (optional)

## Key Requirements for Release Notes

1. **Descriptive Content**: Explain what each feature/fix does and why it matters
2. **Logical Grouping**: Organize under categories (PostgreSQL, MySQL, Monitoring, etc.)
3. **Backtick Formatting**: Use `backticks` around all technical terms
4. **Commit References**: Include commit hashes and PR numbers
5. **No WIP/skip-ci Tags**: Make all entries production-ready
6. **Follow v3.0.3 Format**: Structure like previous release notes

## Example Output

See `ProxySQL-3.0.4-Release-Notes.md` in the root directory for a complete example of descriptive release notes with backtick formatting.

## Tools Directory

All scripts are in `scripts/release-tools/`:

| Script | Purpose |
|--------|---------|
| `orchestrate_release.py` | Main orchestration script |
| `collect_pr_data.py` | Fetch PR details from GitHub |
| `generate_structured_notes.py` | Create commit-level data |
| `categorize_commits.py` | Categorize commits by type |
| `generate_release_notes.py` | Basic release notes (without LLM) |
| `generate_changelog.py` | Basic changelog generation |

See `scripts/release-tools/README.md` for detailed documentation.

## For ProxySQL 3.0.4

The release notes for 3.0.4 have already been generated:
- `ProxySQL-3.0.4-Release-Notes.md` - Final release notes
- Backup: `ProxySQL-3.0.4-Release-Notes-backup.md` - Original version
- Example: `ProxySQL-3.0.4-Release-Notes-Descriptive.md` - Descriptive version

These notes follow all requirements: descriptive content, logical grouping, backtick formatting, and proper references.