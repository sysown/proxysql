# ProxySQL Release Tools

This directory contains Python scripts to help generate release notes and changelogs for ProxySQL releases.

## Prerequisites

- Python 3.6+
- Git command line tools
- GitHub CLI (`gh`) installed and authenticated (for scripts that fetch PR details)

## Scripts Overview

### 1. `categorize_commits.py`

Categorizes git commits based on keywords in commit messages.

**Usage:**
```bash
python categorize_commits.py --from-tag v3.0.3 --to-tag v3.0
python categorize_commits.py --input-file /tmp/commits.txt --output-format text
```

**Options:**
- `--from-tag`, `--to-tag`: Git tags/branches to compare
- `--input-file`: Read commits from a file (format: git log --pretty=format:'%H|%s|%b')
- `--output-format`: `markdown` (default) or `text`
- `--verbose`: Show detailed output

### 2. `generate_changelog.py`

Generates a changelog from git merge commits (pull requests). Uses second parent of merge commits to get PR-specific commits.

**Usage:**
```bash
python generate_changelog.py --from-tag v3.0.3 --to-tag v3.0 --output changelog.md
```

**Options:**
- `--from-tag`, `--to-tag`: Git tags/branches to compare
- `--output`, `-o`: Output file (default: changelog.md)
- `--verbose`: Show progress

### 3. `generate_release_notes.py**

Generates formatted release notes using GitHub API (via `gh` CLI). Provides automatic categorization based on PR labels and titles, with optional manual mapping.

**Usage:**
```bash
python generate_release_notes.py --from-tag v3.0.3 --to-tag v3.0 --output release-notes.md
python generate_release_notes.py --from-tag v3.0.3 --to-tag v3.0 --config category_mapping.json --verbose
```

**Options:**
- `--from-tag`, `--to-tag`: Git tags/branches to compare
- `--output`, `-o`: Output file for release notes (default: release-notes.md)
- `--changelog`, `-c`: Output file for detailed changelog
- `--config`: JSON file with manual category mapping (see example)
- `--verbose`: Show detailed progress

### 4. `fetch_prs.py` (legacy)

Legacy script that was used for ProxySQL 3.0.4. Consider using `generate_release_notes.py` instead.

### 5. `gen_release_notes.py` (legacy)

Legacy script with hardcoded mapping for 3.0.4.

## Category Mapping

For `generate_release_notes.py`, you can provide a JSON file with manual categorization overrides. The format can be:

```json
{
  "5259": ["Bug Fixes", "MySQL"],
  "5257": ["New Features", "MySQL"],
  "5258": "Documentation"
}
```

Each key is a PR number. The value can be:
- A string: category name (e.g., `"Documentation"`)
- An array: `[category, subcategory]` (e.g., `["New Features", "PostgreSQL"]`)

See `category_mapping.example.json` for a complete example.

## Complete Workflow with LLM Integration

For high-quality release notes like ProxySQL v3.0.3, use the orchestrated workflow:

### Option 1: Automated Orchestration (Recommended)

```bash
# Run the complete workflow
python orchestrate_release.py --from-tag v3.0.3 --to-tag v3.0.4 --output-dir release-data --verbose

# This generates:
# - release-data/pr-data-3.0.4.json        # PR details from GitHub
# - release-data/pr-summary-3.0.4.md        # PR summary
# - release-data/structured-notes-3.0.4.md  # Commit-level data
# - release-data/llm-prompt-3.0.4.md        # Complete prompt for LLM
# - release-data/workflow-summary.md        # Instructions summary
```

### Option 2: Manual Steps

#### Step 1: Prepare the environment

Ensure you're on the correct branch and have all tags fetched:
```bash
git fetch --tags
git checkout v3.0  # or your release branch
```

#### Step 2: Collect PR data for LLM analysis

```bash
python collect_pr_data.py --from-tag v3.0.3 --to-tag v3.0.4 --output pr-data.json --verbose
```

#### Step 3: Generate structured analysis files

```bash
python generate_structured_notes.py --input pr-data.json --output structured-notes.md --verbose
python categorize_commits.py --from-tag v3.0.3 --to-tag v3.0.4 --output-format markdown > commit-categories.md
```

#### Step 4: Provide data to LLM with this prompt:

```markdown
Generate ProxySQL 3.0.4 release notes and changelogs using the provided data files.

Available files:
1. pr-data.json - All PR details from GitHub
2. structured-notes.md - Commit-level organized data
3. commit-categories.md - Commits categorized by type

Requirements:
1. Write DESCRIPTIVE release notes (not just PR titles)
2. Group changes logically (PostgreSQL, MySQL, Monitoring, Bug Fixes, etc.)
3. Use `backticks` around all technical terms
4. Include commit hashes and PR numbers
5. Remove any WIP/skip-ci tags
6. Follow the format of ProxySQL v3.0.3 release notes

Output files:
- ProxySQL-3.0.4-Release-Notes.md
- CHANGELOG-3.0.4-detailed.md
- CHANGELOG-3.0.4-commits.md (optional)
```

### Option 3: Quick Generation (Without LLM)

For basic changelogs without descriptive analysis:
```bash
python generate_release_notes.py --from-tag v3.0.3 --to-tag v3.0.4 --output release-notes.md --changelog detailed-changelog.md --verbose
python generate_changelog.py --from-tag v3.0.3 --to-tag v3.0.4 --output changelog.md
```

## Examples

See the `examples/` directory for output generated for ProxySQL 3.0.4:
- `ProxySQL-3.0.4-Release-Notes.md`: Final release notes
- `CHANGELOG-3.0.4-detailed.md`: Detailed changelog with PR summaries
- `CHANGELOG-3.0.4-commits.md`: Complete list of commits

## Generating Descriptive Release Notes

ProxySQL release notes (see v3.0.3 example) are descriptive, not just collections of PR titles. They:
1. Group related changes under feature categories
2. Describe what each feature/fix does and why it matters
3. Reference PR numbers and commit hashes
4. Use backticks around technical terms

The scripts in this directory help collect data, but the LLM should:
1. Analyze PR descriptions and commit messages
2. Write descriptive paragraphs explaining changes
3. Group related changes logically
4. Apply backtick formatting to technical terms

### Backtick Formatting for Technical Terms

ProxySQL release notes use backticks (`) around technical terms such as:
- Function names: `Read_Global_Variables_from_configfile()`
- Variable names: `wait_timeout`, `cur_cmd_cmnt`
- SQL queries: `SELECT @@version`, `SELECT VERSION()`
- Protocol commands: `COM_PING`, `CLIENT_DEPRECATE_EOF`
- Configuration options: `cache_empty_result=0`
- Metrics: `PgSQL_Monitor_ssl_connections_OK`

The scripts do not automatically apply backtick formatting. When generating final release notes with the LLM, ensure you:
1. Manually add backticks around technical terms
2. Use the LLM's understanding of the codebase to identify what needs formatting
3. Review the final output for consistency

## Tips

1. **GitHub CLI Authentication**: Ensure `gh auth login` has been run and you have permissions to access the repository.

2. **Tag Names**: Use exact tag names (e.g., `v3.0.3`) or branch names (e.g., `HEAD` for current branch).

3. **Manual Review**: Always review the generated notes. Automatic categorization is not perfect.

4. **Customization**: Feel free to modify the categorization keywords in the scripts to match your project's conventions.

## License

These tools are part of the ProxySQL project and follow the same licensing terms.