# Enhanced Release Notes Generation Prompt

Generate comprehensive, human-readable release notes for ProxySQL X.X.X using the provided data files. Focus on creating descriptive content that explains what each feature/fix does and why it matters, not just listing PR titles.

## Available Data Files
1. `pr-data.json` - All PR details from GitHub including titles, descriptions, labels
2. `structured-notes.md` - Commit-level organized data with technical details
3. `commit-categories.md` - Commits categorized by type (bug fix, feature, documentation, etc.)

## Requirements

### 1. Overall Structure
- Start with a **concise introduction paragraph** summarizing the release's significance
- Include a **"Highlights" section** with bullet points summarizing key areas of improvement
- Organize changes under logical categories: New Features, Bug Fixes, Improvements, Documentation, Testing, Build/Packaging, Other Changes
- Each major section should have a **brief introductory sentence** explaining its theme
- End with the release commit hash in backticks

### 2. Writing Style
- Write **descriptive paragraphs** for each feature/fix (2-4 sentences minimum)
- Explain **what the change does** and **why it matters** to users/administrators
- Use **complete sentences** with proper grammar and flow
- Avoid jargon without explanation; assume some readers may not be deep technical experts
- Maintain a **professional yet accessible** tone

### 3. Technical Formatting
- Wrap **all technical terms** in backticks:
  - Function names: `Read_Global_Variables_from_configfile()`
  - Variable names: `wait_timeout`, `cur_cmd_cmnt`
  - SQL queries: `SELECT @@version`, `SELECT VERSION()`
  - Protocol commands: `COM_PING`, `CLIENT_DEPRECATE_EOF`
  - Configuration options: `cache_empty_result=0`
  - Metrics: `PgSQL_Monitor_ssl_connections_OK`
  - File paths, command names, code snippets
- Include **commit hashes (short form)** and **PR numbers** in parentheses after each item
- Remove any `[WIP]`, `[skip-ci]`, or similar tags from final output
- Use **bold for feature/fix names** followed by commit/PR references

### 4. Section Guidelines

#### Highlights Section
- 4-6 bullet points summarizing the most significant improvements
- Focus on user/administrator benefits
- Example: "Enhanced PostgreSQL support with SSL/TLS backend connections"

#### New Features Section
- Group related features under subcategories (PostgreSQL Improvements, MySQL Protocol Enhancements, Monitoring & Diagnostics)
- Start each subcategory with a brief introduction sentence
- For each feature: **Bold title**, (commit, #PR), then descriptive paragraph

#### Bug Fixes Section
- Start with an introductory sentence: "This release addresses several critical issues affecting..."
- Group by affected components (MySQL, Monitoring, Security & Configuration)
- For each fix: Clearly state the problem, then explain the solution

#### Improvements Section
- Focus on performance, stability, and efficiency enhancements
- Explain the impact (reduced contention, improved compatibility, etc.)

#### Other Sections (Documentation, Testing, Build/Packaging)
- Include brief introductory sentences for each section
- Explain the practical value (better maintainability, expanded platform support, etc.)

### 5. Quality Checklist
- [ ] Every feature/fix has descriptive paragraph(s), not just title
- [ ] All technical terms properly wrapped in backticks
- [ ] Commit hashes and PR numbers included
- [ ] Section introductions provide context
- [ ] Highlights section gives quick overview
- [ ] No WIP/skip-ci tags remain
- [ ] Consistent formatting throughout
- [ ] Logical grouping of related changes

## Example Format

Follow this structure for each feature/fix entry:

```
**Feature Name** (abc1234, #1234)
Descriptive paragraph explaining what this feature does and why it matters.
Include technical details like `technical terms` in backticks.
Explain benefits to users/administrators.
```

## Output Files
Generate the following files:
- `ProxySQL-X.X.X-Release-Notes-Enhanced.md` - Main enhanced release notes
- `CHANGELOG-X.X.X-detailed.md` - Detailed changelog (optional)
- `CHANGELOG-X.X.X-commits.md` - Complete commit list (optional)

## Tone & Audience
Write for:
1. **Database administrators** who need to understand new features and fixes
2. **Developers** integrating with ProxySQL
3. **System architects** evaluating ProxySQL for their infrastructure
4. **Open source contributors** understanding the project's direction

The release notes should be informative enough for technical decision-making while remaining accessible to those with general database/proxy knowledge.