#!/usr/bin/env python3
"""
Generate structured release notes from PR data.

This script reads PR data collected by collect_pr_data.py and generates
release notes in the style of ProxySQL v3.0.3 release notes, with
descriptive grouping and individual commit references.
"""

import json
import argparse
import sys
from collections import defaultdict


def load_pr_data(filename):
    """Load PR data from JSON file."""
    with open(filename, 'r') as f:
        return json.load(f)


def categorize_pr(pr):
    """Categorize PR based on title, labels, and content."""
    title = pr['title'].lower()
    body = pr.get('body', '').lower()
    labels = [l['name'].lower() for l in pr.get('labels', [])]

    # Check for documentation PRs
    if any(word in title for word in ['doc', 'documentation', 'doxygen']):
        return 'Documentation'
    if any(word in body for word in ['doc', 'documentation', 'doxygen']):
        return 'Documentation'

    # Check for test PRs
    if any(word in title for word in ['test', 'tap', 'regression']):
        return 'Testing'
    if any(word in body for word in ['test', 'tap', 'regression']):
        return 'Testing'

    # Check for build/packaging
    if any(word in title for word in ['build', 'package', 'opensuse', 'docker', 'rpm', 'deb']):
        return 'Build/Packaging'

    # Check for bug fixes
    if any(word in title for word in ['fix', 'bug', 'issue', 'crash', 'vulnerability', 'error']):
        return 'Bug Fixes'

    # Check for PostgreSQL
    if any(word in title for word in ['postgresql', 'pgsql', 'pg']):
        return 'PostgreSQL'
    if any(word in body for word in ['postgresql', 'pgsql', 'pg']):
        return 'PostgreSQL'

    # Check for MySQL
    if any(word in title for word in ['mysql']):
        return 'MySQL'
    if any(word in body for word in ['mysql']):
        return 'MySQL'

    # Check for monitoring
    if any(word in title for word in ['monitor', 'metric', 'log', 'ping', 'keepalive']):
        return 'Monitoring'

    # Check for performance
    if any(word in title for word in ['performance', 'optimize', 'refactor', 'lock-free', 'gtid']):
        return 'Performance'

    # Default
    return 'Other'


def extract_commits_info(pr):
    """Extract structured commit information from PR."""
    commits_info = []
    for commit in pr.get('commits', []):
        headline = commit.get('messageHeadline', '')
        oid = commit.get('oid', '')[:8]  # Short hash
        if headline:
            commits_info.append((oid, headline))
    return commits_info


def generate_release_notes(pr_data, output_file):
    """Generate structured release notes."""
    # Categorize PRs
    categories = defaultdict(list)
    for pr in pr_data:
        cat = categorize_pr(pr)
        categories[cat].append(pr)

    out_lines = []
    out_lines.append('# ProxySQL 3.0.4 Release Notes\n')
    out_lines.append('\n')
    out_lines.append('This release of ProxySQL 3.0.4 includes significant improvements ')
    out_lines.append('to PostgreSQL support, MySQL protocol handling, monitoring accuracy, ')
    out_lines.append('and security.\n')
    out_lines.append('\n')
    out_lines.append('Release commit: `faa64a570d19fe35af43494db0babdee3e3cdc89`\n')
    out_lines.append('\n')

    # Helper to format with backticks
    def add_backticks(text):
        # Simple heuristic: add backticks around likely technical terms
        # This is a placeholder - in production, use more sophisticated detection
        return text

    # New Features section
    out_lines.append('## New Features:\n')
    out_lines.append('\n')

    # PostgreSQL features
    postgres_prs = [p for p in categories['PostgreSQL'] if 'fix' not in p['title'].lower()]
    if postgres_prs:
        out_lines.append('### PostgreSQL Improvements:\n')
        out_lines.append('\n')
        for pr in postgres_prs:
            commits = extract_commits_info(pr)
            if commits:
                for oid, headline in commits:
                    out_lines.append(f'- {headline} ({oid}, #{pr["number"]})\n')
            else:
                out_lines.append(f'- {pr["title"]} ({pr.get("merge_hash", "")[:8]}, #{pr["number"]})\n')
        out_lines.append('\n')

    # MySQL features
    mysql_prs = [p for p in categories['MySQL'] if 'fix' not in p['title'].lower()]
    if mysql_prs:
        out_lines.append('### MySQL Protocol Enhancements:\n')
        out_lines.append('\n')
        for pr in mysql_prs:
            commits = extract_commits_info(pr)
            if commits:
                for oid, headline in commits:
                    out_lines.append(f'- {headline} ({oid}, #{pr["number"]})\n')
            else:
                out_lines.append(f'- {pr["title"]} ({pr.get("merge_hash", "")[:8]}, #{pr["number"]})\n')
        out_lines.append('\n')

    # Monitoring features
    monitoring_prs = [p for p in categories['Monitoring'] if 'fix' not in p['title'].lower()]
    if monitoring_prs:
        out_lines.append('### Monitoring & Diagnostics:\n')
        out_lines.append('\n')
        for pr in monitoring_prs:
            commits = extract_commits_info(pr)
            if commits:
                for oid, headline in commits:
                    out_lines.append(f'- {headline} ({oid}, #{pr["number"]})\n')
            else:
                out_lines.append(f'- {pr["title"]} ({pr.get("merge_hash", "")[:8]}, #{pr["number"]})\n')
        out_lines.append('\n')

    # Bug Fixes section
    bug_fixes = []
    for cat in ['PostgreSQL', 'MySQL', 'Monitoring', 'Other']:
        if cat in categories:
            bug_fixes.extend([p for p in categories[cat] if 'fix' in p['title'].lower()])

    if bug_fixes:
        out_lines.append('## Bug Fixes:\n')
        out_lines.append('\n')
        for pr in bug_fixes:
            commits = extract_commits_info(pr)
            if commits:
                for oid, headline in commits:
                    out_lines.append(f'- {headline} ({oid}, #{pr["number"]})\n')
            else:
                out_lines.append(f'- {pr["title"]} ({pr.get("merge_hash", "")[:8]}, #{pr["number"]})\n')
        out_lines.append('\n')

    # Performance improvements
    perf_prs = categories.get('Performance', [])
    if perf_prs:
        out_lines.append('## Improvements:\n')
        out_lines.append('\n')
        out_lines.append('### Performance Optimizations:\n')
        out_lines.append('\n')
        for pr in perf_prs:
            commits = extract_commits_info(pr)
            if commits:
                for oid, headline in commits:
                    out_lines.append(f'- {headline} ({oid}, #{pr["number"]})\n')
            else:
                out_lines.append(f'- {pr["title"]} ({pr.get("merge_hash", "")[:8]}, #{pr["number"]})\n')
        out_lines.append('\n')

    # Documentation
    doc_prs = categories.get('Documentation', [])
    if doc_prs:
        out_lines.append('## Documentation:\n')
        out_lines.append('\n')
        for pr in doc_prs:
            commits = extract_commits_info(pr)
            if commits:
                for oid, headline in commits:
                    out_lines.append(f'- {headline} ({oid}, #{pr["number"]})\n')
            else:
                out_lines.append(f'- {pr["title"]} ({pr.get("merge_hash", "")[:8]}, #{pr["number"]})\n')
        out_lines.append('\n')

    # Testing
    test_prs = categories.get('Testing', [])
    if test_prs:
        out_lines.append('## Testing:\n')
        out_lines.append('\n')
        for pr in test_prs:
            commits = extract_commits_info(pr)
            if commits:
                for oid, headline in commits:
                    out_lines.append(f'- {headline} ({oid}, #{pr["number"]})\n')
            else:
                out_lines.append(f'- {pr["title"]} ({pr.get("merge_hash", "")[:8]}, #{pr["number"]})\n')
        out_lines.append('\n')

    # Build/Packaging
    build_prs = categories.get('Build/Packaging', [])
    if build_prs:
        out_lines.append('## Build/Packaging:\n')
        out_lines.append('\n')
        for pr in build_prs:
            commits = extract_commits_info(pr)
            if commits:
                for oid, headline in commits:
                    out_lines.append(f'- {headline} ({oid}, #{pr["number"]})\n')
            else:
                out_lines.append(f'- {pr["title"]} ({pr.get("merge_hash", "")[:8]}, #{pr["number"]})\n')
        out_lines.append('\n')

    # Other
    other_prs = categories.get('Other', [])
    if other_prs:
        out_lines.append('## Other Changes:\n')
        out_lines.append('\n')
        for pr in other_prs:
            commits = extract_commits_info(pr)
            if commits:
                for oid, headline in commits:
                    out_lines.append(f'- {headline} ({oid}, #{pr["number"]})\n')
            else:
                out_lines.append(f'- {pr["title"]} ({pr.get("merge_hash", "")[:8]}, #{pr["number"]})\n')
        out_lines.append('\n')

    out_lines.append('## Hashes\n')
    out_lines.append('\n')
    out_lines.append('The release commit is: `faa64a570d19fe35af43494db0babdee3e3cdc89`\n')
    out_lines.append('\n')

    with open(output_file, 'w') as f:
        f.writelines(out_lines)

    return output_file


def main():
    parser = argparse.ArgumentParser(
        description='Generate structured release notes from PR data.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input pr-data.json --output release-notes.md
        """
    )
    parser.add_argument('--input', '-i', required=True, help='Input JSON file with PR data')
    parser.add_argument('--output', '-o', default='release-notes-structured.md', help='Output file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        print(f"Loading PR data from {args.input}")

    pr_data = load_pr_data(args.input)

    if args.verbose:
        print(f"Processing {len(pr_data)} PRs")

    output_file = generate_release_notes(pr_data, args.output)

    if args.verbose:
        print(f"Structured release notes written to {output_file}")


if __name__ == '__main__':
    main()