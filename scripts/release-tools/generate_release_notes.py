#!/usr/bin/env python3
"""
Generate release notes from GitHub pull requests between two git tags.

This script uses the GitHub CLI (gh) to fetch PR details and generates
formatted release notes similar to ProxySQL's release notes format.

Features:
- Automatic categorization based on PR labels and titles
- Optional manual categorization mapping via JSON file
- Support for subcategories (PostgreSQL, MySQL, Monitoring, etc.)
- Outputs both release notes and detailed changelog
"""

import subprocess
import re
import json
import argparse
import sys
from pathlib import Path


def run(cmd_list):
    """Run command and return output."""
    return subprocess.check_output(cmd_list, text=True).strip()


def get_merge_commits(from_tag, to_tag):
    """Get merge commits between two tags and extract PR numbers."""
    merge_log = run(["git", "log", f"{from_tag}..{to_tag}", "--merges", "--pretty=format:%H %s"])
    lines = merge_log.split('\n')
    pr_map = []
    for line in lines:
        if 'Merge pull request' in line:
            hash_, subject = line.split(' ', 1)
            match = re.search(r'#(\d+)', subject)
            if match:
                pr_num = match.group(1)
                # get second parent commit hash (PR head)
                try:
                    second_parent = run(["git", "rev-parse", f"{hash_}^2"])
                except subprocess.CalledProcessError:
                    second_parent = hash_
                pr_map.append((pr_num, hash_, second_parent, subject))
    return pr_map


def fetch_pr_details(pr_numbers, verbose=False):
    """Fetch PR details using GitHub CLI."""
    pr_details = {}
    for pr_num in pr_numbers:
        if verbose:
            print(f"Fetching PR #{pr_num}...")
        try:
            data = run(["gh", "pr", "view", str(pr_num), "--json", "title,body,number,url,labels,state,createdAt,mergedAt"])
            pr = json.loads(data)
            pr_details[pr_num] = pr
        except subprocess.CalledProcessError as e:
            print(f"Failed to fetch PR {pr_num}: {e}", file=sys.stderr)
            continue
    return pr_details


def load_category_mapping(config_file):
    """Load manual category mapping from JSON file."""
    if not config_file or not Path(config_file).exists():
        return {}
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error parsing config file {config_file}: {e}", file=sys.stderr)
        return {}


def auto_categorize(pr, mapping):
    """Categorize a PR based on mapping, labels, and title."""
    pr_num = str(pr['number'])

    # First, check manual mapping
    if pr_num in mapping:
        cat_info = mapping[pr_num]
        if isinstance(cat_info, dict):
            return cat_info.get('category', 'Other'), cat_info.get('subcategory')
        elif isinstance(cat_info, str):
            return cat_info, None
        elif isinstance(cat_info, list) and len(cat_info) >= 1:
            cat = cat_info[0]
            subcat = cat_info[1] if len(cat_info) > 1 else None
            return cat, subcat

    # Auto-categorize based on labels
    title = pr['title'].lower()
    labels = [l['name'].lower() for l in pr.get('labels', [])]

    # Label-based categorization
    for label in labels:
        if 'bug' in label:
            return 'Bug Fixes', None
        if 'feature' in label:
            return 'New Features', None
        if 'documentation' in label:
            return 'Documentation', None
        if 'test' in label:
            return 'Testing', None
        if 'security' in label:
            return 'Security', None
        if 'refactor' in label:
            return 'Improvements', 'Refactoring'
        if 'improvement' in label:
            return 'Improvements', None

    # Title keyword-based categorization
    if any(word in title for word in ['fix', 'bug', 'issue', 'crash', 'vulnerability', 'error']):
        return 'Bug Fixes', None
    if any(word in title for word in ['add', 'new', 'support', 'implement', 'feature', 'introduce', 'enable']):
        return 'New Features', None
    if any(word in title for word in ['improve', 'optimize', 'enhance', 'performance', 'better']):
        return 'Improvements', None
    if any(word in title for word in ['doc', 'documentation', 'doxygen']):
        return 'Documentation', None
    if any(word in title for word in ['test', 'tap', 'regression']):
        return 'Testing', None
    if any(word in title for word in ['build', 'package', 'opensuse', 'docker']):
        return 'Build/Packaging', None
    if any(word in title for word in ['refactor', 'cleanup', 'restructure']):
        return 'Improvements', 'Refactoring'
    if any(word in title for word in ['security', 'injection', 'vulnerability']):
        return 'Security', None
    if any(word in title for word in ['monitor', 'metric', 'log']):
        return 'Monitoring', None
    if any(word in title for word in ['postgresql', 'pgsql', 'pg']):
        return 'New Features', 'PostgreSQL'
    if any(word in title for word in ['mysql']):
        return 'New Features', 'MySQL'

    return 'Other', None


def organize_prs(pr_details, mapping, verbose=False):
    """Organize PRs into categorized structure."""
    categories = {
        'New Features': {
            'PostgreSQL': [],
            'MySQL': [],
            'Monitoring': [],
            'Configuration': [],
            'Performance': [],
            'Other': [],
        },
        'Bug Fixes': {
            'MySQL': [],
            'PostgreSQL': [],
            'Monitoring': [],
            'Configuration': [],
            'Security': [],
            'Other': [],
        },
        'Improvements': {
            'Performance': [],
            'Refactoring': [],
            'Monitoring': [],
            'Other': [],
        },
        'Documentation': [],
        'Testing': [],
        'Build/Packaging': [],
        'Other': [],
    }

    for pr_num, pr in pr_details.items():
        cat, subcat = auto_categorize(pr, mapping)

        if cat in categories:
            if isinstance(categories[cat], dict):
                # Has subcategories
                if subcat and subcat in categories[cat]:
                    categories[cat][subcat].append(pr)
                else:
                    categories[cat]['Other'].append(pr)
            else:
                # Simple list category
                categories[cat].append(pr)
        else:
            categories['Other'].append(pr)

    if verbose:
        for cat, contents in categories.items():
            if isinstance(contents, dict):
                total = sum(len(sub) for sub in contents.values())
                print(f"{cat}: {total} PRs")
                for subcat, prs in contents.items():
                    if prs:
                        print(f"  {subcat}: {len(prs)}")
            else:
                if contents:
                    print(f"{cat}: {len(contents)} PRs")

    return categories


def generate_release_notes(categories, from_tag, to_tag, output_file):
    """Generate formatted release notes."""
    out_lines = []
    out_lines.append(f'# ProxySQL {to_tag} Release Notes\n')
    out_lines.append('\n')
    out_lines.append(f'This release of ProxySQL {to_tag} includes new features, bug fixes, and improvements.\n')
    out_lines.append('\n')
    out_lines.append(f'Release range: {from_tag} to {to_tag}\n')
    out_lines.append('\n')

    def format_pr(pr):
        title = pr['title']
        url = pr['url']
        number = pr['number']
        return f'- {title} (#{number})\n'

    # New Features
    if any(any(subcat) for subcat in categories['New Features'].values()):
        out_lines.append('## New Features:\n')
        for subcat in ['PostgreSQL', 'MySQL', 'Monitoring', 'Configuration', 'Performance', 'Other']:
            entries = categories['New Features'][subcat]
            if entries:
                out_lines.append(f'### {subcat}:\n')
                for pr in entries:
                    out_lines.append(format_pr(pr))
                out_lines.append('\n')

    # Bug Fixes
    if any(any(subcat) for subcat in categories['Bug Fixes'].values()):
        out_lines.append('## Bug Fixes:\n')
        for subcat in ['MySQL', 'PostgreSQL', 'Monitoring', 'Configuration', 'Security', 'Other']:
            entries = categories['Bug Fixes'][subcat]
            if entries:
                out_lines.append(f'### {subcat}:\n')
                for pr in entries:
                    out_lines.append(format_pr(pr))
                out_lines.append('\n')

    # Improvements
    if any(any(subcat) for subcat in categories['Improvements'].values()):
        out_lines.append('## Improvements:\n')
        for subcat in ['Performance', 'Refactoring', 'Monitoring', 'Other']:
            entries = categories['Improvements'][subcat]
            if entries:
                out_lines.append(f'### {subcat}:\n')
                for pr in entries:
                    out_lines.append(format_pr(pr))
                out_lines.append('\n')

    # Simple categories
    simple_cats = ['Documentation', 'Testing', 'Build/Packaging', 'Other']
    for cat in simple_cats:
        entries = categories[cat]
        if entries:
            out_lines.append(f'## {cat}:\n')
            for pr in entries:
                out_lines.append(format_pr(pr))
            out_lines.append('\n')

    out_lines.append('\n')
    out_lines.append('## Hashes\n')
    out_lines.append('\n')
    out_lines.append(f'The release range is: `{from_tag}` to `{to_tag}`\n')
    out_lines.append('\n')

    with open(output_file, 'w') as f:
        f.writelines(out_lines)

    return output_file


def generate_detailed_changelog(pr_details, from_tag, to_tag, output_file):
    """Generate detailed changelog with PR descriptions."""
    out_lines = []
    out_lines.append(f'# Detailed Changelog from {from_tag} to {to_tag}\n')
    out_lines.append('\n')
    out_lines.append(f'This changelog lists all pull requests merged between {from_tag} and {to_tag}.\n')
    out_lines.append('\n')

    for pr in pr_details.values():
        out_lines.append(f'## PR #{pr["number"]}: {pr["title"]}\n')
        out_lines.append(f'- URL: {pr["url"]}\n')
        if pr.get('labels'):
            labels = ', '.join([l['name'] for l in pr['labels']])
            out_lines.append(f'- Labels: {labels}\n')
        if pr.get('body'):
            # Take first paragraph as summary
            lines = pr['body'].split('\n')
            summary = ''
            for line in lines:
                if line.strip() and not line.strip().startswith('#'):
                    summary = line.strip()
                    break
            if summary:
                out_lines.append(f'- Summary: {summary}\n')
        out_lines.append('\n')

    with open(output_file, 'w') as f:
        f.writelines(out_lines)

    return output_file


def main():
    parser = argparse.ArgumentParser(
        description='Generate release notes from GitHub pull requests.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --from-tag v3.0.3 --to-tag v3.0 --output release-notes.md
  %(prog)s --from-tag v3.0.3 --to-tag HEAD --config mapping.json --verbose
        """
    )
    parser.add_argument('--from-tag', required=True, help='Starting tag/branch')
    parser.add_argument('--to-tag', required=True, help='Ending tag/branch')
    parser.add_argument('--output', '-o', default='release-notes.md',
                       help='Output file for release notes (default: release-notes.md)')
    parser.add_argument('--changelog', '-c', help='Output file for detailed changelog')
    parser.add_argument('--config', help='JSON file with manual category mapping')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        print(f"Generating release notes from {args.from_tag} to {args.to_tag}")

    # Get merge commits
    pr_map = get_merge_commits(args.from_tag, args.to_tag)
    pr_numbers = [pr_num for pr_num, _, _, _ in pr_map]

    if args.verbose:
        print(f"Found {len(pr_numbers)} PR merges")

    # Fetch PR details
    pr_details = fetch_pr_details(pr_numbers, args.verbose)

    if not pr_details:
        print("No PR details fetched. Check GitHub CLI authentication.", file=sys.stderr)
        sys.exit(1)

    # Load manual mapping
    mapping = load_category_mapping(args.config)

    # Organize PRs into categories
    categories = organize_prs(pr_details, mapping, args.verbose)

    # Generate release notes
    release_file = generate_release_notes(categories, args.from_tag, args.to_tag, args.output)
    print(f"Release notes written to {release_file}")

    # Generate detailed changelog if requested
    if args.changelog:
        changelog_file = generate_detailed_changelog(pr_details, args.from_tag, args.to_tag, args.changelog)
        print(f"Detailed changelog written to {changelog_file}")

    if args.verbose:
        print("Done!")


if __name__ == '__main__':
    main()