#!/usr/bin/env python3
"""
Generate a changelog from git merge commits between two tags/branches.

This script analyzes merge commits (pull requests) and generates a categorized
changelog. It attempts to get commits within each PR by looking at the second
parent of merge commits.

Usage:
    python generate_changelog.py --from-tag v3.0.3 --to-tag v3.0 --output changelog.md
"""

import subprocess
import re
import argparse
import sys


def run(cmd_list):
    """Run command and return output."""
    return subprocess.check_output(cmd_list, text=True).strip()


def get_merge_commits(from_tag, to_tag):
    """Get merge commits between two tags."""
    merge_log = run(["git", "log", f"{from_tag}..{to_tag}", "--merges", "--pretty=format:%H %s"])
    lines = merge_log.split('\n')
    prs = []
    for line in lines:
        if 'Merge pull request' in line:
            hash_, subject = line.split(' ', 1)
            # extract PR number
            match = re.search(r'#(\d+)', subject)
            if match:
                pr_num = match.group(1)
                prs.append((hash_, pr_num, subject))
        # ignore branch merges
    return prs


def get_pr_commits(prs):
    """For each PR merge commit, get commits in the PR branch (second parent)."""
    pr_commits = {}
    for hash_, pr_num, subject in prs:
        try:
            output = run(["git", "log", "--oneline", "--no-merges", f"{hash_}^2"])
        except subprocess.CalledProcessError:
            # merge commit may have only one parent, skip
            continue
        commits = output.split('\n') if output else []
        pr_commits[pr_num] = (subject, commits)
    return pr_commits


def categorize_pr(subject, commits):
    """Categorize a PR based on its subject and commit messages."""
    subj_lower = subject.lower()
    # keyword matching
    if any(word in subj_lower for word in ['fix', 'bug', 'issue', 'crash', 'vulnerability']):
        return 'Bug Fixes'
    if any(word in subj_lower for word in ['add', 'new', 'support', 'implement', 'feature', 'introduce', 'enable']):
        return 'New Features'
    if any(word in subj_lower for word in ['improve', 'optimize', 'enhance', 'performance', 'better']):
        return 'Improvements'
    if any(word in subj_lower for word in ['doc', 'documentation', 'doxygen']):
        return 'Documentation'
    if any(word in subj_lower for word in ['test', 'tap', 'regression']):
        return 'Testing'
    if any(word in subj_lower for word in ['build', 'package', 'opensuse', 'docker']):
        return 'Build/Packaging'
    if any(word in subj_lower for word in ['refactor', 'cleanup', 'restructure']):
        return 'Refactoring'
    if any(word in subj_lower for word in ['security', 'injection', 'vulnerability']):
        return 'Security'
    if any(word in subj_lower for word in ['monitor', 'metric', 'log']):
        return 'Monitoring'
    if any(word in subj_lower for word in ['postgresql', 'pgsql', 'pg']):
        return 'PostgreSQL'
    if any(word in subj_lower for word in ['mysql']):
        return 'MySQL'
    return 'Other'


def generate_changelog(from_tag, to_tag, output_file, verbose=False):
    """Main function to generate changelog."""
    if verbose:
        print(f"Generating changelog from {from_tag} to {to_tag}...")

    prs = get_merge_commits(from_tag, to_tag)
    if verbose:
        print(f"Found {len(prs)} PR merges")

    pr_commits = get_pr_commits(prs)

    categories = {
        'Bug Fixes': [],
        'New Features': [],
        'Improvements': [],
        'Documentation': [],
        'Testing': [],
        'Build/Packaging': [],
        'Refactoring': [],
        'Security': [],
        'Monitoring': [],
        'PostgreSQL': [],
        'MySQL': [],
        'Other': [],
    }

    for pr_num, (subject, commits) in pr_commits.items():
        cat = categorize_pr(subject, commits)
        categories[cat].append((pr_num, subject, commits))

    # Build output
    output_lines = []
    output_lines.append(f'# Changelog from {from_tag} to {to_tag}\n')
    output_lines.append('\n')
    output_lines.append(f'This changelog summarizes all changes between {from_tag} and {to_tag}.\n')
    output_lines.append('\n')

    for cat in sorted(categories.keys()):
        entries = categories[cat]
        if not entries:
            continue
        output_lines.append(f'## {cat}\n')
        for pr_num, subject, commits in entries:
            output_lines.append(f'- **PR #{pr_num}**: {subject}\n')
            if commits:
                for commit in commits:
                    # commit format: hash message
                    msg = commit.split(' ', 1)[1] if ' ' in commit else commit
                    output_lines.append(f'  - {msg}\n')
        output_lines.append('\n')

    with open(output_file, 'w') as f:
        f.writelines(output_lines)

    if verbose:
        print(f"Changelog written to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Generate a changelog from git merge commits.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --from-tag v3.0.3 --to-tag v3.0 --output changelog.md
  %(prog)s --from-tag v3.0.3 --to-tag HEAD --output changes.md --verbose
        """
    )
    parser.add_argument('--from-tag', required=True, help='Starting tag/branch (e.g., v3.0.3)')
    parser.add_argument('--to-tag', required=True, help='Ending tag/branch (e.g., v3.0 or HEAD)')
    parser.add_argument('--output', '-o', default='changelog.md', help='Output file (default: changelog.md)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    generate_changelog(args.from_tag, args.to_tag, args.output, args.verbose)


if __name__ == '__main__':
    main()