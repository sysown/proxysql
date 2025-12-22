#!/usr/bin/env python3
"""
Categorize git commits based on keywords.

This script reads git commit messages from a git log range or from a file
and categorizes them based on keyword matching.

Usage:
    python categorize_commits.py --from-tag v3.0.3 --to-tag v3.0
    python categorize_commits.py --input-file /tmp/commits.txt
"""

import sys
import re
import subprocess
import argparse

# Categories mapping keywords
CATEGORIES = {
    'Bug Fix': ['fix', 'bug', 'issue', 'crash', 'vulnerability', 'error', 'wrong', 'incorrect', 'failure', 'broken'],
    'New Feature': ['add', 'new', 'support', 'implement', 'feature', 'introduce', 'enable'],
    'Improvement': ['improve', 'optimize', 'enhance', 'speed', 'performance', 'better', 'reduce', 'faster', 'efficient'],
    'Documentation': ['doc', 'documentation', 'comment', 'doxygen', 'readme'],
    'Testing': ['test', 'tap', 'regression', 'validation'],
    'Build/Packaging': ['build', 'package', 'makefile', 'cmake', 'docker', 'opensuse', 'deb', 'rpm'],
    'Refactoring': ['refactor', 'cleanup', 'restructure', 'reorganize', 'rename'],
    'Security': ['security', 'injection', 'vulnerability', 'secure', 'sanitize'],
    'Monitoring': ['monitor', 'metric', 'log', 'warning', 'alert'],
    'PostgreSQL': ['postgresql', 'pgsql', 'pg'],
    'MySQL': ['mysql'],
}


def categorize_commit(message):
    """Categorize a commit message based on keyword matching."""
    msg_lower = message.lower()
    scores = {}
    for cat, keywords in CATEGORIES.items():
        score = 0
        for kw in keywords:
            if re.search(r'\b' + re.escape(kw) + r'\b', msg_lower):
                score += 1
        if score:
            scores[cat] = score
    if scores:
        # return max score category
        return max(scores.items(), key=lambda x: x[1])[0]
    return 'Other'


def get_git_log(from_tag, to_tag):
    """Get git log between two tags/branches in a parsable format."""
    cmd = ["git", "log", f"{from_tag}..{to_tag}", "--no-merges", "--pretty=format:%H%x1f%s%x1f%b%x1e"]
    try:
        output = subprocess.check_output(cmd, text=True).strip()
        # Split on record separator (0x1e), remove empty strings
        commits = [c.strip() for c in output.split('\x1e') if c.strip()]
        return commits
    except subprocess.CalledProcessError as e:
        print(f"Error running git log: {e}", file=sys.stderr)
        sys.exit(1)


def read_commits_from_file(filename):
    """Read commits from a file with the same format as git log output."""
    with open(filename, 'r') as f:
        content = f.read()
    # Split on record separator (0x1e), remove empty strings
    commits = [c.strip() for c in content.split('\x1e') if c.strip()]
    return commits


def parse_commits(commits):
    """Parse commit strings in format 'hash<0x1f>subject<0x1f>body'."""
    parsed = []
    for commit in commits:
        parts = commit.split('\x1f', 2)
        if len(parts) < 3:
            continue
        hash_, subject, body = parts[0], parts[1], parts[2]
        parsed.append((hash_, subject, body))
    return parsed


def main():
    parser = argparse.ArgumentParser(
        description='Categorize git commits based on keywords.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --from-tag v3.0.3 --to-tag v3.0
  %(prog)s --input-file /tmp/commits.txt
  %(prog)s --from-tag v3.0.3 --to-tag v3.0 --output-format markdown
        """
    )
    parser.add_argument('--from-tag', help='Starting tag/branch (e.g., v3.0.3)')
    parser.add_argument('--to-tag', help='Ending tag/branch (e.g., v3.0)')
    parser.add_argument('--input-file', help='Input file with git log output')
    parser.add_argument('--output-format', choices=['text', 'markdown'], default='markdown',
                       help='Output format (default: markdown)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if not (args.from_tag and args.to_tag) and not args.input_file:
        parser.error('Either --from-tag and --to-tag must be specified, or --input-file')

    if args.from_tag and args.to_tag:
        lines = get_git_log(args.from_tag, args.to_tag)
    else:
        lines = read_commits_from_file(args.input_file)

    commits = parse_commits(lines)

    categorized = {}
    for hash_, subject, body in commits:
        full_msg = subject + ' ' + body
        cat = categorize_commit(full_msg)
        categorized.setdefault(cat, []).append((hash_, subject, body))

    # Output
    if args.output_format == 'markdown':
        for cat in sorted(categorized.keys()):
            print(f'\n## {cat}\n')
            for hash_, subject, body in categorized[cat]:
                print(f'- {hash_[:8]} {subject}')
                if body.strip():
                    for line in body.strip().split('\n'):
                        if line.strip():
                            print(f'  {line.strip()}')
            print()

        print('\n---\n')
        for cat in sorted(categorized.keys()):
            print(f'{cat}: {len(categorized[cat])}')
    else:
        # plain text output
        for cat in sorted(categorized.keys()):
            print(f'\n=== {cat} ===')
            for hash_, subject, body in categorized[cat]:
                print(f'  {hash_[:8]} {subject}')
                if body.strip() and args.verbose:
                    for line in body.strip().split('\n'):
                        if line.strip():
                            print(f'    {line.strip()}')
            print()

        print('\nSummary:')
        for cat in sorted(categorized.keys()):
            print(f'  {cat}: {len(categorized[cat])}')


if __name__ == '__main__':
    main()