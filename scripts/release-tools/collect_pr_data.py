#!/usr/bin/env python3
"""
Collect PR data for release notes generation.

This script fetches all PRs between two git tags and saves their details
to a JSON file for analysis and release notes generation.
"""

import subprocess
import re
import json
import argparse
import sys
from datetime import datetime


def run(cmd_list):
    """Run command and return output."""
    return subprocess.check_output(cmd_list, text=True).strip()


def get_merge_commits(from_tag, to_tag):
    """Get merge commits between two tags."""
    merge_log = run(["git", "log", f"{from_tag}..{to_tag}", "--merges", "--pretty=format:%H|%s"])
    lines = merge_log.split('\n')
    prs = []
    for line in lines:
        if 'Merge pull request' in line:
            hash_, subject = line.split('|', 1)
            match = re.search(r'#(\d+)', subject)
            if match:
                pr_num = match.group(1)
                prs.append((pr_num, hash_, subject))
    return prs


def fetch_pr_details(pr_numbers, verbose=False):
    """Fetch PR details using GitHub CLI."""
    pr_details = []
    for pr_num in pr_numbers:
        if verbose:
            print(f"Fetching PR #{pr_num}...")
        try:
            data = run(["gh", "pr", "view", str(pr_num), "--json", "title,body,number,url,labels,state,createdAt,mergedAt,author"])
            pr = json.loads(data)
            # Also get commits in PR if possible
            try:
                commits_data = run(["gh", "pr", "view", str(pr_num), "--json", "commits"])
                commits_json = json.loads(commits_data)
                pr['commits'] = commits_json.get('commits', [])
            except subprocess.CalledProcessError:
                pr['commits'] = []
            pr_details.append(pr)
        except subprocess.CalledProcessError as e:
            print(f"Failed to fetch PR {pr_num}: {e}", file=sys.stderr)
            continue
    return pr_details


def main():
    parser = argparse.ArgumentParser(
        description='Collect PR data for release notes generation.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --from-tag v3.0.3 --to-tag v3.0 --output pr-data.json
  %(prog)s --from-tag v3.0.3 --to-tag HEAD --verbose
        """
    )
    parser.add_argument('--from-tag', required=True, help='Starting tag/branch')
    parser.add_argument('--to-tag', required=True, help='Ending tag/branch')
    parser.add_argument('--output', '-o', default='pr-data.json', help='Output JSON file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        print(f"Collecting PR data from {args.from_tag} to {args.to_tag}")

    # Get merge commits
    prs = get_merge_commits(args.from_tag, args.to_tag)
    pr_numbers = [pr_num for pr_num, _, _ in prs]

    if args.verbose:
        print(f"Found {len(pr_numbers)} PR merges")

    # Fetch PR details
    pr_details = fetch_pr_details(pr_numbers, args.verbose)

    # Add git hash to each PR
    for pr in pr_details:
        for pr_num, hash_, subject in prs:
            if str(pr['number']) == pr_num:
                pr['merge_hash'] = hash_
                pr['merge_subject'] = subject
                break

    # Save to JSON
    with open(args.output, 'w') as f:
        json.dump(pr_details, f, indent=2, default=str)

    if args.verbose:
        print(f"PR data saved to {args.output}")
        print(f"Collected {len(pr_details)} PRs")

    # Also generate a summary markdown for quick review
    summary_file = args.output.replace('.json', '-summary.md')
    with open(summary_file, 'w') as f:
        f.write(f'# PR Summary: {args.from_tag} to {args.to_tag}\n\n')
        f.write(f'Total PRs: {len(pr_details)}\n\n')
        for pr in pr_details:
            f.write(f'## PR #{pr["number"]}: {pr["title"]}\n')
            f.write(f'- URL: {pr["url"]}\n')
            f.write(f'- Author: {pr["author"]["login"]}\n')
            f.write(f'- Labels: {", ".join([l["name"] for l in pr.get("labels", [])])}\n')
            f.write(f'- Merge hash: {pr.get("merge_hash", "N/A")[:8]}\n')
            if pr.get('body'):
                # Take first 200 chars of body
                body_preview = pr['body'][:200].replace('\n', ' ')
                f.write(f'- Preview: {body_preview}...\n')
            f.write('\n')

    if args.verbose:
        print(f"Summary saved to {summary_file}")


if __name__ == '__main__':
    main()