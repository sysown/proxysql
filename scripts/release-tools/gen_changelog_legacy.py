#!/usr/bin/env python3
import subprocess
import re
import sys

def run(cmd_list):
    return subprocess.check_output(cmd_list, text=True).strip()

# Get merge commits since v3.0.3
merge_log = run(["git", "log", "v3.0.3..v3.0", "--merges", "--pretty=format:%H %s"])
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
    elif 'Merge branch' in line:
        # ignore branch merges
        pass

print(f'Found {len(prs)} PR merges')

# For each PR, get commits in PR branch (second parent)
pr_commits = {}
for hash_, pr_num, subject in prs:
    try:
        output = run(["git", "log", "--oneline", "--no-merges", f"{hash_}^2"])
    except subprocess.CalledProcessError as e:
        # maybe merge commit has only one parent? skip
        continue
    commits = output.split('\n') if output else []
    pr_commits[pr_num] = (subject, commits)

# Now categorize based on PR subject and commit messages
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

def categorize_pr(subject, commits):
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

for pr_num, (subject, commits) in pr_commits.items():
    cat = categorize_pr(subject, commits)
    categories[cat].append((pr_num, subject, commits))

# Output markdown
output_lines = []
output_lines.append('# ProxySQL 3.0.4 Changelog\n')
output_lines.append('\n')
output_lines.append('This changelog summarizes all changes since ProxySQL 3.0.3.\n')
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
                # strip hash
                msg = commit.split(' ', 1)[1] if ' ' in commit else commit
                output_lines.append(f'  - {msg}\n')
    output_lines.append('\n')

with open('CHANGELOG-3.0.4.md', 'w') as f:
    f.writelines(output_lines)

print('Generated CHANGELOG-3.0.4.md')