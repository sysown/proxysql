#!/usr/bin/env python3
import subprocess
import json
import re
import sys

def run(cmd_list):
    return subprocess.check_output(cmd_list, text=True).strip()

# Get merge commits since v3.0.3
merge_log = run(["git", "log", "v3.0.3..v3.0", "--merges", "--pretty=format:%H %s"])
lines = merge_log.split('\n')
pr_numbers = []
for line in lines:
    if 'Merge pull request' in line:
        match = re.search(r'#(\d+)', line)
        if match:
            pr_numbers.append(match.group(1))
print(f'Found {len(pr_numbers)} PRs')

# Fetch PR details using gh
prs = []
for num in pr_numbers:
    try:
        data = run(["gh", "pr", "view", str(num), "--json", "title,body,number,url,labels"])
        pr = json.loads(data)
        prs.append(pr)
    except subprocess.CalledProcessError as e:
        print(f'Failed to fetch PR {num}: {e}')
        continue

# Categorize based on labels and title
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

def categorize(pr):
    title = pr['title'].lower()
    labels = [l['name'].lower() for l in pr.get('labels', [])]
    # label hints
    for label in labels:
        if 'bug' in label:
            return 'Bug Fixes'
        if 'feature' in label:
            return 'New Features'
        if 'documentation' in label:
            return 'Documentation'
        if 'test' in label:
            return 'Testing'
        if 'security' in label:
            return 'Security'
        if 'refactor' in label:
            return 'Refactoring'
        if 'improvement' in label:
            return 'Improvements'
    # title keywords
    if any(word in title for word in ['fix', 'bug', 'issue', 'crash', 'vulnerability', 'error']):
        return 'Bug Fixes'
    if any(word in title for word in ['add', 'new', 'support', 'implement', 'feature', 'introduce', 'enable']):
        return 'New Features'
    if any(word in title for word in ['improve', 'optimize', 'enhance', 'performance', 'better']):
        return 'Improvements'
    if any(word in title for word in ['doc', 'documentation', 'doxygen']):
        return 'Documentation'
    if any(word in title for word in ['test', 'tap', 'regression']):
        return 'Testing'
    if any(word in title for word in ['build', 'package', 'opensuse', 'docker']):
        return 'Build/Packaging'
    if any(word in title for word in ['refactor', 'cleanup', 'restructure']):
        return 'Refactoring'
    if any(word in title for word in ['security', 'injection', 'vulnerability']):
        return 'Security'
    if any(word in title for word in ['monitor', 'metric', 'log']):
        return 'Monitoring'
    if any(word in title for word in ['postgresql', 'pgsql', 'pg']):
        return 'PostgreSQL'
    if any(word in title for word in ['mysql']):
        return 'MySQL'
    return 'Other'

for pr in prs:
    cat = categorize(pr)
    categories[cat].append(pr)

# Generate markdown
output = []
output.append('# ProxySQL 3.0.4 Detailed Changelog\n')
output.append('\n')
output.append('This changelog lists all pull requests merged since ProxySQL 3.0.3.\n')
output.append('\n')

for cat in sorted(categories.keys()):
    entries = categories[cat]
    if not entries:
        continue
    output.append(f'## {cat}\n')
    for pr in entries:
        output.append(f'- **PR #{pr["number"]}**: [{pr["title"]}]({pr["url"]})\n')
        if pr.get('body'):
            # take first non-empty line as summary
            lines = pr['body'].split('\n')
            summary = ''
            for line in lines:
                if line.strip():
                    summary = line.strip()
                    break
            if summary:
                output.append(f'  - {summary}\n')
    output.append('\n')

with open('CHANGELOG-3.0.4-detailed.md', 'w') as f:
    f.writelines(output)

print('Generated CHANGELOG-3.0.4-detailed.md')

# Also generate a concise version for release notes
release_notes = []
release_notes.append('# ProxySQL 3.0.4 Release Notes\n')
release_notes.append('\n')
release_notes.append('ProxySQL 3.0.4 includes numerous bug fixes, improvements, and new features.\n')
release_notes.append('\n')

# New Features section
new_features = categories['New Features'] + categories['PostgreSQL'] + categories['MySQL']
if new_features:
    release_notes.append('## New Features\n')
    for pr in new_features:
        release_notes.append(f'- {pr["title"]} [#{pr["number"]}]({pr["url"]})\n')
    release_notes.append('\n')

# Bug Fixes
bug_fixes = categories['Bug Fixes'] + categories['Security']
if bug_fixes:
    release_notes.append('## Bug Fixes\n')
    for pr in bug_fixes:
        release_notes.append(f'- {pr["title"]} [#{pr["number"]}]({pr["url"]})\n')
    release_notes.append('\n')

# Improvements
improvements = categories['Improvements'] + categories['Refactoring'] + categories['Monitoring']
if improvements:
    release_notes.append('## Improvements\n')
    for pr in improvements:
        release_notes.append(f'- {pr["title"]} [#{pr["number"]}]({pr["url"]})\n')
    release_notes.append('\n')

# Documentation
if categories['Documentation']:
    release_notes.append('## Documentation\n')
    for pr in categories['Documentation']:
        release_notes.append(f'- {pr["title"]} [#{pr["number"]}]({pr["url"]})\n')
    release_notes.append('\n')

# Testing
if categories['Testing']:
    release_notes.append('## Testing\n')
    for pr in categories['Testing']:
        release_notes.append(f'- {pr["title"]} [#{pr["number"]}]({pr["url"]})\n')
    release_notes.append('\n')

# Build/Packaging
if categories['Build/Packaging']:
    release_notes.append('## Build/Packaging\n')
    for pr in categories['Build/Packaging']:
        release_notes.append(f'- {pr["title"]} [#{pr["number"]}]({pr["url"]})\n')
    release_notes.append('\n')

with open('RELEASE_NOTES-3.0.4.md', 'w') as f:
    f.writelines(release_notes)

print('Generated RELEASE_NOTES-3.0.4.md')