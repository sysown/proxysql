#!/usr/bin/env python3
import subprocess
import re
import json

def run(cmd_list):
    return subprocess.check_output(cmd_list, text=True).strip()

# Get merge commits since v3.0.3
merge_log = run(["git", "log", "v3.0.3..v3.0", "--merges", "--pretty=format:%H %s"])
lines = merge_log.split('\n')
pr_map = []
for line in lines:
    if 'Merge pull request' in line:
        hash_, subject = line.split(' ', 1)
        match = re.search(r'#(\d+)', subject)
        if match:
            pr_num = match.group(1)
            # get second parent commit hash
            try:
                second_parent = run(["git", "rev-parse", f"{hash_}^2"])
            except subprocess.CalledProcessError:
                second_parent = hash_
            pr_map.append((pr_num, hash_, second_parent, subject))

print(f'Processed {len(pr_map)} PRs')

# Fetch PR details using gh
pr_details = {}
for pr_num, merge_hash, head_hash, subject in pr_map:
    try:
        data = run(["gh", "pr", "view", str(pr_num), "--json", "title,body,number,url"])
        pr = json.loads(data)
        pr['merge_hash'] = merge_hash
        pr['head_hash'] = head_hash
        pr_details[pr_num] = pr
    except subprocess.CalledProcessError as e:
        print(f'Failed to fetch PR {pr_num}: {e}')
        continue

# Manual categorization based on PR title and analysis
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

# Mapping PR numbers to categories (manually curated)
category_map = {
    '5259': ('Bug Fixes', 'MySQL'),
    '5257': ('New Features', 'MySQL'),
    '5258': ('Documentation', None),
    '5254': ('New Features', 'PostgreSQL'),
    '5237': ('New Features', 'PostgreSQL'),
    '5250': ('Bug Fixes', 'MySQL'),
    '5251': ('Testing', None),
    '4889': ('New Features', 'MySQL'),
    '5247': ('Bug Fixes', 'Configuration'),
    '5245': ('Documentation', None),
    '4901': ('New Features', 'MySQL'),
    '5199': ('Bug Fixes', 'Monitoring'),
    '5241': ('Testing', None),
    '5232': ('Bug Fixes', 'MySQL'),
    '5240': ('Improvements', 'Performance'),
    '5225': ('Improvements', 'Performance'),
    '5230': ('Build/Packaging', None),
    '5115': ('Documentation', None),
    '5229': ('Documentation', None),
    '5215': ('Documentation', None),
    '5203': ('New Features', 'MySQL'),
    '5207': ('Testing', None),
    '5200': ('Other', None),
    '5198': ('Testing', None),
    '5228': ('New Features', 'Monitoring'),
    '5226': ('Improvements', 'Performance'),
}

for pr_num, pr in pr_details.items():
    if pr_num in category_map:
        cat, subcat = category_map[pr_num]
        if subcat:
            categories[cat][subcat].append(pr)
        else:
            if isinstance(categories[cat], list):
                categories[cat].append(pr)
            else:
                categories[cat]['Other'].append(pr)
    else:
        categories['Other'].append(pr)

# Generate release notes
out_lines = []
out_lines.append('# ProxySQL 3.0.4 Release Notes\n')
out_lines.append('\n')
out_lines.append('This release of ProxySQL 3.0.4 includes new features, bug fixes, and improvements across PostgreSQL, MySQL, monitoring, and configuration management.\n')
out_lines.append('\n')
out_lines.append(f'Release commit: {pr_map[0][1][:8]} (faa64a57)\n')
out_lines.append('\n')

# Helper to format entry
def format_entry(pr):
    head_short = pr['head_hash'][:8]
    title = pr['title']
    url = pr['url']
    return f'- {title} ({head_short}, #{pr["number"]})\n'

# New Features
if any(any(subcat) for subcat in categories['New Features'].values()):
    out_lines.append('## New Features:\n')
    for subcat in ['PostgreSQL', 'MySQL', 'Monitoring', 'Configuration', 'Performance', 'Other']:
        entries = categories['New Features'][subcat]
        if entries:
            out_lines.append(f'### {subcat}:\n')
            for pr in entries:
                out_lines.append(format_entry(pr))
            out_lines.append('\n')

# Bug Fixes
if any(any(subcat) for subcat in categories['Bug Fixes'].values()):
    out_lines.append('## Bug Fixes:\n')
    for subcat in ['MySQL', 'PostgreSQL', 'Monitoring', 'Configuration', 'Security', 'Other']:
        entries = categories['Bug Fixes'][subcat]
        if entries:
            out_lines.append(f'### {subcat}:\n')
            for pr in entries:
                out_lines.append(format_entry(pr))
            out_lines.append('\n')

# Improvements
if any(any(subcat) for subcat in categories['Improvements'].values()):
    out_lines.append('## Improvements:\n')
    for subcat in ['Performance', 'Refactoring', 'Monitoring', 'Other']:
        entries = categories['Improvements'][subcat]
        if entries:
            out_lines.append(f'### {subcat}:\n')
            for pr in entries:
                out_lines.append(format_entry(pr))
            out_lines.append('\n')

# Documentation
if categories['Documentation']:
    out_lines.append('## Documentation:\n')
    for pr in categories['Documentation']:
        out_lines.append(format_entry(pr))
    out_lines.append('\n')

# Testing
if categories['Testing']:
    out_lines.append('## Testing:\n')
    for pr in categories['Testing']:
        out_lines.append(format_entry(pr))
    out_lines.append('\n')

# Build/Packaging
if categories['Build/Packaging']:
    out_lines.append('## Build/Packaging:\n')
    for pr in categories['Build/Packaging']:
        out_lines.append(format_entry(pr))
    out_lines.append('\n')

# Other (if any)
if categories['Other']:
    out_lines.append('## Other Changes:\n')
    for pr in categories['Other']:
        out_lines.append(format_entry(pr))
    out_lines.append('\n')

out_lines.append('\n')
out_lines.append('## Hashes\n')
out_lines.append('\n')
out_lines.append('The release commit is: `faa64a570d19fe35af43494db0babdee3e3cdc89`\n')
out_lines.append('\n')

with open('RELEASE_NOTES-3.0.4-formatted.md', 'w') as f:
    f.writelines(out_lines)

print('Generated RELEASE_NOTES-3.0.4-formatted.md')

# Also generate a more detailed changelog with commit messages
detailed = []
detailed.append('# ProxySQL 3.0.4 Detailed Changelog\n')
detailed.append('\n')
detailed.append('This changelog includes all individual commits since ProxySQL 3.0.3.\n')
detailed.append('\n')

# Get all non-merge commits
commits = run(["git", "log", "v3.0.3..v3.0", "--no-merges", "--pretty=format:%H|%s|%b"]).split('\n')
for line in commits:
    parts = line.split('|', 2)
    if len(parts) < 2:
        continue
    hash_, subject, body = parts[0], parts[1], parts[2] if len(parts) > 2 else ''
    detailed.append(f'- {hash_[:8]} {subject}\n')
    if body.strip():
        for bline in body.strip().split('\n'):
            if bline.strip():
                detailed.append(f'  {bline.strip()}\n')

with open('CHANGELOG-3.0.4-commits.md', 'w') as f:
    f.writelines(detailed)

print('Generated CHANGELOG-3.0.4-commits.md')