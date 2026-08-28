#!/usr/bin/env python3
import sys
import re

# Categories mapping keywords
categories = {
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
    msg_lower = message.lower()
    scores = {}
    for cat, keywords in categories.items():
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

def main():
    with open('/tmp/commits.txt', 'r') as f:
        lines = f.readlines()

    commits = []
    current = []
    for line in lines:
        line = line.rstrip('\n')
        if line and '|' in line and line.count('|') >= 2:
            if current:
                commits.append(''.join(current))
                current = []
        current.append(line + '\n')
    if current:
        commits.append(''.join(current))

    categorized = {}
    for commit in commits:
        parts = commit.split('|', 2)
        if len(parts) < 3:
            continue
        hash_, subject, body = parts[0], parts[1], parts[2]
        full_msg = subject + ' ' + body
        cat = categorize_commit(full_msg)
        categorized.setdefault(cat, []).append((hash_, subject, body))

    # Print categorized
    for cat in sorted(categorized.keys()):
        print(f'\n## {cat}\n')
        for hash_, subject, body in categorized[cat]:
            # truncate subject if too long
            print(f'- {hash_[:8]} {subject}')
            # print body lines indented
            if body.strip():
                for line in body.strip().split('\n'):
                    if line.strip():
                        print(f'  {line.strip()}')
        print()

    # Print stats
    print('\n---\n')
    for cat in sorted(categorized.keys()):
        print(f'{cat}: {len(categorized[cat])}')

if __name__ == '__main__':
    main()