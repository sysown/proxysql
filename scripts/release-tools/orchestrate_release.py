#!/usr/bin/env python3
"""
Orchestrate release notes generation workflow.

This script runs all required steps to prepare data for LLM analysis,
then generates a comprehensive prompt for the LLM to create release notes
and changelogs.

Workflow:
1. Collect PR data from GitHub
2. Generate structured commit data
3. Create analysis files
4. Generate LLM prompt with instructions
"""

import subprocess
import json
import argparse
import sys
import os
from pathlib import Path
from string import Template


def run_cmd(cmd_list, verbose=False):
    """Run command and return output."""
    if verbose:
        print(f"Running: {' '.join(cmd_list)}")
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {' '.join(cmd_list)}", file=sys.stderr)
        print(f"Error output: {e.stderr}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Exception running command {' '.join(cmd_list)}: {e}", file=sys.stderr)
        return None


def generate_llm_prompt(from_tag, to_tag, data_files, output_dir, verbose=False):
    """Generate comprehensive prompt for LLM using template."""

    # Read the template file
    template_path = Path(__file__).parent / "examples" / "enhanced_prompt_template.md"

    try:
        with open(template_path, 'r') as f:
            template_content = f.read()
    except FileNotFoundError:
        print(f"Error: Template file not found at {template_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading template file: {e}", file=sys.stderr)
        sys.exit(1)

    # Create template and substitute variables
    template = Template(template_content)

    # Extract filenames for template substitution
    pr_data_basename = Path(data_files['pr_data']).name
    pr_summary_basename = Path(data_files['pr_summary']).name
    structured_notes_basename = Path(data_files['structured_notes']).name
    commit_categories_basename = Path(data_files['commit_categories']).name

    # Substitute template variables
    try:
        prompt = template.substitute(
            VERSION=to_tag,
            PR_DATA=pr_data_basename,
            PR_DATA_SUMMARY=pr_summary_basename,
            STRUCTURED_NOTES=structured_notes_basename,
            COMMIT_CATEGORIES=commit_categories_basename
        )
    except KeyError as e:
        print(f"Error: Missing template variable: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error substituting template variables: {e}", file=sys.stderr)
        sys.exit(1)

    # Write the generated prompt
    prompt_file = output_dir / f"llm-prompt-{to_tag}.md"
    try:
        with open(prompt_file, 'w') as f:
            f.write(prompt)
    except Exception as e:
        print(f"Error writing prompt file: {e}", file=sys.stderr)
        sys.exit(1)

    if verbose:
        print(f"LLM prompt written to {prompt_file}")

    return str(prompt_file)


def main():
    parser = argparse.ArgumentParser(
        description='Orchestrate release notes generation workflow.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --from-tag v3.0.3 --to-tag v3.0.4 --output-dir release-data
  %(prog)s --from-tag v3.0.3 --to-tag v3.0.4 --verbose
        """
    )
    parser.add_argument('--from-tag', required=True, help='Starting tag/branch')
    parser.add_argument('--to-tag', required=True, help='Ending tag/branch')
    parser.add_argument('--output-dir', default='release-data', help='Output directory for data files')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    if args.verbose:
        print(f"Starting release notes workflow for {args.from_tag} to {args.to_tag}")
        print(f"Output directory: {output_dir}")

    data_files = {}

    # Step 1: Collect PR data
    if args.verbose:
        print("\n1. Collecting PR data...")

    pr_data_file = output_dir / f"pr-data-{args.to_tag}.json"
    pr_summary_file = output_dir / f"pr-data-{args.to_tag}-summary.md"

    cmd_list = ["python", str(Path(__file__).parent / "collect_pr_data.py"), "--from-tag", args.from_tag, "--to-tag", args.to_tag, "--output", str(pr_data_file)]
    if args.verbose:
        cmd_list.append("--verbose")

    result = run_cmd(cmd_list, args.verbose)
    if result is None:
        print("Failed to collect PR data", file=sys.stderr)
        sys.exit(1)

    data_files['pr_data'] = str(pr_data_file)
    data_files['pr_summary'] = str(pr_summary_file)

    # Step 2: Generate structured notes
    if args.verbose:
        print("\n2. Generating structured notes...")

    structured_file = output_dir / f"structured-notes-{args.to_tag}.md"
    cmd_list = ["python", str(Path(__file__).parent / "generate_structured_notes.py"), "--input", str(pr_data_file), "--output", str(structured_file)]
    if args.verbose:
        cmd_list.append("--verbose")

    result = run_cmd(cmd_list, args.verbose)
    if result is None:
        print("Failed to generate structured notes", file=sys.stderr)
        sys.exit(1)

    data_files['structured_notes'] = str(structured_file)

    # Step 3: Categorize commits
    if args.verbose:
        print("\n3. Categorizing commits...")

    commit_cat_file = output_dir / f"commit-categories-{args.to_tag}.md"
    cmd_list = ["python", str(Path(__file__).parent / "categorize_commits.py"), "--from-tag", args.from_tag, "--to-tag", args.to_tag, "--output-format", "markdown"]
    result = run_cmd(cmd_list, args.verbose)
    if result is not None:
        with open(commit_cat_file, 'w') as f:
            f.write(result)
    if result is None:
        print("Failed to categorize commits", file=sys.stderr)

    data_files['commit_categories'] = str(commit_cat_file)

    # Step 4: Generate LLM prompt
    if args.verbose:
        print("\n4. Generating LLM prompt...")

    prompt_file = generate_llm_prompt(
        args.from_tag,
        args.to_tag,
        data_files,
        output_dir,
        args.verbose
    )

    # Step 5: Create workflow summary
    summary = f"""
# Release Notes Workflow Summary

## Generated Files
- PR Data: {data_files['pr_data']}
- PR Summary: {data_files['pr_summary']}
- Structured Notes: {data_files['structured_notes']}
- Commit Categories: {data_files.get('commit_categories', 'N/A')}
- LLM Prompt: {prompt_file}

## Next Steps
1. Review the generated files in {output_dir}
2. Use the LLM prompt to generate release notes
3. The LLM should create:
   - `ProxySQL-{args.to_tag}-Release-Notes.md`
   - `CHANGELOG-{args.to_tag}-detailed.md`
   - `CHANGELOG-{args.to_tag}-commits.md` (optional)

## LLM Instructions
Provide the LLM with:
1. Access to all files in {output_dir}
2. The prompt: {prompt_file}
3. Instructions to write descriptive release notes with backtick formatting

## Verification Checklist
- [ ] All technical terms have backticks
- [ ] No WIP/skip-ci tags remain
- [ ] Changes are grouped logically
- [ ] Descriptions explain what/why, not just copy titles
- [ ] Commit hashes and PR numbers are referenced
"""

    summary_file = output_dir / "workflow-summary.md"
    with open(summary_file, 'w') as f:
        f.write(summary)

    if args.verbose:
        print(f"\nWorkflow summary written to {summary_file}")
        print("\n✅ Workflow completed!")
        print(f"\nNext: Provide the LLM with files in {output_dir} and prompt: {prompt_file}")


if __name__ == '__main__':
    main()
