# Fork Pull Request Builds Design

## Goal

Run the existing four build variants for approved pull requests from forks without allowing fork-controlled code to execute in the privileged `workflow_run` CI cascade.

## Scope

Fork pull requests must run these build variants on GitHub-hosted runners:

| Variant |
| --- |
| `debian12,-dbg` |
| `ubuntu22,-tap` |
| `ubuntu24,-tap-genai-gcov` |
| `ubuntu22,-tap-mysqlx` |

The existing privileged build cascade remains the path for same-repository branches. Its cache and artifact handoff behavior is not extended to fork code.

## Architecture

`CI-builds` remains a `workflow_run` workflow. It must skip its privileged reusable build job when the upstream workflow run originates from a fork. This prevents `actions/checkout` from trying to fetch a fork commit while the job has the base repository's write-capable token.

A new direct `pull_request` workflow runs the four build variants for fork heads. It uses a separate reusable build implementation designed for untrusted code. The caller grants only `contents: read`; the reusable workflow does not inherit secrets, use self-hosted runners, publish custom check runs, restore or save shared caches, upload handoff artifacts, or trigger downstream test workflows.

GitHub's repository policy remains responsible for requiring a maintainer to approve fork workflow runs. Approval permits restricted GitHub-hosted execution; it does not elevate fork code into the privileged workflow-run context.

## Data Flow

1. A contributor opens or updates a fork pull request.
2. GitHub applies the repository's fork-workflow approval policy.
3. After approval, the new `pull_request` workflow checks out the PR merge commit and builds all four variants with a read-only token on GitHub-hosted runners.
4. The existing `workflow_run` `CI-builds` workflow observes the trigger but skips its trusted build job for the fork source.
5. Same-repository PRs continue to use the existing privileged `CI-trigger` -> `CI-builds` cascade unchanged.

## Security Constraints

- Never set `allow-unsafe-pr-checkout: true` for fork code in a `workflow_run` or `pull_request_target` workflow.
- Never run fork code on self-hosted runners.
- Fork builds receive no secrets and no write-capable token.
- Fork builds do not consume or produce shared CI caches or artifacts that privileged workflows use.
- The fork build workflow must not create custom checks via `LouisBrunner/checks-action`; native job results provide its status.

## Error Handling and Visibility

The fork build workflow's native matrix job names identify the variant that failed. Build logs remain in the GitHub-hosted run. The trusted cascade's fork guard must avoid producing a false failure: it should skip, rather than attempt a protected checkout.

## Verification

- Add static workflow tests that verify the trusted workflow is gated for same-repository heads and the fork workflow uses `pull_request` with read-only permissions.
- Verify the fork workflow has exactly the four existing build variants.
- Validate the workflow YAML locally.
- Exercise the safe path with a fork PR after merge or through a controlled fork, confirming it runs only on a GitHub-hosted runner and does not enter the privileged checkout path.
