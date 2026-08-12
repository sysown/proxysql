# Resilient CI Trigger API Polling Design

## Problem

The `CI-trigger` run for ProxySQL PR #6035 failed even though every job in its
downstream `CI-builds` run succeeded. The trigger uses `gh run watch
--exit-status` to wait for CI-builds. A single GitHub API transport failure
therefore has the same exit status as a completed, unsuccessful build. In the
observed run, the GitHub-hosted runner rejected the TLS certificate returned
for `api.github.com`; `CI-trigger` reported CI-builds as failed while CI-builds
was still running and later completed successfully.

Downstream test workflows run only when `CI-trigger` completes successfully.
The polling error consequently caused those workflows to be created and
skipped, voiding the full CI run without any source or build failure.

## Scope

Modify only `.github/workflows/ci-trigger.yml` and its directly associated
design and implementation-plan documentation on a branch based on
`GH-Actions`. Preserve the existing workflow topology: `CI-trigger` discovers
and waits for `CI-builds`, and downstream workflows continue to gate on the
conclusion of `CI-trigger`.

Do not change ProxySQL source code, build selection, downstream workflow
conditions, workflow permissions, or the 240-minute trigger job timeout.

## Design

Replace the table-parsing `gh run list` calls and `gh run watch --exit-status`
with explicit JSON polling in the existing trigger step.

All GitHub CLI polling calls use one retry helper. Each individual call has a
30-second command timeout so a hung connection cannot bypass the retry budget.
When a call fails, the helper logs a warning containing the attempt and error,
then retries after 5, 10, 20, and at most 30 seconds between later attempts.
It tolerates at most five consecutive minutes, measured from the start of the
first failed call, of API or transport failures. A successful API response
resets that error window. If the window expires, the trigger fails with an
error that explicitly identifies GitHub API polling as the cause rather than
claiming that CI-builds failed.

Run discovery requests structured data from `gh run list --json` and matches
the expected head SHA against the workflow display title. A successful query
with no matching run means the run is not visible yet; it is not an API error
and retains the existing 20-second discovery polling interval.

After discovery, the trigger polls the selected run with `gh run view --json
status,conclusion`. Queued and in-progress states continue polling. Once the
status is `completed`, a `success` conclusion completes the trigger step. Any
other confirmed conclusion fails immediately and reports that exact
conclusion. Non-completed runs are queried every 30 seconds. The poller never
infers a build conclusion from a failed API call.

The housekeeping step remains opportunistic and non-blocking as it is today.

## Error Semantics

- A one-off TLS, HTTP, timeout, or GitHub CLI failure is retried.
- Intermittent failures remain recoverable as long as a successful polling
  response occurs within each five-minute consecutive-error window.
- Five uninterrupted minutes without a successful API response fail the job
  as a polling-infrastructure failure.
- A confirmed completed CI-builds conclusion other than `success` fails the
  job immediately as a CI-builds failure.
- A successful query that does not yet show the expected run continues normal
  discovery polling and does not consume the API-error budget.

## Validation

Validate the workflow YAML and exercise the embedded polling logic with a fake
`gh` command covering these deterministic sequences:

1. A transient API failure followed by discovery and a successful build.
2. Repeated transient failures separated by successful responses, proving the
   consecutive-error budget resets.
3. Continuous API failures until the five-minute budget expires, using reduced
   test timings.
4. A discovered build that completes with a failure conclusion.
5. Successful discovery queries with no initial match, followed by a match.

Finally, trigger the workflow from a test PR or empty commit and confirm that
the CI-builds result is propagated and downstream workflows start only after a
successful CI-builds conclusion.

## Acceptance Criteria

- One transient GitHub API or TLS error cannot fail `CI-trigger`.
- Consecutive API failures are tolerated for five minutes and a successful
  response resets the tolerance window.
- A hung API call is bounded and cannot silently exceed the retry window.
- The trigger distinguishes polling-infrastructure failure from a confirmed
  CI-builds failure in its log and error message.
- A confirmed unsuccessful CI-builds conclusion still fails `CI-trigger`.
- A successful CI-builds conclusion allows `CI-trigger` to succeed and the
  existing downstream workflow fan-out to proceed.
- The workflow remains valid YAML and retains its existing permissions,
  topology, and timeout.
