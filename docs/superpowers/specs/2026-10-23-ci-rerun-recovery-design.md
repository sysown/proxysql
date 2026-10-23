# CI rerun recovery

## Intent

Unblock PR #6520 without changing its artifact implementation or manufacturing passing checks. Its 67 individual checks and coverage passed, but full consumer reruns failed when their binding artifact disappeared, retained successful jobs confused the aggregate, and C++ CodeQL reached its deadline just after completing analysis.

## Approach

Repair the existing CI controller. Repeating whole cascades wastes successful builds and does not repair rerun semantics; overriding checks would discard native validation. These are implementation choices within the request to fix CI. Execution remains native, with one independent final review.

## Required behavior

- A same-repository automatic rerun with no matching local binding may recover only the original trigger's immutable accepted producer. Verify repository, source SHA, trigger ID and trigger attempt, then use its original manifest.
- An existing binding takes precedence. Expired, ambiguous, corrupt or mismatched bindings and API errors fail closed. Missing manual or foreign-repository bindings do not recover from current inputs or labels.
- GitHub clones retained native jobs into later attempts and changes their IDs and attempt numbers. Accept an older successful custom result only when the latest native success exactly matches the original native job's full name and nonempty execution interval. Missing, ambiguous or changed execution intervals remain pending. Native failure, cancellation and unfinished execution retain precedence.
- Increase CodeQL's job budget from 120 to 180 minutes. The observed build and scan consumed essentially all 120 minutes; preserve a finite budget and successful native-job validation.
- Keep PR #6520 and `v3.0` unchanged. Publish a separate PR targeting `GH-Actions`; activation requires merging that CI-control PR.

## Validation

Add failing behavioral regressions before each Python fix. Exercise real artifact selection/ZIP decoding with a fake API transport, and retained-versus-fresh native job responses. Run the entire `.github/scripts/tests` suite and workflow validation, then obtain one fresh branch review.
