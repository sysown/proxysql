# GitHub Actions CI

## Opt-in TAP ASAN

- Add `ci:asan` to an internal PR, then push an empty commit to request an
  ASAN standard-TAP integration run.
- Removing or adding the label alone does not start CI.
- Without the label, push builds, and manual dispatches use the normal build.
- The label replaces the normal `ubuntu24-tap-genai-gcov` handoff for that
  commit; it does not run a second fan-out.
- Unit ASAN coverage and MySQLX behavior are unchanged.
