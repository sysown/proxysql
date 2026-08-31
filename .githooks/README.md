# Repository Git hooks

Enable the tracked hooks once per clone:

```bash
git config core.hooksPath .githooks
```

The pre-push hook runs the same complete lint suite as
`.github/workflows/CI-lint-groups-json.yml` and blocks the push on failure.
The suite requires `envsubst`; install `gettext-base` on Debian/Ubuntu or
`gettext` on macOS before pushing.
Use `git push --no-verify` only when intentionally bypassing local verification.
