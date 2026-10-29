# Temporary CI ASAN validation probe

This disposable file opens a label-controlled CI validation pull request.
Markdown-only changes are ignored by `CI-trigger`; a subsequent non-ignored
no-op change will start the selected run after the `ci:asan` label is applied.
