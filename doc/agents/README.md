# Agent Guidelines for ProxySQL

This directory contains guidance for AI coding agents (Claude Code, GitHub Copilot, etc.) working on the ProxySQL codebase.

| Document | Purpose |
|----------|---------|
| [Architecture](../architecture.md) | Read before implementation or review. Module responsibilities, ownership, execution and lifecycle, with source references and explicit coverage gaps |
| [invariants.md](invariants.md) | **Read first.** Product contracts every change must preserve; changing one needs a maintainer decision |
| [project-conventions.md](project-conventions.md) | ProxySQL-specific rules: where files go, how to build, branch model |
| [task-assignment-template.md](task-assignment-template.md) | Template for writing issues that agents can execute correctly |
| [common-mistakes.md](common-mistakes.md) | Known failure patterns and how to prevent them |
