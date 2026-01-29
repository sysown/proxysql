# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Docusaurus v3 documentation site** for ProxySQL, a high-performance MySQL/PostgreSQL proxy. The documentation is built with React, TypeScript, MDX, and Mermaid diagrams.

**Branch:** `feature/modern-docs` (all changes are made here)
**Main branch for PRs:** `v3.0`
**Deployment:** https://sysown.github.io/proxysql/ (automatic on push to `feature/modern-docs`)

## Development Commands

| Command | Purpose |
|---------|---------|
| `npm install` | Install dependencies (requires Node.js >= 20) |
| `npm start` | Start dev server at http://localhost:3000 |
| `npm run build` | Build for production |
| `npm run serve` | Serve production build locally |
| `npm run typecheck` | Run TypeScript type checking |
| `npm run clear` | Clear Docusaurus cache |

**No test or lint infrastructure** is configured for this documentation-only project.

## Project Structure

```
proxysql/
├── docs/                    # All markdown documentation (72+ files)
├── docusaurus.config.ts     # Site configuration (title, theme, navbar, etc.)
├── sidebars.ts              # Navigation structure - edit when adding new pages
├── src/
│   ├── css/custom.css       # Custom theme colors and dark mode styles
│   └── components/          # Custom React components
├── static/img/              # Images and logos
└── .github/workflows/deploy.yml  # CI/CD for GitHub Pages
```

## Key Configuration Files

- **docusaurus.config.ts**: Main site config, theme settings, Mermaid enablement, edit URLs
- **sidebars.ts**: Hierarchical navigation structure - must be updated when adding new docs
- **src/css/custom.css**: Custom CSS variables for theming (light/dark mode)

## Adding or Editing Documentation

1. **Edit existing content**: Modify `.md` files in `docs/`
2. **Add new documentation**:
   - Create `.md` file in appropriate `docs/` subdirectory
   - Add entry to `sidebars.ts` in the relevant category
   - Use existing files as templates for formatting

## Content Conventions

- **MDX syntax** is supported for interactive elements
- **Mermaid diagrams** are enabled for architectural visualizations
- **Admonitions** (`:::tip`, `:::info`, `:::warning`) for callout blocks
- **Cross-references**: Use relative paths or Markdown reference syntax for internal links
- **Frontmatter**: Include `title` and `sidebar_position` for proper navigation

## Architecture Highlights

The documentation covers 11+ major categories including MySQL/PostgreSQL configuration, Generative AI/MCP integration (v4.0), ProxySQL Cluster, Query Rules, and comprehensive global variable references.

The **Generative AI** section is particularly important - it documents the MCP (Model Context Protocol) server for AI agent integration with detailed endpoint references and authentication methods.
