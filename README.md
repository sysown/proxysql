# ProxySQL Documentation (Modern)

This branch (`feature/modern-docs`) contains the source code for the new Docusaurus-based documentation site for ProxySQL.

## Getting Started

1.  **Install dependencies:**
    ```bash
    npm install
    ```

2.  **Start the development server:**
    ```bash
    npm start
    ```
    This opens the site locally at http://localhost:3000.

3.  **Build for production:**
    ```bash
    npm run build
    ```

## Project Structure

- `docs/`: Markdown documentation files.
- `docusaurus.config.ts`: Site configuration.
- `src/`: Custom components and styles.
- `.github/workflows/deploy.yml`: CI/CD workflow for GitHub Pages.

## Contributing

Edit the markdown files in `docs/` to update documentation.