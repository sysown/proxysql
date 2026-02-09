# Contributing to ProxySQL

Thank you for your interest in contributing to ProxySQL! We welcome contributions from the community.

## Code of Conduct

We expect all contributors to be respectful and constructive. Please help us maintain a welcoming environment for everyone.

## Before You Start

Discuss major changes: For significant features or architectural changes, please open an issue first to discuss.

Check existing issues: Someone might already be working on something similar.

Reference issues: When fixing bugs or implementing requested features, mention the issue number in your PR.

## Development Setup

ProxySQL provides Docker build images for development. The required packages for building are listed in the Dockerfiles at: https://github.com/ProxySQL/docker-images/tree/main/build-images

For example, to see packages needed for Ubuntu 24.04, check: https://github.com/ProxySQL/docker-images/blob/main/build-images/build-ubuntu24/Dockerfile

## Making Changes

- Fork the repository
- Create a feature branch: `git checkout -b feature/your-feature-name`
- Make your changes
- Ensure your code builds successfully
- Submit a Pull Request

## Coding Standards

Follow the existing code style and patterns in the codebase

Use clear, descriptive names for variables and functions

Add comments for complex logic

Keep functions focused and maintainable

### For C++ Code:

- Use C++11/14 features appropriately
- Follow RAII principles for resource management
- Consider performance implications (ProxySQL is performance-critical)

## Testing

All PRs will go through our automated testing suite. While the full testing framework isn't publicly available, we encourage you to test your changes as thoroughly as possible.

## Commit Messages

Recommendations (not strict requirements):

- Use descriptive messages that explain what changed and why
- Reference issue numbers when applicable (`#123`)
- Keep the first line under 72 characters

**Example:** `Fix memory leak in connection pooling (#456)`

## Pull Request Guidelines

- Use a clear title and description
- Explain what was changed and why
- Note any breaking changes or performance impacts
- Update documentation if functionality changes

## Reporting Bugs

Please include in bug reports:

- ProxySQL version
- Steps to reproduce
- Expected vs actual behavior
- Relevant configuration details
- Logs (with sensitive data redacted)

## Feature Requests

For new features, please:

- Describe the feature/problem clearly
- Explain the use case
- Consider performance implications
- Note any backward compatibility concerns

## Questions and Support

- **Mailing list**: Join the ProxySQL mailing list for discussions
- **GitHub issues**: Use GitHub issues for questions, bugs, and feature requests
- **Search existing issues** before creating new ones

## Recognition

Contributors will be credited in the release notes for their contributions.

## License

By contributing to ProxySQL, you agree that your contributions will be licensed under the project's GPLv3 license.

---

Thank you for helping make ProxySQL better!