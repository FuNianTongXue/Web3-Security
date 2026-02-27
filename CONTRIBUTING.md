# Contributing

Thanks for contributing to Web3-Security.

## Issue-First Collaboration

Before opening a PR for a new idea, please open an issue first:

1. Use the issue templates from `Issues -> New issue`.
2. Describe your use case, risk, and expected result.
3. For larger features, wait for maintainer feedback before implementation.

If this project is useful to you, please consider starring the repository and opening one high-quality issue with your real security scenario.

## Workflow

1. Fork the repo and create a branch from `master`.
2. Keep commits focused and descriptive.
3. Run relevant tests/lint checks before opening a PR.
4. Open a pull request with:
   - Summary of changes
   - Impact/risk notes
   - Verification steps

## Issue Writing Guidelines

High-quality issues are much easier to prioritize. Include:

- Scope: affected module/path
- Context: chain/protocol and security objective
- Reproduction: steps, input, sample data, logs/screenshots
- Expected vs actual behavior
- Impact and urgency

For sensitive vulnerabilities, avoid posting exploit details publicly.

## Commit Message Convention

Use concise prefixes:
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `refactor:` code restructuring without behavior change
- `test:` tests
- `chore:` maintenance

## Quality Expectations

- No secrets or tokens in commits.
- No local caches/build artifacts committed.
- Keep top-level structure clear and English-first for discoverability.
