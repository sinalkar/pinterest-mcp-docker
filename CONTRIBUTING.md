# Contributing Guide

Thank you for contributing to `pinterest-mcp-docker`!

## Development Setup

1. **Clone repository:**
   ```bash
   git clone https://github.com/sinalkar/pinterest-mcp-docker.git
   cd pinterest-mcp-docker
   ```

2. **Create virtual environment & install dev dependencies:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

## Running Tests & Linters Locally

- **Run unit & integration tests:**
  ```bash
  pytest
  ```

- **Run linters and formatters:**
  ```bash
  ruff check src/ tests/
  ruff format --check src/ tests/
  ```

- **Run security scanners & allowlist expiry check:**
  ```bash
  bandit -r src/
  pip-audit
  python scripts/check_allowlist_expiry.py
  ```

## Pull Request Guidelines

Before submitting a PR, ensure:
1. All pytest tests pass locally.
2. Ruff formatting and linting pass cleanly without warnings.
3. Any new configuration options are documented in `README.md` and `.env.template`.
4. Any ignore rules added to `.trivyignore` or `.semgrepignore` carry a valid `# expires: YYYY-MM-DD` comment and rationale.
