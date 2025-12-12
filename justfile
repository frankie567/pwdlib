# https://just.systems

install:
    uv sync --all-extras
    @# Copy Rust extension to source directory for editable install
    @cp .venv/lib/python*/site-packages/pwdlib/_zxcvbn.so pwdlib/_zxcvbn.so 2>/dev/null || true

lint:
    uv run ruff format .
    uv run ruff check --fix .
    uv run mypy pwdlib/

lint-check:
    uv run ruff format --check .
    uv run ruff check .
    uv run mypy pwdlib/

test:
    uv run pytest

test-cov-xml:
    uv run pytest --cov-report=xml

docs-serve:
    uv run mkdocs serve

docs-build:
    uv run mkdocs build

version bump:
    uvx hatch version {{bump}}
