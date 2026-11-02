#!/usr/bin/env sh

set -eu

# Fast checks, meant to be run before every commit. The interpreter sweep lives
# in ci-matrix.sh, which is slow and only needed before releases.
#
# Ratchet status: wotmate predates type annotations and the sibling projects'
# lint rules, so the checkers start loose. ruff runs its defaults plus isort,
# with the modernisation rules listed in pyproject.toml ignored; mypy runs with
# check_untyped_defs, pyright at `standard`, and ty at its default rules. Keep
# tightening in pyproject.toml; the goal is `mypy --strict` / pyright `strict`
# / ty `all = "error"`, as in the sibling projects. Prefer real fixes and real
# annotations over suppressions when tightening.

# --locked fails rather than re-resolving, so a pyproject.toml edit that was
# not followed by `uv lock` is caught here instead of silently giving this run
# a different set of tool versions than everyone else's. When it complains,
# run `uv lock` (and `uv export --no-dev --no-emit-project -o requirements.txt`
# if a runtime dependency changed) and commit both.
uv sync --all-groups --locked

uv run ruff format --check
uv run ruff check
uv run ty check
uv run mypy .
uv run pyright
uv run pytest --durations=0
