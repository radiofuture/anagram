## What and why

<!-- What does this change do, and why is it necessary? Link the issue. -->

## How I tested it

<!-- Commands that you ran and what you checked by hand. -->

## Checklist

- [ ] `uv run ruff check src tests` and `uv run ruff format --check src tests` pass.
- [ ] `uv run mypy` passes (strict set).
- [ ] `HF_HUB_OFFLINE=1 uv run pytest -q -p no:randomly --cov` passes, and coverage is not below the floor.
- [ ] Behaviour on the wire changed: the spec in `spec/` changed first, in this pull request.
- [ ] No existing file in `spec/vectors/` changed.
- [ ] No keys, tokens, `.env` files or private research text.
- [ ] `CHANGELOG.md` has an entry under Unreleased, if users can see the change.
