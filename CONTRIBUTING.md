# Contributing

1. Branch from `main` and open a pull request; CI must pass. Commits follow
   [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
2. **A new attack pattern:** first add the case that gets through to `src/hotelplatform/data/redteam_shared.jsonl`
   (and a benign control it must not block), see it fail, then add the pattern. Run `python -m hotelplatform.redteam`.
3. **A new guardrail check:** a pure function in `guardrails.py`, a reason code with a user-facing message, and
   tests for what it must and must not catch.
4. **A schema change** in `oplog.py`: add columns only (apps on older tags still write), and say so in CHANGELOG.
5. **Releasing:** bump `version` in `pyproject.toml` and `__init__.py`, update CHANGELOG, tag `vX.Y.Z`, then bump
   the pin in each app's `requirements.txt` on a branch.
6. Run `make check` before pushing.
