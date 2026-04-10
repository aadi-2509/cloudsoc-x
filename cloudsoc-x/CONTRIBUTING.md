# Contributing to CloudSOC-X

Thanks for taking a look. This is primarily a personal learning project but I'm happy to accept contributions — especially new detection rules.

---

## Adding a new detection rule

1. Open `src/rules.py`
2. Add a new `Rule(...)` entry to the `RULES` list at the bottom
3. Write a test in `tests/test_detector.py` — at minimum, one test that asserts the rule fires and one that asserts it doesn't fire on benign input
4. Update the rules table in `README.md`
5. Add an entry to `CHANGELOG.md` under `[Unreleased]`

Rule naming convention:
- IDs: `CSOC-XXX` where XXX is the next available number
- Names: short, imperative, describe what happened — not what to do about it

---

## Running the test suite

```bash
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
pytest tests/ -v --cov=src
```

All tests must pass before submitting a PR.

---

## Code style

- Line length: 120 chars max
- Docstrings on all public functions and classes
- Type hints where they add clarity (not required everywhere)
- No `print()` in library code — use `logging`

---

## Commit message format

```
type(scope): short description

longer explanation if needed

Refs: #issue-number
```

Types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`

Examples:
```
feat(rules): add detection for GuardDuty Tor client finding
fix(enricher): handle IPv6 addresses in TOR exit check
test(api): add coverage for alert pagination edge cases
```
