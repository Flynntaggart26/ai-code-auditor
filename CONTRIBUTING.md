# Contributing to SafeCode AI

Welcome — especially students and first-time contributors! 🎓

## Ways to contribute
- **New detection rules** — add a check in `auditor.py` (`visit_Call` etc.), document it in `scanner/rules.py`, add a test.
- **New auto-fixes** — extend `scanner/autofix.py` (safe rewrites only; must keep code parsing).
- **Tests** — add cases in `tests/`.
- **Docs/translations** — improve README or translate rules.

## Workflow
1. Fork + clone, create a branch: `git checkout -b feat/my-rule`
2. Install: `pip install -r requirements.txt`
3. Add your rule + test, then run:
   ```bash
   python -m pytest tests/ -q
   python auditor.py sample_vulnerable.py --no-ai
   ```
4. Open a PR describing: what the rule catches, false-positive risk, example.

## Rule guidelines
- Prefer AST over regex. No network calls in the scanner core.
- Every rule needs: `rule_id`, severity (HIGH/MEDIUM/LOW), title, fix advice, and at least one test.
- Avoid flagging test files for style rules (see B107 handling).

## Code style
- Standard library first; keep dependencies minimal.
- Keep the offline scanner working with **zero API keys**.
