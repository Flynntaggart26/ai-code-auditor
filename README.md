# 🛡️ SafeCode AI — Free Offline Python Security Scanner with Auto-Fix

[![Audit](https://github.com/Flynntaggart26/ai-code-auditor/actions/workflows/audit.yml/badge.svg)](https://github.com/Flynntaggart26/ai-code-auditor/actions)
[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://ai-code-auditor-fly.streamlit.app)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

**Live demo:** https://ai-code-auditor-fly.streamlit.app

> Scan any Python file or project ZIP in seconds. Get a **0-100 security score**, one-click **auto-fixes**, and a shareable **HTML report** — 100% free, offline-first, no data leaves your machine unless you opt into AI explanations (BYOK).

Built by a high-school student to make AppSec accessible to every student developer. If it helped you, please ⭐ star the repo!

## ✨ Why SafeCode AI?

| | SafeCode AI | Bandit | Commercial AI scanners |
|---|---|---|---|
| Price | **$0 forever** | $0 | $$$/month |
| Offline AST scan | ✅ | ✅ | ❌ (uploads code) |
| Taint tracking (user input → sink) | ✅ | ❌ | ✅ |
| Auto-fix (`--fix`) | ✅ | ❌ | ✅ |
| Security score 0–100 | ✅ | ❌ | ✅ |
| One-click HTML report | ✅ | ❌ | ✅ |
| GitHub Code Scanning (SARIF) | ✅ | ✅ | ✅ |
| Optional AI explanations (BYOK) | ✅ | ❌ | ✅ |

## 🚀 Quickstart (2 min)

```bash
pip install -r requirements.txt

# 1. Scan a file (no API key needed)
python auditor.py sample_vulnerable.py --no-ai

# 2. Scan + auto-fix + HTML report
python auditor.py sample_vulnerable.py --no-ai --fix --html report.html

# 3. Scan whole folder, fail CI on HIGH
python auditor.py . --no-ai --json report.json --sarif results.sarif --fail-on HIGH

# 4. Launch the web dashboard
streamlit run dashboard.py
```

Open `report.html` in any browser to see the score card. Files ending in `.fixed.py` contain safe auto-fixes — **always review before using**.

## 🧠 How it works

1. **AST parsing** — real syntax-tree analysis (`ast` module), not regex.
2. **22 rules** (B101–B117 + TAINT + COMPLEXITY): RCE, command/SQL injection, pickle, weak crypto, hardcoded secrets, TLS bypass, cleartext protocols, insecure temp files, Flask debug, bare except, taint flows, complexity.
3. **Taint tracking** — follows `input()` / `request.args` / `os.getenv` → `os.system`, `eval`, `execute()` sinks across assignments, f-strings, `+`/`%`/`.format()`.
4. **Security score** — HIGH −15, MEDIUM −5, LOW −1 → grade A–F.
5. **Auto-fix** — safe rewrites only (e.g. `yaml.load` → `yaml.safe_load`, `md5` → `sha256`, `verify=False` → `verify=True`, `random` → `secrets`). Never touches logic.
6. **Optional AI** — only HIGH findings, MD5-cached in SQLite, your own free Gemini key (BYOK). No key = full offline mode.

## 📊 Example

```
$ python auditor.py sample_vulnerable.py --no-ai
sample_vulnerable.py: 12 findings
  [HIGH] B102 run_user:6 - OS command injection
  [HIGH] TAINT <taint>:10 - Tainted flow -> os.system
  ...
SECURITY SCORE: 0/100 (F) (HIGH:8 MEDIUM:3 LOW:1) — 1 files, 12 findings
```

## 🖥️ Dashboard

Upload a `.py` file or project `.zip` (≤10 MB, ≤100 files), filter by severity, download JSON/Markdown, and read cached AI explanations — all in the browser.

## 🔧 CI / Pre-commit

This repo dogfoods itself: every push runs `auditor.py` + `pytest` and uploads SARIF to GitHub Code Scanning.

```bash
# one-click Windows pre-commit install
install-hook.bat
```

## 🗺️ Roadmap

- [x] Offline AST scanner (22 rules)
- [x] Taint tracking
- [x] Security score 0–100
- [x] Auto-fix engine
- [x] HTML report
- [x] SARIF + CI + pre-commit
- [x] Streamlit dashboard (file + ZIP)
- [ ] Multi-language (JS/TS) rules
- [ ] VS Code extension
- [ ] Fix pull-request bot

## 🤝 Contributing

Student-friendly! See [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues: new rules, more auto-fixes, translations.

## 🔒 Security

Found a bypass in the scanner? See [SECURITY.md](SECURITY.md) — please report privately.

## 📄 License

MIT — see [LICENSE](LICENSE). Free for students, schools, and startups.
