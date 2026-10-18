# AI-Powered Code Security Auditor

Free, offline-first Python security scanner for students. $0 cost with BYOK.

## Why?
Most AI code tools send your whole file to expensive APIs. This one scans locally with AST (free), then asks Gemini **only for HIGH findings**, with MD5 caching. Your key, your quota — I pay nothing, you pay nothing.

## Quickstart (2 min)
```bash
pip install -r requirements.txt
cp .env.example .env
# get free key: https://aistudio.google.com/ -> paste into .env
python auditor.py sample_vulnerable.py --no-ai
streamlit run dashboard.py
```

## Deploy free (Streamlit Cloud)
1. Push to GitHub (do NOT commit `.env`)
2. streamlit.io/cloud -> New app -> select repo, `dashboard.py`
3. No secrets needed: users paste their own free key in the sidebar (BYOK).

## Rules
B101 eval/exec, B102 os.system, B103 shell=True, B104 pickle, B105 yaml, B106 weak hash, B108 hardcoded secret, B109 SQLi, B110 verify=False, B112 bare except, COMPLEXITY.

## Roadmap
- [x] Local AST scanner
- [x] BYOK dashboard
- [ ] Pre-commit hook
- [ ] Folder scan + JSON report
