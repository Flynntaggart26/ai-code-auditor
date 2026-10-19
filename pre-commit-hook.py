#!/usr/bin/env python3
"""Git pre-commit hook (Windows uyumlu, .git/hooks/pre-commit olarak calisir).
Staged .py dosyalarinda HIGH bulgu varsa commiti durdurur. AI yok, $0 maliyet.
Gecmek icin: git commit --no-verify (onerilmez)
"""
import subprocess
import sys
import os

# Hook .git/hooks/ altinda calisir; auditor.py repo kokundedir.
# Dogrudan calistirmada (test) dosyanin bulundugu klasoru kullan.
if os.path.basename(os.path.dirname(os.path.abspath(__file__))).lower() == "hooks":
    REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
else:
    REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

def staged_py_files():
    try:
        out = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            cwd=REPO_ROOT, text=True, stderr=subprocess.DEVNULL,
        )
    except Exception:
        return []
    return [l.strip() for l in out.splitlines() if l.strip().endswith(".py")]

def audit_paths(paths):
    """Staged dosya listesini tek tek tara (hizli, sadece degisen)."""
    sys.path.insert(0, REPO_ROOT)
    from auditor import scan_file
    out = []
    for p in paths:
        fp = os.path.join(REPO_ROOT, p)
        if not os.path.isfile(fp):
            continue
        try:
            fs = scan_file(fp)
        except SyntaxError:
            continue
        out.extend(fs)
    return out

def main():
    staged = staged_py_files()
    if not staged:
        return 0
    print(f"[auditor] {len(staged)} staged dosya taraniyor...")
    findings = audit_paths(staged)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda x: (order.get(x["severity"], 3), x["file"], x["line"]))
    highs = [x for x in findings if x.get("severity") == "HIGH"]
    if highs:
        print("[auditor] HIGH bulgu var, commit durduruldu. Detay:")
        for x in highs:
            print(f"  [{x['severity']}] {x['file']}:{x['line']} {x['rule_id']} {x['title']}")
        print("Gecmek icin: git commit --no-verify (onerilmez)")
        return 1
    print(f"[auditor] temiz ({len(findings)} dusuk bulgu).")
    return 0

if __name__ == "__main__":
    sys.exit(main())
