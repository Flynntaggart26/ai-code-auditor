"""AI-Powered Code Security Auditor - Gelistirilmis Scanner"""
import ast, os, re, sys, hashlib, sqlite3
from pathlib import Path
DB_NAME = str(Path(__file__).parent / "audit_cache.db")

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS audits (func_hash TEXT PRIMARY KEY, func_name TEXT, file_path TEXT, severity TEXT, ai_report TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
    conn.commit(); conn.close()

def get_cached_audit(func_code):
    h = hashlib.md5(func_code.encode('utf-8'), usedforsecurity=False).hexdigest()
    conn = sqlite3.connect(DB_NAME); cur = conn.cursor()
    cur.execute("SELECT ai_report FROM audits WHERE func_hash=?", (h,))
    row = cur.fetchone(); conn.close()
    return h, row[0] if row else None

def save_audit_to_cache(h, name, path, sev, report):
    conn = sqlite3.connect(DB_NAME); cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO audits VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)', (h, name, path, sev, report))
    conn.commit(); conn.close()

SECRET_RE = re.compile(r'(password|passwd|pwd|secret|api[_-]?key|token|aws_|private[_-]?key)', re.I)

def full_attr(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr); node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))

class SecurityScanner(ast.NodeVisitor):
    def __init__(self, path):
        self.path = path; self.findings = []; self.stack = []
    def add(self, node, rid, sev, title, detail):
        fn = self.stack[-1] if self.stack else "<module>"
        self.findings.append({"file": self.path, "func": fn, "line": getattr(node, 'lineno', 1), "rule_id": rid, "severity": sev, "title": title, "detail": detail})
    def visit_FunctionDef(self, node):
        self.stack.append(node.name)
        length = node.end_lineno - node.lineno + 1
        cx = 1
        for c in ast.walk(node):
            if isinstance(c, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.With, ast.Assert)):
                cx += 1
            elif isinstance(c, ast.BoolOp):
                cx += len(c.values) - 1
        depth = self._depth(node)
        if node.name.startswith("visit_"):
            pass  # AST visitor fonksiyonlari dogasi geregi dallidir
        elif length > 40 or cx > 10 or depth > 4:
            self.add(node, "COMPLEXITY", "HIGH" if cx >= 15 else "MEDIUM", "Asiri karmasik fonksiyon", f"Length:{length} Cyclomatic:{cx} Nesting:{depth}")
        self.generic_visit(node); self.stack.pop()
    visit_AsyncFunctionDef = visit_FunctionDef
    def _depth(self, node, d=0):
        best = d
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.Try)):
                best = max(best, self._depth(ch, d + 1))
            else:
                best = max(best, self._depth(ch, d))
        return best
    def visit_Call(self, node):
        name = full_attr(node.func) if isinstance(node.func, (ast.Attribute, ast.Name)) else ""
        if name in ("eval", "exec", "compile", "__import__"):
            self.add(node, "B101", "HIGH", f"Tehlikeli: {name}", "RCE riski. ast.literal_eval / whitelist kullan.")
        if name in ("os.system", "os.popen", "system", "popen"):
            self.add(node, "B102", "HIGH", "OS komut enjeksiyonu", "subprocess.run(liste, shell=False) kullan.")
        if name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.add(node, "B103", "HIGH", "subprocess shell=True", "shell=False + liste arguman kullan.")
        if name in ("pickle.loads", "pickle.load", "dill.loads", "shelve.open"):
            self.add(node, "B104", "HIGH", "Guvenilmez pickle", "json kullan.")
        if name in ("yaml.load", "yaml.unsafe_load"):
            if not any(k.arg == "Loader" for k in node.keywords):
                self.add(node, "B105", "HIGH", "yaml SafeLoader yok", "Loader=yaml.SafeLoader kullan.")
        if name in ("hashlib.md5", "hashlib.sha1"):
            skip = any(k.arg == "usedforsecurity" for k in node.keywords)
            if not skip:
                self.add(node, "B106", "MEDIUM", "Zayif hash", "sha256 / bcrypt / argon2 kullan.")
        if name in ("random.random", "random.randint", "random.choice", "random.randrange"):
            self.add(node, "B115", "MEDIUM", "Kriptografide zayif random", "secrets modulu kullanin.")
        if name in ("telnetlib.Telnet", "ftplib.FTP"):
            self.add(node, "B116", "HIGH", "Cleartext protokol", "ssh / https kullanin.")
        if name in ("ssl._create_unverified_context",):
            self.add(node, "B117", "HIGH", "Sertifika dogrulama atlandi", "Dogrulanmis SSL context kullanin.")
        if name in ("socket.bind",) or name.endswith(".bind"):
            for a in node.args:
                if isinstance(a, ast.Tuple) and a.elts:
                    h = a.elts[0]
                    if isinstance(h, ast.Constant) and h.value in ("0.0.0.0", ""):
                        self.add(node, "B113", "MEDIUM", "Soket 0.0.0.0'a bind", "Spesifik interface + auth kullanin.")
        if name in ("tempfile.mktemp",):
            self.add(node, "B114", "MEDIUM", "Guvensiz gecici dosya", "tempfile.mkstemp() kullanin.")
        if name.startswith("requests."):
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self.add(node, "B110", "HIGH", "verify=False", "TLS dogrulamayi acik birak.")
        if name in ("app.run", "flask.Flask.run"):
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.add(node, "B111", "MEDIUM", "Flask debug uretimde", "debug=False yapin.")
        if name.endswith(".execute") or name == "execute":
            if node.args:
                q = node.args[0]
                sus = isinstance(q, ast.JoinedStr) or (isinstance(q, ast.BinOp) and isinstance(q.op, (ast.Add, ast.Mod))) or (isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute) and q.func.attr == "format")
                if sus:
                    self.add(node, "B109", "HIGH", "SQL enjeksiyonu", "Parametreli sorgu (?/%s) kullan.")
        self.generic_visit(node)
    def visit_Assign(self, node):
        for t in node.targets:
            if isinstance(t, ast.Name) and SECRET_RE.search(t.id):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) > 3:
                    self.add(node, "B108", "HIGH", f"Hardcoded secret: {t.id}", ".env + secret manager kullan.")
        self.generic_visit(node)
    def visit_Assert(self, node):
        # test dosyalarindaki assertleri atla (pytest/kaynak kalite araci degiliz)
        if "test" in self.path.lower() or "conftest" in self.path.lower():
            self.generic_visit(node)
            return
        self.add(node, "B107", "LOW", "Assert uretim kodunda", "python -O assertleri siler. if + raise kullanin.")
        self.generic_visit(node)
    def visit_ExceptHandler(self, node):
        if node.type is None:
            self.add(node, "B112", "LOW", "Ciplak except", "Spesifik exception yakala.")
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.add(node, "B112", "MEDIUM", "Sessiz except:pass", "En azindan logla.")
        self.generic_visit(node)

def scan_file(path):
    with open(path, encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src, filename=path)
    sc = SecurityScanner(path); sc.visit(tree)
    # taint: kullanici girdisi -> tehlikeli fonksiyon akisi
    try:
        from scanner.taint import taint_flows
        for fl in taint_flows(tree):
            sc.findings.append({"file": path, "func": "<taint>", "line": fl["line"],
                "rule_id": "TAINT", "severity": "HIGH",
                "title": f"Tainted veri akisi -> {fl['sink']}",
                "detail": "Kullanici girdisi dogrudan tehlikeli fonksiyona ulasiyor. Validate + parametreli API kullanin."})
    except ImportError:
        pass
    return sc.findings
def get_src(path, s, e):
    with open(path, encoding="utf-8") as f:
        return "".join(f.readlines()[s-1:e])
def analyze_ai(code, reason):
    try:
        from dotenv import load_dotenv
        import google.generativeai as genai
        load_dotenv()
        key = os.getenv("AI_API_KEY")
        if not key:
            return "AI atlandi: AI_API_KEY yok."
        genai.configure(api_key=key)
        m = genai.GenerativeModel('gemini-1.5-flash')
        return m.generate_content(f"AppSec denetcisi gibi incele. Bulgu:{reason}. Format Severity/Issue/Fix. Kod:\n{code}").text
    except Exception as e:
        return f"AI hata: {e}"
def audit_file(path, use_ai=True):
    init_db()
    findings = scan_file(path)
    if not findings:
        print("Temiz: bulgu yok."); return findings
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda x: (order.get(x["severity"], 3), x["line"]))
    print(f"{path}: {len(findings)} bulgu")
    for f in findings:
        print(f"  [{f['severity']}] {f['rule_id']} {f['func']}:{f['line']} - {f['title']}")
    if use_ai:
        with open(path, encoding="utf-8") as s:
            tree = ast.parse(s.read())
        fnodes = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        seen = set()
        for f in findings:
            if f["severity"] != "HIGH" or f["func"] in seen or f["func"] not in fnodes:
                continue
            seen.add(f["func"])
            n = fnodes[f["func"]]
            raw = get_src(path, n.lineno, n.end_lineno)
            h, cached = get_cached_audit(raw)
            if cached:
                print(f"  cache: {f['func']}")
            else:
                print(f"  AI soruluyor: {f['func']}")
                save_audit_to_cache(h, f["func"], path, f["severity"], analyze_ai(raw, f['title']))
    return findings
def audit_path(target, use_ai=True, json_out=None, sarif_out=None, fail_on=None, html_out=None, auto_fix=False):
    import json as _json
    from pathlib import Path as _P
    t = _P(target)
    files = []
    if t.is_file():
        files = [str(t)]
    elif t.is_dir():
        skip = {"venv", ".venv", "__pycache__", ".git", "node_modules", ".tox"}
        for p in sorted(t.rglob("*.py")):
            if any(s in p.parts for s in skip):
                continue
            if p.name in {"auditor.py", "dashboard.py", "sample_vulnerable.py", "streamlit_app.py", "pre-commit-hook.py"}:
                pass
            files.append(str(p))
    else:
        print(f"Bulunamadi: {target}")
        return []
    all_f = []
    for fp in files:
        try:
            all_f.extend(audit_file(fp, use_ai=use_ai))
        except SyntaxError as e:
            print(f"SKIP syntax: {fp} ({e})")
        except Exception as e:
            print(f"SKIP hata: {fp} ({e})")
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    all_f.sort(key=lambda x: (order.get(x["severity"], 3), x["file"], x["line"]))
    try:
        from scanner.score import compute_score
        sc = compute_score(all_f)
        print(f"\nSECURITY SCORE: {sc.value}/100 ({sc.grade}) "
              f"(HIGH:{sc.high} MEDIUM:{sc.medium} LOW:{sc.low}) — {len(files)} files, {len(all_f)} findings")
    except Exception:
        print(f"\nOZET: {len(files)} dosya, {len(all_f)} bulgu "
              f"(HIGH:{sum(1 for x in all_f if x['severity']=='HIGH')} "
              f"MEDIUM:{sum(1 for x in all_f if x['severity']=='MEDIUM')} "
              f"LOW:{sum(1 for x in all_f if x['severity']=='LOW')})")
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            _json.dump(all_f, f, ensure_ascii=False, indent=2)
        print(f"JSON rapor: {json_out}")
    if sarif_out:
        from scanner.sarif import write_sarif
        write_sarif(all_f, sarif_out)
        print(f"SARIF rapor: {sarif_out}")
    if html_out:
        from scanner.report import write_html
        write_html(all_f, html_out, target=target)
        print(f"HTML report: {html_out}")
    if auto_fix and t.is_file():
        from scanner.autofix import apply_fixes
        with open(str(t), encoding="utf-8") as fh:
            src = fh.read()
        fixed_src, n = apply_fixes(src, [x for x in all_f if x["file"] == str(t)])
        if n:
            out = str(t) + ".fixed.py"
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(fixed_src)
            print(f"AUTO-FIX: {n} fixes -> {out} (review before using!)")
        else:
            print("AUTO-FIX: no safe fixes applicable.")
    if fail_on:
        rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        thr = rank.get(fail_on.upper(), 3)
        bad = [x for x in all_f if rank.get(x["severity"], 0) >= thr]
        if bad:
            print(f"FAIL: {fail_on}+ seviyede {len(bad)} bulgu -> cikis 1")
            sys.exit(1)
    return all_f
if __name__ == "__main__":
    import argparse as _ap
    ap = _ap.ArgumentParser(description="SafeCode AI — offline Python security scanner with auto-fix")
    ap.add_argument("target", nargs="?", default="sample_vulnerable.py")
    ap.add_argument("--no-ai", action="store_true")
    ap.add_argument("--json", default=None)
    ap.add_argument("--sarif", default=None, help="SARIF 2.1.0 output (GitHub Code Scanning)")
    ap.add_argument("--html", default=None, help="Self-contained HTML report")
    ap.add_argument("--fix", action="store_true", help="Write safe auto-fixes to <file>.fixed.py")
    ap.add_argument("--fail-on", default=None, help="HIGH/MEDIUM/LOW")
    a = ap.parse_args()
    audit_path(a.target, use_ai=not a.no_ai, json_out=a.json, sarif_out=a.sarif, fail_on=a.fail_on,
               html_out=a.html, auto_fix=a.fix)
