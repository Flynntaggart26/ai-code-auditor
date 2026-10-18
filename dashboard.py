"""Dashboard - BYOK destekli ucretsiz panel."""
import tempfile, os, io, json, zipfile
from pathlib import Path
from datetime import datetime
import streamlit as st
import pandas as pd

from auditor import scan_file, analyze_ai, init_db, get_cached_audit, save_audit_to_cache
import ast

st.set_page_config(page_title="AI Code Auditor", page_icon="🛡️", layout="wide")
st.title("🛡️ AI-Powered Code Security Auditor")
st.caption("100% free • BYOK (kendi ücretsiz Gemini anahtarın) • $0 maliyet • TR/EN")

with st.sidebar:
    st.header("⚙️ Ayarlar")
    api_key = st.text_input("Gemini API Key (opsiyonel)", type="password", help="aistudio.google.com adresinden ücretsiz alın. Girmezsen sadece yerel tarama çalışır.")
    if api_key:
        os.environ["AI_API_KEY"] = api_key
    use_ai = st.toggle("HIGH bulgularda AI açıklaması", value=True)
    lang = st.radio("Rapor dili", ["TR", "EN"], horizontal=True)
    st.divider()
    st.markdown("[📄 Ücretsiz API anahtarı al](https://aistudio.google.com/)")
    st.markdown("[⭐ GitHub](https://github.com/)")

def show_metrics(findings):
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Toplam", len(findings))
    c2.metric("HIGH", sum(1 for f in findings if f["severity"] == "HIGH"))
    c3.metric("MEDIUM", sum(1 for f in findings if f["severity"] == "MEDIUM"))
    c4.metric("LOW", sum(1 for f in findings if f["severity"] == "LOW"))

def download_buttons(findings, tag):
    if not findings:
        return
    js = json.dumps(findings, ensure_ascii=False, indent=2)
    st.download_button("⬇ JSON indir", js, file_name=f"audit_{tag}.json", mime="application/json", key=f"j_{tag}")
    lines = [f"# Audit Report {tag} ({datetime.now():%Y-%m-%d %H:%M})", ""]
    for f in findings:
        lines.append(f"## [{f['severity']}] {f['rule_id']} {f['file']}:{f['line']} {f['func']}")
        lines.append(f"**{f['title']}** — {f['detail']}")
        lines.append("")
    st.download_button("⬇ Markdown indir", "\n".join(lines), file_name=f"audit_{tag}.md", key=f"m_{tag}")

def ai_section(code, findings, fname):
    st.subheader("AI Aciklamalari (sadece HIGH)")
    try:
        tree = ast.parse(code)
    except SyntaxError:
        tree = None
    if tree is None:
        st.info("AI aciklamasi icin gecerli kod gerekli.")
        return
    fnodes = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    init_db()
    done = set()
    for f in findings:
        if f["severity"] != "HIGH" or f["func"] in done or f["func"] not in fnodes:
            continue
        done.add(f["func"])
        n = fnodes[f["func"]]
        raw = "".join(code.splitlines(keepends=True)[n.lineno-1:n.end_lineno])
        h, cached = get_cached_audit(raw)
        if cached:
            report = cached
            st.caption(f"cache: {f['func']}")
        else:
            if not os.getenv("AI_API_KEY"):
                st.info(f"{f['func']}: AI icin sidebar'a ucretsiz API anahtari gir.")
                continue
            with st.spinner(f"Gemini inceliyor: {f['func']}"):
                extra = "Turkce, lise ogrencisi diliyle anlat. " if lang == "TR" else ""
                report = analyze_ai(raw, extra + f['title'])
                save_audit_to_cache(h, f["func"], fname, f["severity"], report)
        with st.expander(f"{f['func']}:{f['line']} - {f['title']}"):
            st.markdown(report)

tab1, tab2, tab3 = st.tabs(["📄 Dosya", "📦 ZIP Proje", "📊 AI Raporları"])

with tab1:
    up = st.file_uploader("Python dosyasi yukle (.py)", type=["py"], key="f1")
    code_input = st.text_area("veya kodu yapistir", height=200, key="c1")
    if st.button("Tara", type="primary", key="b1"):
        if not up and not code_input.strip():
            st.warning("Dosya yukle veya kod yapistir.")
            st.stop()
        if up:
            code = up.read().decode("utf-8", errors="ignore")
            fname = up.name
        else:
            code = code_input
            fname = "pasted.py"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as tmp:
            tmp.write(code)
            tpath = tmp.name
        try:
            try:
                findings = scan_file(tpath)
            except SyntaxError as e:
                st.error(f"Syntax hatasi: {e}.")
                st.stop()
            for f in findings:
                f["file"] = fname
            if not findings:
                st.success("Temiz: bulgu yok.")
            else:
                show_metrics(findings)
                sev = st.multiselect("Filtre", ["HIGH", "MEDIUM", "LOW"], default=["HIGH", "MEDIUM", "LOW"], key="s1")
                st.dataframe(pd.DataFrame(findings)[lambda d: d["severity"].isin(sev)], use_container_width=True)
                download_buttons(findings, "file")
                if use_ai:
                    ai_section(code, findings, fname)
        finally:
            os.unlink(tpath)

with tab2:
    zp = st.file_uploader("Proje ZIP'i yukle (.zip)", type=["zip"], key="f2")
    if st.button("Projeyi Tara", type="primary", key="b2"):
        if not zp:
            st.warning("ZIP yukle.")
            st.stop()
        data = zp.read()
        if len(data) > 10 * 1024 * 1024:
            st.error("ZIP 10MB'dan buyuk olamaz (ucretsiz hosting kotasi).")
            st.stop()
        all_f = []
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            names = [n for n in zf.namelist() if n.endswith(".py") and not n.startswith("__MACOSX") and "/venv/" not in n and "/.git/" not in n][:100]
            if not names:
                st.warning("ZIP'te .py bulunamadi.")
                st.stop()
            bar = st.progress(0, text="Taraniyor...")
            for i, name in enumerate(names):
                try:
                    code = zf.read(name).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as tmp:
                    tmp.write(code)
                    tp = tmp.name
                try:
                    try:
                        fs = scan_file(tp)
                    except SyntaxError:
                        continue
                    for f in fs:
                        f["file"] = name
                    all_f.extend(fs)
                finally:
                    os.unlink(tp)
                bar.progress((i + 1) / len(names), text=f"{i+1}/{len(names)} {name}")
            bar.empty()
        except zipfile.BadZipFile:
            st.error("Bozuk ZIP.")
            st.stop()
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        all_f.sort(key=lambda x: (order.get(x["severity"], 3), x["file"], x["line"]))
        st.write(f"**{len(names)} dosya, {len(all_f)} bulgu**")
        if not all_f:
            st.success("Temiz.")
        else:
            show_metrics(all_f)
            sev2 = st.multiselect("Filtre", ["HIGH", "MEDIUM", "LOW"], default=["HIGH", "MEDIUM", "LOW"], key="s2")
            st.dataframe(pd.DataFrame(all_f)[lambda d: d["severity"].isin(sev2)], use_container_width=True)
            download_buttons(all_f, "project")

with tab3:
    import sqlite3
    db = str(Path("audit_cache.db").absolute())
    if Path(db).exists():
        conn = sqlite3.connect(db)
        try:
            df = pd.read_sql_query("SELECT func_name, file_path, severity, timestamp FROM audits ORDER BY timestamp DESC LIMIT 100", conn)
            st.dataframe(df, use_container_width=True)
        except Exception as e:
            st.info(f"Kayit yok: {e}")
        conn.close()
    else:
        st.info("Henuz AI raporu yok.")
