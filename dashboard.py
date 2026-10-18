"""Dashboard - BYOK destekli ucretsiz panel."""
import tempfile, os
from pathlib import Path
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

tab1, tab2 = st.tabs(["📤 Tara", "📊 Son AI Raporları"])

with tab1:
    up = st.file_uploader("Python dosyasi yukle (.py)", type=["py"])
    code_input = st.text_area("veya kodu yapistir", height=200)
    if st.button("Tara", type="primary"):
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
                st.error(f"Syntax hatasi: {e}. Gecerli Python kodu yukleyin.")
                st.stop()
            for f in findings:
                f["file"] = fname
            if not findings:
                st.success("Temiz: bulgu yok.")
            else:
                c1, c2, c3 = st.columns(3)
                c1.metric("HIGH", sum(1 for f in findings if f["severity"] == "HIGH"))
                c2.metric("MEDIUM", sum(1 for f in findings if f["severity"] == "MEDIUM"))
                c3.metric("LOW", sum(1 for f in findings if f["severity"] == "LOW"))
                sev = st.multiselect("Filtre", ["HIGH", "MEDIUM", "LOW"], default=["HIGH", "MEDIUM", "LOW"])
                df = pd.DataFrame(findings)
                st.dataframe(df[df["severity"].isin(sev)], use_container_width=True)
                if use_ai:
                    st.subheader("AI Aciklamalari (sadece HIGH)")
                    try:
                        tree = ast.parse(code)
                    except SyntaxError:
                        tree = None
                    if tree is None:
                        st.info("AI aciklamasi icin gecerli kod gerekli.")
                    else:
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
        finally:
            os.unlink(tpath)
with tab2:
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
