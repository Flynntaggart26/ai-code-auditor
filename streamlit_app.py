"""Streamlit Cloud entrypoint. Gercek uygulama dashboard.py'dadir."""
import runpy
from pathlib import Path
runpy.run_path(str(Path(__file__).parent / "dashboard.py"), run_name="__main__")
