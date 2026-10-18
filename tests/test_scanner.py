import pytest
from auditor import scan_file

def ids(findings):
    return {(f["rule_id"], f["severity"]) for f in findings}

def test_core_rules():
    f = scan_file("sample_vulnerable.py")
    got = ids(f)
    assert ("B102", "HIGH") in got
    assert ("B104", "HIGH") in got
    assert ("B109", "HIGH") in got
    assert ("TAINT", "HIGH") in got
    assert ("B116", "HIGH") in got
    assert ("B117", "HIGH") in got

def test_clean_file(tmp_path):
    p = tmp_path / "clean.py"
    p.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert scan_file(str(p)) == []
