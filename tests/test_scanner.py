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

def test_sarif():
    from scanner.sarif import to_sarif
    findings = [
        {"file": "a.py", "func": "f", "line": 3, "rule_id": "B101", "severity": "HIGH", "title": "x", "detail": "y"},
        {"file": "a.py", "func": "g", "line": 5, "rule_id": "B112", "severity": "LOW", "title": "z", "detail": ""},
    ]
    s = to_sarif(findings)
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert len(run["results"]) == 2
    assert run["results"][0]["level"] == "error"
    assert run["results"][1]["level"] == "note"
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 3


def test_clean_file(tmp_path):
    p = tmp_path / "clean.py"
    p.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert scan_file(str(p)) == []
