from scanner.autofix import apply_fixes, FIXABLE
from scanner.score import compute_score
from scanner.report import to_html


def test_fixable_registry_nonempty():
    assert len(FIXABLE) >= 5


def test_autofix_yaml_and_hash():
    src = "import yaml\nh = hashlib.md5(pw.encode()).hexdigest()\nx = yaml.load(data)\n"
    findings = [
        {"file": "a.py", "func": "f", "line": 2, "rule_id": "B106", "severity": "MEDIUM", "title": "t", "detail": "d"},
        {"file": "a.py", "func": "f", "line": 3, "rule_id": "B105", "severity": "HIGH", "title": "t", "detail": "d"},
    ]
    new_src, n = apply_fixes(src, findings)
    assert n == 2
    assert "sha256" in new_src and "safe_load" in new_src
    import ast
    ast.parse(new_src)


def test_autofix_noop_when_nothing_fixable():
    src = "x = eval(user)\n"
    findings = [{"file": "a.py", "func": "f", "line": 1, "rule_id": "B101", "severity": "HIGH", "title": "t", "detail": "d"}]
    new_src, n = apply_fixes(src, findings)
    assert n == 0 and new_src == src


def test_score_grades():
    assert compute_score([]).value == 100
    assert compute_score([]).grade == "A"
    many_high = [{"severity": "HIGH"}] * 7
    s = compute_score(many_high)
    assert s.value == 0 and s.grade == "F"


def test_html_report_contains_score():
    findings = [{"file": "a.py", "func": "f", "line": 3, "rule_id": "B101", "severity": "HIGH", "title": "eval", "detail": "d"}]
    html = to_html(findings, target="a.py")
    assert "85/100" in html and "B101" in html and "a.py" in html
