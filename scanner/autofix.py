"""Auto-fix engine: safe, rule-based code rewrites (no AI needed)."""
import ast
import re


FIXABLE = {
    "B105": "yaml.load(...) -> yaml.safe_load(...)",
    "B106": "hashlib.md5/sha1 -> hashlib.sha256",
    "B110": "verify=False -> verify=True",
    "B111": "debug=True -> debug=False",
    "B114": "tempfile.mktemp() -> tempfile.mkstemp()",
    "B115": "random.* -> secrets.*",
    "B117": "ssl._create_unverified_context() -> ssl.create_default_context()",
}

_SIMPLE_REPLACEMENTS = [
    # (pattern, replacement) applied line-wise, only on matching rule lines
    (re.compile(r"yaml\.load\("), "yaml.safe_load("),
    (re.compile(r"hashlib\.md5\("), "hashlib.sha256("),
    (re.compile(r"hashlib\.sha1\("), "hashlib.sha256("),
    (re.compile(r"verify\s*=\s*False"), "verify=True"),
    (re.compile(r"debug\s*=\s*True"), "debug=False"),
    (re.compile(r"tempfile\.mktemp\("), "tempfile.mkstemp("),
    (re.compile(r"ssl\._create_unverified_context\(\)"), "ssl.create_default_context()"),
]


def _fix_random_line(line: str) -> str:
    out = line
    if "import random" in line and "secrets" not in line:
        return line  # keep imports; add secrets import at top instead
    out = re.sub(r"\brandom\.randint\b", "secrets.randbelow", out)
    out = re.sub(r"\brandom\.choice\b", "secrets.choice", out)
    out = re.sub(r"\brandom\.random\b", "secrets.SystemRandom().random", out)
    out = re.sub(r"\brandom\.randrange\b", "secrets.randbelow", out)
    return out


def apply_fixes(source: str, findings: list[dict]) -> tuple[str, int]:
    """Apply safe fixes for fixable rules. Returns (new_source, fixed_count)."""
    lines = source.splitlines(keepends=True)
    fix_lines: dict[int, set[str]] = {}
    for f in findings:
        if f["rule_id"] in FIXABLE:
            fix_lines.setdefault(f["line"], set()).add(f["rule_id"])

    if not fix_lines:
        return source, 0

    fixed = 0
    needs_secrets_import = False
    for lineno, rules in fix_lines.items():
        idx = lineno - 1
        if not (0 <= idx < len(lines)):
            continue
        original = lines[idx]
        new = original
        for pat, repl in _SIMPLE_REPLACEMENTS:
            new = pat.sub(repl, new)
        if "B115" in rules:
            probe = _fix_random_line(new)
            if probe != new:
                needs_secrets_import = True
            new = probe
        if new != original:
            lines[idx] = new
            fixed += 1

    new_source = "".join(lines)
    if needs_secrets_import and "import secrets" not in new_source:
        new_source = "import secrets\n" + new_source
        # validate it still parses
    try:
        ast.parse(new_source)
    except SyntaxError:
        return source, 0
    return new_source, fixed
