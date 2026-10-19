"""SARIF 2.1.0 ciktisi — GitHub Code Scanning uyumlu."""
import json

LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

def to_sarif(findings, tool_name="ai-code-auditor"):
    rules = {}
    for f in findings:
        rid = f["rule_id"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f.get("detail", "")},
                "defaultConfiguration": {"level": LEVEL.get(f["severity"], "note")},
            }
    results = []
    for f in findings:
        results.append({
            "ruleId": f["rule_id"],
            "level": LEVEL.get(f["severity"], "note"),
            "message": {"text": f"{f['title']} — {f.get('detail', '')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"].replace("\\", "/")},
                    "region": {"startLine": f["line"]},
                }
            }],
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "rules": list(rules.values())}},
            "results": results,
        }],
    }

def write_sarif(findings, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_sarif(findings), fh, ensure_ascii=False, indent=2)
