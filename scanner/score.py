"""Security score: 0-100 grade from findings (like a report card)."""
from dataclasses import dataclass

WEIGHTS = {"HIGH": 15, "MEDIUM": 5, "LOW": 1}
GRADE_BANDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


@dataclass
class Score:
    value: int
    grade: str
    high: int
    medium: int
    low: int
    total: int


def compute_score(findings: list[dict]) -> Score:
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    penalty = high * WEIGHTS["HIGH"] + medium * WEIGHTS["MEDIUM"] + low * WEIGHTS["LOW"]
    value = max(0, 100 - penalty)
    grade = next(g for bound, g in GRADE_BANDS if value >= bound)
    return Score(value=value, grade=grade, high=high, medium=medium, low=low, total=len(findings))
