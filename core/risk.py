from typing import List, Dict
from core.context import Finding

SEV_SCORE = {
    "Info": 0.0,
    "Low": 2.5,
    "Medium": 5.0,
    "High": 7.5,
    "Critical": 9.5,
}

def score_finding(f: Finding) -> float:
    return float(SEV_SCORE.get(f.severity, 0.0))

def overall_score(findings: List[Finding]) -> Dict[str, float]:
    if not findings:
        return {"overall": 10.0, "max": 0.0, "avg": 0.0}
    scores = [score_finding(f) for f in findings]
    mx = max(scores)
    avg = sum(scores) / len(scores)
    # overall: 10 - avg(weighted); clamp
    ov = max(0.0, min(10.0, 10.0 - avg))
    return {"overall": round(ov, 2), "max": round(mx, 2), "avg": round(avg, 2)}
