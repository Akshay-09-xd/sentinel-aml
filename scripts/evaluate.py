"""Reproducible synthetic detector smoke benchmark, deliberately small and labeled."""
import json

from app.demo import dataset
from app.detection import detect


def evaluate():
    _, transfers = dataset()
    expected = {("circular_flow", frozenset(t["id"] for t in transfers[:3])),
                ("fan_in", frozenset(t["id"] for t in transfers[3:8]))}
    findings, truncated = detect(transfers)
    actual = {(f["rule"], frozenset(f["transactions"])) for f in findings}
    matches = len(expected & actual)
    result = {"dataset": "fictional demo, seed 42", "transactions": len(transfers),
              "labeled_patterns": len(expected), "detected_patterns": len(actual),
              "exact_evidence_matches": matches,
              "precision": matches / len(actual) if actual else 0,
              "recall": matches / len(expected), "truncated": truncated,
              "scope": "Synthetic fixture check only. No real-world performance estimate."}
    print(json.dumps(result, indent=2))
    if actual != expected or truncated:
        raise SystemExit(1)


if __name__ == "__main__":
    evaluate()
