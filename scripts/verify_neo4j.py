"""Live adapter parity check. Set connection variables for a dedicated test database."""
import json

from app.demo import dataset
from app.detection import detect
from app.neo4j_store import detect_native


if __name__ == "__main__":
    accounts, transfers = dataset()
    expected, _ = detect(transfers)
    actual, truncated = detect_native(accounts, transfers)
    expected_ids = {item["id"] for item in expected}
    actual_ids = {item["id"] for item in actual}
    if actual_ids != expected_ids or truncated:
        raise SystemExit("Neo4j evidence differs from the seeded local fixture")
    print(json.dumps({"native_neo4j": "passed", "exact_evidence_matches": len(actual),
                      "rules": sorted(item["rule"] for item in actual)}, indent=2))
