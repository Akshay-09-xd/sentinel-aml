"""Behavior checks for evidence, privacy, idempotency, and decision consistency."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

_temporary = tempfile.TemporaryDirectory()
os.environ["SENTINEL_DATA_DIR"] = _temporary.name

from fastapi.testclient import TestClient
from app.main import app, database
from app.demo import dataset
from app.detection import detect, anomaly_scores


class InvestigationWorkflow(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app, headers={"X-Sentinel-Request": "1"})
        with database() as db:
            for table in ("notes", "cases", "audit", "transfers", "accounts", "sessions", "users", "attempts"):
                db.execute(f"DELETE FROM {table}")
        response = self.client.post("/api/setup", json={"name": "analyst", "password": "a-test-password-123"})
        self.assertEqual(response.status_code, 200)

    def seed(self):
        response = self.client.post("/api/demo")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["new_cases"], 2)
        return self.client.get("/api/workspace").json()

    def test_case_lifecycle_and_privacy(self):
        workspace = self.seed()
        self.assertEqual({c["rule"] for c in workspace["cases"]}, {"circular_flow", "fan_in"})
        self.assertEqual(self.client.post("/api/detect").json()["new_cases"], 0)
        case = workspace["cases"][0]
        endpoint = f"/api/cases/{case['id']}"
        note = "Ask the relationship manager about the underlying invoices."
        self.assertEqual(self.client.post(endpoint + "/notes", json={"text": note}).status_code, 200)
        with database() as db:
            stored = db.execute("SELECT ciphertext FROM notes").fetchone()[0]
            self.assertNotIn(note, stored)
        detail = self.client.get(endpoint).json()
        self.assertEqual(detail["notes"][0]["text"], note)
        self.assertEqual(len(detail["evidence"]), len(case["transactions"]))
        body = {"status": "Closed", "assignee": "analyst", "version": 1}
        self.assertEqual(self.client.patch(endpoint, json=body).status_code, 422)
        body["rationale"] = "Reviewed supporting evidence and documented outcome."
        self.assertEqual(self.client.patch(endpoint, json=body).status_code, 200)
        self.assertEqual(self.client.patch(endpoint, json=body).status_code, 409)
        self.client.post("/api/detect")
        self.assertEqual(self.client.get(endpoint).json()["status"], "Closed")
        self.assertTrue(self.client.get("/api/audit").json()["valid"])
        with database() as db:
            db.execute("UPDATE audit SET action='altered' WHERE id=(SELECT min(id) FROM audit)")
        self.assertFalse(self.client.get("/api/audit").json()["valid"])

    def test_authentication_and_csrf(self):
        outsider = TestClient(app)
        self.assertEqual(outsider.get("/api/workspace").status_code, 401)
        self.assertEqual(outsider.post("/api/demo").status_code, 403)
        self.assertEqual(self.client.post("/api/setup", json={"name": "other", "password": "another-password"}).status_code, 409)
        self.client.post("/api/logout")
        self.assertEqual(self.client.get("/api/workspace").status_code, 401)
        for _ in range(10):
            self.assertEqual(self.client.post("/api/login", json={"name": "analyst", "password": "wrong-password"}).status_code, 401)
        self.assertEqual(self.client.post("/api/login", json={"name": "analyst", "password": "a-test-password-123"}).status_code, 429)

    def test_atomic_import_and_validation(self):
        accounts, transfers = dataset()
        transfers[0]["target"] = "missing"
        self.assertEqual(self.client.post("/api/import", json={"accounts": accounts, "transactions": transfers}).status_code, 422)
        self.assertEqual(self.client.get("/api/workspace").json()["accounts"], [])
        accounts, transfers = dataset()
        body = {"accounts": accounts, "transactions": transfers}
        self.assertEqual(self.client.post("/api/import", json=body).status_code, 200)
        self.assertEqual(self.client.post("/api/import", json=body).status_code, 200)
        transfers[0]["amount_minor"] += 1
        self.assertEqual(self.client.post("/api/import", json=body).status_code, 409)
        transfers[0]["timestamp"] = "2026-11-20T12:00:00"
        self.assertEqual(self.client.post("/api/import", json=body).status_code, 422)
        transfers[0]["timestamp"] = "2026-11-20T12:00:00Z"
        transfers[0]["amount_minor"] = 1.23
        self.assertEqual(self.client.post("/api/import", json=body).status_code, 422)

    def test_detection_temporal_constraints(self):
        _, transfers = dataset()
        cycle = transfers[:3]
        self.assertEqual(len(detect(cycle)[0]), 1)
        cycle[2]["timestamp"] = "2026-12-01T12:00:00+00:00"
        self.assertEqual(detect(cycle)[0], [])
        _, transfers = dataset()
        fanin = transfers[3:8]
        self.assertEqual(len(detect(fanin)[0]), 1)
        self.assertEqual(detect(fanin[:3])[0], [])
        for item in fanin:
            item["amount_minor"] = 10
        self.assertEqual(detect(fanin)[0], [])

    def test_cycle_search_tries_alternate_evidence(self):
        def transfer(identifier, source, target, amount, hour):
            return {"id": identifier, "source": source, "target": target,
                    "amount_minor": amount * 100, "currency": "USD",
                    "timestamp": f"2026-11-20T{hour:02}:00:00+00:00"}
        transfers = [transfer("one", "A", "B", 1200, 1),
                     transfer("too-small", "B", "C", 1000, 2),
                     transfer("valid", "B", "C", 1200, 3),
                     transfer("return", "C", "A", 1400, 4)]
        findings, truncated = detect(transfers)
        self.assertFalse(truncated)
        self.assertEqual(len(findings), 1)
        self.assertEqual(set(findings[0]["transactions"]), {"one", "valid", "return"})

    def test_anomaly_context_is_deterministic_and_relative(self):
        accounts, transfers = dataset()
        scores = anomaly_scores(accounts, transfers)
        self.assertEqual(scores, anomaly_scores(accounts, transfers))
        self.assertEqual(min(scores.values()), 0)
        self.assertEqual(max(scores.values()), 100)
        self.assertEqual(scores["ACC-004"], 100)
        self.assertTrue(all(value is None for value in anomaly_scores(accounts[:3], transfers).values()))

    def test_native_backend_routes_detection(self):
        accounts, transfers = dataset()
        self.client.post("/api/import", json={"accounts": accounts, "transactions": transfers})
        expected = detect(transfers)
        with patch.dict(os.environ, {"SENTINEL_GRAPH_BACKEND": "neo4j"}):
            with patch("app.neo4j_store.detect_native", return_value=expected) as native:
                response = self.client.post("/api/detect")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["new_cases"], 2)
                native.assert_called_once()

    def test_optional_integrations_fail_clearly(self):
        case = self.seed()["cases"][0]
        with patch.dict(os.environ, {"OLLAMA_MODEL": "", "NEO4J_URI": ""}):
            self.assertEqual(self.client.post(f"/api/cases/{case['id']}/draft").status_code, 503)
            self.assertEqual(self.client.post("/api/neo4j/sync").status_code, 503)
        with patch.dict(os.environ, {"OLLAMA_MODEL": "test-model"}):
            with patch("app.main.httpx.post") as mocked:
                mocked.return_value.json.return_value = {"response": "Review TX-0001 and request supporting documentation."}
                result = self.client.post(f"/api/cases/{case['id']}/draft")
                self.assertEqual(result.status_code, 200)
                self.assertTrue(result.json()["requires_review"])
                prompt = mocked.call_args.kwargs["json"]["prompt"]
                self.assertNotIn("Northstar Trading", prompt)


if __name__ == "__main__":
    unittest.main()
