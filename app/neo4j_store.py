"""Optional Neo4j adapter. Credentials remain on the server."""
import os
from pathlib import Path

from neo4j import GraphDatabase, Query

from .detection import finding

QUERIES = Path(__file__).resolve().parent.parent / "queries"


def connection():
    uri, password = os.environ.get("NEO4J_URI"), os.environ.get("NEO4J_PASSWORD")
    if not uri or not password:
        raise ValueError("Configure NEO4J_URI and NEO4J_PASSWORD")
    return GraphDatabase.driver(uri, auth=(os.environ.get("NEO4J_USER", "neo4j"), password), connection_timeout=10)


def mirror(session, accounts, transfers):
    session.run("CREATE CONSTRAINT sentinel_account_id IF NOT EXISTS FOR (a:SentinelAccount) REQUIRE a.id IS UNIQUE").consume()

    def write(tx):
        tx.run("UNWIND $rows AS a MERGE (n:SentinelAccount {id:a.id}) SET n.name=a.name,n.country=a.country", rows=accounts).consume()
        tx.run("UNWIND $rows AS t MATCH (a:SentinelAccount {id:t.source}),(b:SentinelAccount {id:t.target}) "
               "MERGE (a)-[r:SENTINEL_TRANSFER {id:t.id}]->(b) "
               "SET r.amount_minor=t.amount_minor,r.timestamp=t.timestamp,r.currency=t.currency", rows=transfers).consume()
    session.execute_write(write)


def sync(accounts, transfers):
    with connection() as driver:
        with driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
            mirror(session, accounts, transfers)


def detect_native(accounts, transfers):
    by_id = {t["id"]: t for t in transfers}
    findings = {}
    with connection() as driver:
        with driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
            mirror(session, accounts, transfers)
            cycles = list(session.run(Query((QUERIES / "circular_flow.cypher").read_text(), timeout=30), ids=list(by_id)))
            fanins = list(session.run(Query((QUERIES / "fan_in.cypher").read_text(), timeout=30), ids=list(by_id)))
    # Keep one time-respecting path per first transfer and account route, matching
    # the local detector's evidence selection policy.
    seen_routes = set()
    for row in cycles[:10000]:
        edges = [by_id[identifier] for identifier in row["transfer_ids"]]
        key = (edges[0]["id"], tuple(t["source"] for t in edges))
        if key in seen_routes:
            continue
        seen_routes.add(key)
        item = finding("circular_flow", edges)
        findings[item["id"]] = item
    seen_targets = set()
    for row in fanins[:1000]:
        if row["target_id"] in seen_targets:
            continue
        seen_targets.add(row["target_id"])
        edges = sorted([by_id[identifier] for identifier in row["transfer_ids"]], key=lambda t: (t["timestamp"], t["id"]))
        item = finding("fan_in", edges)
        findings[item["id"]] = item
    return sorted(findings.values(), key=lambda f: (-f["score"], f["id"])), len(cycles) > 10000 or len(fanins) > 1000
