"""Deterministic graph evidence and reproducible unsupervised account ranking."""
from collections import defaultdict
from datetime import datetime, timedelta
import hashlib
import json

import networkx as nx
from sklearn.ensemble import IsolationForest


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def fingerprint(rule, ids):
    payload = json.dumps([rule, sorted(ids)], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()[:20]


def finding(rule, edges):
    accounts = sorted({t[field] for t in edges for field in ("source", "target")})
    circular = rule == "circular_flow"
    reason = (f"{len(accounts)} accounts returned funds to the origin within 24 hours; "
              "each leg retained at least 80% of the largest transfer." if circular else
              f"{len({t['source'] for t in edges})} distinct accounts sent at least $20,000 "
              f"to {edges[0]['target']} within a rolling 24-hour window.")
    return {"id": fingerprint(rule, [t["id"] for t in edges]), "rule": rule,
            "title": "Circular money flow" if circular else "Concentrated incoming transfers",
            "score": 94 if circular else 82, "reason": reason,
            "transactions": [t["id"] for t in edges], "accounts": accounts,
            "amount_minor": sum(t["amount_minor"] for t in edges)}


def detect(transactions):
    """Cycles follow chronological edges within 24h. Fan-in uses rolling 24h windows.

    Bounded 2–5 hop cycles and at most 5,000 transactions keep a local review run
    predictable. Monetary values are integer minor units throughout.
    """
    ordered = sorted(transactions, key=lambda t: (t["timestamp"], t["id"]))
    graph = nx.DiGraph()
    outgoing = defaultdict(list)
    incoming = defaultdict(list)
    for tx in ordered:
        if tx["amount_minor"] >= 100000:
            graph.add_edge(tx["source"], tx["target"])
        outgoing[tx["source"]].append(tx)
        incoming[tx["target"]].append(tx)
    findings = {}

    def add(rule, edges):
        item = finding(rule, edges)
        findings[item["id"]] = item

    # Enumerate account cycles first, then choose actual time-respecting transfers.
    # Enumeration is bounded to avoid pathological graphs exhausting the worker.
    inspected = 0
    steps = 0
    truncated = False

    def continue_route(route, edges, start):
        nonlocal steps, truncated
        if len(edges) == len(route):
            return edges
        index = len(edges)
        target = route[(index + 1) % len(route)]
        for candidate in outgoing[route[index]]:
            steps += 1
            if steps > 100000:
                truncated = True
                return None
            amounts = [t["amount_minor"] for t in edges] + [candidate["amount_minor"]]
            if (candidate["target"] == target and min(amounts) >= max(amounts) * 0.8
                    and min(amounts) >= 100000
                    and timestamp(edges[-1]["timestamp"]) < timestamp(candidate["timestamp"])
                    <= start + timedelta(hours=24)):
                result = continue_route(route, edges + [candidate], start)
                if result:
                    return result
        return None

    for cycle in nx.simple_cycles(graph, length_bound=5):
        inspected += 1
        if inspected > 10000:
            truncated = True
            break
        if len(cycle) < 2:
            continue
        for offset in range(len(cycle)):
            route = cycle[offset:] + cycle[:offset]
            for first in outgoing[route[0]]:
                steps += 1
                if steps > 100000:
                    truncated = True
                    break
                if first["target"] != route[1]:
                    continue
                start = timestamp(first["timestamp"])
                edges = continue_route(route, [first], start)
                if edges:
                    add("circular_flow", edges)
            if truncated:
                break
        if truncated:
            break

    for target, transfers in incoming.items():
        # Keep the maximal qualifying window per recipient to reduce duplicate alerts.
        windows = []
        for end in transfers:
            end_time = timestamp(end["timestamp"])
            window = [t for t in transfers if end_time - timedelta(hours=24)
                      <= timestamp(t["timestamp"]) <= end_time]
            sources = {t["source"] for t in window}
            if len(sources) >= 4 and sum(t["amount_minor"] for t in window) >= 2000000:
                windows.append(window)
        if windows:
            best = max(windows, key=lambda w: (len({t["source"] for t in w}), sum(t["amount_minor"] for t in w)))
            add("fan_in", best)
    return sorted(findings.values(), key=lambda f: (-f["score"], f["id"])), truncated


def anomaly_scores(accounts, transactions):
    """Isolation Forest ranks account behavior. Scores are relative, not probabilities."""
    rows = []
    for account in accounts:
        incoming = [t for t in transactions if t["target"] == account["id"]]
        outgoing = [t for t in transactions if t["source"] == account["id"]]
        in_total = sum(t["amount_minor"] for t in incoming)
        out_total = sum(t["amount_minor"] for t in outgoing)
        rows.append([len(incoming), len(outgoing), len({t["source"] for t in incoming}),
                     len({t["target"] for t in outgoing}), in_total, out_total,
                     abs(in_total - out_total)])
    if len(rows) < 8:
        return {a["id"]: None for a in accounts}
    model = IsolationForest(n_estimators=150, random_state=42, contamination="auto")
    model.fit(rows)
    raw = -model.score_samples(rows)
    low, high = float(min(raw)), float(max(raw))
    return {a["id"]: round(100 * (float(score) - low) / (high - low)) if high > low else 0
            for a, score in zip(accounts, raw)}
