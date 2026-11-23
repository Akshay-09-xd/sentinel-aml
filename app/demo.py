"""Entirely fictional demonstration data, including ordinary background activity."""
from datetime import datetime, timedelta, timezone
import random


def dataset():
    names = ["Northstar Trading", "Harbor Holdings", "Meridian Partners", "Atlas Exchange",
             "Cedar Services", "Orion Imports", "Summit Logistics", "Vale Consulting",
             "Juniper Studio", "Bluebird Market", "Riverbend Cafe", "Elm Design",
             "Copper Books", "Willow Bakery", "Pine Software", "Meadow Supplies",
             "Brook Fitness", "Luna Florist", "Ash Hardware", "Maple Print"]
    accounts = [{"id": f"ACC-{i + 1:03}", "name": name,
                 "country": ["US", "GB", "SG", "AE"][i % 4], "type": "Business"}
                for i, name in enumerate(names)]
    transactions = []
    base = datetime(2026, 11, 20, 8, tzinfo=timezone.utc)

    def transfer(source, target, dollars, hours):
        transactions.append({"id": f"TX-{len(transactions) + 1:04}",
                             "source": accounts[source]["id"], "target": accounts[target]["id"],
                             "amount_minor": dollars * 100, "currency": "USD",
                             "timestamp": (base + timedelta(hours=hours)).isoformat()})

    transfer(0, 1, 48000, 1)
    transfer(1, 2, 46500, 2)
    transfer(2, 0, 45200, 3)
    for i, amount in zip(range(4, 9), [6800, 7200, 5900, 8100, 6400]):
        transfer(i, 3, amount, 4 + i)
    rng = random.Random(42)
    for i in range(70):
        source, target = rng.sample(range(9, 20), 2)
        transfer(source, target, rng.randint(30, 850), 24 + i * 5)
    return accounts, transactions
