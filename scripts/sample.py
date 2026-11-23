"""Export the public, fictional JSON import fixture."""
import json
from pathlib import Path
from app.demo import dataset


if __name__ == "__main__":
    accounts, transfers = dataset()
    target = Path("sample-network.json")
    target.write_text(json.dumps({"accounts": accounts, "transactions": transfers}, indent=2), encoding="utf-8")
    print(f"Wrote {target.resolve()}")
