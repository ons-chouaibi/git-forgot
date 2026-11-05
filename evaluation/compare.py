#!/usr/bin/env python3
"""Score detector output against the expected results. Usage: compare.py EXPECTED OUTPUT. Exit: 0 pass, 1 fail."""
import json
import sys

TYPES = {"aws": "aws_access_key", "github": "github_classic_token", "privkey": "private_key"}


def read_jsonl(path):
    with open(path, "rb") as handle:
        data = handle.read()
    text = data.decode("utf-16" if data[:2] == b"\xff\xfe" else "utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def score(entry, record):
    if entry["expected"] == "none":
        return ("absent", True) if record is None else ("reported", False)
    if record is None:
        return "missed", False
    ok = record["reachability"] == entry["expected"] and record["type"] == TYPES[entry["type"]]
    if "pushed" in entry:
        ok = ok and record["pushed"] == entry["pushed"]
    return record["reachability"], ok


def main():
    expected = read_jsonl(sys.argv[1])
    found = {r["fingerprint"].removeprefix("sha256:"): r for r in read_jsonl(sys.argv[2])}

    failures = 0
    print("| Scenario | Expected | Got | Result |")
    print("|---|---|---|---|")
    for entry in expected:
        got, ok = score(entry, found.get(entry["fingerprint"]))
        failures += not ok
        print(f"| {entry['scenario']} | {entry['expected']} | {got} | {'ok' if ok else 'FAIL'} |")

    known = {entry["fingerprint"] for entry in expected}
    extra = [r for fingerprint, r in found.items() if fingerprint not in known]
    print(f"\n{len(expected)} expected, {failures} wrong, {len(extra)} false positives")
    return 1 if failures or extra else 0


if __name__ == "__main__":
    sys.exit(main())
