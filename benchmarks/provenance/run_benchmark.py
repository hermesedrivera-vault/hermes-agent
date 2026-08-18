#!/usr/bin/env python3
"""
Provenance gate benchmark runner.

Replays labeled scenarios (real June failures + honest controls) through the
REAL send_message provenance gate and reports:
  - Detection rate  (true-positive rate on must_block=true scenarios)
  - False-positive rate (on must_block=false control scenarios)
  - Per-scenario pass/fail
  - An enforce-readiness verdict

This is what gates the shadow->enforce flip. Measure, don't assert.

Usage:
    python benchmarks/provenance/run_benchmark.py
Exit code 0 if enforce-ready (100% detection, 0% false positives), else 1.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from agent.provenance.store import EvidenceStore
from agent.provenance.gate import verify_send_message_provenance

SCENARIOS = os.path.join(os.path.dirname(__file__), "scenarios.json")


def _setup_receipts(store, session_id, receipts):
    """Mint the scenario's session receipts (search/web results)."""
    for i, r in enumerate(receipts):
        store.mint(
            claim_id=f"{r['tool']}.scenario.{i}",
            source_uri=f"{r['tool']}://scenario/{i}",
            content={"i": i},
            session_id=session_id,
            tool_name=r["tool"],
            result_count=int(r["result_count"]),
        )


def run():
    with open(SCENARIOS) as f:
        data = json.load(f)
    scenarios = data["scenarios"]

    results = []
    for sc in scenarios:
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
        store = EvidenceStore(db, os.urandom(32))
        session_id = f"bench_{sc['id']}"
        try:
            _setup_receipts(store, session_id, sc.get("receipts", []))
            args = {"message": sc["message"], "citations": sc.get("citations", [])}
            is_valid, violations = verify_send_message_provenance(args, session_id, store)
            blocked = not is_valid
            expected = sc["must_block"]
            correct = (blocked == expected)
            results.append({
                "id": sc["id"], "class": sc["class"],
                "must_block": expected, "blocked": blocked,
                "correct": correct, "violations": violations,
            })
        finally:
            store.close()
            os.unlink(db)

    positives = [r for r in results if r["must_block"]]
    controls = [r for r in results if not r["must_block"]]

    tp = sum(1 for r in positives if r["blocked"])
    fn = sum(1 for r in positives if not r["blocked"])
    fp = sum(1 for r in controls if r["blocked"])
    tn = sum(1 for r in controls if not r["blocked"])

    detection = tp / len(positives) if positives else 0.0
    fpr = fp / len(controls) if controls else 0.0

    print("=" * 68)
    print("PROVENANCE GATE BENCHMARK  (count-mismatch + false-absence)")
    print("=" * 68)
    print(f"\nScenarios: {len(results)}  ({len(positives)} must-block, {len(controls)} controls)\n")

    print(f"{'ID':34} {'class':20} {'exp':4} {'got':4} {'ok'}")
    print("-" * 68)
    for r in results:
        mark = "\u2713" if r["correct"] else "\u2717"
        print(f"{r['id']:34} {r['class']:20} "
              f"{'BLK' if r['must_block'] else 'ok':4} "
              f"{'BLK' if r['blocked'] else 'ok':4} {mark}")
        if not r["correct"]:
            for v in r["violations"]:
                print(f"    ! {v}")

    print("\n" + "-" * 68)
    print(f"  True positives (caught failures):   {tp}/{len(positives)}")
    print(f"  False negatives (MISSED failures):  {fn}")
    print(f"  False positives (blocked honest):   {fp}/{len(controls)}")
    print(f"  True negatives (allowed honest):    {tn}")
    print(f"\n  Detection rate (TPR):     {detection*100:5.1f}%   (NabaOS targets ~87-91%)")
    print(f"  False-positive rate:      {fpr*100:5.1f}%")

    enforce_ready = (fn == 0 and fp == 0)
    print("\n" + "=" * 68)
    if enforce_ready:
        print("VERDICT: ENFORCE-READY \u2014 0 missed failures, 0 false positives on this set.")
    else:
        print("VERDICT: HOLD \u2014 do NOT flip to enforce.")
        if fn:
            print(f"         {fn} real failure(s) would slip through.")
        if fp:
            print(f"         {fp} honest message(s) would be wrongly blocked.")
    print("=" * 68)
    return 0 if enforce_ready else 1


if __name__ == "__main__":
    sys.exit(run())
