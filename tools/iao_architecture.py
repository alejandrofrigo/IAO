#!/usr/bin/env python3
"""Inspect the canonical IAO distributed architecture."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from omega.architecture import run_inspection


def main() -> int:
    report = run_inspection()
    summary = report["summary"]

    print("IAO — CANONICAL DISTRIBUTED ARCHITECTURE")
    print("=" * 48)
    print("ARCHITECTURE:", report["architecture_id"])
    print("MODE:", report["mode"])
    print("SUBSYSTEMS:", summary["subsystem_count"])
    print("IMPLEMENTED:", summary["IMPLEMENTED"])
    print("PARTIAL:", summary["PARTIAL"])
    print("MISSING:", summary["MISSING"])
    print("EXTERNAL_NODES_CONFIRMED:", summary["external_nodes_confirmed"])
    print("EXTERNAL_REPLICAS_CONFIRMED:", summary["external_replicas_confirmed"])
    print("GLOBAL_AUTONOMY_CONFIRMED:", summary["global_autonomy_confirmed"])

    for name, item in report["subsystems"].items():
        print(f"\n{name}: {item['status']}")
        if item["missing_contracts"]:
            print("  missing:", ", ".join(item["missing_contracts"]))
        if item["future_capabilities"]:
            print("  future:", ", ".join(item["future_capabilities"]))

    print("\nREPORT:", ROOT / ".state/architecture/architecture-status.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
