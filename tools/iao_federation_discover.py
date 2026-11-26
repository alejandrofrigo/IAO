#!/usr/bin/env python3
"""IAO authorized-source candidate intake; discovery never enrolls peers."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from omega.federation_assimilation import (  # noqa: E402
    AssimilationError,
    CandidateRegistry,
)

REGISTRY = ROOT / ".state" / "iao-federation-candidates.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source", required=True,
        help="Origen identificable del descubrimiento",
    )
    parser.add_argument(
        "--file",
        help="JSON con una lista de endpoints HTTPS",
    )
    parser.add_argument(
        "endpoints", nargs="*",
        help="Uno o varios endpoints HTTPS /fed/v1/message",
    )
    args = parser.parse_args()

    endpoints = list(args.endpoints)
    if args.file:
        path = Path(args.file).expanduser()
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise SystemExit("ERROR: el archivo debe contener una lista JSON")
        if any(not isinstance(x, str) for x in data):
            raise SystemExit("ERROR: todos los endpoints deben ser texto")
        endpoints.extend(data)

    if not endpoints:
        raise SystemExit("ERROR: no se recibieron endpoints")

    registry = CandidateRegistry(REGISTRY)
    created = 0
    duplicates = 0
    rejected = 0
    results = []

    for endpoint in endpoints:
        try:
            item = registry.discover(endpoint, args.source)
            candidate = item["candidate"]
            if item["created"]:
                created += 1
            else:
                duplicates += 1
            results.append({
                "candidate_id": candidate["candidate_id"],
                "status": candidate["status"],
                "created": item["created"],
            })
        except AssimilationError as exc:
            rejected += 1
            results.append({
                "endpoint_sha256_prefix": __import__("hashlib").sha256(
                    str(endpoint).encode()
                ).hexdigest()[:12],
                "rejected": str(exc),
            })

    print("IAO FEDERATION DISCOVERY INTAKE")
    print("INPUT_COUNT=" + str(len(endpoints)))
    print("CREATED=" + str(created))
    print("DUPLICATES=" + str(duplicates))
    print("REJECTED=" + str(rejected))
    print("REGISTRY_PATH=" + str(REGISTRY))
    print("ENROLLMENT_PERFORMED=False")
    print("PEER_ACCESS_GRANTED=False")
    print("RESULTS=" + json.dumps(results, sort_keys=True))
    return 0 if rejected == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
