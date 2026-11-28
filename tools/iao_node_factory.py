#!/usr/bin/env python3
"""IAO node workspace factory. It does not create accounts or deploy servers."""
from __future__ import annotations

import argparse
import json

from omega.node_factory import create_nodes, inspect_nodes


def main() -> int:
    parser = argparse.ArgumentParser(description="Create isolated IAO node workspaces")
    parser.add_argument("action", choices=("create", "status"))
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--role", choices=("worker", "observer", "indexer"), default="worker")
    parser.add_argument("--output", default=".state/node-factory")
    args = parser.parse_args()

    if args.action == "create":
        result = create_nodes(args.count, output_dir=args.output, role=args.role)
    else:
        result = inspect_nodes(args.output)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
