#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from omega.knowledge_store import ingest, search, status


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Base persistente de conocimiento documental de IAO"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ingest", help="Indexar documentos reales del proyecto")
    sub.add_parser("status", help="Consultar el estado de la base")
    find = sub.add_parser("search", help="Buscar conocimiento indexado")
    find.add_argument("query")
    find.add_argument("--limit", type=int, default=8)
    args = parser.parse_args()

    if args.command == "ingest":
        result = ingest()
    elif args.command == "status":
        result = status()
    else:
        result = {"results": search(args.query, args.limit)}

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
