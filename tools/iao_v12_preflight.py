#!/usr/bin/env python3
"""IAO V12: validación estática de candidatos sin ejecución."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 2 * 1024 * 1024


def inspect_candidate(raw_path: str) -> dict:
    result = {
        "path": raw_path,
        "status": "REJECTED",
        "checks": {},
        "warnings": [],
    }

    try:
        supplied = Path(raw_path)
        candidate = supplied if supplied.is_absolute() else ROOT / supplied

        if candidate.is_symlink():
            raise ValueError("SYMLINK_NOT_ALLOWED")

        path = candidate.resolve(strict=True)
        path.relative_to(ROOT)

        if not path.is_file():
            raise ValueError("NOT_A_REGULAR_FILE")

        data = path.read_bytes()

        if not data or len(data) > MAX_BYTES:
            raise ValueError("INVALID_FILE_SIZE")

        source = data.decode("utf-8")
        tree = ast.parse(source, filename=str(path))
        compile(tree, str(path), "exec", dont_inherit=True)

        imports = []
        functions = []
        classes = []
        warnings = []

        dangerous = {
            "eval", "exec", "__import__", "compile",
        }

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imports.append(ast.unparse(node))

            elif isinstance(node, (ast.FunctionDef,
                                   ast.AsyncFunctionDef)):
                functions.append(node.name)

            elif isinstance(node, ast.ClassDef):
                classes.append(node.name)

            elif isinstance(node, ast.Call):
                name = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else ""
                )
                if name in dangerous:
                    warnings.append(
                        f"DYNAMIC_EXECUTION_CALL:{name}:"
                        f"line={node.lineno}"
                    )
                elif name in {"system", "popen", "Popen"}:
                    warnings.append(
                        f"PROCESS_EXECUTION_CALL:{name}:"
                        f"line={node.lineno}"
                    )

        result.update({
            "status": "PASS_STATIC_WITH_WARNINGS"
            if warnings else "PASS_STATIC",
            "resolved_path": str(path),
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "lines": len(source.splitlines()),
            "ast_nodes": sum(1 for _ in ast.walk(tree)),
            "imports": sorted(set(imports)),
            "functions": functions,
            "classes": classes,
            "warnings": warnings,
            "checks": {
                "inside_repository": True,
                "regular_file": True,
                "utf8": True,
                "size_limit": True,
                "ast_parse": True,
                "python_compile": True,
                "candidate_executed": False,
            },
        })

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["checks"]["candidate_executed"] = False

    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "paths",
        nargs="*",
        default=["omega/federation_proposal_validator.py"],
    )
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )
    output = ROOT / ".state/operator-patches" / (
        f"v12-preflight-{stamp}"
    )
    output.mkdir(parents=True, exist_ok=False)

    results = [inspect_candidate(p) for p in args.paths]
    passed = sum(
        r["status"].startswith("PASS_STATIC")
        for r in results
    )

    report = {
        "system": "IAO",
        "component": "V12_PREFLIGHT",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_policy": "STATIC_ONLY",
        "candidates": len(results),
        "passed": passed,
        "rejected": len(results) - passed,
        "results": results,
    }

    json_path = output / "report.json"
    txt_path = output / "report.txt"

    json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    lines = [
        "IAO V12 PREFLIGHT",
        f"Fecha: {report['timestamp']}",
        f"Candidatos: {len(results)}",
        f"Aprobados estáticamente: {passed}",
        f"Rechazados: {len(results) - passed}",
        "Los candidatos NO fueron ejecutados.",
        "",
    ]

    for item in results:
        lines.extend([
            f"Archivo: {item['path']}",
            f"Estado: {item['status']}",
            f"SHA256: {item.get('sha256', 'N/A')}",
            f"Funciones: {len(item.get('functions', []))}",
            f"Clases: {len(item.get('classes', []))}",
            f"Advertencias: {item.get('warnings', [])}",
            f"Error: {item.get('error', 'ninguno')}",
            "",
        ])

    txt_path.write_text(
        "\n".join(lines), encoding="utf-8"
    )

    print("\n".join(lines))
    print(f"JSON: {json_path.relative_to(ROOT)}")
    print(f"TXT: {txt_path.relative_to(ROOT)}")

    return 0 if passed == len(results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
