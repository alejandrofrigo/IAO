from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / ".state" / "iao-knowledge.db"

ALLOWED = {".md", ".rst", ".txt"}
EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "__pycache__", ".state",
    "node_modules", "dist", "build", "site-packages",
}

CHUNK_SIZE = 1800
OVERLAP = 250


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS knowledge (
            id INTEGER PRIMARY KEY,
            source TEXT NOT NULL,
            source_hash TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            content TEXT NOT NULL,
            UNIQUE(source, source_hash, chunk_index)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS ingestion (
            source TEXT PRIMARY KEY,
            source_hash TEXT NOT NULL,
            chunks INTEGER NOT NULL,
            indexed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts
        USING fts5(content, source UNINDEXED, source_hash UNINDEXED)
    """)
    db.commit()
    return db


def split_text(text: str) -> list[str]:
    text = "\n".join(line.rstrip() for line in text.splitlines()).strip()
    if not text:
        return []
    chunks = []
    start = 0
    while start < len(text):
        end = min(start + CHUNK_SIZE, len(text))
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end == len(text):
            break
        start = end - OVERLAP
    return chunks


def document_paths():
    """Solo documentación del proyecto; excluye diagnósticos y muestras."""
    for current, dirs, files in os.walk(ROOT):
        dirs[:] = sorted(
            d for d in dirs
            if d not in EXCLUDED_DIRS
            and not d.startswith(".")
            and not d.endswith(".egg-info")
        )
        for filename in sorted(files):
            path = Path(current) / filename
            relative = path.relative_to(ROOT).as_posix()
            if path.suffix.lower() not in ALLOWED:
                continue
            if relative != "README.md" and not relative.startswith("docs/"):
                continue
            lowered = filename.lower()
            if lowered in {
                "injection-sample.txt",
                "license", "license.txt", "changelog.txt",
            }:
                continue
            if ".backup-" in lowered or ".bak" in lowered:
                continue
            yield path


def ingest() -> dict[str, Any]:
    db = connect()
    files_seen = 0
    files_indexed = 0
    chunks_added = 0

    try:
        paths = list(document_paths())
        allowed_sources = {
            path.relative_to(ROOT).as_posix() for path in paths
        }
        for path in paths:
            files_seen += 1
            try:
                raw = path.read_bytes()
                content = raw.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            digest = hashlib.sha256(raw).hexdigest()
            source = path.relative_to(ROOT).as_posix()
            chunks = split_text(content)

            previous = db.execute(
                "SELECT source_hash FROM ingestion WHERE source=?",
                (source,),
            ).fetchone()

            if previous and previous[0] == digest:
                continue

            db.execute("DELETE FROM knowledge WHERE source=?", (source,))
            db.execute("DELETE FROM knowledge_fts WHERE source=?", (source,))

            for index, chunk in enumerate(chunks):
                db.execute(
                    """INSERT INTO knowledge
                       (source, source_hash, chunk_index, content)
                       VALUES (?, ?, ?, ?)""",
                    (source, digest, index, chunk),
                )
                db.execute(
                    """INSERT INTO knowledge_fts
                       (content, source, source_hash)
                       VALUES (?, ?, ?)""",
                    (chunk, source, digest),
                )
                chunks_added += 1

            db.execute(
                """INSERT INTO ingestion(source, source_hash, chunks)
                   VALUES (?, ?, ?)
                   ON CONFLICT(source) DO UPDATE SET
                   source_hash=excluded.source_hash,
                   chunks=excluded.chunks,
                   indexed_at=CURRENT_TIMESTAMP""",
                (source, digest, len(chunks)),
            )
            files_indexed += 1

        # Retirar del índice fuentes que ya no pertenecen al corpus permitido.
        existing_sources = db.execute(
            "SELECT source FROM ingestion"
        ).fetchall()
        for (source,) in existing_sources:
            if source not in allowed_sources:
                db.execute("DELETE FROM knowledge WHERE source=?", (source,))
                db.execute("DELETE FROM knowledge_fts WHERE source=?", (source,))
                db.execute("DELETE FROM ingestion WHERE source=?", (source,))

        db.commit()
        total = db.execute("SELECT COUNT(*) FROM knowledge").fetchone()[0]
        sources = db.execute("SELECT COUNT(*) FROM ingestion").fetchone()[0]
        return {
            "files_examined": files_seen,
            "files_indexed_or_updated": files_indexed,
            "new_chunks": chunks_added,
            "indexed_sources": sources,
            "total_knowledge_chunks": total,
            "database": str(DB_PATH),
        }
    finally:
        db.close()


def search(query: str, limit: int = 8) -> list[dict[str, Any]]:
    """Busca fragmentos documentales y devuelve su procedencia verificable."""
    import re

    terms = list(dict.fromkeys(re.findall(r"[\\w-]{2,}", query.casefold())))
    if not terms:
        return []

    expression = " OR ".join(
        '"' + term.replace('"', '""') + '"' for term in terms[:16]
    )
    db = connect()
    try:
        rows = db.execute(
            """SELECT source, source_hash, content
               FROM knowledge_fts
               WHERE knowledge_fts MATCH ?
               ORDER BY bm25(knowledge_fts)
               LIMIT ?""",
            (expression, max(1, min(limit, 8))),
        ).fetchall()

        return [
            {"source": source, "sha256": digest, "content": content}
            for source, digest, content in rows
        ]
    finally:
        db.close()


def status() -> dict[str, Any]:
    db = connect()
    try:
        return {
            "database_exists": DB_PATH.is_file(),
            "sources": db.execute(
                "SELECT COUNT(*) FROM ingestion"
            ).fetchone()[0],
            "chunks": db.execute(
                "SELECT COUNT(*) FROM knowledge"
            ).fetchone()[0],
        }
    finally:
        db.close()
