#!/usr/bin/env python3
"""IAO continuous information flow: HTTPS polling, durable inbox/outbox."""
import argparse
import hashlib
import ipaddress
import json
import os
import socket
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

HOME = Path.home()
CONFIG = HOME / ".config/iao/flow-config.json"
DB = HOME / ".local/share/iao/information-flow.sqlite3"
MAX_BYTES = 1_500_000
UA = "IAO-Information-Flow/1.0"


def now():
    return datetime.now(timezone.utc).isoformat()


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts):
        super().__init__()
        self.allowed_hosts = set(allowed_hosts)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Revalidate every redirect: HTTPS, explicit host allowlist,
        # public DNS addresses and port 443 only.
        validate_url(newurl, self.allowed_hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_url(url, allowed_hosts):
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password:
        raise ValueError("HTTPS_REQUIRED")
    host = p.hostname.lower().rstrip(".")
    if host not in {h.lower().rstrip(".") for h in allowed_hosts}:
        raise ValueError("HOST_NOT_ALLOWLISTED")
    if p.port not in (None, 443):
        raise ValueError("PORT_NOT_ALLOWED")
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise ValueError("DNS_UNAVAILABLE") from None
    ips = {x[4][0] for x in addresses}
    if not ips:
        raise ValueError("DNS_EMPTY")
    for value in ips:
        ip = ipaddress.ip_address(value)
        if not ip.is_global:
            raise ValueError("NON_PUBLIC_ADDRESS_BLOCKED")
    return host


def fetch(url, allowed_hosts):
    validate_url(url, allowed_hosts)
    req = urllib.request.Request(
        url, headers={"User-Agent": UA, "Accept": "application/rss+xml, "
                      "application/atom+xml, application/xml, text/xml"}
    )
    try:
        with urllib.request.build_opener(SafeRedirect(allowed_hosts)).open(req, timeout=15) as response:
            if response.status != 200:
                raise ValueError("HTTP_STATUS_" + str(response.status))
            data = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as e:
        raise ValueError("HTTP_STATUS_" + str(e.code)) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ValueError("SOURCE_UNREACHABLE") from None
    if len(data) > MAX_BYTES:
        raise ValueError("SOURCE_TOO_LARGE")
    return data


def local_name(tag):
    return tag.rsplit("}", 1)[-1].lower()


def parse_feed(data, source_id, limit):
    root = ET.fromstring(data)
    entries = []
    for node in root.iter():
        if local_name(node.tag) not in ("item", "entry"):
            continue
        fields = {}
        for child in list(node):
            name = local_name(child.tag)
            value = "".join(child.itertext()).strip()
            if name == "link" and not value:
                value = child.attrib.get("href", "")
            if name not in fields and value:
                fields[name] = value
        title = fields.get("title", "").strip()
        link = fields.get("link", "").strip()
        summary = (fields.get("description") or fields.get("summary")
                   or fields.get("content") or "").strip()
        if not title and not link:
            continue
        summary = summary[:4000]
        identity = hashlib.sha256(
            (source_id + "\n" + link + "\n" + title).encode("utf-8")
        ).hexdigest()
        entries.append({
            "id": identity, "source": source_id, "title": title[:500],
            "link": link[:2000], "summary": summary, "received_at": now()
        })
        if len(entries) >= limit:
            break
    return entries


def open_db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB, timeout=10)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
      CREATE TABLE IF NOT EXISTS inbox (
        id TEXT PRIMARY KEY, source TEXT NOT NULL, title TEXT NOT NULL,
        link TEXT NOT NULL, summary TEXT NOT NULL, received_at TEXT NOT NULL
      )
    """)
    con.execute("""
      CREATE TABLE IF NOT EXISTS outbox (
        id TEXT PRIMARY KEY, payload TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
        sent_at TEXT
      )
    """)
    con.execute("""
      CREATE TABLE IF NOT EXISTS source_status (
        source TEXT PRIMARY KEY, checked_at TEXT NOT NULL,
        status TEXT NOT NULL, items_new INTEGER NOT NULL DEFAULT 0
      )
    """)
    con.commit()
    return con


def poll(con, config):
    sources = config.get("sources", [])
    hosts = {
        urllib.parse.urlsplit(s.get("url", "")).hostname.lower()
        for s in sources if urllib.parse.urlsplit(s.get("url", "")).hostname
    }
    good = 0
    for source in sources:
        sid, url = source.get("id", ""), source.get("url", "")
        try:
            if not sid or not url:
                raise ValueError("SOURCE_CONFIG_INVALID")
            data = fetch(url, hosts)
            items = parse_feed(
                data, sid, max(1, min(100, int(config.get("max_items_per_source", 30))))
            )
            added = 0
            for item in items:
                cur = con.execute(
                    "INSERT OR IGNORE INTO inbox VALUES (?,?,?,?,?,?)",
                    (item["id"], item["source"], item["title"], item["link"],
                     item["summary"], item["received_at"])
                )
                if cur.rowcount:
                    con.execute(
                        "INSERT OR IGNORE INTO outbox (id,payload) VALUES (?,?)",
                        (item["id"], json.dumps(item, ensure_ascii=False))
                    )
                    added += 1
            con.execute(
                "INSERT OR REPLACE INTO source_status VALUES (?,?,?,?)",
                (sid, now(), "OK", added)
            )
            con.commit()
            print(json.dumps({"source": sid, "status": "OK",
                              "new_items": added, "feed_items": len(items)}),
                  flush=True)
            good += 1
        except Exception as e:
            reason = str(e)[:100] or type(e).__name__
            con.execute(
                "INSERT OR REPLACE INTO source_status VALUES (?,?,?,?)",
                (sid or "invalid-source", now(), reason, 0)
            )
            con.commit()
            print(json.dumps({"source": sid or "invalid-source",
                              "status": "ERROR", "reason": reason}), flush=True)
    return good


def deliver(con, config):
    dest = config.get("outbound")
    if not isinstance(dest, dict):
        return
    url = dest.get("url", "")
    env_name = dest.get("token_env", "")
    allowed = config.get("outbound_allow_hosts", [])
    if not env_name or not os.environ.get(env_name):
        print('{"outbound":"disabled","reason":"DESTINATION_TOKEN_NOT_SET"}',
              flush=True)
        return
    try:
        validate_url(url, allowed)
    except Exception as e:
        print(json.dumps({"outbound": "blocked", "reason": str(e)}), flush=True)
        return

    opener = urllib.request.build_opener(SafeRedirect(allowed))

    rows = con.execute(
        "SELECT id,payload,attempts FROM outbox "
        "WHERE sent_at IS NULL AND next_attempt <= ? ORDER BY rowid LIMIT 10",
        (time.time(),)
    ).fetchall()
    for event_id, payload, attempts in rows:
        try:
            body = json.dumps({"type": "iao.information.event", "event":
                               json.loads(payload)}).encode()
            req = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer " + os.environ[env_name],
                         "User-Agent": UA}
            )
            with opener.open(req, timeout=12) as response:
                if not 200 <= response.status < 300:
                    raise ValueError("HTTP_STATUS_" + str(response.status))
                response.read(4096)
            con.execute("UPDATE outbox SET sent_at=? WHERE id=?", (now(), event_id))
            con.commit()
            print(json.dumps({"outbound": "sent", "event_id": event_id[:12]}),
                  flush=True)
        except Exception:
            delay = min(3600, 15 * (2 ** min(attempts, 8)))
            con.execute(
                "UPDATE outbox SET attempts=attempts+1,next_attempt=? WHERE id=?",
                (time.time() + delay, event_id)
            )
            con.commit()
            print(json.dumps({"outbound": "retry_scheduled",
                              "event_id": event_id[:12], "delay_seconds": delay}),
                  flush=True)


def status(con):
    count = con.execute("SELECT COUNT(*) FROM inbox").fetchone()[0]
    pending = con.execute(
        "SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL"
    ).fetchone()[0]
    sources = con.execute(
        "SELECT source,checked_at,status,items_new FROM source_status ORDER BY source"
    ).fetchall()
    print(json.dumps({"component": "IAO_INFORMATION_FLOW",
                      "database": str(DB), "stored_events": count,
                      "pending_outbound": pending, "sources": sources},
                     ensure_ascii=False), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--loop", action="store_true")
    args = ap.parse_args()
    config = json.loads(CONFIG.read_text())
    interval = max(30, min(3600, int(config.get("poll_seconds", 60))))
    con = open_db()
    try:
        if args.status:
            status(con)
            return
        while True:
            poll(con, config)
            deliver(con, config)
            status(con)
            if not args.loop:
                break
            time.sleep(interval)
    finally:
        con.close()


if __name__ == "__main__":
    main()
