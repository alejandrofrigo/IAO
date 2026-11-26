#!/usr/bin/env python
"""Operaciones locales de administración de dispositivos IAO."""
import argparse
import os
from pathlib import Path

from omega.store import Store
from omega.device_authority import issue_enrollment, revoke_device


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("issue", "revoke"))
    parser.add_argument("device_id", nargs="?")
    parser.add_argument("--state", default=os.environ.get("OMEGA_STATE_DIR", ".state"))
    args = parser.parse_args()

    key_path = Path.home() / ".config" / "iao" / "audit-hmac-key"
    if not key_path.is_file():
        raise SystemExit("ERROR: falta la clave persistente de auditoría")
    audit_key = key_path.read_text().strip().encode()
    if len(audit_key) < 32:
        raise SystemExit("ERROR: clave de auditoría no válida")

    store = Store(Path(args.state) / "omega.db", audit_key=audit_key)
    try:
        if args.action == "issue":
            code = issue_enrollment(store, ttl=600)
            print("CODIGO_DE_ENROLAMIENTO (válido 10 minutos; úsalo una sola vez):")
            print(code)
        else:
            if not args.device_id:
                raise SystemExit("Uso: tools/iao_device_authority.py revoke DEVICE_ID")
            print("REVOCADO" if revoke_device(store, args.device_id) else "NO_CAMBIADO")
    finally:
        store.close()


if __name__ == "__main__":
    main()
