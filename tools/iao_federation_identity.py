#!/usr/bin/env python3
"""Create or verify IAO's persistent local federation identity."""
import hashlib
import stat
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from omega.federation_identity import KEY_PATH, load_or_create_key, public_identity  # noqa: E402

def main() -> int:
    key = load_or_create_key()
    node_id, public_hex = public_identity(key)
    path = KEY_PATH.resolve()
    mode = stat.S_IMODE(path.stat().st_mode)

    print("IAO FEDERATION IDENTITY")
    print("IDENTITY_STATUS=READY")
    print("NODE_ID=" + node_id)
    print("PUBLIC_KEY_SHA256=" + hashlib.sha256(bytes.fromhex(public_hex)).hexdigest())
    print("PRIVATE_KEY_PATH=" + str(path))
    print("PRIVATE_KEY_MODE=" + oct(mode))
    print("PRIVATE_KEY_EXPORTED=NO")
    print("IDENTITY_PERSISTENCE=LOCAL_FILE")
    return 0 if mode == 0o600 else 1

if __name__ == "__main__":
    raise SystemExit(main())
