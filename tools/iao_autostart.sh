#!/data/data/com.termux/files/usr/bin/bash
# Arranca FedServer + Cloudflare Quick Tunnel + actualiza directorio + pipeline --watch
set -euo pipefail
cd ~/so-omega-prime

LOG="$HOME/iao-autostart.log"
FED_LOG="$HOME/.iao-fedserver.log"
CF_LOG="$HOME/.iao-cloudflared.log"
WATCH_LOG="$HOME/.iao-federation-watch.log"

exec >> "$LOG" 2>&1
echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) arrancando federación ==="

pkill -f "iao_fedserver_public.py" 2>/dev/null || true
pkill -f "cloudflared tunnel" 2>/dev/null || true
pkill -f "iao_federation_autonomous.py --watch" 2>/dev/null || true
sleep 2

nohup python3 tools/iao_fedserver_public.py --port 8443 > "$FED_LOG" 2>&1 &
FED_PID=$!
sleep 3
if ! kill -0 "$FED_PID" 2>/dev/null; then
  echo "ERROR: FedServer no arrancó. Log:"
  cat "$FED_LOG"
  exit 1
fi

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "ERROR: cloudflared no instalado"
  exit 1
fi

nohup cloudflared tunnel --url http://127.0.0.1:8443 > "$CF_LOG" 2>&1 &
sleep 12

TUNNEL_URL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$CF_LOG" | tail -1)
if [[ -z "$TUNNEL_URL" ]]; then
  echo "ERROR: no se pudo extraer URL del túnel"
  tail -30 "$CF_LOG"
  exit 1
fi
echo "Túnel activo: $TUNNEL_URL"

python3 - "$TUNNEL_URL" <<'PY'
import json, sys
from pathlib import Path
url = sys.argv[1]
p = Path(".state/iao-external-nodes.json")
d = json.loads(p.read_text()) if p.exists() else {"nodes": []}
for n in d.get("nodes", []):
    if n.get("id") == "9db367aad0b70421":
        n["url"] = url; n["authorized"] = True
p.write_text(json.dumps(d, indent=2))
print("iao-external-nodes.json ->", url)
PY

python3 - "$TUNNEL_URL" <<'PY'
import json, base64, sys
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
url = sys.argv[1]
key = load_pem_private_key(Path(".state/federation/identity/private.pem").read_bytes(), password=None)
manifest = json.loads(Path(".state/federation/identity/manifest.json").read_text())
pub = key.public_key().public_bytes_raw().hex()
doc = {"protocol": "iao-federation-directory", "version": 1,
       "peers": [{"id": manifest["node_id"], "url": url,
                  "public_key": pub, "capabilities": ["health", "knowledge.search"]}]}
body = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
doc["sig"] = base64.b64encode(key.sign(body)).decode()
Path(".state/my-federation-directory.json").write_text(json.dumps(doc, indent=2))
print("Directorio firmado actualizado")
PY

nohup python3 tools/iao_federation_autonomous.py --watch > "$WATCH_LOG" 2>&1 &
echo "Pipeline --watch arrancado. Log: $WATCH_LOG"
echo "=== Completado. URL: $TUNNEL_URL ==="
