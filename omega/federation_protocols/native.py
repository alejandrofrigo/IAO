"""Adaptador iao-federation (protocolo propio de omega.federation)."""
from __future__ import annotations
import base64, json, os, ssl, urllib.request
from . import ProtocolAdapter, register
import omega.federation_transport as federation_transport

class NativeAdapter(ProtocolAdapter):
    name = "iao-federation"

    @staticmethod
    def _ssl_context():
        """Contexto TLS desde IAO_TLS_CA_FILE si está definido.

        En producción no se define: se usa el almacén del sistema.
        En tests con CA propia, se confía explícitamente en esa CA.
        Sin esto, un certificado autofirmado haría fallar el probe aunque
        el servidor TLS sea correcto.
        """
        ca_file = os.environ.get("IAO_TLS_CA_FILE")
        if not ca_file:
            return None
        ctx = ssl.create_default_context(cafile=ca_file)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def probe(self, addr: str, timeout: float = 5.0):
        endpoint = addr.rstrip("/")
        try:
            doc = federation_transport.request_json(
                endpoint + "/fed/v1/identity",
                method="GET",
                timeout=timeout,
                max_bytes=4096,
                ssl_context=self._ssl_context(),
                allow_loopback=(
                    os.environ.get("IAO_ALLOW_LOOPBACK_HTTP", "") == "1"
                ),
            )
            if (
                isinstance(doc, dict)
                and doc.get("protocol") == "iao-federation"
                and doc.get("version") == 1
                and isinstance(doc.get("node_id"), str)
                and isinstance(doc.get("public_key"), str)
            ):
                return {
                    "endpoint": endpoint,
                    "identity_doc": doc,
                    "protocol": "iao-federation",
                }
        except Exception:
            pass
        return None

    def to_participation_contract(self, candidate: dict) -> dict | None:
        doc = candidate["identity_doc"]
        try: raw = bytes.fromhex(doc["public_key"])
        except ValueError: return None
        return {"peer_id": doc["node_id"], "pubkey": base64.b64encode(raw).decode(),
                "capabilities": ["knowledge.search"], "lease_expires_at": 0.0,
                "rate_limit_per_min": 30,
                "endpoint": candidate["endpoint"].rstrip("/") + "/fed/v1/message"}
register(NativeAdapter())
