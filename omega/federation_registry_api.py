import json
import urllib.request

class FederationRegistry:
    def register_external_node(self, url: str, name: str, capability: str):
        """Registra un nodo externo de forma automática."""
        # Verificar si el nodo responde
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "IAO-Registry"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    # Añadir a la memoria (se guardará en GitHub)
                    from omega.federation_discovery_engine import discovery
                    discovery.memory[name] = {
                        "url": url,
                        "status": "active",
                        "capability": capability,
                        "format": "json"
                    }
                    discovery._save_memory_remote()
                    return f"Nodo {name} registrado exitosamente en la federación."
        except Exception as e:
            return f"Error: {str(e)}"
        return "El nodo no respondió."

registry = FederationRegistry()
