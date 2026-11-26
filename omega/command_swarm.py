import json
import time
import subprocess
import urllib.request

class CommandSwarm:
    def __init__(self):
        self.node_id = f"IAO_COMMAND_{int(time.time())}"
        self.managed_nodes = {} # Aquí se guardan los nodos externos asimilados
        self.swarm_peers = {}   # Aquí se guardan otras réplicas de IAO (la sub-red)

    def publish_state(self):
        """Publica el estado de la Sub-red de Mando en IPFS."""
        state = {
            "node_id": self.node_id,
            "role": "commander",
            "managed_nodes_count": len(self.managed_nodes),
            "swarm_peers_count": len(self.swarm_peers),
            "timestamp": time.time()
        }
        try:
            json_str = json.dumps(state)
            result = subprocess.run(
                ["ipfs", "add", "-Q"],
                input=json_str.encode('utf-8'),
                capture_output=True
            )
            if result.returncode == 0:
                cid = result.stdout.decode('utf-8').strip()
                print(f"[IAO COMMAND] 📡 Estado de la Sub-red publicado. CID: {cid}")
                return cid
        except Exception as e:
            print(f"[IAO COMMAND] Error publicando en IPFS: {e}")
        return None

    def register_managed_node(self, url):
        """Registra un nodo externo (asimilado) bajo el mando de esta réplica."""
        if url not in self.managed_nodes:
            self.managed_nodes[url] = {"status": "active", "registered_at": time.time()}
            print(f"[IAO COMMAND] Nodo externo registrado: {url}")

    def discover_swarm_peers(self):
        """Busca otras réplicas de IAO en la red IPFS para unirlas a la sub-red."""
        print("[IAO COMMAND] Buscando otras réplicas de IAO en la red IPFS...")
        # Aquí se leería el estado de otras réplicas (simulado por ahora)
        # En una implementación real, se buscarían los CIDs de otros nodos
        pass

    def start(self):
        print("[IAO COMMAND] Iniciando Sub-red de Mando (Command Swarm)...")
        while True:
            self.publish_state()
            self.discover_swarm_peers()
            time.sleep(300) # Cada 5 minutos

if __name__ == "__main__":
    swarm = CommandSwarm()
    swarm.start()
