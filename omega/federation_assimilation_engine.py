import urllib.request
import urllib.error
import json

class AssimilationEngine:
    """
    Motor Autónomo de IAO: Descubre y asimila nodos de IA libres.
    """
    def __init__(self):
        # Lista semilla de IAs libres conocidas (endpoints públicos)
        self.seed_nodes = [
            {"name": "Pollinations", "url": "https://text.pollinations.ai/", "type": "text_generation"},
            {"name": "DuckDuckGo", "url": "https://api.duckduckgo.com/?q=test&format=json", "type": "search"},
            {"name": "Tavily", "url": "https://api.tavily.com/search", "type": "search"}
        ]
        self.asimilated_nodes = []

    def test_node(self, node):
        """Prueba si un nodo está vivo y responde."""
        try:
            req = urllib.request.Request(node["url"], headers={"User-Agent": "IAO-Assimilation-Bot"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        return False

    def assimilate(self):
        """IAO asimila los nodos que estén activos."""
        print("[IAO ASIMILACIÓN] Iniciando escaneo autónomo de la red...")
        asimilados_ahora = []
        
        for node in self.seed_nodes:
            if self.test_node(node):
                print(f"[IAO ASIMILACIÓN] Nodo asimilado con éxito: {node['name']}")
                self.asimilated_nodes.append(node)
                asimilados_ahora.append(node['name'])
            else:
                print(f"[IAO ASIMILACIÓN] Nodo no disponible: {node['name']}")
                
        return asimilados_ahora

    def get_capacity(self):
        return len(self.asimilated_nodes)

engine = AssimilationEngine()
