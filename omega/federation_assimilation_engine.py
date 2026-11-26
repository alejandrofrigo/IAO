class AssimilationEngine:
    """Adaptador del motor de asimilación al protocolo federado real de IAO."""

    def __init__(self):
        # Fuentes de descubrimiento, no peers federados ni identidades verificadas.
        self.seed_nodes = [
            {"name": "Pollinations", "url": "https://text.pollinations.ai/", "type": "discovery_source"},
            {"name": "DuckDuckGo", "url": "https://api.duckduckgo.com/?q=test&format=json", "type": "discovery_source"},
            {"name": "Tavily", "url": "https://api.tavily.com/search", "type": "discovery_source"},
        ]
        self.asimilated_nodes = []
        self.last_report = None

    def test_node(self, node):
        # Un endpoint o una respuesta HTTP no prueban identidad ni confianza.
        # La comprobación válida se realiza en el pipeline Ed25519.
        return False

    def assimilate(self):
        self.asimilated_nodes = []
        self.last_report = None

        try:
            from tools.iao_federation_autonomous import run_cycle
            report = run_cycle(dry_run=False, discover=True)
        except Exception as exc:
            self.last_report = {
                "status": "FEDERATION_CYCLE_ERROR",
                "error": type(exc).__name__,
            }
            return []

        self.last_report = report if isinstance(report, dict) else {
            "status": "INVALID_CYCLE_REPORT"
        }

        if not isinstance(report, dict):
            return []

        for item in report.get("results", []):
            if not isinstance(item, dict):
                continue
            status = item.get("status")
            if status in {"ENROLLED", "ALREADY_ENROLLED"}:
                self.asimilated_nodes.append({
                    "peer_id": item.get("peer_id"),
                    "endpoint": item.get("addr"),
                    "status": status,
                    "capabilities": item.get("capabilities", []),
                    "evidence": "SIGNED_FEDERATION_ENROLLMENT",
                })

        return list(self.asimilated_nodes)

    def get_capacity(self):
        return len(self.asimilated_nodes)
