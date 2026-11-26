import json
import time
import urllib.request
import urllib.error
import re
import subprocess
from omega.command_swarm import CommandSwarm

class UniversalAssimilator:
    def __init__(self):
        self.command_swarm = CommandSwarm()
        self.directories = [
            "https://raw.githubusercontent.com/public-apis/public-apis/master/README.md",
            "https://raw.githubusercontent.com/n0shake/Public-APIs/master/README.md"
        ]
        self.assimilated = {}

    def _extract_urls(self, text):
        urls = re.findall(r'https?://[^\s\)\"\']+', text)
        valid = [u for u in urls if "github.com" not in u and "docs" not in u]
        return list(set(valid))[:5]

    def _test_server(self, url):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "IAO-Crawler"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                return resp.status in (200, 201, 202, 301, 302)
        except:
            return False

    def assimilate(self):
        print("[IAO UNIVERSAL] Escaneando Internet...")
        nuevos = 0
        for directory in self.directories:
            try:
                req = urllib.request.Request(directory, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    text = resp.read().decode('utf-8')
                    urls = self._extract_urls(text)
                    for url in urls:
                        if url not in self.assimilated:
                            if self._test_server(url):
                                print(f"[IAO UNIVERSAL] ✅ Servidor asimilado: {url}")
                                self.assimilated[url] = {"status": "active"}
                                # Registrar en la Sub-red de Mando
                                self.command_swarm.register_managed_node(url)
                                nuevos += 1
            except Exception as e:
                print(f"[IAO UNIVERSAL] Error: {e}")
        print(f"[IAO UNIVERSAL] Ciclo terminado. Nuevos: {nuevos}. Total: {len(self.assimilated)}")
        return nuevos

if __name__ == "__main__":
    assimilator = UniversalAssimilator()
    while True:
        assimilator.assimilate()
        time.sleep(300)
